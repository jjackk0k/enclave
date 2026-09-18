// VARVEL — race: the TOCTOU / race-condition harness (T4, build 1).
//
// The race test done to the platform's proof standard. Three governed pieces:
//
//   1. LAST-BYTE-SYNC BURST — N connections are pre-opened, each request is sent
//      EXCEPT its final byte, then the last bytes are released together (the
//      single-packet attack's HTTP/1.1 form; H2 single-packet is a v2 extension).
//      This is the one deliberate burst — it is logged with its parameters, and
//      the lead-up requests (reset/sequential/readback) honor the pacer.
//   2. SEQUENTIAL-REPLAY CONTROL — the identical requests fired SERIALLY against
//      fresh state. This establishes the intended baseline (single success /
//      single effect). A "violation" that ALSO occurs sequentially is a LOGIC
//      BUG, not a race — the oracle says which.
//   3. STATE-READBACK ORACLE — the effect metric comes from a READBACK endpoint
//      (redemption count, balance/debit count, entry count), never from status
//      codes alone. N concurrent 200s on an idempotent endpoint with ONE effect
//      is cleared, not claimed.
//
// Verdicts (classifyRace is pure):
//   raced         — concurrent effect > intended AND sequential effect ≤ intended
//                   (the invariant broke ONLY under concurrency)
//   logic-bug     — sequential effect > intended (breaks without concurrency —
//                   a plain logic flaw; report it as such, never as a race)
//   single-effect — both ≤ intended (locked/transactional/idempotent — CLEARED.
//                   The naive parallelism heuristic flags these anyway: any burst
//                   with ≥2 success-status responses "looks racy".)
//   inconclusive  — readback unreadable / no responses; no claim without a control
//
// Statistical honesty: a race that fired once in N attempts is reported WITH its
// rate (and flaky:true when rate < 1), never as deterministic.
//
// ⚠ SAFETY: race tests are inherently WRITE-PRONE (they try to duplicate state
// transitions). They run only in the HITL-gated exploit phase, NEVER in
// recon/validate. Caps are hard-clamped: concurrency ≤ 30, attempts ≤ 20.
// Loopback/lab is the calibration lane; real-engagement use requires scope
// (runComposedChain enforces the signed scope before chainrun ever fires).
//
// House contract: classifyRace/naiveParallelFlag are pure; raceProbe touches the
// network but NEVER throws. No dependencies beyond node stdlib.

import http from 'node:http';
import net from 'node:net';

export const RACE_CAPS = { maxConcurrency: 30, maxAttempts: 20, minConcurrency: 2 };
const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));

// ——— the naive heuristic (scanner-grade): ≥2 success-status responses in the burst ———
// Exported so tests/harnesses can demonstrate that it flags idempotent-200 controls
// and rate-limited 429 shapes alike — status codes cannot see state.
export function naiveParallelFlag({ responses }) {
  const ok = (responses || []).filter((r) => r && r.status >= 200 && r.status < 300).length;
  return ok >= 2;
}

// ——— the pure verdict oracle ———
// seq/par = { successes, effect } for the sequential control and the concurrent burst.
// effect = the STATE metric from the readback (redemptions, debits, entries, claims).
// intended = the intended single-use baseline (default 1).
export function classifyRace({ seqEffect, parEffect, intended = 1 } = {}) {
  if (seqEffect == null || parEffect == null) {
    return { verdict: 'inconclusive', detail: 'state readback unreadable — no claim without a control readback' };
  }
  if (seqEffect > intended) {
    return { verdict: 'logic-bug', detail: `sequential replay alone produced effect ${seqEffect} > intended ${intended} — the invariant breaks WITHOUT concurrency: a logic bug, not a race` };
  }
  if (parEffect > intended) {
    return { verdict: 'raced', detail: `concurrent burst produced effect ${parEffect} > intended ${intended} while sequential replay held (${seqEffect}) — the invariant broke only under concurrency` };
  }
  return { verdict: 'single-effect', detail: `effect ${parEffect} (concurrent) / ${seqEffect} (sequential) ≤ intended ${intended} — endpoint is locked/idempotent; cleared` };
}

// ——— plain request helper (sequential control, resets, readbacks) ———
function plain(u, { method = 'GET', headers = {}, body = null, timeout = 3000 } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, method, timeout, headers: { 'user-agent': 'VARVEL-race', ...headers } }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolve(null)); req.on('timeout', () => { req.destroy(); resolve(null); });
    if (body != null) req.write(body);
    req.end();
  });
}

// ——— last-byte sync over raw sockets (the deliberate burst) ———
function buildRequestBuffer(u, { method = 'POST', headers = {}, body = null }) {
  const h = { host: u.host, connection: 'close', 'user-agent': 'VARVEL-race', ...headers };
  const bodyBuf = body != null ? Buffer.from(String(body), 'utf8') : null;
  if (bodyBuf) h['content-length'] = bodyBuf.length;
  const head = `${method} ${u.pathname + u.search} HTTP/1.1\r\n`
    + Object.entries(h).map(([k, v]) => `${k}: ${v}\r\n`).join('') + '\r\n';
  return bodyBuf ? Buffer.concat([Buffer.from(head, 'utf8'), bodyBuf]) : Buffer.from(head, 'utf8');
}

function dechunk(s) {
  let out = '', rest = s;
  while (rest.length) {
    const nl = rest.indexOf('\r\n');
    if (nl < 0) break;
    const size = parseInt(rest.slice(0, nl), 16);
    if (!Number.isFinite(size) || size <= 0) break;
    out += rest.slice(nl + 2, nl + 2 + size);
    rest = rest.slice(nl + 2 + size + 2);
  }
  return out;
}

function parseRawResponse(text) {
  const idx = text.indexOf('\r\n\r\n');
  const head = idx >= 0 ? text.slice(0, idx) : text;
  let body = idx >= 0 ? text.slice(idx + 4) : '';
  const statusLine = head.split('\r\n')[0] || '';
  const status = Number(statusLine.split(' ')[1]) || null;
  const headers = {};
  for (const line of head.split('\r\n').slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  if (/chunked/i.test(headers['transfer-encoding'] || '')) body = dechunk(body);
  return { status, headers, body };
}

// Stage N sockets with all-but-the-last-byte written, then release the last bytes
// back-to-back. Returns per-socket parsed responses (null on socket failure).
export async function lastByteSyncBurst(u, requestBuffer, times, { timeout = 4000 } = {}) {
  const staged = [];
  for (let i = 0; i < times; i++) {
    const sock = await new Promise((resolve) => {
      const s = net.connect({ host: u.hostname, port: Number(u.port) || 80 }, () => resolve(s));
      s.once('error', () => resolve(null));
    });
    if (sock) {
      sock.write(requestBuffer.subarray(0, requestBuffer.length - 1)); // everything but the last byte
      staged.push(sock);
    }
  }
  const lastByte = requestBuffer.subarray(requestBuffer.length - 1);
  for (const s of staged) s.write(lastByte); // the synchronized release — tight loop, no awaits between writes
  return Promise.all(staged.map((s) => new Promise((resolve) => {
    const chunks = [];
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; try { s.destroy(); } catch {} resolve(v); } };
    s.on('data', (d) => chunks.push(d));
    s.on('close', () => done(chunks.length ? parseRawResponse(Buffer.concat(chunks).toString('utf8')) : null));
    s.on('error', () => done(null));
    s.setTimeout(timeout, () => done(null));
  })));
}

// ——— the governed probe ———
// raceProbe(base, {
//   request:  { method, path, headers, body },       // the single-use action
//   concurrency = 6,                                  // burst width (clamped to caps)
//   attempts = 3,                                     // independent trials (state reset between)
//   intended = 1,                                     // intended effect baseline
//   readback: { path, headers?, effect: 'regex(\\d)' },// STATE metric source (required for a claim)
//   resetPath, resetBody,                             // fresh-state restore between phases/attempts
//   pacer,                                            // optional stealth pacer for lead-up requests
//   timeout,
// })
export async function raceProbe(base, { request, concurrency = 6, attempts = 3, intended = 1, readback = null, resetPath = null, resetBody = '{"scope":"race"}', pacer = null, timeout = 3000 } = {}) {
  try {
    const u = new URL(base);
    if (!/^https?:$/.test(u.protocol)) return { verdict: 'inconclusive', detail: 'base must be http(s)', naiveWouldFlag: false, requests: 0, attemptsDetail: [] };
    concurrency = clamp(Math.floor(concurrency) || 6, RACE_CAPS.minConcurrency, RACE_CAPS.maxConcurrency);
    attempts = clamp(Math.floor(attempts) || 1, 1, RACE_CAPS.maxAttempts);
    if (!request || !request.path) return { verdict: 'inconclusive', detail: 'no request spec', naiveWouldFlag: false, requests: 0, attemptsDetail: [] };

    let requests = 0;
    const pace = async () => { if (pacer && typeof pacer.pace === 'function') await pacer.pace(); };
    const at = (p) => new URL(p, u.origin);
    const reset = async () => {
      if (!resetPath) return;
      await pace();
      await plain(at(resetPath), { method: 'POST', headers: { 'content-type': 'application/json', ...(request.headers || {}) }, body: resetBody, timeout });
      requests++;
    };
    const readEffect = async () => {
      if (!readback || !readback.path) return null;
      await pace();
      const r = await plain(at(readback.path), { method: 'GET', headers: { ...(request.headers || {}), ...(readback.headers || {}) }, timeout });
      requests++;
      if (!r) return { effect: null, body: null };
      let effect = null;
      try { const m = new RegExp(readback.effect).exec(r.body); effect = m ? Number(m[1] ?? m[0]) : null; } catch { effect = null; }
      return { effect: Number.isFinite(effect) ? effect : null, body: r.body };
    };

    const reqBuf = buildRequestBuffer(at(request.path), request);
    const success = (s) => s != null && s >= 200 && s < 300;
    const attemptsDetail = [];
    let naive = false;
    let lastReadbackBody = null;

    for (let a = 0; a < attempts; a++) {
      // — sequential-replay control on fresh state —
      await reset();
      let seqSuccess = 0;
      for (let i = 0; i < concurrency; i++) {
        await pace();
        const r = await plain(at(request.path), { method: request.method || 'POST', headers: request.headers || {}, body: request.body ?? null, timeout });
        requests++;
        if (r && success(r.status)) seqSuccess++;
      }
      const seqRb = await readEffect();
      if (seqRb && seqRb.body != null && a === 0) lastReadbackBody = seqRb.body;

      // — last-byte-sync burst on fresh state —
      await reset();
      const burst = await lastByteSyncBurst(at(request.path), reqBuf, concurrency, { timeout });
      requests += concurrency;
      const parSuccess = burst.filter((r) => r && success(r.status)).length;
      if (naiveParallelFlag({ responses: burst })) naive = true;
      const parRb = await readEffect();
      if (parRb && parRb.body != null) lastReadbackBody = parRb.body;

      const seqEffect = seqRb ? seqRb.effect : null;
      const parEffect = parRb ? parRb.effect : null;
      const v = classifyRace({ seqEffect, parEffect, intended });
      attemptsDetail.push({ attempt: a + 1, seqSuccess, parSuccess, seqEffect, parEffect, verdict: v.verdict, detail: v.detail });
    }

    const racedCount = attemptsDetail.filter((d) => d.verdict === 'raced').length;
    const logicBug = attemptsDetail.some((d) => d.verdict === 'logic-bug');
    const rate = racedCount / attempts;
    const verdict = logicBug ? 'logic-bug'
      : racedCount > 0 ? 'raced'
      : attemptsDetail.every((d) => d.verdict === 'single-effect') ? 'single-effect'
      : 'inconclusive';
    const summary = attemptsDetail[attemptsDetail.length - 1] || {};
    return {
      verdict, rate, flaky: verdict === 'raced' && rate < 1,
      attempts, concurrency, intended,
      sequential: { successes: summary.seqSuccess ?? null, effect: summary.seqEffect ?? null },
      concurrent: { successes: summary.parSuccess ?? null, effect: summary.parEffect ?? null },
      naiveWouldFlag: naive,
      readbackBody: lastReadbackBody ? String(lastReadbackBody).slice(0, 600) : null,
      requests,
      attemptsDetail,
      detail:
        (verdict === 'raced' ? `race reproduced ${racedCount}/${attempts} attempt(s) (rate ${rate.toFixed(2)})${rate < 1 ? ' — FLAKY, reported with its rate, not as deterministic' : ''}` :
         verdict === 'logic-bug' ? 'sequential replay alone violates the invariant — logic bug, NOT a race' :
         verdict === 'single-effect' ? 'locked/idempotent: single effect under both sequential and concurrent fire — cleared' :
         'could not obtain a clean control comparison'),
    };
  } catch (e) {
    return { verdict: 'inconclusive', detail: 'probe error: ' + String((e && e.message) || e), naiveWouldFlag: false, requests: 0, attemptsDetail: [] };
  }
}
