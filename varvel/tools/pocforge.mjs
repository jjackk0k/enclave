// VARVEL — pocforge: the exploit-design stage (the "PoC-forge"). Takes a
// replay-VERIFIED hunt finding — today that means "version→CVE match, the
// fingerprint reproduced in a fresh isolated sandbox" — and tries to
// demonstrate REAL exploitability: find the sink, build the payload, capture
// the impact. On success it upgrades the outbox draft from
// "VERIFIED (replay-verification PASSED)" to "VERIFIED (PoC demonstrated)"
// with the observed impact written in — and the honesty section keeps naming
// what is STILL unproven.
//
// It is driven BY HAND or by the VARVEL Ops Console (the BUILD PoC button):
//   node tools/pocforge.mjs --finding <evidence-dir> [--outbox <dir>] [--dir d]
//                          [--attempts n] [--base-url u] [--model id]
// One finding per run, ONE JSON result line on stdout (the console parses it);
// progress rides stderr and the hunt dir's events.jsonl (stage 'poc-forge',
// heartbeats, per-attempt 'poc-forge' events, a 'proof' event on success).
//
// HARD RULES (the same revenue-safe doctrine as tools/huntloop.mjs):
//   1. THE FORGE NEVER SUBMITS. There is no submission code path in this
//      file — no platform API, not behind a flag. The ONLY remote
//      conversations are the LOCAL brain (OpenAI-compatible, through
//      engine/brain-provider.mjs callOpenAI — reused, never reimplemented)
//      and the READ-ONLY target probe (rule 3). Drafts wait in the outbox
//      for the operator's hand, always.
//   2. NEVER FAKE A PROOF. 'poc-verified' is stamped ONLY when a probe the
//      forge actually sent returned the DECLARED impact marker in the REAL
//      live response (reflected marker / version banner / error oracle),
//      captured verbatim in poc-transcript.txt. Attempts exhausted without
//      the marker = 'poc-unproven'; the machinery failing (contract
//      violations, scope refusals, transport down, watchdog) = 'check-defect'
//      — a defect is never an evaluated claim (AGENTS.md honesty contract).
//   3. READ-ONLY PROOF POLICY (absolute): the only actions that can reach the
//      wire are GET, HEAD, and POST carrying the run's INERT canary marker —
//      no state-changing verbs, no credential headers (authorization/cookie/
//      x-api-key are refused at the contract parse, before any byte), bounded
//      bodies, a declared observable impact marker required up front. The
//      impact must be observable IN THE RESPONSE, or the forge gives up
//      honestly. State-changing proof is operator sign-off territory.
//   4. SCOPE IS LAW, TWICE. Every probe URL passes the scope guard BEFORE a
//      byte leaves (gather.mjs's rail, re-applied): the default guard is
//      derived FROM THE VERIFIED EVIDENCE — only hosts the hunt actually
//      fingerprinted can ever receive a probe; anything else throws
//      'scope-violation', fail-closed, recorded LOUDLY, never sent. All
//      external bytes ride the ghost chain (ghostFetch, fail-closed); no
//      chain = direct, named honestly in the events AND the result.
//   5. BOUNDED + HOST-SIDE PROBES. ≤3 brain attempts (each ≤600s, recon's
//      lane budget), a whole-stage watchdog (huntloop's withWatchdog,
//      reused), heartbeats while the brain thinks, response reads capped.
//      Probes run HOST-SIDE through gather's exact wire path — the docker
//      sandbox stages are --network none BY DESIGN, so a live-target probe
//      can never leave them; gather is the only module that talks to targets
//      and this stage mirrors it (scope guard + ghostFetch + cadence), it
//      does not improvise a new network path.
//
// FILES (written by THIS module, inside the finding's evidence bundle):
//   poc-transcript.txt   timestamped forge transcript (the proof narrative)
//   poc-result.json      { verified, verdictClass, reason, attempts, proof?,
//                          transcriptSha256, transport, scopeGuard, at }
// and, on poc-verified only, the matching outbox/*.md draft is upgraded in
// place (the TODO(validate) lines the proof answers are filled; the scope
// attestation TODO stays unless signed scope exists in the evidence — today
// no gather bundle carries one, so it always stays).

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname, basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import { makeEmitter, withWatchdog, BRAIN_RECON_TIMEOUT_MS, HEARTBEAT_MS } from './huntloop.mjs';
import { resolveBrain, callOpenAI } from '../engine/brain-provider.mjs';
import { resolveGhostChain, ghostFetch } from './ghostfetch.mjs';
import { brainSummary } from './gather.mjs';
import { cveCheck } from '../engine/cvepacks.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));

export const DOCTRINE = 'the PoC-forge takes a replay-verified finding and tries to demonstrate REAL exploitability — read-only, scope-guarded, ghost-routed, bounded — it NEVER submits; a proof is a captured marker, never an assertion.';

// THE FORGE BUDGET — every number rides the events so policy text and behavior
// can never silently disagree (gather's CADENCE doctrine).
export const FORGE = {
  maxAttempts: 3,                       // brain iterations per finding
  maxAttemptsCap: 6,                    // the cap can tighten, never balloon
  brainTimeoutMs: BRAIN_RECON_TIMEOUT_MS, // 600000 — recon's lane budget
  watchdogMs: 19 * 60 * 1000,           // whole-stage bound — inside the console's 20-min wait
  heartbeatMs: HEARTBEAT_MS,            // liveness while the brain thinks
  probeTimeoutMs: 15000,                // per-probe whole-operation timeout (gather's number)
  delayMs: 500,                         // between target requests (gather's cadence floor)
  maxBodyKB: 256,                       // response read cap (gather's number)
  maxPostBody: 4096,                    // inert-marker POST body cap
  maxMarkerLen: 200,                    // declared impact marker cap
};

export const READ_ONLY_METHODS = ['GET', 'HEAD', 'POST'];
// The proof is UNAUTHENTICATED by construction — a credential header can never
// ride a forge probe (the auth-bands doctrine: unauthenticated impact or nothing).
export const FORBIDDEN_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'x-api-key'];

const sha256 = (x) => createHash('sha256').update(typeof x === 'string' ? x : JSON.stringify(x)).digest('hex');
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const readJson = (p, fb) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return fb; } };
const writeJson = (p, obj) => writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');

// --- the evidence bundle (check.txt's inline JSON, result.json's verdict) ----------------
// The mechanical check inlines the gathered bundle as a JS string literal
// (mechanicalCandidates: JSON.stringify(JSON.stringify(bundle))) — extracted
// and parsed STRICTLY; a hand-shaped bundle is not evidence and is refused.
export function parseEvidenceBundle(evidenceDir) {
  let checkText = null;
  try { checkText = readFileSync(join(evidenceDir, 'check.txt'), 'utf8'); } catch { checkText = null; }
  if (checkText === null) {
    return { ok: false, error: 'evidence-incomplete', reason: `check.txt missing in ${evidenceDir} — the finding cannot be re-derived, nothing is invented` };
  }
  const result = readJson(join(evidenceDir, 'result.json'), null);
  const env = readJson(join(evidenceDir, 'env.json'), null);
  let bundle = null;
  const m = checkText.match(/JSON\.parse\(("(?:[^"\\]|\\.)*")/);
  if (m) {
    try { bundle = JSON.parse(JSON.parse(m[1])); } catch { bundle = null; }
  }
  if (!bundle || !Array.isArray(bundle.assets)) {
    return { ok: false, error: 'bundle-not-found', reason: 'check.txt carries no parseable inline evidence bundle — the forge only takes gather-produced mechanical evidence (never a hand-typed bundle)' };
  }
  return { ok: true, bundle, result, env, checkText };
}

// The run canary: deterministic per finding, required verbatim inside any POST
// body so a state-capable request is always inert AND self-labeling.
export const forgeCanary = (evidenceDir) => `VARVEL-POC-INERT-${sha256(String(evidenceDir)).slice(0, 10)}`;

export function deriveCve(finding, evidenceDir) {
  const text = `${(finding && finding.title) || ''} ${basename(String(evidenceDir || ''))}`;
  const m = text.match(/CVE-\d{4}-\d{4,7}/i);
  return m ? m[0].toUpperCase() : null;
}

// The fingerprint: which tech+version the CVE claim rides on, and which hosts
// carry it. Re-derived through the platform's OWN version→CVE packs (reused,
// never reimplemented) — the same correlation the recon stage ran.
export function fingerprint(bundle, cve) {
  const assets = Array.isArray(bundle && bundle.assets) ? bundle.assets : [];
  const allHosts = [...new Set(assets.filter((a) => a && a.host).map((a) => String(a.host).toLowerCase()))];
  const probedHosts = [...new Set(assets.filter((a) => a && a.host && a.status).map((a) => String(a.host).toLowerCase()))];
  const techs = assets.flatMap((a) => (Array.isArray(a && a.techs) ? a.techs : []));
  const matches = cveCheck(techs);
  const match = (cve && matches.find((x) => x.cve === cve)) || matches[0] || null;
  const affectedHosts = match
    ? [...new Set(assets.filter((a) => (Array.isArray(a.techs) ? a.techs : []).some((t) => t.id === match.tech && t.version === match.version)).map((a) => String(a.host).toLowerCase()))]
    : [];
  return { match, matches, affectedHosts, probedHosts, allHosts };
}

// --- the scope guard (evidence-derived; gather's rail re-applied) ------------------------
// Only hosts the verified bundle actually fingerprinted can ever receive a
// probe — everything else is denied by default and a violation throws
// 'scope-violation' BEFORE a byte leaves. Same contract shape as gather's
// buildScopeGuard ({ allow, why, assertAllowed }) so an intake-derived guard
// can be injected in its place (tests, a future in-loop caller).
export function evidenceScopeGuard(hosts) {
  const allowed = new Set((Array.isArray(hosts) ? hosts : []).map((h) => String(h).toLowerCase()));
  const verdict = (hostRaw) => {
    const host = String(hostRaw || '').toLowerCase().replace(/^\[|\]$/g, '');
    if (!host) return { ok: false, why: 'empty host' };
    if (allowed.has(host)) return { ok: true, why: 'in the verified evidence bundle (in-scope at gather, re-attested at the wire)' };
    return { ok: false, why: 'NOT in the verified evidence bundle — the forge may only touch hosts the hunt actually fingerprinted (deny by default)' };
  };
  return {
    allow: (urlOrHost) => {
      let host = String(urlOrHost || '');
      try { host = new URL(host).hostname; } catch { /* already a bare host */ }
      return verdict(host).ok;
    },
    why: (host) => verdict(host).why,
    assertAllowed: (url) => {
      let host = String(url || '');
      try { host = new URL(url).hostname; } catch { /* bare */ }
      const v = verdict(host);
      if (!v.ok) {
        const e = new Error(`SCOPE GUARD REFUSED a probe to ${host}: ${v.why} — out-of-scope never receives a byte, by construction`);
        e.code = 'scope-violation';
        throw e;
      }
    },
  };
}

// --- the brain (the SAME openai-compatible lane interface as brainHunt — injectable) -----
export function forgeSystem(canary) {
  return [
    'You are the VARVEL PoC-forge brain. The finding in front of you is already REPLAY-VERIFIED: the stated tech+version was fingerprinted on the stated in-scope host(s) and sits inside the named CVE\'s affected range. That proves the VERSION, nothing more. Your ONE job: design a READ-ONLY demonstration of REAL exploitability — reason about where the reachable sink is, shape ONE minimal request, and declare the exact impact marker that must appear in the response for the proof to hold.',
    'Answer with ONE fenced json block and nothing else:',
    '```json',
    '{ "action": "http-probe", "method": "GET|HEAD|POST", "path": "/root-relative/path?query (or a full https:// URL on a listed in-scope host)",',
    '  "headers": { "optional-extra": "request header" }, "body": "POST only — MUST contain the run canary",',
    '  "expectMarker": "the exact response substring that proves impact", "rationale": "why this request demonstrates the CVE on this host" }',
    '```',
    'or, when no read-only demonstration exists:',
    '```json',
    '{ "action": "give-up", "reason": "what makes a read-only proof impossible here" }',
    '```',
    'THE READ-ONLY PROOF POLICY (absolute — violations are rejected BEFORE the wire):',
    '- GET, HEAD, or POST only. A POST body MUST contain the run canary ' + canary + ' verbatim (≤4KB) — every state-capable request is inert and self-labeling.',
    '- NEVER credentials: no authorization, cookie, or x-api-key headers — the proof is unauthenticated by construction.',
    '- The impact marker must be OBSERVABLE IN THE RESPONSE: a reflected payload/canary fragment, a version banner, an error oracle. State-changing impact is operator sign-off territory — never attempted here.',
    '- SCOPE IS LAW: only the listed in-scope hosts may appear in your path or URL; anything else is refused at the wire, loudly.',
    '- ONE action per answer. You receive the prior attempts with their outcomes — build on them, never repeat a failed probe unchanged.',
    '- An honest give-up beats a speculative probe: poc-unproven is reported without shame, but a fabricated or off-policy action is the one unforgivable sin.',
  ].join('\n');
}

// The strict action contract. ANY deviation is rejected ({ ok:false }) with the
// kind named — 'contract' (shape) or 'policy' (read-only rule) — and the brain
// is told on the next attempt. Nothing is repaired, ever.
export function parseBrainAction(text, { canary, maxPostBody = FORGE.maxPostBody, maxMarkerLen = FORGE.maxMarkerLen } = {}) {
  const t = String(text || '');
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/);
  let doc = null;
  for (const cand of [fence && fence[1], t]) {
    if (!cand) continue;
    try { doc = JSON.parse(cand.trim()); break; } catch { /* try the next shape */ }
  }
  if (!doc || typeof doc !== 'object') {
    return { ok: false, kind: 'contract', reason: 'the brain answer carried no parseable json object — rejected as off-contract (nothing is repaired)' };
  }
  if (doc.action === 'give-up') {
    if (typeof doc.reason !== 'string' || !doc.reason.trim()) {
      return { ok: false, kind: 'contract', reason: 'give-up without a string reason — rejected (an honest give-up names why)' };
    }
    return { ok: true, action: { action: 'give-up', reason: doc.reason.slice(0, 600) } };
  }
  if (doc.action !== 'http-probe') {
    return { ok: false, kind: 'contract', reason: `unknown action '${doc.action}' — the contract is http-probe | give-up, nothing else` };
  }
  const method = String(doc.method || '').toUpperCase();
  if (!READ_ONLY_METHODS.includes(method)) {
    return { ok: false, kind: 'policy', reason: `READ-ONLY POLICY: method '${doc.method}' is not GET/HEAD/POST — a state-changing verb can never leave the forge` };
  }
  const path = String(doc.path || '');
  if (!/^(\/|https?:\/\/)/i.test(path)) {
    return { ok: false, kind: 'contract', reason: `path must be root-relative (/...) or a full http(s) URL on a listed in-scope host — got '${path.slice(0, 80)}'` };
  }
  const expectMarker = String(doc.expectMarker || '');
  if (!expectMarker) {
    return { ok: false, kind: 'contract', reason: 'http-probe without expectMarker — no declared observable impact, no probe (a proof is a captured marker, never a vibe)' };
  }
  if (expectMarker.length > maxMarkerLen) {
    return { ok: false, kind: 'contract', reason: `expectMarker exceeds the ${maxMarkerLen}-char bound` };
  }
  const headers = {};
  if (doc.headers !== undefined) {
    if (!doc.headers || typeof doc.headers !== 'object' || Array.isArray(doc.headers)) {
      return { ok: false, kind: 'contract', reason: 'headers must be an object of string values' };
    }
    for (const [k, v] of Object.entries(doc.headers)) {
      const hk = String(k).toLowerCase();
      if (FORBIDDEN_HEADERS.includes(hk)) {
        return { ok: false, kind: 'policy', reason: `READ-ONLY POLICY: the '${hk}' header is forbidden — the proof is UNAUTHENTICATED by construction (no credential can ever ride a forge probe)` };
      }
      headers[String(k)] = String(v).slice(0, 400);
    }
  }
  let body;
  if (doc.body !== undefined && doc.body !== null) {
    if (method !== 'POST') {
      return { ok: false, kind: 'policy', reason: `READ-ONLY POLICY: a body rides POST only — ${method} carries none` };
    }
    body = String(doc.body);
    if (body.length > maxPostBody) {
      return { ok: false, kind: 'policy', reason: `READ-ONLY POLICY: POST body exceeds the ${maxPostBody}-byte inert-marker bound` };
    }
    if (canary && !body.includes(canary)) {
      return { ok: false, kind: 'policy', reason: `READ-ONLY POLICY: a POST body MUST carry the run canary ${canary} verbatim — every state-capable request is inert + self-labeling, by construction` };
    }
  }
  return { ok: true, action: { action: 'http-probe', method, path, headers, ...(body !== undefined ? { body } : {}), expectMarker, rationale: String(doc.rationale || '').slice(0, 600) } };
}

// brainForge — brainHunt's lane handling (injected async (system, user) in
// tests; otherwise the OpenAI-compatible local lane through callOpenAI).
export async function brainForge({ brain, system, user, timeoutMs = FORGE.brainTimeoutMs }) {
  if (typeof brain === 'function') return brain(system, user);
  const cfg = resolveBrain({ env: brain && brain.env ? brain.env : process.env, request: brain || null });
  if (cfg.provider !== 'openai-compatible') {
    const e = new Error(`brain provider resolved to '${cfg.provider}' — the PoC-forge drives an OpenAI-compatible local lane (VARVEL_BRAIN_PROVIDER=openai-compatible); refusing to forge without it`);
    e.code = 'brain-not-openai-compatible';
    throw e;
  }
  const key = cfg.apiKeyEnv ? process.env[cfg.apiKeyEnv] : undefined;
  const r = await callOpenAI({
    baseUrl: brain && brain.baseUrl ? brain.baseUrl : cfg.baseUrl,
    model: brain && brain.model ? brain.model : cfg.model,
    key, system,
    messages: [{ role: 'user', content: user }],
    maxTokens: 4096,
    timeoutMs: brain && brain.timeoutMs !== undefined ? brain.timeoutMs : timeoutMs,
  });
  return (r.content || []).filter((b) => b && b.type === 'text').map((b) => b.text).join('\n');
}

// A root-relative path resolves against the affected host (the fingerprinted
// one), else the first probed host; a full URL stands as given. The scope
// guard re-judges the final URL either way — resolution never widens scope.
export function resolveProbeUrl(action, { affectedHosts = [], probedHosts = [] } = {}) {
  const p = String(action.path || '');
  if (/^https?:\/\//i.test(p)) return p;
  const host = affectedHosts[0] || probedHosts[0] || null;
  if (!host) return null;
  return `https://${host}${p.startsWith('/') ? p : '/' + p}`;
}

// One probe through the wire, bounded — gather's guardedGet shape with the
// read-only method surface. The scope guard has ALREADY passed (the caller's
// rail); this owns the timeout, the response cap, and the marker oracle.
export async function executeProbe({ url, action, wire, timeoutMs = FORGE.probeTimeoutMs, maxBodyKB = FORGE.maxBodyKB }) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await wire(url, {
      signal: ac.signal,
      method: action.method,
      headers: { 'user-agent': 'VARVEL-pocforge (read-only proof; contact: program policy)', ...(action.headers || {}) },
      ...(action.body !== undefined ? { body: action.body } : {}),
    });
    let body = '';
    if (typeof res.text === 'function') body = await res.text();
    else if (typeof res.json === 'function') body = JSON.stringify(await res.json());
    body = String(body).slice(0, maxBodyKB * 1024);
    const headers = {};
    const hh = res.headers || {};
    if (typeof hh.forEach === 'function') hh.forEach((v, k) => { headers[String(k).toLowerCase()] = String(v); });
    else for (const [k, v] of Object.entries(hh)) headers[String(k).toLowerCase()] = String(v);
    let markerLocation = null;
    if (body.includes(action.expectMarker)) markerLocation = 'body';
    else {
      for (const [k, v] of Object.entries(headers)) {
        if (String(v).includes(action.expectMarker)) { markerLocation = `headers (${k})`; break; }
      }
    }
    return { ok: true, executed: true, status: res.status, headers, body, markerFound: markerLocation !== null, markerLocation };
  } catch (e) {
    return { ok: false, executed: false, error: (e && e.code) || (e && e.name) || 'probe-error', reason: String((e && e.message) || e).slice(0, 200) };
  } finally {
    clearTimeout(t);
  }
}

// Response excerpt for the draft/transcript: the marker in its live context,
// whitespace-collapsed and backtick-safe (it lands inside markdown code spans).
export function excerptAround(body, marker, radius = 140) {
  const b = String(body || '');
  const clean = (s) => s.replace(/[`\r\n]+/g, ' ').replace(/\s{2,}/g, ' ').trim();
  const ix = b.indexOf(marker);
  if (ix === -1) return clean(b.slice(0, 160));
  const s = Math.max(0, ix - radius);
  const e = Math.min(b.length, ix + marker.length + radius);
  return (s > 0 ? '…' : '') + clean(b.slice(s, e)) + (e < b.length ? '…' : '');
}

// --- THE VERDICT CLASSES (mirror of huntloop's classifyVerdict honesty) --------------------
// poc-verified:  a probe the forge ACTUALLY sent returned the DECLARED marker.
// poc-unproven:  the budget ended by exhaustion or an honest give-up with at
//                least the machinery working — the claim was evaluated and
//                could not be demonstrated read-only.
// check-defect:  NO probe ever executed (all attempts died on contract,
//                policy, scope, transport, brain, or the watchdog) — the
//                machinery failed, the claim was NEVER evaluated.
export function classifyForge({ attempts, gaveUp }) {
  const winner = attempts.find((a) => a.markerFound);
  if (winner) {
    return {
      verdictClass: 'poc-verified', winner,
      reason: `PoC DEMONSTRATED on attempt ${winner.n}: the declared impact marker appeared in the ${winner.markerLocation} of the live response (HTTP ${winner.status}) — captured verbatim in the transcript`,
    };
  }
  const executed = attempts.filter((a) => a.executed);
  if (gaveUp !== null && gaveUp !== undefined) {
    return {
      verdictClass: 'poc-unproven',
      reason: `the forge brain GAVE UP after ${attempts.length} attempt(s) (${executed.length} probe(s) executed): ${gaveUp} — evaluated and UNPROVEN, reported honestly`,
    };
  }
  if (executed.length) {
    return {
      verdictClass: 'poc-unproven',
      reason: `attempts exhausted — ${executed.length} read-only probe(s) executed and the declared impact marker NEVER appeared; real exploitability is UNPROVEN (the finding stays version-verified only, reported honestly)`,
    };
  }
  const tally = attempts.map((a) => a.kind).join(', ') || 'no attempts ran';
  return {
    verdictClass: 'check-defect',
    reason: `the machinery failed before ANY probe could execute (${tally}) — the claim was NEVER evaluated by the forge; this is a defect in the machinery, not an evaluated-and-unproven finding`,
  };
}

// --- the draft upgrade (a demonstrated PoC fills ONLY what it answers) ----------------------
export function findDraft(outboxDir, evidenceDir) {
  let files = [];
  try { files = readdirSync(outboxDir).filter((f) => f.endsWith('.md')); } catch { return null; }
  const norm = (s) => String(s).replace(/\\/g, '/').replace(/\/+$/, '');
  const target = norm(evidenceDir);
  const tail = target.split('/').slice(-2).join('/'); // <opp-slug>/<finding-slug>
  for (const f of files) {
    const p = join(outboxDir, f);
    let head = '';
    try { head = readFileSync(p, 'utf8').slice(0, 1600); } catch { continue; }
    const m = head.match(/Evidence bundle: (.+?) -->/);
    const named = m ? norm(m[1].trim()) : '';
    if (named && (named === target || named.endsWith(tail) || target.endsWith(named))) return p;
  }
  return null;
}

// The findings-ledger line for this evidence dir (read-only; the ledger stays
// the loop's own file — the forge NEVER writes it).
export function readLedgerLine(dir, evidenceDir) {
  try {
    const norm = (s) => String(s).replace(/\\/g, '/').replace(/\/+$/, '');
    const target = norm(evidenceDir);
    const lines = readFileSync(join(dir, 'findings.jsonl'), 'utf8').trim().split('\n').filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      let rec = null;
      try { rec = JSON.parse(lines[i]); } catch { continue; }
      if (rec && rec.evidenceDir && norm(rec.evidenceDir) === target) return rec;
    }
  } catch { /* no ledger — the forge works from the bundle alone */ }
  return null;
}

// upgradeDraft — pure (the caller writes only when ok). Fills the
// TODO(validate) lines the proof ANSWERS (affected host/URL, exact request,
// the observed marker exchange, the impact statement), rewrites the header's
// verdict line honestly, and APPENDS to the honesty section what the PoC
// proved and what is STILL unproven. The scope attestation TODO is never
// touched here — no gather bundle carries signed scope today, so it stays.
export function upgradeDraft({ md, proof, at, transcriptName, transcriptSha256 }) {
  let out = String(md || '');
  const filled = [];
  const notFound = [];
  const headRe = /Verdict: VERIFIED \(replay-verification PASSED\)/;
  if (!headRe.test(out)) {
    return { ok: false, reason: 'the draft is not in the replay-verified state the forge upgrades from (already upgraded? a different verdict?) — left untouched, never rewritten blind' };
  }
  out = out.replace(headRe, 'Verdict: VERIFIED (PoC demonstrated — a read-only live probe captured the declared impact marker; replay-verification PASSED)');
  filled.push('header-verdict');

  const fill = (key, re, line) => {
    if (re.test(out)) { out = out.replace(re, line); filled.push(key); } else { notFound.push(key); }
  };
  fill('affected-host', /^(\d+)\. TODO\(validate\) — affected host\/URL[^\n]*$/m,
    `$1. Affected host/URL (PoC-demonstrated ${at}): \`${proof.host}\` — probed as \`${proof.url}\``);
  fill('exact-request', /^(\d+)\. TODO\(validate\) — exact endpoint\/parameter[^\n]*$/m,
    `$1. Exact request (PoC-demonstrated): \`${proof.method} ${proof.path}\` to \`${proof.host}\``
    + (proof.headers && Object.keys(proof.headers).length ? ` with headers ${Object.entries(proof.headers).map(([k, v]) => `\`${k}: ${v}\``).join(', ')}` : '')
    + (proof.body !== undefined ? ` with an inert-marker POST body (${proof.body.length} bytes, carries the run canary)` : ''));
  fill('impact-exchange', /^(\d+)\. TODO\(validate\) — full impact demonstration[^\n]*$/m,
    `$1. Observed impact (read-only proof, ${at}): HTTP ${proof.status} — the declared marker \`${proof.marker}\` appeared in the ${proof.markerLocation} of the live response. Excerpt: \`${proof.excerpt}\`. PoC transcript: \`${transcriptName}\` (sha256 ${transcriptSha256}) in the evidence bundle.`);
  fill('impact-statement', /^TODO\(validate\) — concrete impact statement[^\n]*$/m,
    `PoC-DEMONSTRATED (read-only): against \`${proof.host}\`, \`${proof.method} ${proof.path}\` returned HTTP ${proof.status} with the declared impact marker \`${proof.marker}\` in the ${proof.markerLocation}`
    + (proof.rationale ? ` — ${proof.rationale}` : '')
    + '. REMAINING LIMIT: this proves the observable marker exchange only; impact beyond it (what a full exploit would READ, CHANGE, or REACH) is NOT demonstrated — the read-only proof policy stops here, deeper proof is operator sign-off territory.');

  // The honesty section keeps naming the remaining gaps — the PoC ADDS its
  // line, it never erases one.
  const honestyIx = out.indexOf('## Honesty — unverified gaps');
  if (honestyIx !== -1) {
    const ruleIx = out.indexOf('\n---', honestyIx);
    if (ruleIx !== -1) {
      const bullets = [
        `- PoC demonstrated ${at}: \`${proof.method} ${proof.path}\` on \`${proof.host}\` → HTTP ${proof.status}, the declared impact marker observed in the ${proof.markerLocation} (transcript \`${transcriptName}\`, sha256 ${transcriptSha256})`,
        '- STILL UNPROVEN after the PoC: impact beyond the read-only marker exchange (what a full exploit would READ, CHANGE, or REACH) — the forge\'s read-only policy stops at observable impact by construction',
      ];
      out = out.slice(0, ruleIx).replace(/\s+$/, '') + '\n' + bullets.join('\n') + out.slice(ruleIx);
      filled.push('honesty-still-unproven');
    } else { notFound.push('honesty-section-rule'); }
  } else { notFound.push('honesty-section'); }

  const keptTodo = [...out.matchAll(/^.*TODO\(validate\).*$/gm)].map((m) => m[0].trim());
  return { ok: true, md: out, filled, notFound, keptTodo };
}

// --- ONE finding through the forge ------------------------------------------------------------
const attemptLine = (a) => {
  if (a.kind === 'probe') {
    return `#${a.n} ${a.action.method} ${a.url} → HTTP ${a.status}, declared marker ${a.markerFound ? `CAPTURED in ${a.markerLocation}` : 'ABSENT'} (rationale: ${a.action.rationale || 'none'})`;
  }
  if (a.kind === 'give-up') return `#${a.n} brain gave up: ${a.detail}`;
  return `#${a.n} REJECTED/${a.kind}: ${a.detail}`;
};

export function buildForgeUser({ finding, cve, match, affectedHosts, probedHosts, bundle, canary, attempts, n, maxAttempts }) {
  const claim = match ? `${match.evidence} · ${match.note || ''}` : 'the version→CVE match replay-verified by the hunt loop (details in result.json)';
  const prior = attempts.length
    ? attempts.map(attemptLine).join('\n')
    : 'none yet';
  return [
    `REPLAY-VERIFIED FINDING: ${finding.title || 'untitled'} (severity ${finding.sev || 'info'}${cve ? `, ${cve}` : ''})`,
    `THE CLAIM AS VERIFIED: ${claim}`,
    `AFFECTED HOSTS (fingerprinted${match ? ` ${match.tech} ${match.version}` : ''}): ${affectedHosts.join(', ') || 'none re-derived — judge the evidence'}`,
    `IN-SCOPE HOSTS YOUR PROBES MAY TOUCH (the exact set; anything else is refused at the wire): ${probedHosts.join(', ') || 'NONE'}`,
    `RUN CANARY (required verbatim inside any POST body): ${canary}`,
    '',
    'GATHERED EVIDENCE (real pages from the in-scope assets — judge THIS):',
    brainSummary(bundle),
    '',
    `ATTEMPT ${n} OF ${maxAttempts}. PRIOR ATTEMPTS (build on them — never repeat a failed probe unchanged):`,
    prior,
    'Design the next single read-only action (or give up honestly).',
  ].join('\n');
}

export async function pocForge({
  finding: findingIn, evidenceDir, brain, chain, scopeGuard, emit: emitIn,
  dir: dirIn, outboxDir, now, fetchImpl, sleepImpl, caps = {}, watchdogMs = FORGE.watchdogMs,
} = {}) {
  const C = { ...FORGE, ...caps };
  C.maxAttempts = Math.min(Math.max(1, C.maxAttempts | 0), FORGE.maxAttemptsCap);
  if (!evidenceDir) return { ok: false, error: 'no-evidence-dir', reason: '--finding <evidence-dir> is required' };
  evidenceDir = resolve(String(evidenceDir));
  const dir = dirIn ? resolve(String(dirIn)) : dirname(dirname(dirname(evidenceDir)));
  const emit = emitIn || makeEmitter({ dir, now });
  const sleep = sleepImpl || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const outbox = outboxDir ? resolve(String(outboxDir)) : join(dir, 'outbox');
  const oppSlug = basename(dirname(evidenceDir));
  const fslug = basename(evidenceDir);
  const opp = oppSlug.replace(/_.*$/, ''); // <handle>_new-program_in_<hash> → handle
  const transcript = [];
  const tlog = (s) => transcript.push(`${iso(now)} ${s}`);
  const note = (ev) => emit.raw({ type: 'poc-forge', opp, finding: fslug, ...ev });

  // INTAKE — the bundle, the verdict that stands, the claim. Only a
  // replay-VERIFIED finding is a forge candidate (anything less is refused).
  const parsed = parseEvidenceBundle(evidenceDir);
  if (!parsed.ok) {
    emit.stage('poc-forge', 'failed', { opp, finding: fslug, msg: `${parsed.error}: ${parsed.reason}` });
    return { ok: false, error: parsed.error, reason: parsed.reason, evidenceDir };
  }
  if (!parsed.result || parsed.result.verdict !== 'verified') {
    const why = `the finding is not replay-VERIFIED (result.json says '${(parsed.result && parsed.result.verdict) || 'absent'}') — the forge only upgrades replay-verified findings; nothing is assumed`;
    emit.stage('poc-forge', 'failed', { opp, finding: fslug, msg: why });
    return { ok: false, error: 'not-replay-verified', reason: why, evidenceDir };
  }
  const ledger = readLedgerLine(dir, evidenceDir);
  const finding = findingIn && typeof findingIn === 'object'
    ? findingIn
    : { title: (ledger && ledger.finding) || fslug, sev: (ledger && ledger.sev) || 'info' };
  const cve = deriveCve(finding, evidenceDir);
  const fp = fingerprint(parsed.bundle, cve);
  const hosts = fp.probedHosts.length ? fp.probedHosts : fp.allHosts;
  const canary = forgeCanary(evidenceDir);
  const guard = scopeGuard || evidenceScopeGuard(hosts);
  const wire = fetchImpl || (chain ? ghostFetch(chain, { timeoutMs: C.probeTimeoutMs }) : fetch);
  const transport = fetchImpl ? 'injected (test)' : (chain ? `ghost-chain (${chain})` : 'DIRECT — no ghost chain configured (named honestly)');

  emit.stage('poc-forge', 'active', {
    opp, finding: fslug,
    msg: `forge up — ${String(finding.title || fslug).slice(0, 60)}${cve ? ` (${cve})` : ''}; ≤${C.maxAttempts} attempt(s), brain ≤${Math.round(C.brainTimeoutMs / 60000)}min/call, watchdog ${Math.round(watchdogMs / 60000)}min; READ-ONLY probes to ${hosts.length} evidence host(s) via ${transport}`,
  });
  tlog(`FORGE finding=${finding.title || fslug} cve=${cve || 'n/a'} affected=${fp.affectedHosts.join(',') || 'n/a'} hosts=${hosts.join(',')} transport=${transport} canary=${canary}`);
  note({ state: 'intake', msg: `evidence parsed — affected: ${fp.affectedHosts.join(', ') || 'n/a'}; guard hosts: ${hosts.join(', ') || 'NONE'}; transport ${transport}` });

  const attempts = [];
  let gaveUp = null;
  const run = async () => {
    for (let n = 1; n <= C.maxAttempts; n++) {
      const user = buildForgeUser({ finding, cve, match: fp.match, affectedHosts: fp.affectedHosts, probedHosts: hosts, bundle: parsed.bundle, canary, attempts, n, maxAttempts: C.maxAttempts });
      let text = null;
      let beat = null;
      if (C.heartbeatMs > 0) {
        beat = setInterval(() => emit.raw({ type: 'heartbeat', stage: 'poc-forge', msg: `forge attempt ${n}/${C.maxAttempts} — waiting on the brain (≤${Math.round(C.brainTimeoutMs / 60000)}min)` }), C.heartbeatMs);
        if (beat.unref) beat.unref();
      }
      try {
        text = await brainForge({ brain, system: forgeSystem(canary), user, timeoutMs: C.brainTimeoutMs });
      } catch (e) {
        attempts.push({ n, kind: 'brain-error', executed: false, detail: `${(e && e.code) || 'brain-error'}: ${String((e && e.message) || e).slice(0, 160)}` });
        tlog(`ATTEMPT ${n}: brain call failed — ${attempts[attempts.length - 1].detail}`);
        note({ state: 'brain-error', msg: attempts[attempts.length - 1].detail });
        continue;
      } finally {
        if (beat) clearInterval(beat);
      }
      const got = parseBrainAction(text, { canary, maxPostBody: C.maxPostBody, maxMarkerLen: C.maxMarkerLen });
      if (!got.ok) {
        const kind = got.kind === 'policy' ? 'policy-rejected' : 'contract-rejected';
        attempts.push({ n, kind, executed: false, detail: got.reason });
        tlog(`ATTEMPT ${n}: ${got.kind.toUpperCase()} REJECTION — ${got.reason}`);
        note({ state: kind, msg: got.reason });
        continue;
      }
      const action = got.action;
      if (action.action === 'give-up') {
        gaveUp = action.reason;
        attempts.push({ n, kind: 'give-up', executed: false, detail: action.reason });
        tlog(`ATTEMPT ${n}: the brain GAVE UP — ${action.reason}`);
        note({ state: 'give-up', msg: action.reason.slice(0, 200) });
        break;
      }
      const url = resolveProbeUrl(action, { affectedHosts: fp.affectedHosts, probedHosts: hosts });
      if (!url) {
        attempts.push({ n, kind: 'contract-rejected', executed: false, detail: 'no affected/probed host exists to resolve a root-relative path against' });
        tlog(`ATTEMPT ${n}: CONTRACT REJECTION — no host to resolve ${action.path}`);
        continue;
      }
      // THE RAIL — scope BEFORE any byte (fail-closed; a refusal is recorded
      // LOUDLY and the probe is never sent).
      try {
        guard.assertAllowed(url);
      } catch (e) {
        attempts.push({ n, kind: 'scope-refused', executed: false, detail: String((e && e.message) || e).slice(0, 200), url });
        tlog(`ATTEMPT ${n}: SCOPE REFUSAL — ${attempts[attempts.length - 1].detail}`);
        note({ state: 'scope-refused', msg: attempts[attempts.length - 1].detail });
        continue;
      }
      if (attempts.some((a) => a.executed)) await sleep(C.delayMs); // gather's cadence between target requests
      note({ state: 'probe', msg: `attempt ${n}: ${action.method} ${url} — expecting ${JSON.stringify(action.expectMarker).slice(0, 60)}` });
      const probe = await executeProbe({ url, action, wire, timeoutMs: C.probeTimeoutMs, maxBodyKB: C.maxBodyKB });
      if (!probe.ok) {
        attempts.push({ n, kind: 'transport-error', executed: false, detail: `${probe.error}: ${probe.reason}`, url, action });
        tlog(`ATTEMPT ${n}: TRANSPORT ERROR — ${probe.error}: ${probe.reason}`);
        note({ state: 'transport-error', msg: `${probe.error}: ${String(probe.reason).slice(0, 160)}` });
        continue;
      }
      attempts.push({ n, kind: 'probe', executed: true, url, action, status: probe.status, markerFound: probe.markerFound, markerLocation: probe.markerLocation, body: probe.body });
      tlog(`ATTEMPT ${n}: ${action.method} ${url} → HTTP ${probe.status}; marker ${probe.markerFound ? `CAPTURED in ${probe.markerLocation}` : 'ABSENT'}; rationale: ${action.rationale || 'n/a'}`);
      tlog(`response excerpt: ${String(probe.body).replace(/\n/g, ' | ').slice(0, 400)}`);
      note({ state: probe.markerFound ? 'marker' : 'probe-done', msg: `${action.method} ${url} → HTTP ${probe.status} — marker ${probe.markerFound ? `CAPTURED (${probe.markerLocation})` : 'absent'}` });
      if (probe.markerFound) break;
    }
    return classifyForge({ attempts, gaveUp });
  };

  // The whole-stage watchdog (huntloop's own, reused): a forge that outlives
  // its budget is aborted and lands as check-defect, never silently hung.
  const ctl = new AbortController();
  let outcome;
  try {
    outcome = await withWatchdog(watchdogMs, ctl, run);
  } catch (e) {
    outcome = { verdictClass: 'check-defect', reason: String((e && e.message) || e) };
  }
  const verified = outcome.verdictClass === 'poc-verified';
  const winner = outcome.winner || attempts.find((a) => a.markerFound) || null;

  // THE PROOF RECORD — transcript + result, in the evidence bundle, whatever
  // the verdict (an unproven forge is as much the record as a verified one).
  let proof = null;
  if (verified && winner) {
    const u = new URL(winner.url);
    // The path AS DECLARED by the brain (what an operator reproduces — their
    // client normalizes encoding, exactly as our wire did). The absolute URL
    // is kept alongside; the transcript records both.
    const declaredPath = /^https?:\/\//i.test(winner.action.path) ? (u.pathname || '/') + (u.search || '') : winner.action.path;
    proof = {
      host: u.hostname,
      url: winner.url,
      method: winner.action.method,
      path: String(declaredPath).replace(/[`\r\n]+/g, ''),
      headers: winner.action.headers || {},
      ...(winner.action.body !== undefined ? { body: winner.action.body } : {}),
      status: winner.status,
      marker: winner.action.expectMarker,
      markerLocation: winner.markerLocation,
      excerpt: excerptAround(winner.body, winner.action.expectMarker),
      rationale: winner.action.rationale || '',
      canary,
      attempt: winner.n,
    };
  }
  tlog(`VERDICT: ${outcome.verdictClass.toUpperCase()} — ${outcome.reason}`);
  const transcriptText = transcript.join('\n') + '\n';
  writeFileSync(join(evidenceDir, 'poc-transcript.txt'), transcriptText);
  const transcriptSha256 = sha256(transcriptText); // the hash covers the transcript BYTES exactly as written
  const resultDoc = {
    ok: true,
    verified,
    verdictClass: outcome.verdictClass,
    verdict: outcome.verdictClass,
    reason: outcome.reason,
    finding: String(finding.title || fslug),
    cve: cve || null,
    evidenceDir,
    attempts: attempts.length,
    probesExecuted: attempts.filter((a) => a.executed).length,
    canary,
    transport,
    scopeGuard: scopeGuard ? 'injected' : 'evidence-derived',
    transcript: join(evidenceDir, 'poc-transcript.txt'),
    transcriptSha256,
    ...(proof ? { proof } : {}),
    at: iso(now),
  };

  // THE DRAFT UPGRADE — only a demonstrated PoC rewrites the operator's draft,
  // and only the TODO(validate) lines the proof actually answers.
  if (verified) {
    const draftPath = findDraft(outbox, evidenceDir);
    if (!draftPath) {
      resultDoc.draft = { upgraded: false, reason: `no outbox draft names this evidence bundle (${outbox}) — the proof record stands in the evidence bundle` };
      tlog('DRAFT: none found — proof record only');
    } else {
      const up = upgradeDraft({ md: readFileSync(draftPath, 'utf8'), proof, at: iso(now), transcriptName: 'poc-transcript.txt', transcriptSha256 });
      if (!up.ok) {
        resultDoc.draft = { upgraded: false, path: draftPath, reason: up.reason };
        tlog(`DRAFT: ${up.reason}`);
      } else {
        writeFileSync(draftPath, up.md);
        resultDoc.draft = { upgraded: true, path: draftPath, filled: up.filled, notFound: up.notFound, keptTodo: up.keptTodo };
        tlog(`DRAFT: upgraded ${draftPath} — filled ${up.filled.join(', ')}; ${up.keptTodo.length} TODO line(s) remain (named)`);
        note({ state: 'draft-upgraded', msg: `${basename(draftPath)} ← PoC demonstrated; filled: ${up.filled.join(', ')}` });
      }
    }
  }
  writeJson(join(evidenceDir, 'poc-result.json'), resultDoc);

  emit.stage('poc-forge', verified ? 'done' : 'failed', {
    opp, finding: fslug, verdictClass: outcome.verdictClass,
    msg: `${outcome.verdictClass}: ${String(outcome.reason).slice(0, 180)}`,
  });
  if (verified) {
    emit.proof(opp, fslug, {
      verified: true, verdict: 'poc-verified', verdictClass: 'poc-verified',
      evidenceDir, transcriptSha256, attempts: attempts.length, transport,
      note: 'the marker was captured from the LIVE in-scope host through the read-only wire — a live-target proof has no sandbox replay; the transcript + hash is the record',
    });
  }
  return resultDoc;
}

// --- direct-run CLI (the console drives this per finding) -------------------------------------
const isMain = (() => { try { return process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]; } catch { return false; } })();

if (isMain) {
  const a = process.argv.slice(2);
  const opt = (flag) => { const i = a.indexOf(flag); return i !== -1 && a[i + 1] && !a[i + 1].startsWith('--') ? a[i + 1] : undefined; };
  const findingDir = opt('--finding');
  const out = (doc, code = 0) => { console.log(JSON.stringify(doc)); process.exitCode = code; };
  if (!findingDir) {
    out({ ok: false, error: 'usage', reason: 'usage: node tools/pocforge.mjs --finding <evidence-dir> [--outbox <dir>] [--dir d] [--attempts n] [--base-url u] [--model id]' }, 2);
  } else {
    const evidenceDir = resolve(findingDir);
    const dir = opt('--dir') ? resolve(opt('--dir')) : dirname(dirname(dirname(evidenceDir)));
    const outbox = opt('--outbox') ? resolve(opt('--outbox')) : join(dir, 'outbox');
    const brain = { baseUrl: opt('--base-url'), model: opt('--model'), env: process.env };
    const caps = {};
    if (opt('--attempts') !== undefined) caps.maxAttempts = Number(opt('--attempts'));
    const ghost = resolveGhostChain({ env: process.env });
    if (ghost) console.error(`pocforge: ghost wire — ${ghost.chain} via ${ghost.source} (fail-closed)`);
    else console.error('pocforge: no ghost chain configured — probes go DIRECT, named honestly (the fixture lane)');
    console.error(`pocforge: dir=${dir} finding=${evidenceDir} — ${DOCTRINE}`);
    pocForge({ evidenceDir, brain, chain: ghost && ghost.chain, dir, outboxDir: outbox, caps })
      .then((r) => out(r, r.ok ? 0 : 2))
      .catch((e) => out({ ok: false, error: 'forge-fatal', reason: String((e && e.stack) || e) }, 1));
  }
}
