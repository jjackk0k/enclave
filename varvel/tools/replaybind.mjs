// VARVEL — replaybind: REPLAYABLE-EVIDENCE BINDING (winner-copyables build, Tool 2).
//
// The verified-earner insight (research/2026-08-31-ai-hunter-practitioner-brief.md §5.1,
// Brutecat's "click Play, see if it still works"): every validated finding's evidence
// must be bound to the captured bytes with a ONE-COMMAND replay — expected-vs-actual
// assertions, garbage/unauth controls included — so a triager-grade reproduction is
// one command, not a trust-me writeup. Today's raw material is the .tmp/*matrix.json
// captures and the authzsweep evidence pairs; this module formalizes both into:
//
//   replay.json — the machine plan: ordered requests (observation + control legs),
//                 each with its CAPTURED response turned into assertions (status must
//                 match, body marker must be present). Credentials are REDACTED-BUT-
//                 REFERENCED: a '<session:A>' cookie never lands in the bundle; the plan
//                 carries a credential reference the runner resolves at replay time.
//   replay.sh   — the human one-click: curl through the ghost chain
//                 (socks5h://10.64.0.1:1080) with the X-HackerOne: varvel attestation
//                 header, assertions inline, credential vars documented at the top.
//
// ORACLE CONTRACT: a replay PASSES a leg only when the live response reproduces the
// captured one (status equal; marker present). A leg that no longer reproduces is
// reported as such — 'fixed-or-changed' is an honest outcome, never hidden. Requests
// whose credentials cannot be resolved are SKIPPED and named, never fired baldly with
// someone else's guess.
//
// GOVERNANCE: the default runner transport rides the ghost agents and carries the
// attestation header; tests inject a fake transport (no live network). The EMIT half
// (planFromPairs/planFromMatrix/emitBundle) is pure fs + string work — the bountyline
// wiring imports only that half's behavior (the pipeline-never-submits pin is a static
// scan of engine/bountyline.mjs, which this module is not part of). Never throws.
//
// usage:
//   import { planFromPairs, planFromMatrix, emitBundle, runPlan } from './tools/replaybind.mjs';
//   const plan = planFromPairs(finding.authz.bundle.pairs, { base, finding, program });
//   const b = emitBundle(plan, { outDir });                        // replay.json + replay.sh
//   const r = await runPlan(plan, { transport, resolveCredential });

import http from 'node:http';
import https from 'node:https';
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dir, '..');

export const REPLAY_CAPS = { maxRequests: 24, markerLen: 120, bodySnippet: 600, timeoutMs: 20000 };
export const GHOST_PROXY = 'socks5h://10.64.0.1:1080';
export const ATTEST_HEADER = 'X-HackerOne: varvel';

const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const SESSION_REF_RE = /^<session:([^>]+)>$/;

// ——— markers: the captured response's distinctive substring ———
// JSON bodies: a stable scalar field (message/error/status) wins. Else the first
// non-whitespace run, capped. null = no usable marker (status-only assertion, honest).
export function markerFrom(body) {
  const s = String(body || '').trim();
  if (!s) return null;
  try {
    const j = JSON.parse(s);
    if (j && typeof j === 'object') {
      for (const k of ['message', 'error', 'status', 'detail', 'title']) {
        if (typeof j[k] === 'string' && j[k].trim().length >= 4) return j[k].trim().slice(0, REPLAY_CAPS.markerLen);
      }
      return null; // parsed JSON with no stable scalar marker — status-only assertion, honest
    }
  } catch { /* not JSON — fall through to the raw run */ }
  const run = s.replace(/\s+/g, ' ').trim().slice(0, REPLAY_CAPS.markerLen);
  return run.length >= 4 ? run : null;
}

// ——— role inference ———
// authzsweep pair labels: 'read:cross(A→B)', 'read:unauth-control(B)', 'seed:lowpriv',
// 'write:cross(A→B)', 'ladder:role=A'… Controls are named by what they control FOR.
export function roleOfLabel(label) {
  const l = String(label || '').toLowerCase();
  if (l.startsWith('seed:')) return 'seed';
  if (/unauth/.test(l)) return 'control-unauth';
  if (/garbage/.test(l)) return 'control-garbage';
  if (/control/.test(l)) return 'control';
  return 'observation';
}

// ——— planFromPairs: authzsweep evidence pairs → replay plan ———
// pair = { label, request:{ method, path, headers:{cookie:'<session:A>'|…}, body },
//          response:{ status, body } | null }
export function planFromPairs(pairs, { base, finding = {}, program = null, now } = {}) {
  if (!Array.isArray(pairs) || !pairs.length) return { ok: false, error: 'no-pairs', reason: 'planFromPairs needs the captured request/response pairs (authzsweep bundle.pairs shape)' };
  let b;
  try { b = new URL(base).origin; } catch { return { ok: false, error: 'bad-base', reason: `base '${base}' is not a parseable http(s) URL` }; }
  const requests = [];
  const skipped = [];
  for (const p of pairs.slice(0, REPLAY_CAPS.maxRequests)) {
    if (!p || !p.request || typeof p.request.path !== 'string') { skipped.push({ label: (p && p.label) || '?', reason: 'pair carries no request path' }); continue; }
    const headers = {};
    let credential = null;
    for (const [k, v] of Object.entries(p.request.headers || {})) {
      const m = typeof v === 'string' ? SESSION_REF_RE.exec(v) : null;
      if (m) { credential = { kind: k.toLowerCase() === 'cookie' ? 'session-cookie' : 'session-header', header: k.toLowerCase(), ref: m[1] }; continue; }
      if (typeof v === 'string' && v === '<redacted>') { credential = credential || { kind: 'unresolved', header: k.toLowerCase(), ref: null }; continue; }
      if (typeof v === 'string' && v !== '<none>') headers[k.toLowerCase()] = v;
    }
    const captured = p.response && Number.isFinite(p.response.status) ? p.response : null;
    requests.push({
      id: `${requests.length + 1}`,
      role: roleOfLabel(p.label),
      label: String(p.label || `request-${requests.length + 1}`),
      method: String(p.request.method || 'GET').toUpperCase(),
      url: b + p.request.path,
      headers,
      credential, // { kind:'session-cookie'|'session-header', header, ref } | { kind:'unresolved' } | null
      body: p.request.body != null ? String(p.request.body) : null,
      expect: captured
        ? { status: captured.status, bodyIncludes: markerFrom(captured.body) }
        : { status: null, bodyIncludes: null, note: 'the capture carried NO response for this leg — replay asserts nothing, records only' },
      captured: captured ? { status: captured.status, body: String(captured.body || '').slice(0, REPLAY_CAPS.bodySnippet) } : null,
    });
  }
  if (!requests.length) return { ok: false, error: 'no-usable-pairs', reason: `every pair was unusable (${skipped.map((s) => s.reason).join('; ')})`, skipped };
  return {
    ok: true,
    plan: {
      v: 1, kind: 'varvel-replay-bundle', createdAt: iso(now),
      program: program || null, base: b,
      finding: { title: finding.title || finding.label || 'finding', ref: finding.ref || null, sev: finding.sev || null },
      proxy: GHOST_PROXY, attestHeader: ATTEST_HEADER,
      requests, skipped,
      controls: requests.filter((r) => r.role.startsWith('control')).length,
      note: 'every leg asserts it REPRODUCES ITS CAPTURE (status equal, marker present) — a leg that no longer reproduces is reported fixed-or-changed, never hidden',
    },
  };
}

// ——— planFromMatrix: today's .tmp/*matrix.json captures → replay plan ———
// Matrix entries ({key:{http,body}}) carry responses only — the REQUEST paths must be
// supplied via `paths: { <key>: '/route/...' }` (with optional `methods`). Keys without
// a path are skipped and NAMED — no route is ever invented.
export function planFromMatrix(matrix, { base, paths = {}, methods = {}, finding = {}, program = null, sessionRefs = {}, now } = {}) {
  if (!matrix || typeof matrix !== 'object' || Array.isArray(matrix)) return { ok: false, error: 'no-matrix', reason: 'planFromMatrix needs the {key:{http,body}} capture object' };
  let b;
  try { b = new URL(base).origin; } catch { return { ok: false, error: 'bad-base', reason: `base '${base}' is not a parseable http(s) URL` }; }
  const requests = [];
  const skipped = [];
  for (const [key, cap] of Object.entries(matrix)) {
    const path = paths[key];
    if (typeof path !== 'string' || !path.startsWith('/')) { skipped.push({ key, reason: 'no request path supplied for this capture — the matrix stores responses only; routes are never invented' }); continue; }
    const credential = sessionRefs[key] ? { kind: 'session-cookie', header: 'cookie', ref: sessionRefs[key] } : null;
    requests.push({
      id: `${requests.length + 1}`,
      role: roleOfLabel(key),
      label: key,
      method: String(methods[key] || 'GET').toUpperCase(),
      url: b + path,
      headers: {},
      credential,
      body: null,
      expect: { status: Number.isFinite(cap && cap.http) ? cap.http : null, bodyIncludes: markerFrom(cap && cap.body) },
      captured: cap && Number.isFinite(cap.http) ? { status: cap.http, body: String(cap.body || '').slice(0, REPLAY_CAPS.bodySnippet) } : null,
    });
  }
  if (!requests.length) return { ok: false, error: 'no-usable-captures', reason: `no matrix key had a supplied request path (${skipped.length} skipped)`, skipped };
  return {
    ok: true,
    plan: {
      v: 1, kind: 'varvel-replay-bundle', createdAt: iso(now),
      program: program || null, base: b,
      finding: { title: finding.title || finding.label || 'finding', ref: finding.ref || null, sev: finding.sev || null },
      proxy: GHOST_PROXY, attestHeader: ATTEST_HEADER,
      requests, skipped,
      controls: requests.filter((r) => r.role.startsWith('control')).length,
      note: 'formalized from a matrix.json capture — every leg asserts it reproduces its capture; fixed-or-changed legs are reported, never hidden',
    },
  };
}

// ——— emitBundle: plan → replay.json + replay.sh on disk ———
export function emitBundle(plan, { outDir } = {}) {
  if (!plan || plan.kind !== 'varvel-replay-bundle') return { ok: false, error: 'bad-plan', reason: 'emitBundle needs a plan object from planFromPairs/planFromMatrix' };
  if (!outDir) return { ok: false, error: 'no-outdir', reason: 'emitBundle needs outDir' };
  const sh = renderShell(plan);
  try {
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'replay.json'), JSON.stringify(plan, null, 2) + '\n');
    writeFileSync(join(outDir, 'replay.sh'), sh);
  } catch (e) { return { ok: false, error: 'persist-failed', reason: String((e && e.message) || e) }; }
  return { ok: true, dir: outDir, files: ['replay.json', 'replay.sh'], requests: plan.requests.length, controls: plan.controls, skipped: plan.skipped.length };
}

// The one-click script. Credentials are VARS at the top, documented by reference —
// the secret never lands in the bundle.
export function renderShell(plan) {
  const credVars = new Map();
  for (const r of plan.requests) {
    if (r.credential && r.credential.ref && !credVars.has(r.credential.ref)) {
      credVars.set(r.credential.ref, 'CRED_' + String(r.credential.ref).replace(/[^A-Za-z0-9]/g, '_').toUpperCase());
    }
  }
  const L = [];
  L.push('#!/usr/bin/env bash');
  L.push(`# VARVEL replay bundle — ${plan.finding.title}`);
  if (plan.finding.ref) L.push(`# ref: ${plan.finding.ref}`);
  L.push(`# program: ${plan.program || '—'} · base: ${plan.base} · generated ${plan.createdAt}`);
  L.push('#');
  L.push('# ONE COMMAND: bash replay.sh   — every leg asserts it REPRODUCES ITS CAPTURE');
  L.push('# (status equal, marker present). A leg that no longer reproduces prints');
  L.push('# FIXED-OR-CHANGED — an honest outcome, never hidden.');
  L.push('#');
  L.push(`# All requests ride the ghost chain (${plan.proxy}) and carry '${plan.attestHeader}'.`);
  L.push('# Credentials are REFERENCED, never inlined — fill from the session broker:');
  for (const [ref, v] of credVars) {
    L.push(`#   ${v}="$(node tools/sessionbroker.mjs print-cookie <program> ${String(ref).toLowerCase()})"   # <session:${ref}>`);
  }
  L.push('set -u');
  L.push(`PROXY="${plan.proxy}"`);
  L.push('FAIL=0');
  for (const v of credVars.values()) L.push(`${v}="\${${v}:-}"`);
  L.push('');
  L.push('req() { # $1 id $2 method $3 url $4 expectStatus $5 marker $6 cookieVarName $7 body');
  L.push('  local bodyfile; bodyfile="$(mktemp)"');
  L.push('  local args=(-sS -o "$bodyfile" -w "%{http_code}" --proxy "$PROXY" -H "X-HackerOne: varvel" -X "$2")');
  L.push('  if [ -n "$6" ]; then local cv="${!6}"; if [ -z "$cv" ]; then echo "SKIP  leg $1 — credential $6 unresolved (see header)"; return; fi; args+=(-H "Cookie: $cv"); fi');
  L.push('  if [ -n "$7" ]; then args+=(-H "Content-Type: application/json" --data "$7"); fi');
  L.push('  local code; code="$(curl "${args[@]}" "$3")"');
  L.push('  if [ "$code" = "$4" ] && { [ -z "$5" ] || grep -qF "$5" "$bodyfile"; }; then');
  L.push('    echo "PASS  leg $1 ($2 $3 → $code, marker reproduced)"');
  L.push('  else');
  L.push('    echo "FAIL  leg $1 ($2 $3 → $code, expected $4${5:+ + marker}) — FIXED-OR-CHANGED, investigate before citing"');
  L.push('    FAIL=1');
  L.push('  fi');
  L.push('  rm -f "$bodyfile"');
  L.push('}');
  L.push('');
  for (const r of plan.requests) {
    const marker = (r.expect && r.expect.bodyIncludes) || '';
    const cookieVar = r.credential && r.credential.ref && r.credential.kind === 'session-cookie' ? credVars.get(r.credential.ref) : '';
    const esc = (s) => String(s).replace(/'/g, `'\\''`);
    L.push(`# leg ${r.id} [${r.role}] ${r.label}${r.credential && r.credential.kind === 'unresolved' ? ' — credential <redacted> at capture time; unresolved' : ''}`);
    L.push(`req ${r.id} '${esc(r.method)}' '${esc(r.url)}' '${r.expect && r.expect.status != null ? r.expect.status : ''}' '${esc(marker)}' '${cookieVar}' '${esc(r.body || '')}'`);
  }
  L.push('');
  L.push('exit $FAIL');
  return L.join('\n') + '\n';
}

// ——— runPlan: execute the plan against a transport, assert every leg ———
// transport injectable: ({method, url, headers, body}) → { status, body } | null.
// resolveCredential injectable: (ref) → secret string | null. A leg with an
// unresolvable credential is SKIPPED (named) — never fired with a guessed cookie.
export async function runPlan(plan, { transport, resolveCredential, now } = {}) {
  if (!plan || plan.kind !== 'varvel-replay-bundle') return { ok: false, error: 'bad-plan', reason: 'runPlan needs a replay plan (replay.json)' };
  const t = transport || defaultTransport();
  const resolve = typeof resolveCredential === 'function' ? resolveCredential : () => null;
  const legs = [];
  let pass = 0, fail = 0, skippedLegs = 0;
  for (const r of plan.requests.slice(0, REPLAY_CAPS.maxRequests)) {
    const headers = { ...(r.headers || {}) };
    if (r.credential) {
      const secret = r.credential.ref ? resolve(r.credential.ref) : null;
      if (!secret) {
        legs.push({ id: r.id, role: r.role, label: r.label, outcome: 'skipped', reason: r.credential.ref ? `credential '<session:${r.credential.ref}>' unresolved — resolve it from the session broker (never guessed)` : 'credential was <redacted> at capture time and carries no reference — unresolvable' });
        skippedLegs++;
        continue;
      }
      headers[r.credential.header || 'cookie'] = secret;
    }
    const res = await t({ method: r.method, url: r.url, headers, body: r.body });
    const assertions = [];
    if (!res || !Number.isFinite(res.status)) {
      legs.push({ id: r.id, role: r.role, label: r.label, outcome: 'transport-failed', reason: 'no response — the leg is UNVERIFIED, neither reproduced nor refuted' });
      fail++;
      continue;
    }
    let legOk = true;
    if (r.expect && r.expect.status != null) {
      const ok = res.status === r.expect.status;
      assertions.push({ kind: 'status', ok, detail: ok ? `status ${res.status} reproduced` : `status ${res.status} ≠ captured ${r.expect.status}` });
      if (!ok) legOk = false;
    }
    if (r.expect && r.expect.bodyIncludes) {
      const ok = String(res.body || '').includes(r.expect.bodyIncludes);
      assertions.push({ kind: 'marker', ok, detail: ok ? 'captured marker present' : `captured marker absent ('${r.expect.bodyIncludes.slice(0, 60)}…')` });
      if (!ok) legOk = false;
    }
    if (legOk) pass++; else fail++;
    legs.push({ id: r.id, role: r.role, label: r.label, outcome: legOk ? 'reproduced' : 'fixed-or-changed', status: res.status, assertions });
  }
  return {
    ok: true, at: iso(now),
    finding: plan.finding, base: plan.base,
    summary: { legs: legs.length, reproduced: pass, failed: fail, skipped: skippedLegs },
    verdict: fail === 0 && skippedLegs === 0 && pass > 0 ? 'REPRODUCED'
      : fail > 0 ? 'FIXED-OR-CHANGED'
      : 'INCOMPLETE', // all legs skipped — nothing verified, named honestly
    legs,
  };
}

// default runner transport — governed: ghost agents + attestation header. Never throws.
export function defaultTransport({ agents = null, timeoutMs = REPLAY_CAPS.timeoutMs } = {}) {
  return ({ method = 'GET', url, headers = {}, body = null }) => new Promise((resolvePromise) => {
    let u;
    try { u = new URL(url); } catch { return resolvePromise(null); }
    const lib = u.protocol === 'https:' ? https : http;
    const hdrs = { 'x-hackerone': 'varvel', ...headers };
    if (body != null && !hdrs['content-type']) hdrs['content-type'] = 'application/json';
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout: timeoutMs, headers: hdrs, agent: agents ? agents[u.protocol === 'https:' ? 'https' : 'http'] : undefined }, (res) => {
      let b = '';
      res.on('data', (d) => { if (b.length < 262144) b += d; });
      res.on('end', () => resolvePromise({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolvePromise(null));
    req.on('timeout', () => { req.destroy(); resolvePromise(null); });
    if (body != null) req.write(body);
    req.end();
  });
}

// CLI default credential resolution: env REPLAY_CRED_<REF> first, then the session
// broker store (ref = broker label under --program, or 'program:label').
export function makeCliResolver({ program } = {}) {
  return (ref) => {
    const envName = 'REPLAY_CRED_' + String(ref).replace(/[^A-Za-z0-9]/g, '_').toUpperCase();
    if (process.env[envName]) return process.env[envName];
    // broker lookup (lazy import to keep the emit half import-light)
    try {
      const modPath = join(__dir, 'sessionbroker.mjs');
      if (!existsSync(modPath)) return null;
      // NOTE: sync require of an ESM module is unavailable — this resolver is sync by
      // contract, so the broker leg reads the store file directly (same on-disk shape).
      const dir = process.env.VARVEL_SESSIONS_DIR || join(REPO, '.tmp', 'sessions');
      const [p, l] = String(ref).includes(':') ? String(ref).split(':') : [program, ref];
      if (!p || !l) return null;
      const f = join(dir, `${String(p).toLowerCase()}-${String(l).toLowerCase()}.json`);
      if (!existsSync(f)) return null;
      const rec = JSON.parse(readFileSync(f, 'utf8'));
      const cookies = (rec.session && rec.session.cookies) || [];
      return cookies.length ? cookies.map((c) => `${c.name}=${c.value}`).join('; ') : null;
    } catch { return null; }
  };
}

// ——— CLI ———
//   node tools/replaybind.mjs emit --pairs <pairs.json>  --base https://app.example.com --title "IDOR …" --out <dir>
//   node tools/replaybind.mjs emit --matrix <matrix.json> --base … --paths '{"B_as_A":"/webroutes/cart?uid=…"}' --out <dir>
//   node tools/replaybind.mjs run <bundleDir> [--program zomato]     (LIVE — ghost chain)
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const args = process.argv.slice(2);
  const flag = (n) => { const i = args.indexOf('--' + n); return i >= 0 ? args[i + 1] : null; };
  const out = (o) => console.log(JSON.stringify(o, null, 1));
  const cmd = args[0];
  if (cmd === 'emit') {
    const pairsFile = flag('pairs'), matrixFile = flag('matrix');
    const base = flag('base'), outDir = flag('out');
    const finding = { title: flag('title') || 'finding', ref: flag('ref'), sev: flag('sev') };
    const program = flag('program');
    let r = { ok: false, error: 'bad-input', reason: 'emit needs --pairs <file> or --matrix <file>' };
    if (pairsFile) {
      const pairs = JSON.parse(readFileSync(pairsFile, 'utf8'));
      r = planFromPairs(pairs, { base, finding, program });
    } else if (matrixFile) {
      const matrix = JSON.parse(readFileSync(matrixFile, 'utf8'));
      r = planFromMatrix(matrix, { base, finding, program, paths: flag('paths') ? JSON.parse(flag('paths')) : {}, methods: flag('methods') ? JSON.parse(flag('methods')) : {}, sessionRefs: flag('sessions') ? JSON.parse(flag('sessions')) : {} });
    }
    if (!r.ok) { out(r); process.exit(1); }
    out(emitBundle(r.plan, { outDir }));
  } else if (cmd === 'run') {
    const dirName = args[1];
    const plan = JSON.parse(readFileSync(join(dirName, 'replay.json'), 'utf8'));
    const { Ghost } = await import('../engine/ghost.mjs');
    const ghost = new Ghost({});
    try { ghost.configure({ mode: 'on', chain: process.env.VARVEL_REPLAY_CHAIN || 'socks5://10.64.0.1:1080' }); } catch (e) { console.error('ghost chain: ' + e.message); process.exit(1); }
    const ag = ghost.agents();
    const agents = ag ? { http: ag.httpAgent, https: ag.httpsAgent } : null;
    const r = await runPlan(plan, { transport: defaultTransport({ agents }), resolveCredential: makeCliResolver({ program: flag('program') || plan.program }) });
    out(r);
    process.exit(r.verdict === 'REPRODUCED' ? 0 : 2);
  } else {
    console.error('usage: replaybind.mjs emit --pairs|--matrix <file> --base <url> --out <dir> [--title …] [--ref …] [--program …] [--paths/--sessions <json>]');
    console.error('       replaybind.mjs run <bundleDir> [--program <p>]   (live replay through the ghost chain)');
    process.exit(1);
  }
}
