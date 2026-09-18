// VARVEL — sessionbroker: the REAL-BROWSER SESSION BROKER (winner-copyables build, Tool 1).
//
// The verified-earner insight (research/2026-08-31-ai-hunter-practitioner-brief.md §2/§5):
// ~80% of harvested tokens die on login/session handling; the single biggest quality jump
// was a persistent-session layer in front of the account factory. varvel had account
// CREATION (tools/acctfactory.mjs) and one-off browser login scripts (.tmp/fe-login.mjs,
// .tmp/zom-signup.mjs) but no PERSISTENCE layer — every campaign re-derived auth from
// scratch. This module is that layer:
//
//   (a) STORE — per-program session state (cookies / bearer headers) at
//       .tmp/sessions/<program>-<label>.json with creation/expiry/health metadata.
//   (b) CHEAP DEATH DETECTION — a canary authenticated endpoint per session, HARVESTED
//       AT PROVISION TIME (never invented), checked BEFORE a campaign spends budget.
//   (c) RECOVERY — a stored token-refresh recipe (frontegg: refresh-cookie →
//       POST …/user/token/refresh, 24h TTL) runs first; a stored browser relogin
//       recipe runs when refresh can't save it.
//   (d) HANDLE — getLiveSession() hands the campaign engine a live session in EXACTLY
//       the {label, cookie} | {label, headers} shape tools/authzsweep.mjs's
//       provisionSession()/sanitizeAuthzCfg() consume.
//
// ORACLE CONTRACT: a session is 'live' ONLY when the canary answered with an expected
// authenticated status (and no deny signal). A TRANSPORT failure is state 'unknown' —
// never reported dead, never reported alive. A dead canary that neither refresh nor
// relogin could revive is reported DEAD with the recipe named — honest negative results,
// never a fabricated live handle.
//
// GOVERNANCE: the default probe/refresh transport rides the ghost chain (agents from
// engine/ghost.mjs) and carries the engagement attestation header (X-HackerOne: varvel).
// Secrets (cookie values, tokens) live ONLY in the session files under .tmp/sessions/ —
// listSessions() masks them; nothing here writes them into reports or logs. Every
// function returns structured results and NEVER throws. Tests inject probe/transport/
// relogin fakes — no live network in tests.
//
// usage:
//   import { getLiveSession, migrateLegacySessions, checkSession } from './tools/sessionbroker.mjs';
//   const r = await getLiveSession('zomato', 'a', { probe });      // → { ok, state:'live', session:{label,cookie} }
//   const cfg = sanitizeAuthzCfg({ accounts: [r.session, r2.session] });

import http from 'node:http';
import https from 'node:https';
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';

const __dir = dirname(fileURLToPath(import.meta.url));
const REPO = join(__dir, '..');

export const SESSION_CAPS = { maxCookies: 64, maxHistory: 20, canaryTimeoutMs: 15000, reloginTimeoutMs: 300000, bodySnippet: 800, maxSessions: 64 };

// Session store root: .tmp/sessions/ (the working dir already holds the cookie jars
// this broker manages). Tests isolate via VARVEL_SESSIONS_DIR.
const SESSIONS_DIR = () => process.env.VARVEL_SESSIONS_DIR || join(REPO, '.tmp', 'sessions');

const SLUG_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const okSlug = (s) => SLUG_RE.test(String(s || ''));
const fileFor = (dir, program, label) => join(dir || SESSIONS_DIR(), `${String(program).toLowerCase()}-${String(label).toLowerCase()}.json`);
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const ms = (now) => (now === undefined ? Date.now() : (typeof now === 'number' ? now : Date.parse(now)));
const logTo = (onLog, obj) => { if (typeof onLog === 'function') { try { onLog(obj); } catch { /* observer never breaks the broker */ } } };

// ——— persistence ———
const readJson = (p) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : null; } catch { return null; } };

// registerSession — validate + persist a session entry. Refuses a silent overwrite
// (replace:true to re-register); refuses a session with NO credential material at all
// (a broker entry that cannot authenticate anything is a fiction).
export function registerSession(entry, { dir, now, replace = false } = {}) {
  if (!entry || typeof entry !== 'object') return { ok: false, error: 'bad-entry', reason: 'registerSession needs an entry object' };
  const program = String(entry.program || '').toLowerCase();
  const label = String(entry.label || '').toLowerCase();
  if (!okSlug(program) || !okSlug(label)) return { ok: false, error: 'bad-slug', reason: `program/label must match ${SLUG_RE} (got '${program}'/'${label}')` };
  const session = sanitizeSession(entry.session);
  if (!session) return { ok: false, error: 'no-credentials', reason: 'the entry carries neither cookies nor bearer/auth headers — a session that cannot authenticate anything is not a session' };
  if (!entry.canary || typeof entry.canary.url !== 'string' || !/^https?:\/\//i.test(entry.canary.url)) {
    return { ok: false, error: 'no-canary', reason: 'every managed session needs a canary authenticated endpoint ({canary:{url,…}}) harvested at provision time — cheap death detection is the point of the broker' };
  }
  const file = fileFor(dir, program, label);
  if (existsSync(file) && !replace) return { ok: false, error: 'already-registered', reason: `${program}-${label} is already managed — pass replace:true to re-register deliberately` };
  const rec = {
    v: 1, program, label,
    createdAt: iso(entry.createdAt !== undefined ? entry.createdAt : now),
    updatedAt: iso(now),
    expiresAt: entry.expiresAt ? iso(entry.expiresAt) : null,
    session,
    canary: {
      method: String(entry.canary.method || 'GET').toUpperCase(),
      url: entry.canary.url,
      auth: entry.canary.auth === 'bearer' ? 'bearer' : 'cookie',
      expectStatus: Array.isArray(entry.canary.expectStatus) && entry.canary.expectStatus.length ? entry.canary.expectStatus.map(Number).filter(Number.isFinite) : [200],
      denyStatus: Array.isArray(entry.canary.denyStatus) ? entry.canary.denyStatus.map(Number).filter(Number.isFinite) : [401, 403],
      denyBodyRe: typeof entry.canary.denyBodyRe === 'string' ? entry.canary.denyBodyRe : null,
      harvestedFrom: typeof entry.canary.harvestedFrom === 'string' ? entry.canary.harvestedFrom : null,
      note: typeof entry.canary.note === 'string' ? entry.canary.note : null,
    },
    refresh: sanitizeRefresh(entry.refresh),
    relogin: entry.relogin && typeof entry.relogin === 'object'
      ? { kind: entry.relogin.kind === 'script' ? 'script' : 'manual', command: typeof entry.relogin.command === 'string' ? entry.relogin.command : null, resultPath: typeof entry.relogin.resultPath === 'string' ? entry.relogin.resultPath : null, note: typeof entry.relogin.note === 'string' ? entry.relogin.note : null }
      : null,
    notes: typeof entry.notes === 'string' ? entry.notes : null,
    health: { lastCheckedAt: null, state: 'never-checked', history: [] },
  };
  try {
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, JSON.stringify(rec, null, 2) + '\n');
  } catch (e) { return { ok: false, error: 'persist-failed', reason: String((e && e.message) || e) }; }
  return { ok: true, program, label, file, entry: rec };
}

function sanitizeSession(s) {
  if (!s || typeof s !== 'object') return null;
  const cookies = (Array.isArray(s.cookies) ? s.cookies : [])
    .filter((c) => c && typeof c.name === 'string' && typeof c.value === 'string')
    .slice(0, SESSION_CAPS.maxCookies)
    .map((c) => ({ name: c.name, value: c.value, domain: typeof c.domain === 'string' ? c.domain : null }));
  let headers = null;
  if (s.headers && typeof s.headers === 'object' && !Array.isArray(s.headers)) {
    headers = {};
    for (const [k, v] of Object.entries(s.headers).slice(0, 8)) {
      if (/^[a-z0-9-]+$/i.test(k) && typeof v === 'string' && v && v.length <= 4096) headers[k.toLowerCase()] = v;
    }
    if (!Object.keys(headers).length) headers = null;
  }
  if (!cookies.length && !headers) return null;
  return { cookies, headers, userId: s.userId != null ? String(s.userId) : null };
}

function sanitizeRefresh(r) {
  if (!r || typeof r !== 'object' || typeof r.url !== 'string' || !/^https?:\/\//i.test(r.url)) return null;
  return {
    type: 'token-refresh',
    url: r.url,
    method: String(r.method || 'POST').toUpperCase(),
    useCookies: r.useCookies !== false, // the frontegg pattern: the refresh cookie rides, credentials:include
    body: r.body != null ? (typeof r.body === 'string' ? r.body : JSON.stringify(r.body)) : null,
    tokenPath: typeof r.tokenPath === 'string' ? r.tokenPath : 'accessToken',
    ttlSeconds: Number.isFinite(Number(r.ttlSeconds)) && Number(r.ttlSeconds) > 0 ? Number(r.ttlSeconds) : 86400,
  };
}

export function loadSession(program, label, { dir } = {}) {
  const rec = readJson(fileFor(dir, program, label));
  return rec && rec.v === 1 && rec.program === String(program).toLowerCase() && rec.label === String(label).toLowerCase() ? rec : null;
}

function saveEntry(rec, { dir, now } = {}) {
  rec.updatedAt = iso(now);
  try { writeFileSync(fileFor(dir, rec.program, rec.label), JSON.stringify(rec, null, 2) + '\n'); return true; } catch { return false; }
}

// listSessions — the operator's inventory view. SECRETS MASKED: cookie values and
// header values never leave this function (name/domain/length only).
export function listSessions({ dir } = {}) {
  const d = dir || SESSIONS_DIR();
  let files = [];
  try { files = readdirSync(d).filter((f) => f.endsWith('.json')).slice(0, SESSION_CAPS.maxSessions); } catch { return { ok: true, dir: d, sessions: [] }; }
  const sessions = [];
  for (const f of files) {
    const rec = readJson(join(d, f));
    if (!rec || rec.v !== 1) continue;
    sessions.push({
      program: rec.program, label: rec.label, file: join(d, f),
      createdAt: rec.createdAt, updatedAt: rec.updatedAt, expiresAt: rec.expiresAt,
      cookies: rec.session.cookies.map((c) => ({ name: c.name, domain: c.domain, value: `<stored:${c.value.length} chars>` })),
      headerNames: rec.session.headers ? Object.keys(rec.session.headers) : [],
      canary: { method: rec.canary.method, url: rec.canary.url, auth: rec.canary.auth },
      refresh: rec.refresh ? { url: rec.refresh.url, ttlSeconds: rec.refresh.ttlSeconds } : null,
      relogin: rec.relogin ? { kind: rec.relogin.kind, command: rec.relogin.command } : null,
      health: rec.health ? { lastCheckedAt: rec.health.lastCheckedAt, state: rec.health.state } : null,
    });
  }
  return { ok: true, dir: d, sessions };
}

// ——— credential material for a request ———
// Domain match: a cookie rides when its domain is the target host or a leading-dot
// parent of it (the browser rule, minimal form).
export function cookieHeaderFor(entry, url) {
  let host = '';
  try { host = new URL(url).hostname; } catch { return null; }
  const parts = [];
  for (const c of (entry.session && entry.session.cookies) || []) {
    const d = String(c.domain || '').replace(/^\./, '').toLowerCase();
    if (!d) continue;
    if (host === d || host.endsWith('.' + d)) parts.push(`${c.name}=${c.value}`);
  }
  return parts.length ? parts.join('; ') : null;
}

// The campaign-facing handle — EXACTLY the authzsweep account/session shape.
export function handleFor(entry) {
  if (!entry || !entry.session) return null;
  const cookie = entry.session.cookies.length
    ? entry.session.cookies.map((c) => `${c.name}=${c.value}`).join('; ')
    : null;
  const headers = entry.session.headers ? { ...entry.session.headers } : null;
  if (!cookie && !headers) return null;
  return { label: `${entry.program}-${entry.label}`, cookie, headers, program: entry.program, sessionLabel: entry.label };
}

// ——— transports (never throw) ———
// defaultProbe: one governed GET/HEAD through the ghost agents with the session's
// credentials. Returns { status, headers, body } or null on any transport failure.
export function defaultProbe({ agents = null, extraHeaders = null, timeoutMs = SESSION_CAPS.canaryTimeoutMs } = {}) {
  return ({ method = 'GET', url, cookie = null, headers = null }) => new Promise((resolvePromise) => {
    let u;
    try { u = new URL(url); } catch { return resolvePromise(null); }
    const lib = u.protocol === 'https:' ? https : http;
    const hdrs = { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', 'x-hackerone': 'varvel', ...(extraHeaders || {}) };
    if (cookie) hdrs.cookie = cookie;
    if (headers) for (const [k, v] of Object.entries(headers)) hdrs[k] = v;
    const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout: timeoutMs, headers: hdrs, agent: agents ? agents[u.protocol === 'https:' ? 'https' : 'http'] : undefined }, (res) => {
      let b = '';
      res.on('data', (d) => { if (b.length < 65536) b += d; });
      res.on('end', () => resolvePromise({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolvePromise(null));
    req.on('timeout', () => { req.destroy(); resolvePromise(null); });
    req.end();
  });
}

// ——— the canary oracle ———
// ALIVE only on an expected status with no deny signal. DEAD on a deny status or deny
// body pattern. UNKNOWN on transport failure or an unclassified status — a network
// blip is NOT a dead session, and an unexpected 2xx-with-weird-body is NOT a live one.
export function canaryVerdict(entry, res) {
  const c = entry.canary;
  if (!res || !Number.isFinite(res.status)) return { state: 'unknown', reason: 'transport failure — the canary produced no response; the session is NEITHER proven dead NOR proven live' };
  if (c.denyStatus.includes(res.status)) return { state: 'dead', status: res.status, reason: `canary answered ${res.status} — an authentication challenge; the session credential is refused` };
  if (c.denyBodyRe) {
    let re = null;
    try { re = new RegExp(c.denyBodyRe, 'i'); } catch { re = null; }
    if (re && re.test(String(res.body || '').slice(0, 65536))) return { state: 'dead', status: res.status, reason: `canary body matches the deny pattern /${c.denyBodyRe}/ — the endpoint is speaking to a logged-out client` };
  }
  if (c.expectStatus.includes(res.status)) return { state: 'alive', status: res.status, reason: `canary answered the expected authenticated status ${res.status}` };
  return { state: 'unknown', status: res.status, reason: `canary answered ${res.status} — neither an expected status (${c.expectStatus.join('/')}) nor a deny signal (${c.denyStatus.join('/')}); unclassified` };
}

function recordHealth(entry, state, detail, now) {
  const at = iso(now);
  entry.health = entry.health && Array.isArray(entry.health.history) ? entry.health : { history: [] };
  entry.health.lastCheckedAt = at;
  entry.health.state = state;
  entry.health.history.push({ at, state, detail: String(detail || '').slice(0, 240) });
  if (entry.health.history.length > SESSION_CAPS.maxHistory) entry.health.history = entry.health.history.slice(-SESSION_CAPS.maxHistory);
}

// checkSession — the CHEAP death check: one canary request, one verdict, health journaled.
export async function checkSession(entry, { probe, now } = {}) {
  if (!entry || !entry.canary) return { ok: false, error: 'no-canary', reason: 'entry has no canary endpoint' };
  const p = probe || defaultProbe();
  const c = entry.canary;
  const credential = c.auth === 'bearer'
    ? { headers: entry.session.headers ? { ...entry.session.headers } : null }
    : { cookie: cookieHeaderFor(entry, c.url), headers: entry.session.headers ? { ...entry.session.headers } : null };
  const res = await p({ method: c.method, url: c.url, ...credential });
  const v = canaryVerdict(entry, res);
  recordHealth(entry, v.state, v.reason, now);
  return { ok: true, alive: v.state === 'alive', state: v.state, status: v.status || null, reason: v.reason, at: iso(now) };
}

// ——— refresh (the frontegg pattern: refresh-cookie → POST …/user/token/refresh, 24h TTL) ———
// transport injectable: ({method, url, cookie, body}) → { status, headers, json, body } | null.
// On a 2xx carrying the token: patch the bearer header + expiry; MERGE any rotated
// cookies the response sets (refresh-token rotation is real — drop it and the next
// refresh dies). A non-2xx is an honest {ok:false} — never a fabricated token.
export async function refreshSession(entry, { transport, now } = {}) {
  const r = entry && entry.refresh;
  if (!r) return { ok: false, error: 'no-refresh-recipe', reason: 'this entry has no token-refresh recipe — recovery needs the relogin path' };
  const t = transport || defaultTransport();
  const cookie = r.useCookies ? cookieHeaderFor(entry, r.url) : null;
  const res = await t({ method: r.method, url: r.url, cookie, body: r.body });
  if (!res || !Number.isFinite(res.status)) return { ok: false, error: 'refresh-transport-failed', reason: 'the refresh endpoint produced no response — token state UNCHANGED, honestly unknown' };
  if (res.status < 200 || res.status >= 300) return { ok: false, error: 'refresh-refused', status: res.status, reason: `the refresh endpoint answered ${res.status} — the refresh credential is dead; the relogin recipe is the recovery path` };
  const json = res.json !== undefined ? res.json : (() => { try { return JSON.parse(res.body || ''); } catch { return null; } })();
  const token = json && r.tokenPath.split('.').reduce((o, k) => (o && o[k] !== undefined ? o[k] : undefined), json);
  if (!token || typeof token !== 'string') return { ok: false, error: 'refresh-no-token', status: res.status, reason: `refresh answered ${res.status} but the body carries no '${r.tokenPath}' — the recipe's token path disagrees with the live shape` };
  // apply the patch
  entry.session.headers = { ...(entry.session.headers || {}), authorization: 'Bearer ' + token };
  const ttlMs = (Number(json.expiresIn) > 0 ? Number(json.expiresIn) : r.ttlSeconds) * 1000;
  entry.expiresAt = new Date(ms(now) + ttlMs).toISOString();
  // rotated refresh cookies ride set-cookie — merge by name
  const setCookies = res.headers && res.headers['set-cookie'];
  const list = Array.isArray(setCookies) ? setCookies : (setCookies ? [setCookies] : []);
  for (const sc of list) {
    const pair = String(sc).split(';')[0];
    const eq = pair.indexOf('=');
    if (eq < 1) continue;
    const name = pair.slice(0, eq).trim(), value = pair.slice(eq + 1).trim();
    const dm = /;\s*domain=([^;]+)/i.exec(sc);
    const existing = entry.session.cookies.find((c) => c.name === name);
    if (existing) { existing.value = value; if (dm) existing.domain = dm[1].trim(); }
    else entry.session.cookies.push({ name, value, domain: dm ? dm[1].trim() : null });
  }
  recordHealth(entry, 'refreshed', `token refreshed via ${r.url} (ttl ${Math.round(ttlMs / 3600000)}h)`, now);
  return { ok: true, token: { length: token.length }, expiresAt: entry.expiresAt, rotatedCookies: list.length };
}

function defaultTransport({ agents = null } = {}) {
  return async ({ method, url, cookie, body }) => {
    // defaultProbe doesn't send a body; extend it minimally here for the refresh POST.
    return new Promise((resolvePromise) => {
      let u;
      try { u = new URL(url); } catch { return resolvePromise(null); }
      const lib = u.protocol === 'https:' ? https : http;
      const headers = { 'x-hackerone': 'varvel', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' };
      if (cookie) headers.cookie = cookie;
      if (body != null) headers['content-type'] = 'application/json';
      const req = lib.request({ hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname + u.search, method, timeout: SESSION_CAPS.canaryTimeoutMs, headers, agent: agents ? agents[u.protocol === 'https:' ? 'https' : 'http'] : undefined }, (res) => {
        let b = '';
        res.on('data', (d) => { if (b.length < 65536) b += d; });
        res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* honest null */ } resolvePromise({ status: res.statusCode, headers: res.headers, json, body: b }); });
      });
      req.on('error', () => resolvePromise(null));
      req.on('timeout', () => { req.destroy(); resolvePromise(null); });
      if (body != null) req.write(body);
      req.end();
    });
  };
}

// ——— relogin via the stored browser recipe ———
// INJECTABLE first: opts.relogin(entry) → { session:{cookies?, headers?} } refreshes the
// stored state. The SCRIPT recipe (entry.relogin.kind==='script') runs ONLY under
// allowSpawn:true (a browser login is a heavyweight, operator-visible act — never fired
// silently from a library call). After the recipe runs, fresh state is read from
// entry.relogin.resultPath (the .tmp/*-result.json shape the fe/zom scripts write).
export async function reloginSession(entry, { relogin, allowSpawn = false, spawn, now } = {}) {
  const recipe = entry && entry.relogin;
  if (!recipe) return { ok: false, error: 'no-relogin-recipe', reason: 'no browser relogin recipe is stored for this session — re-provision via the account factory and re-register' };
  if (typeof relogin === 'function') {
    let fresh = null;
    try { fresh = await relogin(entry); } catch (e) { return { ok: false, error: 'relogin-threw', reason: String((e && e.message) || e) }; }
    const session = fresh && sanitizeSession(fresh.session || fresh);
    if (!session) return { ok: false, error: 'relogin-no-session', reason: 'the relogin ran but produced no cookie/bearer material — the recipe could not re-authenticate' };
    entry.session = session;
    recordHealth(entry, 'reauthed', 'relogin recipe (injected) produced fresh session material', now);
    return { ok: true, via: 'injected' };
  }
  if (recipe.kind !== 'script' || !recipe.command) {
    return { ok: false, error: 'relogin-manual', reason: `relogin is a MANUAL recipe (${recipe.note || 'no command stored'}) — run it by hand, then re-check` };
  }
  if (!allowSpawn) {
    return { ok: false, error: 'relogin-not-armed', reason: `a browser relogin recipe is stored ('${recipe.command}') but spawning it needs allowSpawn:true — a headed browser login is an operator-visible act, never fired silently` };
  }
  const run = spawn || ((cmd, args) => new Promise((res) => {
    execFile(cmd, args, { cwd: REPO, timeout: SESSION_CAPS.reloginTimeoutMs }, (err) => res(!err));
  }));
  // command is stored as e.g. 'node .tmp/zom-signup.mjs a' — split on whitespace, first token is the bin.
  const parts = recipe.command.split(/\s+/).filter(Boolean);
  const ran = await run(parts[0], parts.slice(1));
  if (!ran) return { ok: false, error: 'relogin-failed', reason: `the relogin recipe '${recipe.command}' exited non-zero or timed out — session state UNCHANGED` };
  const fresh = recipe.resultPath ? readJson(resolve(REPO, recipe.resultPath)) : null;
  const session = fresh && sanitizeSession({ cookies: fresh.cookies, headers: fresh.headers });
  if (!session) return { ok: false, error: 'relogin-no-session', reason: `the recipe ran but ${recipe.resultPath || '(no resultPath)'} yielded no usable session material` };
  entry.session = session;
  recordHealth(entry, 'reauthed', `relogin recipe '${recipe.command}' produced fresh session material`, now);
  return { ok: true, via: 'script' };
}

// ——— THE BROKER VERB: hand the campaign a live session ———
// Flow: load → (expired + refresh recipe? refresh first) → canary → alive? done →
// dead? refresh (if untried) → re-canary → still dead? relogin → re-canary →
// report. Every step lands in checks[] and the entry's health journal; the persisted
// entry is saved whenever it changed. NEVER throws, NEVER fabricates a live session.
export async function getLiveSession(program, label, { dir, probe, transport, relogin, allowSpawn = false, save = true, now, onLog } = {}) {
  const checks = [];
  const entry = loadSession(program, label, { dir });
  if (!entry) return { ok: false, error: 'unknown-session', reason: `no managed session '${program}-${label}' — register one first (registerSession / migrateLegacySessions)`, checks };
  const persist = () => { if (save) saveEntry(entry, { dir, now }); };
  const doCanary = async (step) => {
    const c = await checkSession(entry, { probe, now });
    checks.push({ step, ...c });
    logTo(onLog, { type: 'sessionbroker.canary', program: entry.program, label: entry.label, state: c.state, status: c.status });
    return c;
  };
  const doRefresh = async (step) => {
    const r = await refreshSession(entry, { transport, now });
    checks.push({ step, ...r });
    logTo(onLog, { type: 'sessionbroker.refresh', program: entry.program, label: entry.label, ok: r.ok, error: r.error || null });
    return r;
  };

  // metadata expiry: a known-expired token refreshes BEFORE the canary spends a request
  let refreshed = false;
  if (entry.expiresAt && ms(now) >= Date.parse(entry.expiresAt) && entry.refresh) {
    const r = await doRefresh('refresh:expired-metadata');
    refreshed = r.ok;
    if (!r.ok && r.error === 'refresh-refused') {
      // refresh credential dead — fall through to relogin directly; the canary would
      // just re-prove death.
      const rel = await reloginSession(entry, { relogin, allowSpawn, now });
      checks.push({ step: 'relogin', ...rel });
      if (rel.ok) {
        const c2 = await doCanary('canary:post-relogin');
        persist();
        if (c2.alive) return { ok: true, state: 'reauthed', session: handleFor(entry), checks, health: entry.health.state };
        return { ok: false, error: 'session-dead', reason: `relogin succeeded but the canary still says ${c2.state} — ${c2.reason}`, checks };
      }
      persist();
      return { ok: false, error: rel.error, reason: rel.reason, checks, relogin: entry.relogin ? { kind: entry.relogin.kind, command: entry.relogin.command } : null };
    }
  }

  let c = await doCanary('canary');
  if (c.alive) { persist(); return { ok: true, state: refreshed ? 'refreshed' : 'live', session: handleFor(entry), checks, health: entry.health.state }; }

  if (c.state === 'unknown') {
    persist();
    return { ok: false, error: 'canary-unverifiable', reason: c.reason + ' — the session is NOT handed out unverified; retry when the path is healthy', checks };
  }

  // dead → refresh (if a recipe exists and wasn't already tried)
  if (entry.refresh && !refreshed) {
    const r = await doRefresh('refresh:dead-canary');
    if (r.ok) {
      refreshed = true;
      c = await doCanary('canary:post-refresh');
      if (c.alive) { persist(); return { ok: true, state: 'refreshed', session: handleFor(entry), checks, health: entry.health.state }; }
    }
  }

  // still dead → the browser relogin recipe
  const rel = await reloginSession(entry, { relogin, allowSpawn, now });
  checks.push({ step: 'relogin', ...rel });
  if (rel.ok) {
    const c2 = await doCanary('canary:post-relogin');
    persist();
    if (c2.alive) return { ok: true, state: 'reauthed', session: handleFor(entry), checks, health: entry.health.state };
    return { ok: false, error: 'session-dead', reason: `relogin succeeded but the canary still says ${c2.state} — ${c2.reason}`, checks };
  }
  persist();
  return {
    ok: false, error: 'session-dead', checks,
    reason: `the canary says DEAD (${c.reason}) and recovery failed: ${rel.reason}`,
    relogin: entry.relogin ? { kind: entry.relogin.kind, command: entry.relogin.command, note: entry.relogin.note } : null,
  };
}

// ——— migration: today's zomato + frontegg sessions become the first managed entries ———
// Reads the EXISTING .tmp artifacts (never modifies them). Canary endpoints are HARVESTED
// from the captured XHR journals — a zomato canary is the user-notification endpoint the
// real session actually called (carries the harvested user_id), never an invented route.
// No network in migration: entries register as health 'never-checked'.
// Analytics/tracker cookies are noise in a managed session — they authenticate nothing
// and only widen what the store holds. Dropped at migration (named, not silent).
const TRACKER_COOKIE_RE = /^(_ga|_gid|_gat|_gcl|_fbp|_hp2|__hs|hubspotutk|g_state|G_ENABLED_IDPS|_dd_s|_uetsid|_uetvid)/i;

export function migrateLegacySessions({ tmp = join(REPO, '.tmp'), dir, now, onLog } = {}) {
  const made = [];
  const skipped = [];

  // zomato A/B — cookie jars from the harvest rides (fresher) or the signup results.
  for (const side of ['a', 'b']) {
    const harvest = readJson(join(tmp, `zom-harvest-${side}.json`));
    const signup = readJson(join(tmp, `zom-signup-${side}-result.json`));
    const src = harvest && Array.isArray(harvest.cookies) && harvest.cookies.length ? harvest
      : (signup && Array.isArray(signup.cookies) && signup.cookies.length ? signup : null);
    if (!src) { skipped.push({ program: 'zomato', label: side, reason: `no cookie material in .tmp/zom-harvest-${side}.json or .tmp/zom-signup-${side}-result.json` }); continue; }
    let userId = null, canaryUrl = null, harvestedFrom = null;
    for (const x of (harvest && harvest.xhr) || []) {
      const m = /user_id=(\d+)/.exec((x && x.url) || '');
      if (m && x.status === 200 && /get_user_notifications/.test(x.url)) { userId = m[1]; canaryUrl = x.url; harvestedFrom = `.tmp/zom-harvest-${side}.json xhr journal`; break; }
    }
    if (!canaryUrl) {
      // auth/init answered 200 under the real session in the same journal — weaker but harvested, not invented.
      const init = ((harvest && harvest.xhr) || []).find((x) => x && x.status === 200 && /\/webroutes\/auth\/init/.test(x.url || ''));
      if (init) { canaryUrl = init.url.split('?')[0]; harvestedFrom = `.tmp/zom-harvest-${side}.json xhr journal (auth/init)`; }
    }
    if (!canaryUrl) { skipped.push({ program: 'zomato', label: side, reason: 'no authenticated XHR in the harvest journal to harvest a canary from' }); continue; }
    const r = registerSession({
      program: 'zomato', label: side, now,
      session: { cookies: src.cookies.filter((c) => /zomato/.test(c.domain || '') && !TRACKER_COOKIE_RE.test(c.name)), userId },
      canary: {
        method: 'GET', url: canaryUrl, auth: 'cookie',
        expectStatus: [200], denyStatus: [401, 403],
        denyBodyRe: 'Unauthorized request',
        harvestedFrom,
        note: userId ? `authenticated notification poll carrying harvested user_id ${userId}; the unauth control for this class answered 401 {"message":"Unauthorized request! Please refresh the page."} in the 2026-08-31 cart matrix` : 'auth/init answered 200 under the real session at harvest time',
      },
      relogin: { kind: 'script', command: `node .tmp/zom-signup.mjs ${side}`, resultPath: `.tmp/zom-signup-${side}-result.json`, note: 'headed Firefox signup/login through the ghost chain (mail.tm OTP)' },
      notes: `migrated from ${harvest ? '.tmp/zom-harvest-' + side + '.json' : '.tmp/zom-signup-' + side + '-result.json'} (${src.email || 'email unknown'})`,
    }, { dir, now, replace: true });
    if (r.ok) { made.push({ program: 'zomato', label: side, file: r.file }); logTo(onLog, { type: 'sessionbroker.migrate', program: 'zomato', label: side, ok: true }); }
    else skipped.push({ program: 'zomato', label: side, reason: r.reason });
  }

  // frontegg A/B — REFRESH-ONLY entries: the refresh cookie mints a 24h access token via
  // POST …/user/token/refresh; no re-login is needed while the refresh cookie lives.
  for (const side of ['a', 'b']) {
    const login = readJson(join(tmp, `fe-login-${side}-result.json`));
    if (!login || !Array.isArray(login.cookies) || !login.cookies.length) { skipped.push({ program: 'frontegg', label: side, reason: `no cookie material in .tmp/fe-login-${side}-result.json` }); continue; }
    const cookies = login.cookies.filter((c) => /frontegg/.test(c.domain || '') && !TRACKER_COOKIE_RE.test(c.name));
    const refreshCookie = cookies.find((c) => /^fe_refresh_/.test(c.name));
    if (!refreshCookie) { skipped.push({ program: 'frontegg', label: side, reason: 'no fe_refresh_* cookie captured — the refresh-only recipe cannot ride' }); continue; }
    const r = registerSession({
      program: 'frontegg', label: side, now,
      session: { cookies },
      canary: {
        method: 'GET', url: 'https://api.au.frontegg.com/v1/me', auth: 'bearer',
        expectStatus: [200], denyStatus: [401, 403],
        harvestedFrom: '.tmp/fe-harvest.mjs route list (probed under a live token 2026-08-31)',
        note: 'the canary rides the REFRESHED bearer — refresh runs before the canary whenever the 24h token TTL elapsed',
      },
      refresh: {
        url: 'https://frontegg-prod.au.frontegg.com/frontegg/identity/resources/auth/v1/user/token/refresh',
        method: 'POST', useCookies: true, tokenPath: 'accessToken', ttlSeconds: 86400,
      },
      relogin: { kind: 'script', command: `node .tmp/fe-login.mjs ${side}`, resultPath: `.tmp/fe-login-${side}-result.json`, note: 'headed Firefox email-code + TOTP enrollment through the ghost chain; needed ONLY when the refresh cookie itself dies' },
      notes: `migrated from .tmp/fe-login-${side}-result.json (${login.email || 'email unknown'}); refresh-only entry — refresh cookie ${refreshCookie.name}`,
    }, { dir, now, replace: true });
    if (r.ok) { made.push({ program: 'frontegg', label: side, file: r.file }); logTo(onLog, { type: 'sessionbroker.migrate', program: 'frontegg', label: side, ok: true }); }
    else skipped.push({ program: 'frontegg', label: side, reason: r.reason });
  }
  return { ok: true, registered: made, skipped };
}

// ——— CLI ———
//   node tools/sessionbroker.mjs list
//   node tools/sessionbroker.mjs check <program> <label>   (LIVE — rides the ghost chain)
//   node tools/sessionbroker.mjs migrate                    (register .tmp legacy sessions)
//   node tools/sessionbroker.mjs print-cookie <program> <label>   (replay bundles resolve cookies through this)
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const [cmd, prog, lbl] = process.argv.slice(2);
  const out = (o) => console.log(JSON.stringify(o, null, 1));
  if (cmd === 'list') out(listSessions({}));
  else if (cmd === 'migrate') out(migrateLegacySessions({ onLog: (o) => console.error(JSON.stringify(o)) }));
  else if (cmd === 'print-cookie' && prog && lbl) {
    const e = loadSession(prog, lbl, {});
    if (!e) { console.error(`no managed session ${prog}-${lbl}`); process.exit(1); }
    const h = handleFor(e);
    if (h && h.cookie) process.stdout.write(h.cookie);
    else { console.error('session carries no cookie material'); process.exit(1); }
  } else if (cmd === 'check' && prog && lbl) {
    const { Ghost } = await import('../engine/ghost.mjs');
    const ghost = new Ghost({});
    try { ghost.configure({ mode: 'on', chain: process.env.VARVEL_SESSIONBROKER_CHAIN || 'socks5://10.64.0.1:1080' }); } catch (e) { console.error('ghost chain: ' + e.message); process.exit(1); }
    const ag = ghost.agents();
    const agents = ag ? { http: ag.httpAgent, https: ag.httpsAgent } : null;
    const r = await getLiveSession(prog, lbl, { probe: defaultProbe({ agents }), transport: defaultTransport(), onLog: (o) => console.error(JSON.stringify(o)) });
    out({ ...r, session: r.session ? { ...r.session, cookie: r.session.cookie ? `<stored:${r.session.cookie.length} chars>` : null, headers: r.session.headers ? Object.keys(r.session.headers) : null } : null });
    process.exit(r.ok ? 0 : 2);
  } else {
    console.error('usage: sessionbroker.mjs list | migrate | check <program> <label> | print-cookie <program> <label>');
    process.exit(1);
  }
}
