// VARVEL -- sessride: the governed SESSION ride. ONE request path that carries BOTH
// identities an authenticated engagement needs:
//   (a) the vaulted cf_clearance (the edge identity -- IP+UA bound, TTL-validated by the
//       clearance vault, the same vault cfride/wafbypass ride), and
//   (b) an operator-supplied authenticated session jar: a JSON array of [name, value]
//       pairs (the sess_jar.json shape, e.g. wordpress_logged_in_*).
//
// This productizes the field-expedient session.mjs written under fire on the manhuaus
// engagement -- with the governance stack that script lacked, and WITHOUT its
// host-corruption bug (it built targets by string concat and once dialed the hostname
// 'manhuaus.comc'; here EVERY hop is parsed as an absolute http(s) URL -- hosts are
// never concatenated, and the default port comes from the parsed protocol).
//
// GOVERNANCE (the platform's absolute rules, non-negotiable):
// * SCOPE: the signed engagement scope is checked BEFORE any request (the
//   wafbypass/lfichain doctrine: resolve the host, EVERY resolved IP must sit inside
//   the signed CIDRs, the refusal prints the scope) and RE-CHECKED on every redirect
//   hop -- a redirect can never walk the ride out of scope. The session also never
//   leaves its host: a cross-host Location is reported as data, never followed with
//   the credentials (credential-leak guard).
// * EGRESS PARITY: identical to cfride -- the vault entry's egressId is the binding
//   contract. broker.resolveRideTransport maps it to the armed ghost chain (canonical
//   ids must match), a sanctioned direct ride, or a fail-closed refusal; ghost
//   'required' never rides direct to a public target. The default fetcher ALSO refuses
//   a public target with no agents unless the gate sanctioned direct (defense in
//   depth, the cfride pattern). The lookup egressId defaults the wafbypass way: the
//   armed chain's canonical id, else 'direct'; opts.egressId overrides explicitly.
// * HONESTY: network failure is DATA ({ status: 0, error }), never an exception; a
//   challenged response is reported CHALLENGED with the evidence (ok:false), never
//   claimed as a completed action; a missing/corrupt jar is a plain refusal, never a
//   silent cookieless ride.
// * CALIBRATION: --authcheck reports authentication state as EVIDENCE, never proof --
//   it verdicts from observable response markers only (a bare 200 is 'unverifiable',
//   never 'authenticated'), lists the markers that fired, and says so in its wording.
//
// COOKIE MERGE ORDER (defined, tested): the jar lays the base (file order), the vault
// clearance OVERLAYS it (the vault entry is TTL-validated and IP/UA-bound -- a jar copy
// of cf_clearance may be stale), and an explicit Cookie header REPLACES the merge
// entirely (the operator's literal header wins; the report says so). The report names
// WHICH cookies were sent per source -- names only: values are live credentials and
// never appear in the report (the wafbypass rideReport doctrine; set-cookie values in
// the response are redacted the same way, and persisted to the jar file, not the log).

import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import fs from 'node:fs';
import path from 'node:path';
import { clearanceFor, resolveRideTransport, ghostRideState } from './clearance/broker.mjs';
import { isPrivateDest, scrubHeaders, chainEgressId } from '../engine/ghost.mjs';
import { detectChallenge } from '../engine/challenge.mjs';
import { inAnyCidr, parseIp } from '../engine/ipaddr.mjs';

const BODY_CAP = 65536;        // the cfmap/egressbench cap, mirrored from cfride
const DEFAULT_TIMEOUT = 12000; // cfride's pre-fix fetcher contract
const MAX_REDIRECTS = 5;       // bounded redirect:'follow' parity, cfride doctrine

const msg = (e) => String((e && e.message) || e);

// ---------------------------------------------------------------------------
// Governance: signed-scope check. Mirrors tools/wafbypass.mjs + lfichain.mjs (same
// doctrine, deliberately re-implemented so this tool stays standalone): every resolved
// IP inside the signed CIDRs; the refusal prints the signed scope. Never throws.
// ---------------------------------------------------------------------------
async function defaultResolve(host) {
  const r = await dns.promises.lookup(host, { all: true });
  return r.map((x) => x.address);
}

export async function scopeCheck(u, scope, resolve) {
  const cidrs = (Array.isArray(scope) ? scope : String(scope || '').split(',')).map((s) => String(s).trim()).filter(Boolean);
  if (!cidrs.length) {
    return { ok: false, reason: 'no signed engagement scope supplied -- refusing (fail-closed). Re-run with --scope <cidrCsv> from the signed session scope.', scope: [] };
  }
  const host = u.hostname;
  let ips = [];
  const literal = parseIp(host);
  if (literal) {
    ips = [literal.text];
  } else {
    try { ips = await resolve(host); } catch (e) { return { ok: false, reason: 'could not resolve ' + host + ' for scope verification (' + msg(e) + ') -- refusing (fail-closed)', scope: cidrs }; }
    if (!ips.length) return { ok: false, reason: host + ' resolved to no addresses -- scope unverifiable, refusing (fail-closed)', scope: cidrs };
  }
  const outside = ips.filter((ip) => !inAnyCidr(ip, cidrs));
  if (outside.length) {
    return {
      ok: false,
      reason: 'target ' + host + ' resolves outside the signed engagement scope (' + outside.join(', ') + ' not in scope) -- request REFUSED. Signed scope: ' + cidrs.join(','),
      scope: cidrs, resolved: ips, outside,
    };
  }
  return { ok: true, scope: cidrs, resolved: ips };
}

// ---------------------------------------------------------------------------
// The session jar: a JSON array of [name, value] pairs (the sess_jar.json shape).
// readJar NEVER throws: a missing file is an empty jar WITH A NOTE (the first signin
// run legitimately starts empty; the note keeps it loud), a corrupt or malformed file
// is an honest refusal -- the operator believes they are riding a session, so a jar we
// cannot read plainly must never silently degrade to clearance-only.
// ---------------------------------------------------------------------------
export function readJar(jarPath) {
  let raw;
  try { raw = fs.readFileSync(jarPath, 'utf8'); } catch (e) {
    if (e && e.code === 'ENOENT') return { ok: true, entries: [], note: 'jar file not found -- starting with an EMPTY jar (a first-run signin legitimately does); it is created on save. If you expected an existing session, check the path.' };
    return { ok: false, error: 'session jar unreadable (' + msg(e) + ') -- refusing: the session you meant to ride is not the one on disk' };
  }
  let parsed;
  try { parsed = JSON.parse(raw); } catch (e) {
    return { ok: false, error: 'session jar is not valid JSON (' + msg(e) + ') -- refusing: never ride a session we could not read plainly' };
  }
  if (!Array.isArray(parsed)) {
    return { ok: false, error: 'session jar must be a JSON array of [name, value] pairs (the sess_jar.json shape), got ' + (parsed === null ? 'null' : typeof parsed) };
  }
  const entries = [];
  for (const p of parsed) {
    if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== 'string' || !p[0]) {
      return { ok: false, error: 'session jar entry malformed (expected a [name, value] pair): ' + JSON.stringify(p).slice(0, 80) };
    }
    entries.push([p[0], String(p[1])]);
  }
  return { ok: true, entries };
}

// writeJar(entries, jarPath) -> { ok, count }. Atomic (tmp + rename, the writeVault
// pattern). Never throws.
export function writeJar(entries, jarPath) {
  try {
    fs.mkdirSync(path.dirname(jarPath), { recursive: true });
    const tmp = jarPath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(entries));
    fs.renameSync(tmp, jarPath);
    return { ok: true, count: entries.length };
  } catch (e) { return { ok: false, error: 'session jar write failed (' + msg(e) + ')' }; }
}

// mergeCookies({ jar, clearance, explicitCookie }) -> { header, sent, fromJar,
// fromClearance, explicit }. THE DEFINED MERGE ORDER:
//   1. jar entries lay the base, in file order;
//   2. vault clearance cookies OVERLAY (a name collision sends the VAULT's value -- it
//      is TTL-validated and IP/UA-bound; the jar's copy may be stale);
//   3. an explicit Cookie header REPLACES the merged header entirely (the operator's
//      literal header wins; explicit:true in the report makes the override loud).
// `sent`/`fromJar`/`fromClearance` carry NAMES ONLY -- values are live credentials.
export function mergeCookies({ jar = [], clearance = [], explicitCookie } = {}) {
  const fromJar = [];
  const fromClearance = [];
  const merged = new Map();
  for (const [n, v] of jar) { if (!merged.has(n)) fromJar.push(n); merged.set(n, String(v)); }
  for (const ck of clearance || []) {
    if (!ck || typeof ck.name !== 'string' || !ck.name) continue;
    merged.set(ck.name, String(ck.value));
    fromClearance.push(ck.name);
  }
  if (explicitCookie != null && String(explicitCookie).trim() !== '') {
    const sent = String(explicitCookie).split(';').map((p) => p.split('=')[0].trim()).filter(Boolean);
    return { header: String(explicitCookie), sent, fromJar, fromClearance, explicit: true };
  }
  return { header: [...merged.entries()].map(([n, v]) => n + '=' + v).join('; '), sent: [...merged.keys()], fromJar, fromClearance, explicit: false };
}

// ingestSetCookie(headers) -> [{ name, value }]: the first pair of each set-cookie
// line (attributes are the server's business, not the jar's).
function ingestSetCookie(headers) {
  const sc = headers && headers['set-cookie'];
  if (!sc) return [];
  const arr = Array.isArray(sc) ? sc : [sc];
  const got = [];
  for (const line of arr) {
    const pair = String(line).split(';')[0];
    const i = pair.indexOf('=');
    if (i > 0) got.push({ name: pair.slice(0, i).trim(), value: pair.slice(i + 1).trim() });
  }
  return got;
}

// ---------------------------------------------------------------------------
// authEvidence({ status, finalUrl, headers, body }) -> the AUTH-STATE READ, pure and
// injectable-testable. This is EVIDENCE, never proof: the verdict is driven ONLY by
// observable markers in the response, a bare 200 with no markers is 'unverifiable'
// (never 'authenticated' -- the calibration doctrine: a verify mode must be able to
// falsify its own success signature, and a hollow 200 falsifies nothing), and an
// absence of markers is unobserved, not absent.
// ---------------------------------------------------------------------------
export function authEvidence({ status = 0, finalUrl = '', headers = {}, body = '' } = {}) {
  const evidenceFor = [];
  const evidenceAgainst = [];
  const b = String(body || '');
  const loc = String(finalUrl || '');

  // Markers of an ANONYMOUS session (the site asking us to authenticate).
  if (/wp-login\.php/i.test(loc)) evidenceAgainst.push('the final URL is the wp-login.php form -- the app redirected the session to login');
  if (/name=["']log["']/i.test(b) && /name=["']pwd["']/i.test(b)) evidenceAgainst.push('the response carries the WordPress login form (name="log" / name="pwd") -- the site is asking this session to authenticate');
  if (/id=["']loginform["']/i.test(b)) evidenceAgainst.push('a loginform element rendered');
  if (status === 401 || status === 403) evidenceAgainst.push('HTTP ' + status + ' -- the resource refused the presented identity');

  // Markers of an AUTHENTICATED session (chrome the server emits only when logged in).
  if (/wp-admin-bar|id=["']wpadminbar["']/i.test(b)) evidenceFor.push('the WordPress admin bar rendered -- server-side chrome emitted only for authenticated sessions');
  if (/action=logout/i.test(b)) evidenceFor.push('a logout link (action=logout) is offered -- logging OUT is only offered to a logged-in session');
  if (/\/wp-admin\//i.test(b) && /dashboard/i.test(b)) evidenceFor.push('wp-admin dashboard links rendered');

  let verdict;
  if (evidenceFor.length && !evidenceAgainst.length) verdict = 'looks-authenticated';
  else if (evidenceAgainst.length && !evidenceFor.length) verdict = 'looks-anonymous';
  else if (evidenceFor.length && evidenceAgainst.length) verdict = 'conflicting-evidence';
  else verdict = 'unverifiable';
  return {
    verdict,
    evidenceFor,
    evidenceAgainst,
    caveat: 'EVIDENCE, never proof: this is inferred from observable markers in ONE response (HTTP ' + status + '). A bare 200 is not evidence of anything; a cached or templated page can carry stale chrome; "unverifiable" means unobserved, not absent. Before relying on the session, re-check against a page that renders ONLY for the account (e.g. a user-settings page).',
  };
}

// ---------------------------------------------------------------------------
// Default fetcher: the cfride pattern (node http(s) on the gate's transport; a PUBLIC
// target with no agents is refused IN the requester unless the gate sanctioned direct;
// the vault's EXACT UA is pinned through scrubHeaders). Beyond cfride it adds the two
// session-ride guards: EVERY redirect hop re-passes the signed-scope gate BEFORE the
// next request leaves, and a cross-host Location is reported as data, never followed
// with the session (credential-leak guard). Resolves { status, headers, body, finalUrl,
// hops, setCookies, redirectRefused? }; network failure is DATA, never an exception.
// ---------------------------------------------------------------------------
function defaultFetcher({ agents, directPublic, hdrs, ua, method, body, timeoutMs = DEFAULT_TIMEOUT, scopeGate }) {
  const one = (target, mth, bod, redirectsLeft, hops) => new Promise((resolve) => {
    let u;
    try { u = new URL(String(target)); } catch { return resolve({ status: 0, error: 'unparseable request URL' }); }
    if (!isPrivateDest(u.hostname) && !agents && !directPublic) {
      return resolve({ status: 0, error: 'ghost chain unavailable -- public egress refused' });
    }
    const lib = u.protocol === 'https:' ? https : http;
    let settled = false;
    const done = (v) => { if (settled) return; settled = true; resolve(v); };
    let req;
    try {
      req = lib.request({
        hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, method: mth || 'GET', timeout: timeoutMs,
        rejectUnauthorized: false,
        agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
        headers: scrubHeaders(hdrs(), { ua }),
      }, (r) => {
        let text = '';
        r.on('data', (d) => { if (text.length < BODY_CAP) text += d.toString('latin1', 0, Math.max(0, BODY_CAP - text.length)); });
        r.on('end', async () => {
          const status = r.statusCode || 0;
          const setCookies = ingestSetCookie(r.headers);
          const loc = r.headers && r.headers.location;
          // redirect:'follow' parity (bounded), with the session-ride guards.
          if (redirectsLeft > 0 && loc && (status === 301 || status === 302 || status === 303 || status === 307 || status === 308)) {
            let next;
            try { next = new URL(loc, u); } catch { return done({ status, headers: r.headers, body: text, finalUrl: u.href, hops, setCookies }); }
            if (next.host !== u.host) {
              return done({
                status, headers: r.headers, body: text, finalUrl: u.href, hops, setCookies,
                redirectRefused: { location: next.href, reason: 'cross-host redirect NOT followed -- the ridden session (clearance + jar) never leaves its host. Re-aim sessride at the new host explicitly if it is in the signed scope.' },
              });
            }
            if (scopeGate) {
              let g;
              try { g = await scopeGate(next); } catch (e) { g = { ok: false, reason: 'scope re-check failed (' + msg(e) + ')' }; }
              if (!g.ok) {
                return done({
                  status, headers: r.headers, body: text, finalUrl: u.href, hops, setCookies,
                  redirectRefused: { location: next.href, reason: 'redirect hop REFUSED by the signed-scope gate: ' + g.reason },
                });
              }
            }
            const drop = status === 303 || ((status === 301 || status === 302) && mth !== 'GET' && mth !== 'HEAD');
            one(next.href, drop ? 'GET' : mth, drop ? null : bod, redirectsLeft - 1, hops + 1).then((out) => {
              out.setCookies = [...setCookies, ...(out.setCookies || [])];
              done(out);
            });
            return;
          }
          done({ status, headers: r.headers, body: text, finalUrl: u.href, hops, setCookies });
        });
      });
    } catch (e) { return done({ status: 0, error: msg(e) }); }
    req.on('timeout', () => { try { req.destroy(); } catch {} done({ status: 0, error: 'request timed out (' + timeoutMs + 'ms)' }); });
    req.on('error', (e) => done({ status: 0, error: msg(e) }));
    if (bod != null) req.write(bod);
    req.end();
  });
  return (target) => one(target, method, body, MAX_REDIRECTS, 0);
}

// ---------------------------------------------------------------------------
// sessRide(url, opts) -> the governed session ride. GET/POST with headers/body;
// NEVER throws -- every refusal/failure is data. opts:
//   method, body, contentType           the request shape (GET default)
//   headers                             explicit headers; a Cookie header here WINS the merge
//   jarPath | jar                       the session jar file, or inline [[name, value]] (test seam)
//   saveJar !== false                   persist server set-cookies back to jarPath (default on)
//   mode 'fetch' | 'authcheck'          authcheck adds the evidence-graded auth-state read
//   scope (REQUIRED), resolve           signed engagement scope + injectable resolver
//   egressId, ghost, ghostMode,         the cfride seams (defaults read the same Settings
//     engagement, vaultPath               the mint/lookup sides read via ghostRideState)
//   fetcher, timeoutMs                  transport seams for hermetic tests
// ---------------------------------------------------------------------------
export async function sessRide(url, {
  method = 'GET', body, contentType, headers: extraHeaders,
  jarPath, jar: jarInline, saveJar = true, mode = 'fetch',
  scope, resolve, egressId: egressOpt, ghost, ghostMode, engagement, vaultPath,
  fetcher, timeoutMs,
} = {}) {
  try {
    let u;
    try {
      u = new URL(String(url || ''));
      if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('scheme');
    } catch { return { ok: false, reason: 'usage: url must be an absolute http(s) URL, got ' + JSON.stringify(url) }; }
    const m = String(method || 'GET').toUpperCase();
    if (m !== 'GET' && m !== 'POST') {
      return { ok: false, reason: 'usage: method must be GET or POST (the session-ride transport carries reading + form submission), got ' + JSON.stringify(method) };
    }

    // -- governance gate 1: signed scope (BEFORE any request; refusal prints the CIDRs) --
    const scopeRes = await scopeCheck(u, scope, resolve || defaultResolve);
    if (!scopeRes.ok) return { ok: false, reason: scopeRes.reason, scope: scopeRes.scope || [], resolved: scopeRes.resolved };

    // -- governance gate 2: egress parity (the cfride wiring, same Settings source) --
    const st = ghost ? { ghost, ghostMode: ghostMode || ghost.mode } : ghostRideState(engagement);
    let egressId = 'direct';
    if (egressOpt) egressId = String(egressOpt);
    else if (st.ghostMode !== 'off' && st.ghost && st.ghost.chain && st.ghost.chain.length) {
      try { egressId = chainEgressId(st.ghost.chain); } catch { egressId = 'direct'; }
    }
    const c = await clearanceFor(u.href, { egressId, ...(vaultPath ? { vaultPath } : {}) });
    if (!c) return { ok: false, reason: 'no valid clearance in the vault for this zone -- mint (clearance mint) or provide operator clearance first' };
    const t = await resolveRideTransport({ ghost: st.ghost, ghostMode: st.ghostMode, egressId, hostname: u.hostname });
    if (!t.ok) return { ok: false, reason: t.reason };

    // -- the session jar (the tool's defining half: BOTH identities ride, never just one) --
    let jarPairs;
    let jarNote = null;
    if (Array.isArray(jarInline)) {
      jarPairs = jarInline.map((p) => [String(p[0]), String(p[1])]);
    } else if (jarPath) {
      const j = readJar(jarPath);
      if (!j.ok) return { ok: false, reason: j.error };
      jarPairs = j.entries;
      jarNote = j.note || null;
    } else {
      return { ok: false, reason: 'no session jar supplied -- sessride rides BOTH the vault clearance AND an authenticated session jar. Pass --jar <file.json> (a JSON array of [name, value] pairs); for a clearance-only ride use cfride.' };
    }

    // -- the merge: jar base + clearance overlay; an explicit Cookie header wins --
    let explicitCookie = null;
    const rest = {};
    for (const [k, v] of Object.entries(extraHeaders || {})) {
      if (String(k).toLowerCase() === 'cookie') explicitCookie = String(v);
      else rest[String(k).toLowerCase()] = String(v);
    }
    const merged = mergeCookies({ jar: jarPairs, clearance: c.cookies || [], explicitCookie });
    const hdrs = () => {
      const h = { 'user-agent': c.ua, cookie: merged.header, accept: 'text/html,application/xhtml+xml,application/json,*/*', ...rest };
      if (body != null && !h['content-type']) h['content-type'] = contentType || 'application/x-www-form-urlencoded';
      return h;
    };

    // -- the ride (scopeGate re-checks EVERY redirect hop before it leaves) --
    const scopeGate = (nu) => scopeCheck(nu, scopeRes.scope, resolve || defaultResolve);
    const doFetch = fetcher || defaultFetcher({ agents: t.agents, directPublic: t.direct, hdrs, ua: c.ua, method: m, body, timeoutMs, scopeGate });
    let res;
    try { res = await doFetch(u.href); } catch (e) { res = { status: 0, error: msg(e) }; }
    const status = res.status || 0;
    const detection = detectChallenge({ status, headers: res.headers || {}, body: res.body || '' });

    // HONESTY GATE (the cfride contract): a challenged response is clearance/session
    // failure WITH EVIDENCE, never a completed action.
    if (detection.present) {
      return {
        ok: false,
        reason: 'the ridden session was CHALLENGED -- expired/ drifted clearance (IP+UA bound), or the session itself was burned at the edge. Re-mint or refresh; NOTHING about this response can be claimed as the intended action.',
        proof: { status, detection },
        scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved },
      };
    }
    // A transport failure is reported plainly: the request did not complete, so nothing
    // can be claimed about the action (a POST certainly did not happen).
    if (res.error && !status) {
      return {
        ok: false,
        reason: 'transport failure (' + res.error + ') -- the request did not complete; nothing can be claimed about the action',
        scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved },
      };
    }

    // Persist the session state the server set (values go to the JAR FILE, never the
    // report). The vault's clearance values are never written into the jar -- the vault
    // owns the edge identity; the jar owns the app session.
    const setCookies = res.setCookies || [];
    const clearanceNames = new Set((c.cookies || []).map((ck) => ck.name));
    let jarSaved = null;
    if (jarPath && saveJar !== false) {
      const next = new Map(jarPairs);
      for (const s of setCookies) if (!clearanceNames.has(s.name)) next.set(s.name, s.value);
      const w = writeJar([...next.entries()], jarPath);
      jarSaved = w.ok ? { path: jarPath, count: w.count } : { ok: false, error: w.error };
    }

    // Report headers with set-cookie VALUES redacted (live session credentials ride the
    // jar file, never the report/log -- the wafbypass rideReport doctrine).
    const reportHeaders = { ...(res.headers || {}) };
    if (reportHeaders['set-cookie']) {
      reportHeaders['set-cookie'] = setCookies.map((s) => s.name + '=<redacted -- live session credential; persisted to the jar, never the report>');
    }

    const out = {
      ok: true,
      tool: 'sessride',
      url: u.href,
      finalUrl: res.finalUrl || u.href,
      method: m,
      status,
      headers: reportHeaders,
      body: res.body || '',
      bodyBytes: (res.body || '').length,
      bodyCapped: (res.body || '').length >= BODY_CAP,
      cookies: {
        sent: merged.sent,
        fromJar: merged.fromJar,
        fromClearance: merged.fromClearance,
        explicitHeader: merged.explicit,
        note: 'names only -- cookie VALUES are live credentials and never appear in a report',
      },
      setCookies: setCookies.map((s) => s.name),
      ride: { egressId, engine: c.engine || 'operator-provided', expiresAt: c.expiresAt, transport: t.transport },
      scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved },
      detection,
      at: new Date().toISOString(),
    };
    if (jarNote) out.jarNote = jarNote;
    if (jarSaved) out.jarSaved = jarSaved;
    if (res.redirectRefused) out.redirectRefused = res.redirectRefused;
    if (res.hops) out.redirectHops = res.hops;
    if (mode === 'authcheck') {
      out.authState = authEvidence({ status, finalUrl: out.finalUrl, headers: res.headers || {}, body: res.body || '' });
    }
    return out;
  } catch (e) {
    return { ok: false, reason: 'sessride failed: ' + msg(e) };
  }
}

// ---------------------------------------------------------------------------
// CLI surface (registered by the orchestrator in tools/cli.mjs):
//   sessride <url> --jar <file.json> --scope <cidrCsv> [--method POST]
//            [--body <str> | --body-json '<json>'] [--content-type <ct>]
//            [--headers <file.json>] [--cookie <header>] [--authcheck]
//            [--no-save-jar] [--engagement <id>] [--egress-id <id>]
// ---------------------------------------------------------------------------
export const SESSRIDE_USAGE = "sessride <url> --jar <file.json> --scope <cidrCsv> [--method POST] [--body <str>|--body-json '<json>'] [--content-type <ct>] [--headers <file.json>] [--cookie <header>] [--authcheck] [--no-save-jar] [--engagement <id>] [--egress-id <id>] -- governed session ride: vaulted cf_clearance + authenticated cookie jar in ONE request path (scope-gated, ghost-ridden, challenge-honest; cookie values never reported)";

const enc = (o) => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');

export async function cli(args, deps = {}) {
  const { readFileSync } = await import('node:fs');
  const a = Array.isArray(args) ? args.slice() : String(args || '').split(/\s+/).filter(Boolean);
  const flag = (name) => {
    const i = a.indexOf('--' + name);
    return i >= 0 && i + 1 < a.length ? a[i + 1] : null;
  };
  const opts = { ...deps };
  opts.method = flag('method') || undefined;
  opts.contentType = flag('content-type') || undefined;
  opts.jarPath = flag('jar') || undefined;
  opts.scope = flag('scope') || undefined;
  opts.engagement = flag('engagement') || undefined;
  opts.egressId = flag('egress-id') || undefined;
  if (a.includes('--authcheck')) opts.mode = 'authcheck';
  if (a.includes('--no-save-jar')) opts.saveJar = false;
  const bodyRaw = flag('body');
  const bodyJson = flag('body-json');
  if (bodyJson != null) {
    try { opts.body = enc(JSON.parse(bodyJson)); } catch (e) { return { ok: false, reason: '--body-json is not valid JSON: ' + msg(e) }; }
  } else if (bodyRaw != null) {
    opts.body = bodyRaw;
  }
  const headers = {};
  const hdrFile = flag('headers');
  if (hdrFile) {
    try { Object.assign(headers, JSON.parse(readFileSync(hdrFile, 'utf8'))); } catch (e) { return { ok: false, reason: 'could not read/parse --headers file ' + hdrFile + ': ' + msg(e) }; }
  }
  const cookieFlag = flag('cookie');
  if (cookieFlag != null) headers.cookie = cookieFlag;
  if (Object.keys(headers).length) opts.headers = headers;
  const url = flag('url') || a[0];
  return sessRide(url, opts);
}
