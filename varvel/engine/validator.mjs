// VARVEL — the validator gate (proof vs belief, enforced in code).
// The XBOW/ARTEMIS discipline as a platform rail: nothing is REPORTED as proven that was
// not reproduced against an objective oracle (AISLE measured the LLM specificity collapse
// without one). Three pieces, all deterministic — no model call anywhere in this module:
//
//   1) HARD INGEST RULE — hasObjectiveOracle(): a finding claimed at the confirmed tier
//      whose evidence/ref cite NO objective oracle is downgraded to suspected at ingest
//      (engine/campaign.mjs `_ingest`), with GATE_NOTE appended. Never deleted, never
//      blocked — suspected findings were never exploitable anyway (only confirmed may be
//      exploited), so the gate makes the existing contract real.
//   2) validate <findingIndex> — Campaign.validateFinding(): an EXPLICIT (never auto-fired)
//      reproduction pass. http-class findings get the lightest objective reproduction
//      available: ONE governed re-read (paced, ghost-riding, scope fail-closed). Other
//      classes honestly report 'no automatic oracle for this class — reproduce manually'.
//      The result lands on the finding as validation { state, oracle, at } with
//      state validated | refuted | untestable — REFUTED is a first-class outcome (the
//      gate's whole point) and flips confidence back to suspected with a refutation note.
//   3) Report/console honesty renders that state per finding (validated /
//      claimed-unvalidated / refuted), so the operator sees at a glance what is proven.
//
// v2 — the manhuaus doctrine, platformized (a hollow-success signature once burned days
// of operator time: the target answered the IDENTICAL '200 + empty body' to the real
// payload AND to garbage, and a marker check matched the operator's own USERNAME in the
// page chrome):
//   4) GARBAGE-CONTROL SECOND READ — every reproduction fires a PAIRED control request
//      (same shape, garbage/canary input). Success signature present under real AND
//      absent under control => validated; present under BOTH => refuted 'hollow success
//      signature (control matched)'; absent under real => refuted. No claim without a
//      control: a failed control read is untestable, never a pass.
//   5) COLLISION-PROOF MARKERS — validatorMarker() mints 'vrv' + crypto-random hex
//      (never usernames, never dictionary words), and a marker counts ONLY where the
//      payload placed it: occurrences inside the echoed request URL are scrubbed before
//      the hit test (an error page parroting the request line is not reflection).
//   6) PER-CLASS ORACLES (ORACLES below: xss/sqli/lfi/exposure/header/cookie/redirect,
//      default = the v1 re-read + control) and STALENESS (validated findings carry
//      validatedAt; past validator.staleDays the state RENDERS as 'stale' — a rendering
//      of validated, never a new stored state).
//
// Noise doctrine: validation NEVER auto-fires (no background sweeps). One invocation =
// ONE request pair (real + control), both paced and both charged to the noise budget
// like any other http fingerprint — and both reported on the record.

import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { scrubHeaders } from './ghost.mjs';
import { bracketHost } from './ipaddr.mjs';

export const GATE_NOTE = 'validator gate: no objective oracle cited';
export const UNTESTABLE_NOTE = 'no automatic oracle for this class — reproduce manually';

// The objective-oracle vocabulary, pinned. An oracle is one of: a collision-proof MARKER
// planted + read back, a READ-BACK of observed output, a DIFF/control comparison, a
// governed TOOL reference, or a REPRODUCTION step (verb + target / command). A bare
// opinion, a severity word, or an opaque ref (F-01) is NONE of these — by design.
const ORACLE_RES = [
  /\b(marker|nonce|canary)\b/i,                                                             // marker planted + read back
  /\b(read[- ]?back|returned|responds?|responded|served|renders?|rendered|observed|displays?|displayed|showed|shows|shown|contained|contains|leaks?|leaked|exposed)\b/i, // read-back: the observed output is named
  /\b(diff(?:erential|ed)?|baseline|control)\b/i,                                           // a diff/control comparison
  /\b(webscan|crawl|apisurface|vulncheck|rendercheck|sessride|cfride|cfcheck|cfmap|detoracle|fporacle|floworacle|tradecraft|chainrun|tlsscan|originintel|egressbench|preflight|ssrfprobe?|jwt-(?:decode|forge|verify))\b/i, // a governed tool ref
  /\b(?:GET|POST|PUT|DELETE|HEAD|PATCH)\s+(?:\/\S*|https?:\/\/\S*)/,                        // a reproduction step (verb + target)
  /\bcurl\s+\S/i,                                                                           // a reproduction command
  /\breproduc(?:e|ed|ion)\b/i,                                                              // an explicit reproduction note
];

// Does a finding's evidence/ref cite an objective oracle? Deterministic string
// heuristics over those two fields ONLY (never the title — the claim is not its own proof).
export function hasObjectiveOracle(f) {
  const evidence = String((f && f.evidence) || '');
  const ref = String((f && f.ref) || '');
  if (/^(?:https?:\/\/\S+|\/\S*)$/.test(ref.trim())) return true; // a concrete read-back location
  const text = evidence + '\n' + ref;
  return ORACLE_RES.some((re) => re.test(text));
}

// Extract a cited collision-proof marker from evidence, when the claim names one
// ('marker: vv-9f2k…', 'nonce=…', 'canary …'). Used by the re-read as the refutation
// oracle: cited marker ABSENT on the governed re-read = the claim no longer reproduces.
export function extractMarker(evidence) {
  const m = String(evidence || '').match(/\b(?:marker|nonce|canary)\b\s*[:=]?\s*["'`]?([A-Za-z0-9][\w-]{5,79})["'`]?/i);
  return m ? m[1] : null;
}

// Derive the ONE re-read URL for an http-class finding: an absolute URL cited in
// ref/evidence wins; else a cited path (a 'GET /path' reproduction step in evidence, or a
// ref that IS a path) resolved against the finding's parent host's first http(s) service.
// Returns null when no http-class oracle can be constructed (→ untestable, honestly).
export function validationUrl(f, surface) {
  const text = String((f && f.ref) || '') + '\n' + String((f && f.evidence) || '');
  const abs = text.match(/https?:\/\/[^\s"'<>)\]]+/i);
  if (abs) return abs[0];
  let path = null;
  const step = String((f && f.evidence) || '').match(/\b(?:GET|POST|PUT|DELETE|HEAD|PATCH)\s+(\/[^\s"']*)/i);
  if (step) path = step[1];
  else if (/^\/[^\s]*$/.test(String((f && f.ref) || '').trim())) path = String(f.ref).trim();
  if (!path || !surface) return null;
  const nodes = surface.nodes instanceof Map ? [...surface.nodes.values()] : (surface.nodes || []);
  const edges = surface.edges || [];
  const host = nodes.find((n) => edges.some((e) => e.kind === 'finding' && e.to === f.id && e.from === n.id));
  if (!host) return null;
  const svc = nodes.find((n) => n.type === 'service' && /^https?:/.test(n.label || '') && edges.some((e) => e.kind === 'svc' && e.from === host.id && e.to === n.id));
  if (!svc) return null;
  const addr = host.ip || host.label;
  if (!addr) return null;
  return `${svc.label.split(':')[0]}://${bracketHost(addr)}:${svc.port}${path}`; // v6 literals bracketed — a bare 'http://fd00::1:8080/x' is not a URL
}

const BODY_CAP = 65536; // a re-read needs the marker window, not the whole page
const msg = (e) => String((e && e.message) || e);

// ONE governed re-read — the native ride/fetch path (webscan's get + the ride family's
// persona scrub + ghost agents). Exactly one request: redirects are DATA, never followed
// (a 3xx still answers "does the endpoint respond", and following would break the
// one-request noise cap). Network failure is DATA ({ status: 0, error }), never a throw.
export function reRead(url, { timeout = 4000, agents = null } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(String(url)); } catch { return resolve({ status: 0, error: 'unparseable request URL' }); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return resolve({ status: 0, error: 'not an http(s) URL' });
    const lib = u.protocol === 'https:' ? https : http;
    let body = '', settled = false;
    const done = (v) => { if (settled) return; settled = true; clearTimeout(deadline); resolve(v); };
    let req;
    try {
      req = lib.request({
        hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search, method: 'GET', timeout, rejectUnauthorized: false,
        agent: agents ? (u.protocol === 'https:' ? agents.httpsAgent : agents.httpAgent) : undefined,
        headers: scrubHeaders({}),
      }, (r) => {
        r.on('data', (d) => { if (body.length < BODY_CAP) body += d.toString('latin1', 0, Math.max(0, BODY_CAP - body.length)); });
        r.on('end', () => done({ status: r.statusCode || 0, len: Number(r.headers['content-length']) || body.length, body, headers: r.headers || {} }));
      });
    } catch (e) { return resolve({ status: 0, error: msg(e) }); }
    const deadline = setTimeout(() => { try { req.destroy(); } catch {} done({ status: 0, error: 'timeout' }); }, Math.max(timeout * 3, 5000)); // slowloris guard
    req.on('timeout', () => { try { req.destroy(); } catch {} done({ status: 0, error: 'timeout' }); });
    req.on('error', (e) => done({ status: 0, error: msg(e) }));
    req.end();
  });
}


/* ============================== VALIDATOR GATE v2 ============================== */
// The manhuaus doctrine as code (see the header block): falsify your own success
// signature with a garbage-control read before claiming, and never trust a marker that
// can collide with page chrome. All deterministic — still no model call anywhere here.

export const HOLLOW_REASON = 'hollow success signature (control matched)';
export const REPRO_REASON = 'success signature absent under the real input (does not reproduce)';

// Collision-proof markers: 'vrv' + 64 bits of crypto-random hex. Never an operator
// username, never a URL-echoable dictionary word — collision with page chrome is
// excluded by construction, not by luck.
export function validatorMarker() {
  return 'vrv' + randomBytes(8).toString('hex');
}

const tryEnc = (s, fn) => { try { return fn(s); } catch { return s; } };

// The v2 placement assertion: a marker counts ONLY where the payload placed it. Any
// occurrence living inside an echo of the request target (error pages parrot the request
// line — that is not reflection into the page) is scrubbed before the hit test, in raw /
// partially- / fully-URL-encoded forms. The scrub only applies to echo-forms that
// themselves contain the marker, so a cited marker planted out-of-band is never scrubbed
// away. (Logged-in-user chrome collision needs no region check: vrv tokens are
// crypto-random and can never BE a username — that class of false positive is gone by
// construction.)
export function markerPlaced(body, marker, reqTarget) {
  if (typeof body !== 'string' || !marker || !body.includes(marker)) return false;
  let scrub = body;
  for (const form of [reqTarget, tryEnc(reqTarget, encodeURI), tryEnc(reqTarget, encodeURIComponent)]) {
    if (form && form.includes(marker)) scrub = scrub.split(form).join('');
  }
  return scrub.includes(marker);
}

const targetOf = (rawUrl) => { try { const u = new URL(String(rawUrl)); return u.pathname + u.search; } catch { return String(rawUrl || ''); } };

// The control input, same shape as the real request, garbage values:
//  - shape 'param' (injection classes — the input rides in the query): param keys and
//    path preserved, every VALUE swapped for the canary;
//  - shape 'path' (endpoint-bound classes — the claim is that a resource exists / a
//    header holds THERE): the last path segment swapped, depth + query preserved.
// A catch-all that answers garbage exactly like the real input is the hollow server.
export function controlUrl(rawUrl, garbage, { shape = 'param' } = {}) {
  let u;
  try { u = new URL(String(rawUrl)); } catch { return null; }
  const keys = [...new Set([...u.searchParams.keys()])];
  if (shape === 'param' && keys.length) {
    for (const k of keys) u.searchParams.set(k, garbage);
    return u.toString();
  }
  const segs = u.pathname.split('/').filter(Boolean);
  if (segs.length) segs[segs.length - 1] = garbage; else segs.push(garbage);
  u.pathname = '/' + segs.join('/');
  return u.toString();
}

// Finding-class detection, deterministic over the finding's own text (label + evidence +
// ref). Most-specific classes first; anything unrecognized lands on 'default', never on
// nothing.
const CLASS_RES = [
  ['xss', /xss|cross[- ]?site scripting?|<script|<svg[^>]*onload|<img[^>]*onerror|reflect(?:ed|ion|s)?\b.{0,40}(?:payload|script|marker|input|html)/i],
  ['sqli', /\bsqli?\b|sql injection|you have an error in your sql|unterminated (?:string|quote)|\bmysql\b|\bora-\d{4}|sqlite.?error|postgres(?:ql)? error/i],
  ['lfi', /\blfi\b|local file (?:inclusion|read|disclosure)|(?:path|directory) traversal|\.\.[\/\\]|\/etc\/passwd|boot\.ini|php:\/\/filter/i],
  ['redirect', /open[- ]?redirect|unvalidated redirect|redirect(?:s|ed|ion)?\b.{0,40}(?:param|next|url|host|location)|\b(?:next|returnto|returnurl|redir(?:ect)?)=https?/i],
  ['cookie', /cookie|set-cookie|httponly|samesite|secure flag/i],
  ['header', /(?:missing|absent|no|without|leaks?|verbose|weak).{0,30}headers?\b|headers?\b.{0,30}(?:missing|absent|x-frame-options|content-security-policy|strict-transport-security|x-content-type-options)|x-frame-options|content-security-policy|\bhsts\b|x-content-type-options|x-powered-by|server banner/i],
  ['exposure', /expos(?:ed|ure|es)\b|backup|\.(?:sql|bak|old|env|git|svn|log|zip|tar)\b|directory listing|publicly accessible|sensitive (?:file|data|path|directory)|config file/i],
];
export function oracleClass(f) {
  const text = `${(f && (f.label || f.title)) || ''}\n${(f && f.evidence) || ''}\n${(f && f.ref) || ''}`;
  for (const [name, re] of CLASS_RES) if (re.test(text)) return name;
  return 'default';
}

const SQL_ERROR_RE = /you have an error in your sql|sql syntax|mysql_fetch|\bmysqli?\b|unterminated (?:string|quote)|\bora-\d{4,5}|pg_query|sqlite.?error|odbc.{0,20}driver|jdbc|syntax error.{0,40}(?:sql|query)/i;
const FILE_TOKEN_RE = /root:.{0,16}:0:0|\[boot loader\]|\[fonts\]|daemon:\*:|nobody:x:/i;
const KNOWN_HEADERS = ['x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'x-xss-protection', 'x-powered-by', 'server'];

// A header finding cites a known header + a direction ('missing X-Frame-Options' vs a
// banner/version LEAK where presence is the claim).
function headerClaim(f) {
  const text = `${(f && (f.label || f.title)) || ''}\n${(f && f.evidence) || ''}`;
  const name = KNOWN_HEADERS.find((h) => text.toLowerCase().includes(h));
  if (!name) return null;
  const expect = /missing|absent|\bno\b|without|not (?:set|present)|lacks?/i.test(text) ? 'absent' : 'present';
  return { name, expect };
}

function cookieClaim(f) {
  const text = `${(f && (f.label || f.title)) || ''}\n${(f && f.evidence) || ''}`;
  const m = text.match(/httponly|samesite|secure/i);
  return m ? m[0].toLowerCase() : null;
}

// The destination an open-redirect claim names (evidence 'redirects to X' / 'Location: X'
// or the next=-style param in the cited URL). The verdict anchors on its HOST.
function redirectDest(f) {
  const text = `${(f && f.evidence) || ''}\n${(f && f.ref) || ''}`;
  const m = text.match(/location:\s*(https?:\/\/[^\s"'<>)\]]+)|redirect(?:s|ed|ing)?\s+to\s+(https?:\/\/[^\s"'<>)\]]+)|\b(?:next|returnto|returnurl|redir(?:ect)?)=(https?:\/\/[^\s&"'<>)\]]+)/i);
  const dest = m && (m[1] || m[2] || m[3]);
  if (!dest) return null;
  try { return new URL(dest).host; } catch { return dest; }
}

// Shared signature predicates. detail strings keep the v1 phrasing ('cited marker
// present' / 'ABSENT') so existing consumers keep matching.
function markerHit(resp, ctx) {
  const hit = markerPlaced(resp && resp.body, ctx.plan.marker, targetOf(ctx.reqUrl || ctx.plan.real));
  const what = ctx.plan.signature === 'planted marker' ? 'planted marker' : 'cited marker';
  return { hit, detail: hit ? `${what} present` : `${what} ABSENT` };
}
function statusHit(resp) {
  const hit = !!resp && (resp.status || 0) > 0 && (resp.status || 0) < 400;
  return { hit, detail: hit ? 'endpoint responds' : 'endpoint does NOT respond' };
}
function tokenHit(re, label) {
  return (resp) => {
    const body = (resp && typeof resp.body === 'string') ? resp.body : '';
    const hit = re.test(body);
    return { hit, detail: hit ? `${label} present` : `${label} ABSENT` };
  };
}

// The per-class oracle registry. Each oracle knows three things: how to BUILD the
// reproduction pair from the finding's evidence (plan → { real, control, marker,
// signature, ... }), what its SUCCESS SIGNATURE is (hit(resp, ctx) → { hit, detail }),
// and what its CONTROL input is (the garbage half of the pair, via controlUrl()). plan()
// returns null when the evidence can't construct a class-specific probe — the caller
// falls back to the default oracle, never to nothing.
export const ORACLES = {
  // Reflected XSS: the marker must come back where the payload placed it (never the URL
  // echo). Evidence citing no marker gets a fresh planted vrv token probed into every
  // query param; the control carries a DIFFERENT garbage token, so a genuine reflector
  // still differentiates (the control echoes its own token, never the real one).
  xss: {
    name: 'xss',
    plan(f, url) {
      const cited = extractMarker(f.evidence);
      if (cited) return { real: url, control: controlUrl(url, validatorMarker()), marker: cited, signature: 'cited marker' };
      let u;
      try { u = new URL(url); } catch { return null; }
      const keys = [...new Set([...u.searchParams.keys()])];
      if (!keys.length) return null; // no reflection point to probe — default oracle
      const marker = validatorMarker();
      for (const k of keys) u.searchParams.set(k, marker);
      return { real: u.toString(), control: controlUrl(url, validatorMarker()), marker, signature: 'planted marker' };
    },
    hit(resp, ctx) { return markerHit(resp, ctx); },
  },
  // SQLi: the cited marker, else a SQL error token in the body. A genuine injection
  // errors under the quote-breaking payload and NOT under benign garbage; an app that
  // errors on everything is hollow by definition.
  sqli: {
    name: 'sqli',
    plan(f, url) {
      const cited = extractMarker(f.evidence);
      return { real: url, control: controlUrl(url, validatorMarker()), marker: cited || null, signature: cited ? 'cited marker' : 'SQL error token' };
    },
    hit(resp, ctx) { return ctx.plan.marker ? markerHit(resp, ctx) : tokenHit(SQL_ERROR_RE, 'SQL error token')(resp); },
  },
  // LFI: the cited marker, else recognizable file content (passwd / boot.ini tokens).
  lfi: {
    name: 'lfi',
    plan(f, url) {
      const cited = extractMarker(f.evidence);
      return { real: url, control: controlUrl(url, validatorMarker()), marker: cited || null, signature: cited ? 'cited marker' : 'file-content token' };
    },
    hit(resp, ctx) { return ctx.plan.marker ? markerHit(resp, ctx) : tokenHit(FILE_TOKEN_RE, 'file-content token')(resp); },
  },
  // Exposure: the resource responds (or a cited marker reads back). Control is a garbage
  // PATH of the same depth — a catch-all that 200s everything cannot prove the file is
  // there.
  exposure: {
    name: 'exposure',
    plan(f, url) {
      const cited = extractMarker(f.evidence);
      return { real: url, control: controlUrl(url, validatorMarker(), { shape: 'path' }), marker: cited || null, signature: cited ? 'cited marker' : 'endpoint responds' };
    },
    hit(resp, ctx) { return ctx.plan.marker ? markerHit(resp, ctx) : statusHit(resp); },
  },
  // Header: the cited header condition (missing vs leaky) holds AND the endpoint
  // responds. The status term keeps the signature endpoint-specific: a garbage path that
  // 404s differentiates; a catch-all that 200s everything with the same header posture
  // is hollow.
  header: {
    name: 'header',
    plan(f, url) {
      const claim = headerClaim(f);
      if (!claim) return null; // no known header cited — default oracle
      return { real: url, control: controlUrl(url, validatorMarker(), { shape: 'path' }), marker: null, claim, signature: `${claim.name} ${claim.expect}` };
    },
    hit(resp, ctx) {
      const headers = resp && resp.headers;
      if (!headers || typeof headers !== 'object') return { hit: false, detail: 'no response headers captured' };
      const present = headers[ctx.plan.claim.name] !== undefined;
      const cond = ctx.plan.claim.expect === 'absent' ? !present : present;
      const hit = (resp.status || 0) > 0 && (resp.status || 0) < 400 && cond;
      const state = ctx.plan.claim.expect === 'absent' ? (present ? 'PRESENT (claim said missing)' : 'absent as claimed') : (present ? 'present as claimed' : 'ABSENT (claim said it leaks)');
      return { hit, detail: `${ctx.plan.claim.name} ${state} on HTTP ${resp.status || 0}` };
    },
  },
  // Cookie: a Set-Cookie arrives WITHOUT the cited flag, on a responding endpoint.
  cookie: {
    name: 'cookie',
    plan(f, url) {
      const flag = cookieClaim(f);
      if (!flag) return null; // no flag named — default oracle
      return { real: url, control: controlUrl(url, validatorMarker(), { shape: 'path' }), marker: null, flag, signature: `set-cookie without ${flag}` };
    },
    hit(resp, ctx) {
      const headers = resp && resp.headers;
      if (!headers || typeof headers !== 'object') return { hit: false, detail: 'no response headers captured' };
      const sc = headers['set-cookie'];
      const raw = Array.isArray(sc) ? sc.join('; ') : String(sc || '');
      const flag = ctx.plan.flag;
      const weakness = raw.length > 0 && !new RegExp(`(?:^|[;\\s])${flag}(?:=|;|\\s|$)`, 'i').test(raw);
      const hit = (resp.status || 0) > 0 && (resp.status || 0) < 400 && weakness;
      const detail = !raw ? 'no set-cookie issued' : weakness ? `set-cookie present without ${flag}` : `set-cookie now carries ${flag} (weakness gone)`;
      return { hit, detail };
    },
  },
  // Open redirect: 3xx whose Location matches the CITED destination. A fixed redirect
  // (login wall) fails the real read; a genuine open redirector reflects the garbage
  // control target, which does NOT match the cited destination — differential either way.
  redirect: {
    name: 'redirect',
    plan(f, url) {
      const dest = redirectDest(f);
      return { real: url, control: controlUrl(url, validatorMarker()), marker: null, dest, signature: dest ? `redirect to ${dest}` : 'redirects' };
    },
    hit(resp, ctx) {
      const headers = resp && resp.headers;
      const loc = headers ? (Array.isArray(headers.location) ? headers.location[0] : headers.location) : null;
      const st = (resp && resp.status) || 0;
      const isRedir = st >= 300 && st < 400;
      const matched = !!(isRedir && loc && (!ctx.plan.dest || String(loc).includes(ctx.plan.dest)));
      const detail = !isRedir ? `HTTP ${st} — not a redirect`
        : `Location: ${loc || '(none)'}${ctx.plan.dest ? (String(loc || '').includes(ctx.plan.dest) ? ' matches the cited destination' : ' does NOT match the cited destination') : ''}`;
      return { hit: matched, detail };
    },
  },
  // Default (unknown class — the v1 behavior + control): cited marker wins, else the
  // endpoint responding (<400) is the signature; control is a garbage path.
  default: {
    name: 'default',
    plan(f, url) {
      const cited = extractMarker(f.evidence);
      return { real: url, control: controlUrl(url, validatorMarker(), { shape: 'path' }), marker: cited || null, signature: cited ? 'cited marker' : 'endpoint responds' };
    },
    hit(resp, ctx) { return ctx.plan.marker ? markerHit(resp, ctx) : statusHit(resp); },
  },
};

// Select the oracle and build the reproduction pair. An unknown class or an unplannable
// class-specific probe falls back to the default oracle, so EVERY http-class finding gets
// the paired read. plan.class records the oracle actually used.
export function planValidation(f, url) {
  const oracle = ORACLES[oracleClass(f)] || ORACLES.default;
  let plan = null;
  try { plan = oracle.plan(f, url); } catch { plan = null; }
  if (!plan || !plan.real || !plan.control) {
    plan = ORACLES.default.plan(f, url);
    return { ...plan, oracle: ORACLES.default, class: 'default' };
  }
  return { ...plan, oracle, class: oracle.name };
}

// The paired-read truth table — THE falsification doctrine:
//   real HIT  + control MISS → validated (the signature is specific to the real input)
//   real HIT  + control HIT  → refuted, HOLLOW_REASON (the signature fires on garbage too)
//   real MISS (either way)   → refuted, REPRO_REASON (the claim no longer reproduces;
//                              a control that matched while the real missed is noted)
// Read FAILURES never reach this table — the caller reports them as untestable (no claim
// without a control).
export function verdictFor(plan, realResp, controlResp) {
  const real = plan.oracle.hit(realResp, { plan, reqUrl: plan.real });
  const control = plan.oracle.hit(controlResp, { plan, reqUrl: plan.control });
  const head = `${plan.class} oracle: real GET ${plan.real} → HTTP ${(realResp && realResp.status) || 0}; ${real.detail}`;
  const controlLine = `control GET ${plan.control} → HTTP ${(controlResp && controlResp.status) || 0}; ${control.detail}`;
  if (!real.hit) {
    return { state: 'refuted', reason: REPRO_REASON, real, control, controlLine, oracle: `${head} — the claim does not reproduce. ${controlLine} (${control.hit ? 'control matched' : 'control absent'})` };
  }
  if (control.hit) {
    return { state: 'refuted', reason: HOLLOW_REASON, real, control, controlLine, oracle: `${head}. ${controlLine} — signature present under BOTH: ${HOLLOW_REASON}` };
  }
  return { state: 'validated', reason: null, real, control, controlLine, oracle: `${head}. ${controlLine} — differential holds: ${plan.signature} is specific to the real input` };
}

/* ---------- staleness: 'stale' is a RENDERING of validated, never a stored state ----- */

const DAY_MS = 86400000;

// A validated finding whose validatedAt is older than the TTL renders as 'stale'
// (validated-but-old, revalidation advised). Exactly TTL-days old is NOT stale yet;
// staleDays 0 = never stale. Missing/invalid timestamps are honestly not-stale.
export function isStale(validation, { now = Date.now(), staleDays = 30 } = {}) {
  if (!validation || validation.state !== 'validated') return false;
  const days = Number(staleDays);
  if (!Number.isFinite(days) || days <= 0) return false;
  const t = Date.parse(validation.validatedAt || validation.at || '');
  if (!Number.isFinite(t)) return false;
  return now - t > days * DAY_MS;
}

export function renderValidationState(validation, opts = {}) {
  if (!validation || !validation.state) return null;
  return isStale(validation, opts) ? 'stale' : validation.state;
}

// Console-API annotation: findings get validation.stale + validation.display ('stale'
// when validated-but-old). Returns NEW node objects — the live surface is never mutated,
// so the stored vocabulary stays clean.
export function annotateValidation(nodes, opts = {}) {
  return (nodes || []).map((n) => {
    if (!n || n.type !== 'finding' || !n.validation) return n;
    return { ...n, validation: { ...n.validation, stale: isStale(n.validation, opts), display: renderValidationState(n.validation, opts) } };
  });
}
