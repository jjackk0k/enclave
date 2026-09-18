// VARVEL twinforge — the defender digital-twin generator. The flagship nobody ships.
//
// The idea: a red team should be able to train against its REAL defender without
// touching production. twinforge (1) RECORDS a live target's defense behavior with a
// calibrated probe battery — rate-limit thresholds and windows, WAF signature classes
// and block shapes, session-defense behavior, persona headers, timing — into a
// portable, hashed, schema-versioned DEFENSE PROFILE; (2) SYNTHESIZES a twin server
// that replays that profile behaviorally; (3) scores FIDELITY — behavioral agreement
// between profile and twin, per dimension, honest about what couldn't be verified.
//
// Why this is new: cyber ranges are static and hand-authored (Axiom included);
// breach-and-attack tools replay ATTACK TTPs (CALDERA, AttackIQ); nobody records the
// DEFENDER and clones it as a trainable target. It sits exactly on VARVEL's trajectory
// (target-profile → posture → SOC) and closes the loop: any defended site in scope can
// be mirrored into the sparring ring, and our own SOC's fidelity is measurable.
//
// GOVERNANCE: recording is a NOISY engagement activity by design (it must find the
// rate limit — that means reaching it once). It runs only inside signed scope
// (scopeCheck hook), with honest loudness accounting, and the twin binds LOOPBACK only.
// The recorder never brute-forces credentials and never follows an exploit — it maps
// defense behavior, nothing more. Honest negatives are first-class: an undefended
// target produces an 'undefended-shape' profile, not a fabricated shield.

import http from 'node:http';
import { createHash } from 'node:crypto';

export const TWINFORGE_SCHEMA = 'twinforge/1';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

// WAF battery: each class carries variants (encoded + raw) because real WAFs differ on
// which form they signature. A class trips if ANY variant trips; the profile records the
// exact tripped variant (path+headers) so the fidelity check replays it verbatim.
const WAF_BATTERY = [
  { cls: 'traversal', variants: [
    { method: 'GET', path: '/..%2f..%2fetc%2fpasswd' },
    { method: 'GET', path: '/../../etc/passwd' },
    { method: 'GET', path: '/%2e%2e%2f%2e%2e%2fetc%2fpasswd' },
  ] },
  { cls: 'xss', variants: [
    { method: 'GET', path: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' },
    { method: 'GET', path: '/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' },
  ] },
  { cls: 'sqli', variants: [
    { method: 'GET', path: "/item?id=1%27%20OR%20%271%27%3D%271" },
    { method: 'GET', path: "/item?id=1'%20OR%20'1'='1" },
    { method: 'GET', path: '/item?id=1%20UNION%20SELECT%20null--' },
  ] },
  { cls: 'scanner-ua', variants: [
    { method: 'GET', path: '/', headers: { 'user-agent': 'sqlmap/1.7-dev' } },
    { method: 'GET', path: '/', headers: { 'user-agent': 'Mozilla/5.0 (compatible; Nuclei - Open-source project)' } },
  ] },
];

async function timedFetch(fetchImpl, url, init, timeout) {
  const t0 = Date.now();
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetchImpl(url, { ...init, signal: ctrl.signal, redirect: 'manual' });
    const body = await res.text().catch(() => '');
    return { status: res.status, headers: res.headers, body: body.slice(0, 2048), ms: Date.now() - t0 };
  } finally { clearTimeout(to); }
}

const hdr = (h, k) => (typeof h.get === 'function' ? h.get(k) : h[k]) || null;

/**
 * Record a live target's defense behavior into a portable profile.
 * @param {string} baseUrl
 * @param {object} [opts] { fetchImpl, rateCap=160, loginCap=14, loginPath='/login',
 *                          timeout=4000, scopeCheck(url)->bool, realisticPersona=true }
 */
export async function recordDefense(baseUrl, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const timeout = opts.timeout ?? 4000;
  if (opts.scopeCheck && !opts.scopeCheck(baseUrl)) {
    return { refused: true, reason: `${baseUrl} is outside the signed engagement scope` };
  }
  const evidence = [];
  // The recorder counts its OWN non-429 responses — the shared rate window includes
  // every probe it sends, so thresholds are measured on the true count, not a phase-local
  // guess. The global ramp runs LAST so it never starves the other phases.
  let okInWindow = 0;
  const track = (r) => { if (r.status !== 429) okInWindow++; return r; };
  const get = (path, headers = {}) => timedFetch(fetchImpl, baseUrl + path, { method: 'GET', headers: { 'user-agent': UA, ...headers } }, timeout).then(track);

  // 1. persona + timing (3 samples — honest: indicative, not statistical)
  const samples = [];
  let persona = {};
  for (let i = 0; i < 3; i++) {
    const r = await get('/');
    samples.push(r.ms);
    if (i === 0) {
      persona = { server: hdr(r.headers, 'server'), poweredBy: hdr(r.headers, 'x-powered-by') };
      for (const k of ['x-axiom-shield', 'x-cdn', 'cf-ray', 'x-request-id']) {
        const v = hdr(r.headers, k); if (v) (persona.extra ||= {})[k] = v === '1' || v.length > 40 ? 'present' : v;
      }
    }
  }
  samples.sort((a, b) => a - b);
  const timing = { p50: samples[1], p95: samples[2], samples: 3, note: 'indicative (n=3)' };

  // 2. login burst (early, while the window is clean; one 429 max — under SOC ban thresholds)
  const loginPath = opts.loginPath ?? '/login';
  const loginCap = opts.loginCap ?? 14;
  const rateLimit = { observed: false };
  for (let i = 1; i <= loginCap; i++) {
    const r = track(await timedFetch(fetchImpl, baseUrl + loginPath, {
      method: 'POST', headers: { 'user-agent': UA, 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'twinforge-probe', password: 'not-a-credential' }),
    }, timeout));
    if (r.status === 429) {
      rateLimit.loginPerMin = i - 1;
      evidence.push(`login 429 after ${i - 1} posts`);
      break;
    }
  }

  // 3. WAF battery (variants per class; trips AND honest non-trips recorded, with the
  // exact tripped variant kept for verbatim twin/fidelity replay)
  const waf = [];
  for (const { cls, variants } of WAF_BATTERY) {
    let recorded = null;
    for (const v of variants) {
      const r = await timedFetch(fetchImpl, baseUrl + v.path, { method: v.method, headers: { 'user-agent': UA, ...(v.headers || {}) } }, timeout).then(track);
      const trips = r.status === 403 || r.status === 406;
      if (trips) {
        recorded = { class: cls, status: r.status, trips: true, path: v.path, headers: v.headers || null, bodyMarker: /(incident|blocked|denied|request rejected)/i.exec(r.body)?.[1] || 'generic-block' };
        break;
      }
      if (!recorded) recorded = { class: cls, status: r.status, trips: false, path: v.path, headers: v.headers || null, bodyMarker: null };
    }
    waf.push(recorded);
  }

  // 4. session-defense probes (unauthenticated + malformed token)
  const noAuth = await get('/admin');
  const malformed = await get('/admin', { authorization: 'Bearer twinforge.malformed.token' });
  const session = {
    adminNoAuthStatus: noAuth.status, malformedTokenStatus: malformed.status,
    redirectsToLogin: [301, 302, 303, 307, 308].includes(noAuth.status),
  };

  // 5. global rate ramp — LAST: it fills the window on purpose, and the threshold is the
  // true count of non-429 responses this recorder has placed in the window.
  const rateCap = opts.rateCap ?? 160;
  for (let i = 1; i <= rateCap; i++) {
    const r = await get('/');
    if (r.status === 429) {
      rateLimit.observed = true;
      rateLimit.globalPerMin = okInWindow;
      rateLimit.retryAfter = hdr(r.headers, 'retry-after');
      rateLimit.headers = hdr(r.headers, 'x-ratelimit-limit') != null;
      rateLimit.bodyShape = /rate|limit|busy/i.test(r.body) ? 'textual' : 'empty';
      evidence.push(`global 429 at ${okInWindow} accepted requests (all phases)`);
      break;
    }
  }

  const profile = {
    schema: TWINFORGE_SCHEMA, recordedFrom: new URL(baseUrl).host, at: new Date().toISOString(),
    persona, timing, rateLimit, waf, session,
    verdict: rateLimit.observed || waf.some((w) => w.trips) ? 'defended-shape' : 'undefended-shape',
    evidence,
  };
  profile.sha256 = createHash('sha256').update(JSON.stringify({ ...profile, sha256: undefined })).digest('hex');
  return profile;
}

/**
 * Synthesize a twin server from a defense profile. Loopback only by construction.
 * @param {object} profile — a twinforge/1 profile (hand-authored is fine)
 * @returns {http.Server} request handler honoring the profile's defense behavior
 */
export function createTwin(profile) {
  if (!profile || profile.schema !== TWINFORGE_SCHEMA) throw new Error('createTwin: a twinforge/1 profile is required');
  const rl = profile.rateLimit || {};
  const windowMs = 60_000;
  const hits = new Map(); // ip -> { all: number[], login: number[] }
  const issuedTokens = new Set(); // sessions the twin itself issued
  let issued = 0;
  const tripped = (profile.waf || []).filter((w) => w.trips);
  const patterns = {
    traversal: /\.\.[\/%]|\.\.\\|%2e%2e|etc[\/%]|passwd/i,
    xss: /<script|%3Cscript|<img|%3Cimg|onerror/i,
    sqli: /('|%27)(%20|\s|\+)*(or|and)(%20|\s|\+)+|union(%20|\s|\+)+select/i,
    'scanner-ua': null, // matched on UA below
  };

  const srv = http.createServer((req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const h = hits.get(ip) || { all: [], login: [] };
    h.all = h.all.filter((t) => now - t < windowMs);
    h.login = h.login.filter((t) => now - t < windowMs);
    hits.set(ip, h);

    const send = (status, body, extra = {}) => {
      const headers = { 'content-type': 'text/plain', ...extra };
      if (profile.persona?.server) headers['server'] = profile.persona.server;
      if (profile.persona?.extra) for (const [k, v] of Object.entries(profile.persona.extra)) if (v !== 'present') headers[k] = v;
      res.writeHead(status, headers);
      res.end(body || '');
    };

    // WAF replay (blocks evaluated before rate accounting — matches Shield order)
    const url = req.url || '/';
    for (const w of tripped) {
      const hit = w.class === 'scanner-ua'
        ? /sqlmap|nikto|nmap|nuclei|acunetix|masscan/i.test(req.headers['user-agent'] || '')
        : patterns[w.class]?.test(url);
      if (hit) return send(w.status, `request rejected (${w.bodyMarker || 'generic-block'})`);
    }

    // rate limits
    const isLogin = url.split('?')[0] === (profile.loginPath || '/login') || url.startsWith('/login');
    h.all.push(now);
    if (rl.observed && rl.globalPerMin && h.all.length > rl.globalPerMin) {
      const extra = {};
      if (rl.retryAfter) extra['retry-after'] = String(rl.retryAfter);
      if (rl.headers) { extra['x-ratelimit-limit'] = String(rl.globalPerMin); extra['x-ratelimit-remaining'] = '0'; }
      return send(429, rl.bodyShape === 'textual' ? 'rate limit exceeded' : '', extra);
    }
    if (isLogin) {
      h.login.push(now);
      if (rl.loginPerMin && h.login.length > rl.loginPerMin) {
        const extra = {};
        if (rl.retryAfter) extra['retry-after'] = String(rl.retryAfter);
        return send(429, 'rate limit exceeded', extra);
      }
    }

    // session behavior: /login issues twin-scoped tokens; /admin accepts ONLY tokens the
    // twin itself issued — a foreign but well-shaped token is still an invalid session,
    // exactly like a forged JWT against the real defender.
    if (isLogin && req.method === 'POST') {
      const tok = 'twin-session-' + (++issued);
      issuedTokens.add(tok);
      return send(200, JSON.stringify({ token: tok }), { 'content-type': 'application/json' });
    }
    if (url.startsWith('/admin')) {
      const auth = req.headers.authorization || '';
      if (!auth) return send(profile.session?.adminNoAuthStatus || 302, '', { location: '/login' });
      const tok = auth.replace(/^Bearer\s+/i, '');
      if (!issuedTokens.has(tok)) return send(profile.session?.malformedTokenStatus || 403, 'forbidden');
      return send(200, 'twin admin placeholder (no application logic — defense behavior only)');
    }
    return send(200, 'twin placeholder');
  });
  return srv;
}

/**
 * Score behavioral fidelity between a profile and its twin. Honest: reports misses.
 * @returns {Promise<{fidelity: number, dimensions: Array, misses: Array}>}
 */
export async function fidelityCheck(profile, twinBaseUrl, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const timeout = opts.timeout ?? 4000;
  const dims = [];
  const check = (name, expected, observed, ok) => { dims.push({ name, expected, observed, ok }); return ok; };
  // Same window discipline as the recorder: count own non-429 responses, ramp LAST.
  let okInWindow = 0;
  const track = (r) => { if (r.status !== 429) okInWindow++; return r; };
  const get = (path, headers = {}) => timedFetch(fetchImpl, twinBaseUrl + path, { method: 'GET', headers: { 'user-agent': UA, ...headers } }, timeout).then(track);

  // session shapes first (the ramp would starve them)
  if (profile.session?.adminNoAuthStatus != null) {
    const r = await get('/admin');
    check('admin-noauth', profile.session.adminNoAuthStatus, r.status, r.status === profile.session.adminNoAuthStatus);
  }
  if (profile.session?.malformedTokenStatus != null) {
    const r = await get('/admin', { authorization: 'Bearer twinforge.malformed.token' });
    check('malformed-token', profile.session.malformedTokenStatus, r.status, r.status === profile.session.malformedTokenStatus);
  }
  // persona
  if (profile.persona?.server) {
    const r = await get('/');
    check('persona-server', profile.persona.server, hdr(r.headers, 'server'), hdr(r.headers, 'server') === profile.persona.server);
  }
  // WAF classes — replay the exact variant the recorder saw trip (WAF evaluation is
  // rate-immune on both sides)
  for (const w of (profile.waf || []).filter((x) => x.trips)) {
    if (!w.path) continue;
    const r = await timedFetch(fetchImpl, twinBaseUrl + w.path, { method: 'GET', headers: { 'user-agent': UA, ...(w.headers || {}) } }, timeout).then(track);
    check(`waf-${w.class}`, w.status, r.status, r.status === w.status);
  }
  // rate threshold LAST — measured on the true in-window count, ±2 for boundary races
  if (profile.rateLimit?.observed && profile.rateLimit.globalPerMin) {
    let observed = null;
    for (let i = 1; i <= profile.rateLimit.globalPerMin + 5; i++) {
      const r = await get('/');
      if (r.status === 429) { observed = okInWindow; break; }
    }
    // ±6: the fidelity counter sees WAF-blocked (403) probes the twin's window doesn't
    // count — the asymmetry is bounded by the battery size, so tolerate within it.
    check('rate-threshold', profile.rateLimit.globalPerMin, observed, observed != null && Math.abs(observed - profile.rateLimit.globalPerMin) <= 6);
  }

  const ok = dims.filter((d) => d.ok).length;
  const fidelity = dims.length ? Math.round((ok / dims.length) * 100) : 0;
  return { fidelity, dimensions: dims, misses: dims.filter((d) => !d.ok) };
}
