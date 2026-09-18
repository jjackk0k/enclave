// VARVEL — malleable C2 profiles (Cobalt's home turf, governed).
//
// A malleable profile is the agent's TIMING shape as first-class config: how often it
// checks in, how that cadence jitters, and whether it occasionally bursts (a real
// operator's tradecraft for making C2 traffic look like something else). This is
// documented simulation tradecraft for the authorized range — it teaches timing shape,
// never evasion (everything still crosses the governed channel, scope, HMAC, audit).
//
// Curves: each profile = { intervalMs, jitterMs, burst: { chance, minN, maxN, gapMs } }.
// The agent samples gap = interval ± jitter; with `chance` probability it instead fires
// a BURST of 2–5 quick check-ins (browser-tab behavior), then returns to baseline.

export const MALLEABLE_PROFILES = {
  'web-browse':  { label: 'Web browsing',   intervalMs: 5000,  jitterMs: 2500, burst: { chance: 0.08, minN: 2, maxN: 4, gapMs: 700 }, note: 'human-ish: slow baseline with tab bursts' },
  'update-check':{ label: 'Update checker', intervalMs: 30000, jitterMs: 8000, burst: { chance: 0.0, minN: 0, maxN: 0, gapMs: 0 }, note: 'metronomic service cadence, small drift' },
  'streaming':   { label: 'Streaming app',  intervalMs: 1200,  jitterMs: 400,  burst: { chance: 0.15, minN: 3, maxN: 6, gapMs: 250 }, note: 'fast baseline with longer buffer bursts' },
  'ops-tempo':   { label: 'Ops tempo',      intervalMs: 2500,  jitterMs: 1500, burst: { chance: 0.05, minN: 2, maxN: 3, gapMs: 500 }, note: 'brisk operator cadence for lab work' },
};

// Resolve a profile by name, or a custom object { intervalMs, jitterMs, burst? }.
// Unknown names fall back to ops-tempo (lab default) — never to zero-wait.
export function malleableProfile(p) {
  if (p && typeof p === 'object') {
    const intervalMs = Math.max(200, Number(p.intervalMs) || 2500);
    const jitterMs = Math.max(0, Number(p.jitterMs) || 0);
    const jitterPct = Math.min(0.9, Math.max(0, Number(p.jitterPct) || 0)); // v2: proportional jitter
    const b = p.burst || {};
    return { label: p.label || 'custom', intervalMs, jitterMs, jitterPct,
      burst: { chance: Math.min(1, Math.max(0, Number(b.chance) || 0)), minN: Math.max(0, b.minN | 0), maxN: Math.max(0, b.maxN | 0), gapMs: Math.max(0, Number(b.gapMs) || 0) } };
  }
  return MALLEABLE_PROFILES[p] || MALLEABLE_PROFILES['ops-tempo'];
}

// The cadence sampler the agent uses per cycle. Returns { gapMs, burst } — when burst
// is a number > 1, the agent fires that many quick cycles at burst.gapMs spacing, then
// resumes baseline. `rand` injectable for deterministic tests.
// v2: a cadence may carry jitterPct (PROPORTIONAL jitter: gap = interval * (1 ± pct*r))
// instead of absolute jitterMs — a fixed ±ms band is trivially uniform-looking to a
// dispersion scorer, a fraction of the interval scales with the cadence the way real
// application timers drift.
export function nextGap(profile, { rand = Math.random } = {}) {
  const p = malleableProfile(profile);
  const b = p.burst;
  if (b.chance > 0 && b.maxN > 0 && rand() < b.chance) {
    const n = b.minN + Math.floor(rand() * (b.maxN - b.minN + 1));
    return { gapMs: b.gapMs, burst: Math.max(1, n) };
  }
  const pct = Math.min(0.9, Math.max(0, Number(p.jitterPct) || 0));
  const gap = pct > 0
    ? Math.round(p.intervalMs * (1 + (rand() * 2 - 1) * pct))
    : p.intervalMs + Math.round((rand() * 2 - 1) * p.jitterMs);
  return { gapMs: Math.max(200, gap), burst: 1 };
}

// ————————————————————————————————————————————————————————————————————————————————
// MALLEABLE PROFILE LIBRARY v2 (the C2 shaping pack): a profile is no longer only a
// timing curve — it is the whole WIRE SHAPE: request path templates, ordered header
// sets, UA families, the cadence model above (jitterPct + optional batch/dwell windows
// + optional padding), and the JA4H class the shape is EXPECTED to measure as. The
// expected fingerprint is never asserted: engine/shapegrade measures the live wire and
// reports claimed-vs-measured, loudly when they diverge.
//
// 'plain' is today's shape, byte-identical: null blocks mean "no shaping applied" and
// every consumer falls through to the legacy path. All shaping is OPT-IN.
//
// Honest limit (documented, never papered over): these templates shape the HTTP REQUEST
// layer only (paths, headers, cadence). The TLS ClientHello — JA4 — belongs to the
// runtime's TLS stack; shaping it needs native TLS control, which this pure-ESM stack
// does not have. shapegrade says so on every report.
// ————————————————————————————————————————————————————————————————————————————————

const UA_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
const UA_CHROME_EDG = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0';
const UA_UPDATE = 'Microsoft-Update-Agent/10.0.10011.16384 Client-Protocol/2.0';
const UA_TELEMETRY = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';

export const SHAPE_PROFILES = {
  // TODAY'S SHAPE. null cadence/http/batch/padding = every consumer takes the legacy
  // path; applying 'plain' is exactly "no shaping" (and clears a previously set shape).
  plain: {
    label: 'Plain (default wire)',
    cadence: null, batch: null, padding: null, http: null,
    expect: { ja4h: null, h2: 'http/1.1 stack (no native H2 control)' },
    note: "today's shape: minimal header set on /c /r /d routes, no claim made or measured against a template",
  },
  // Cacheable static-asset GET cadence: a page's JS/CSS fetches — bursty on load, then
  // quiet; cache-busting query key; full browser header set; Chrome-family UAs.
  'cdn-asset': {
    label: 'CDN static assets',
    cadence: { intervalMs: 4000, jitterPct: 0.4, burst: { chance: 0.10, minN: 2, maxN: 4, gapMs: 400 } },
    batch: null, padding: null,
    http: {
      pullPaths: ['/assets/js/app.min.js', '/assets/css/site.css', '/static/img/logo.svg', '/assets/js/vendor.min.js'],
      pushPaths: ['/api/telemetry'],
      queryKey: 'v',
      headers: [
        ['user-agent', '{ua}'],
        ['accept', '*/*'],
        ['accept-language', 'en-US,en;q=0.9'],
        ['accept-encoding', 'gzip, deflate, br'],
        ['cache-control', 'no-cache'],
        ['pragma', 'no-cache'],
      ],
      uaPool: [UA_CHROME, UA_CHROME_EDG],
    },
    expect: { ja4h: 'browser-header GET/1.1 class (ge11nn..enus)', h2: 'http/1.1 stack (no native H2 control)' },
    note: 'cacheable-static-asset fetch shape: jittered baseline with page-load bursts',
  },
  // Version-check shape: a metronomic service cadence with small drift, vendor update
  // UA, tight Accept set. HONESTLY the most beacon-like of the set — the pre-flight
  // grade says so; it exists for engagements whose cover story IS a service.
  'software-update': {
    label: 'Software update check',
    cadence: { intervalMs: 30000, jitterPct: 0.15, burst: { chance: 0, minN: 0, maxN: 0, gapMs: 0 } },
    batch: null, padding: null,
    http: {
      pullPaths: ['/update/check', '/v2/manifest.json'],
      pushPaths: ['/update/telemetry'],
      queryKey: 'cb',
      headers: [
        ['user-agent', '{ua}'],
        ['accept', 'application/json'],
        ['accept-encoding', 'gzip, deflate'],
      ],
      uaPool: [UA_UPDATE],
    },
    expect: { ja4h: 'update-client GET/1.1 class (ge11nn..0000)', h2: 'http/1.1 stack (no native H2 control)' },
    note: 'version-check shape: near-metronomic BY DESIGN (a service cadence is the cover); shapegrade reports its real beacon score, never a claim',
  },
  // Analytics-ping shape: regular small pings, dwell-window batching available, full
  // browser header set with the telemetry endpoint as the collection path.
  'telemetry-beacon': {
    label: 'Analytics telemetry ping',
    cadence: { intervalMs: 15000, jitterPct: 0.5, burst: { chance: 0.06, minN: 2, maxN: 3, gapMs: 600 } },
    batch: null, padding: null,
    http: {
      pullPaths: ['/collect', '/telemetry/v2/events', '/analytics/ping'],
      pushPaths: ['/collect', '/telemetry/v2/events'],
      queryKey: 'z',
      headers: [
        ['user-agent', '{ua}'],
        ['accept', '*/*'],
        ['accept-language', 'en-US,en;q=0.9'],
        ['accept-encoding', 'gzip, deflate, br'],
      ],
      uaPool: [UA_TELEMETRY, UA_CHROME],
    },
    expect: { ja4h: 'browser-header GET/1.1 class (ge11nn..enus)', h2: 'http/1.1 stack (no native H2 control)' },
    note: 'analytics-ping shape: heavy jitter baseline; pairs with batch windows for dwell-style tasking',
  },
};

// Resolve a v2 shape profile by name (or pass a custom object through, validated the
// same way). 'plain' and unknown names resolve honestly: 'plain' IS the library entry;
// anything else unknown returns null — callers report it, never silently reshape.
export function shapeProfile(p) {
  if (p && typeof p === 'object') {
    const src = p;
    const cad = src.cadence || null;
    return {
      name: src.name || 'custom',
      label: src.label || src.name || 'custom',
      cadence: cad ? {
        intervalMs: Math.max(200, Number(cad.intervalMs) || 2500),
        jitterPct: Math.min(0.9, Math.max(0, Number(cad.jitterPct) || 0)),
        jitterMs: Math.max(0, Number(cad.jitterMs) || 0),
        burst: cad.burst ? { chance: Math.min(1, Math.max(0, Number(cad.burst.chance) || 0)), minN: Math.max(0, cad.burst.minN | 0), maxN: Math.max(0, cad.burst.maxN | 0), gapMs: Math.max(0, Number(cad.burst.gapMs) || 0) } : { chance: 0, minN: 0, maxN: 0, gapMs: 0 },
      } : null,
      batch: src.batch && Number(src.batch.windowMs) > 0 ? { windowMs: Math.max(1000, Number(src.batch.windowMs)) } : null,
      padding: src.padding && Number(src.padding.perCycle) > 1 ? { perCycle: Math.min(8, Math.floor(Number(src.padding.perCycle))) } : null,
      http: src.http && Array.isArray(src.http.pullPaths) && src.http.pullPaths.length ? {
        pullPaths: src.http.pullPaths.map(String).slice(0, 8),
        pushPaths: (Array.isArray(src.http.pushPaths) && src.http.pushPaths.length ? src.http.pushPaths : src.http.pullPaths).map(String).slice(0, 8),
        queryKey: String(src.http.queryKey || 'v').slice(0, 12),
        headers: (Array.isArray(src.http.headers) ? src.http.headers : []).filter((h) => Array.isArray(h) && h.length >= 2).map(([n, v]) => [String(n), String(v)]).slice(0, 16),
        uaPool: (Array.isArray(src.http.uaPool) && src.http.uaPool.length ? src.http.uaPool : ['{ua}']).map(String).slice(0, 6),
      } : null,
      expect: src.expect || { ja4h: null },
      note: src.note || '',
    };
  }
  if (p == null || p === '' || p === 'plain') return { name: 'plain', ...SHAPE_PROFILES.plain };
  const hit = SHAPE_PROFILES[String(p)];
  return hit ? { name: String(p), ...hit } : null;
}

// Batch/dwell windows: both channel and agent must agree on the randomized flush point
// WITHOUT coordination, so it is derived from the shared secret the wire already
// carries — HMAC(token, 'varvel-batch:<windowIndex>'). Deterministic per window,
// unpredictable without the token, hermetic to test. Engine-pure (node:crypto only).
import crypto from 'node:crypto';
export function windowIndexAt(anchorMs, windowMs, nowMs) {
  return Math.max(0, Math.floor((Number(nowMs) - Number(anchorMs)) / Math.max(1, Number(windowMs))));
}
export function windowOffsetMs(token, windowMs, windowIndex) {
  const h = crypto.createHmac('sha256', String(token)).update('varvel-batch:' + windowIndex).digest();
  const frac = h.readUInt32BE(0) / 4294967296;
  return Math.floor(frac * Math.max(1, Number(windowMs)));
}
// The flush point of a given window: anchor + i*window + seeded offset inside it.
export function windowFlushAt(token, anchorMs, windowMs, windowIndex) {
  return Number(anchorMs) + windowIndex * Number(windowMs) + windowOffsetMs(token, windowMs, windowIndex);
}

// EXPECTED JA4H: computed, never asserted. Builds the exact ordered header list the sim
// agent's fetch puts on the wire for this profile — template headers in order, then the
// auth headers, then the runtime's own additions. The undici append contract (measured
// on this stack, engine side of the shapegrade loop): missing defaults are appended in
// the fixed sequence accept → accept-language → sec-fetch-mode → user-agent →
// accept-encoding; sec-fetch-mode is FORCED to 'cors' (a template value is replaced in
// place); a Buffer body adds content-length last and no content-type. UA pool entries do
// not change the fingerprint (JA4H hashes header NAMES + the accept-language value, not
// the UA string). If a future runtime changes any of this, the measured ring diverges
// from this string and shapegrade reports it — that divergence report is the feature
// working, not a bug it hides.
export function expectedWireHeaders(shape, { method = 'GET' } = {}) {
  const s = shapeProfile(shape);
  if (!s || !s.http) return null;
  const headers = [['host', ''], ['connection', '']];
  const set = new Set();
  const ua = s.http.uaPool[0];
  for (const [n, v] of s.http.headers) { headers.push([n.toLowerCase(), v === '{ua}' ? ua : v]); set.add(n.toLowerCase()); }
  if (method === 'GET') headers.push(['x-agent', ''], ['x-seq', ''], ['x-auth', '']);
  else headers.push(['x-agent', ''], ['x-seq', ''], ['x-task', ''], ['x-auth', '']);
  if (set.has('sec-fetch-mode')) { // forced to cors in place
    const i = headers.findIndex(([n]) => n === 'sec-fetch-mode');
    headers[i] = ['sec-fetch-mode', 'cors'];
  }
  if (!set.has('accept')) headers.push(['accept', '*/*']);
  if (!set.has('accept-language')) headers.push(['accept-language', '*']);
  if (!set.has('sec-fetch-mode')) headers.push(['sec-fetch-mode', 'cors']);
  if (!set.has('user-agent')) headers.push(['user-agent', 'node']);
  if (!set.has('accept-encoding')) headers.push(['accept-encoding', 'gzip, deflate']);
  if (method !== 'GET') headers.push(['content-length', '']);
  return headers;
}

export function expectedJa4h(shape, { method = 'GET', ja4hFn } = {}) {
  const headers = expectedWireHeaders(shape, { method });
  if (!headers) return null;
  return ja4hFn({ method, httpVersion: '1.1', headers });
}
