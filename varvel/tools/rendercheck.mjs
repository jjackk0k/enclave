// tools/rendercheck.mjs -- RENDERCHECK: VISUAL confirmation of a target-side change,
// the way a real visitor's browser would show it.
//
// Why it exists (the 2026-08 lesson): the AI proved a change server-side (a write
// landed, an edit returned 200) while the operator's browser showed NOTHING -- it was
// serving a cached page. Cheap HTTP rides (cfride/sessride) prove what the WIRE says;
// they cannot prove what a browser RENDERS, and they cannot by themselves answer the
// question that actually matters post-change: "what do visitors see RIGHT NOW -- the
// live origin, or a cached copy that cloaks my change?" rendercheck closes that gap:
// it renders the page in a REAL browser (the nodriver raw-CDP sidecar's one-shot
// --render mode: headless navigate + settle + wire/DOM/text dump + viewport PNG
// screenshot) and reads the cache evidence (cf-cache-status/age) off the Document
// response, so the verdict distinguishes "change live at origin" from "visitors see a
// cached page". A change behind an edge HIT is REAL-BUT-CLOAKED -- the report says
// exactly that, never "confirmed" and never "failed".
//
// GOVERNANCE (the platform's absolute rules, mirrored from sessride/cfride/cfbrowser):
// * SCOPE: the signed engagement scope is checked BEFORE any request -- the host is
//   resolved, EVERY resolved IP must sit inside the signed CIDRs, and the refusal
//   prints the scope (the wafbypass/sessride doctrine, deliberately re-implemented so
//   this tool stays standalone). BROWSER-TIER HONESTY (a deliberate deviation from
//   sessride's per-hop re-check): a real browser follows redirects ITSELF, so per-hop
//   gating is not enforceable here -- instead the FINAL landed host is re-checked
//   against the signed scope AFTER the render and reported loudly (redirect block),
//   and ridden cookies are domain-scoped to the requested zone (CDP cookie scoping),
//   so the session never rides to a redirected host. Reported, never hidden.
// * EGRESS PARITY: identical to cfride -- the vault entry's egressId is the binding
//   contract. broker.resolveRideTransport maps it to the armed ghost chain (canonical
//   ids must match); a chain-keyed entry launches the browser THROUGH the chain's
//   single-hop proxy (Chrome --proxy-server, applied at LAUNCH before any window
//   opens -- the cfbrowser/ndmint doctrine), a multi-hop chain is refused fail-closed
//   (a browser rides exactly ONE hop), ghost 'required' never renders a public target
//   direct. The lookup egressId defaults the sessride way (the armed chain's
//   canonical id, else 'direct'); opts.egressId overrides explicitly.
// * THE RIDE: the vault clearance (clearanceFor: exact UA is implied by the minted
//   browser profile; the cookies are seeded BEFORE navigation) plus an OPTIONAL
//   session jar (--jar, the sessride sess_jar.json shape; merge order: jar base,
//   clearance overlays -- the sessride contract). --no-ride forces a COOKIELESS
//   render (what a fresh anonymous visitor sees) and contradicting it with --jar is a
//   plain refusal. Cookie VALUES never appear in the report (names only), are passed
//   to the sidecar via a temp FILE (never argv/process lists), and the file is
//   deleted with the throwaway browser profile after the run.
// * HONESTY: NEVER throws -- every failure resolves { ok:false, reason }. A
//   challenge-dominated render (cf-mitigated, managed-js DOM, ...) is ok:false
//   CHALLENGED with evidence (screenshot included), never a claim. A missing sidecar
//   or Chrome is an honest UNSUPPORTED state. A missing --expect marker is a FAIL
//   (ok:false EXPECT-FAILED), never a soft pass. Screenshot bytes never ride the
//   report -- the path + byte size only. The browser profile is a THROWAWAY temp dir:
//   nothing carries between runs, and a render can never deadlock on the profile lock
//   of a live mint/cfbrowser window (the broker's profile-lock note).
//
// CACHE-AWARE VERDICT LANGUAGE (the core lesson, verbatim rules):
//   expect passes + origin-live (DYNAMIC/MISS/...)  -> "CONFIRMED LIVE AT ORIGIN"
//   expect passes + cached-copy (HIT, age)          -> "CONFIRMED VISIBLE TO VISITORS
//                                                      (the cached copy carries it)"
//   expect ABSENT  + origin-live                    -> "NOT LIVE AT ORIGIN" -- refutes
//                                                      the 'cached browser' alibi
//   expect ABSENT  + cached-copy                    -> "REAL-BUT-CLOAKED cannot be
//                                                      ruled out" -- visitors see the
//                                                      stale page; origin state unproven
//   no cf-cache-status                              -> cache UNOBSERVABLE, reported
//                                                      never assumed
// Every render requests with a UNIQUE cache-busting query param (__varvel_rc=<rand>).
// A zone that still answers HIT to a never-before-seen URL has a cache key that
// IGNORES query strings -- that is precisely the operator's-cached-browser case, and
// the report says so.
//
// ASSERTIONS: --expect/--deny, each `text` (literal substring) or `re:<pattern>`
// (regex), run against ALL THREE captured surfaces: the rendered DOM TEXT
// (innerText), the rendered DOM HTML, and the raw WIRE HTML. DOCTRINE: assert on
// collision-proof markers (unique random strings, e.g. the varvel-rc-* marker you
// planted with the change) -- never on page furniture like "Welcome".
//
// INJECTABLE SEAMS (hermetic tests -- no real browser, no network): opts.sidecarRun
// (the nodriver subprocess), opts.env/exists/spawnSync (detectNodriver + resolveChrome
// pass-throughs, the broker's seams), opts.chromePath, opts.clearanceLookup,
// opts.ghost/ghostMode (transport), opts.resolve (scope DNS), opts.vaultPath,
// opts.jar (inline jar), opts.rand (cache-buster token), opts.now.

import crypto from 'node:crypto';
import dns from 'node:dns';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { clearanceFor, resolveRideTransport, ghostRideState, resolveChrome, detectNodriver, parseSidecarJson } from './clearance/broker.mjs';
import { isPrivateDest, chainEgressId } from '../engine/ghost.mjs';
import { detectChallenge } from '../engine/challenge.mjs';
import { inAnyCidr, parseIp } from '../engine/ipaddr.mjs';
import { readJar } from './sessride.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(HERE, '..', 'data');
const EVIDENCE_DIR = path.join(DATA_DIR, 'evidence'); // default screenshot home (--out overrides)
const NDMINT_PY = path.join(HERE, 'clearance', 'py', 'ndmint.py');
const DEFAULT_TIMEOUT_MS = 60000;  // the whole render (launch + navigate + settle + shot)
const DEFAULT_SETTLE_MS = 10000;   // max wait for a readable document inside the render
const SIDECAR_GRACE_MS = 45000;    // the broker's hard-kill grace beyond the sidecar budget

const msg = (e) => String((e && e.message) || e);

// ---------------------------------------------------------------------------
// Governance: signed-scope check. Mirrors tools/sessride.mjs + wafbypass.mjs (same
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
      reason: 'target ' + host + ' resolves outside the signed engagement scope (' + outside.join(', ') + ' not in scope) -- render REFUSED. Signed scope: ' + cidrs.join(','),
      scope: cidrs, resolved: ips, outside,
    };
  }
  return { ok: true, scope: cidrs, resolved: ips };
}

// ---------------------------------------------------------------------------
// Assertions. parseAssertion(spec): 're:<pattern>' is a regex; anything else is a
// literal substring. A bad regex is a USAGE refusal BEFORE any request, never a
// mid-run surprise. runAssertions: an expect PASSES when found on ANY surface (the
// rendered DOM text, the rendered DOM HTML, or the raw wire HTML); a deny passes when
// found on NONE. A missing expect is a FAIL -- never a soft pass. Pure; never throws.
// ---------------------------------------------------------------------------
export function parseAssertion(spec) {
  const s = String(spec == null ? '' : spec);
  if (!s) return { error: 'empty assertion -- pass text or re:<pattern>' };
  if (s.startsWith('re:')) {
    try { return { kind: 'regex', re: new RegExp(s.slice(3)), label: s }; } catch (e) { return { error: 'invalid regex in assertion ' + JSON.stringify(s) + ' (' + msg(e) + ')' }; }
  }
  return { kind: 'text', text: s, label: JSON.stringify(s) };
}

function matchOn(assertion, haystack) {
  const h = String(haystack == null ? '' : haystack);
  return assertion.kind === 'regex' ? assertion.re.test(h) : h.includes(assertion.text);
}

export function runAssertions({ expect = null, deny = null, surfaces = {} } = {}) {
  const surfaceNames = ['domText', 'domHtml', 'wireHtml'];
  const checks = [];
  const failures = [];
  for (const [which, a] of [['expect', expect], ['deny', deny]]) {
    if (!a) continue;
    const matchedSurfaces = surfaceNames.filter((n) => matchOn(a, surfaces[n]));
    if (which === 'expect') {
      const pass = matchedSurfaces.length > 0;
      checks.push({ which, assertion: a.label, pass, matchedSurfaces });
      if (!pass) failures.push('expected marker ' + a.label + ' NOT FOUND on any captured surface (rendered DOM text, rendered DOM HTML, raw wire HTML) -- a missing expect is a FAIL, never a soft pass');
    } else {
      const pass = matchedSurfaces.length === 0;
      checks.push({ which, assertion: a.label, pass, matchedSurfaces });
      if (!pass) failures.push('denied marker ' + a.label + ' IS PRESENT on surface(s): ' + matchedSurfaces.join(', '));
    }
  }
  return { pass: failures.length === 0, checks, failures };
}

// ---------------------------------------------------------------------------
// cacheRead(headers) -- THE cache-cloak read, pure and injectable-testable. Classifies
// the edge cache state from the Document response headers:
//   HIT/STALE/UPDATING              -> 'cached-copy' (visitors see a CACHED page)
//   MISS/DYNAMIC/EXPIRED/REVALIDATED/BYPASS -> 'origin-live' (the render shows the
//                                      live origin state; MISS carries the "the edge
//                                      may have just cached this for the NEXT visitor"
//                                      caveat)
//   no header / unknown token       -> 'unknown' (unobservable, reported never assumed)
// ---------------------------------------------------------------------------
export function cacheRead(headers = {}) {
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[String(k).toLowerCase()] = String(v);
  const raw = h['cf-cache-status'] || null;
  const ray = h['cf-ray'] || null;
  const ageRaw = h['age'];
  const ageSeconds = ageRaw != null && /^\d+$/.test(ageRaw) ? Number(ageRaw) : null;
  if (!raw) {
    return {
      observed: false, status: null, ageSeconds, ray, classification: 'unknown',
      note: 'no cf-cache-status response header -- the edge cache state is UNOBSERVABLE from here (the zone is not Cloudflare-fronted, or this path is not cache-eligible). Cache cloaking can be neither confirmed nor excluded -- reported, never assumed.',
    };
  }
  const status = raw.toUpperCase();
  const ageStr = ageSeconds != null ? ', age ' + ageSeconds + 's' : '';
  if (status === 'HIT' || status === 'STALE' || status === 'UPDATING') {
    return {
      observed: true, status, ageSeconds, ray, classification: 'cached-copy',
      note: 'the edge served a CACHED copy (cf-cache-status: ' + status + ageStr + ') -- and it served it DESPITE this request\'s unique cache-busting query param, so this zone\'s cache key IGNORES query strings. What a visitor\'s browser shows right now IS this cached copy.',
    };
  }
  if (status === 'DYNAMIC') {
    return {
      observed: true, status, ageSeconds, ray, classification: 'origin-live',
      note: 'cf-cache-status: DYNAMIC -- Cloudflare does not cache this content; the response came straight from ORIGIN. This render shows the LIVE origin state -- no cache layer exists here that could cloak a change.',
    };
  }
  if (status === 'MISS') {
    return {
      observed: true, status, ageSeconds, ray, classification: 'origin-live',
      note: 'cf-cache-status: MISS -- no cached copy was served; this response was fetched fresh from ORIGIN, so this render shows the LIVE origin state. Caveat, honestly: a MISS also means the edge may have just cached this copy for the NEXT visitor.',
    };
  }
  if (status === 'EXPIRED' || status === 'REVALIDATED' || status === 'BYPASS') {
    return {
      observed: true, status, ageSeconds, ray, classification: 'origin-live',
      note: 'cf-cache-status: ' + status + ' -- the edge went to ORIGIN for this response; this render shows the LIVE origin state.',
    };
  }
  return {
    observed: true, status, ageSeconds, ray, classification: 'unknown',
    note: 'cf-cache-status: ' + status + ' -- an unrecognized token; the cache classification is unknown, reported verbatim, never guessed.',
  };
}

// composeReading(cache, { expectGiven, expectPass }) -- the cache-aware verdict
// language (the tool's core lesson). Pure. The four live cases are spelled out in the
// header comment; the language never upgrades a cloaked read to a confirmation and
// never downgrades an origin-fresh absence to "maybe cached".
export function composeReading(cache, { expectGiven = false, expectPass = null } = {}) {
  const ageStr = cache.ageSeconds != null ? ', age ' + cache.ageSeconds + 's' : '';
  if (!expectGiven) {
    return cache.note + ' No --expect assertion was given -- this run is a RENDER + cache observation only: a render with no assertion proves NOTHING about a change. Assert on a collision-proof marker (a unique random string you planted with the change).';
  }
  if (expectPass === true) {
    if (cache.classification === 'cached-copy') {
      return 'CONFIRMED VISIBLE TO VISITORS: the expected marker IS present in the CACHED copy the edge is serving (' + cache.status + ageStr + ') -- visitors see it right now. ' + cache.note;
    }
    if (cache.classification === 'origin-live') {
      return 'CONFIRMED LIVE AT ORIGIN: the expected marker IS present in a response served fresh from origin (cf-cache-status: ' + cache.status + ') -- the change is live and visible. ' + cache.note;
    }
    return 'CONFIRMED (cache unobservable): the expected marker IS present in the rendered page. ' + cache.note;
  }
  // expect given and ABSENT
  if (cache.classification === 'cached-copy') {
    return 'REAL-BUT-CLOAKED cannot be ruled out: the expected marker is ABSENT, but the edge served a CACHED copy (' + cache.status + ageStr + ') that IGNORED this request\'s unique cache-buster -- so this render shows what VISITORS see (the stale page), NOT the origin state. An origin-side change here would be real-but-cloaked behind the cached copy until it expires or is purged. To confirm the origin state: purge the cache or await expiry, then re-run -- only an origin-fetched read (MISS/DYNAMIC) can settle it.';
  }
  if (cache.classification === 'origin-live') {
    return 'NOT LIVE AT ORIGIN: the expected marker is ABSENT and this response came fresh from origin (cf-cache-status: ' + cache.status + ') with no cache in between -- the change did NOT take effect at origin (at least not on this route). This REFUTES the "your browser is just showing a cached page" explanation: the origin itself is not serving it.';
  }
  return 'the expected marker is ABSENT and the cache state is UNOBSERVABLE -- "the change never landed" and "landed but cache-cloaked" CANNOT be distinguished from this render. ' + cache.note;
}

// ---------------------------------------------------------------------------
// The cache-buster: every render requests a never-before-seen URL. A zone that still
// answers HIT to it has a cache key that ignores query strings -- exactly the
// operator's-cached-browser case, and cacheRead's language says so.
// ---------------------------------------------------------------------------
export function cacheBust(url, token) {
  const u = new URL(String(url));
  u.searchParams.set('__varvel_rc', String(token));
  return u.href;
}

// ---------------------------------------------------------------------------
// sidecarCookies({ jarPairs, clearanceCookies, zoneHost }) -> the cookie objects the
// sidecar seeds BEFORE navigation, plus the names-only report view. THE MERGE ORDER is
// the sessride contract: jar lays the base (file order), vault clearance OVERLAYS name
// collisions (the vault entry is TTL-validated and IP/UA-bound; a jar copy may be
// stale). Domain dot-prefixed to the zone (the cfbrowser seedCookies doctrine:
// subdomains ride the same session); a session cookie's expires:-1 is dropped. VALUES
// never enter the report -- names only.
// ---------------------------------------------------------------------------
export function sidecarCookies({ jarPairs = [], clearanceCookies = [], zoneHost = '' } = {}) {
  const merged = new Map();
  const fromJar = [];
  const fromClearance = [];
  const shape = (name, value, src) => {
    const out = { name, value: String(value), path: (src && src.path) || '/' };
    const d = String((src && src.domain) || zoneHost);
    out.domain = d.startsWith('.') ? d : '.' + d;
    if (src && src.secure != null) out.secure = !!src.secure;
    if (src && src.httpOnly != null) out.httpOnly = !!src.httpOnly;
    if (src && Number.isFinite(src.expires) && src.expires > 0) out.expires = src.expires;
    return out;
  };
  for (const [n, v] of jarPairs || []) {
    if (!merged.has(n)) fromJar.push(n);
    merged.set(n, shape(n, v, null));
  }
  for (const ck of clearanceCookies || []) {
    if (!ck || typeof ck.name !== 'string' || !ck.name) continue;
    merged.set(ck.name, shape(ck.name, ck.value, ck));
    fromClearance.push(ck.name);
  }
  return { cookies: [...merged.values()], names: [...merged.keys()], fromJar, fromClearance };
}

// Default sidecar spawn: mirrors the broker's defaultSidecarRun (private there) -- the
// venv python + ndmint.py as an ARGS ARRAY (never a shell string), stdout/stderr
// collected to strings, a hard kill at timeoutMs so the Node side can never hang past
// the sidecar's own budget + grace. Never rejects.
function defaultSidecarRun(pythonPath, args, { timeoutMs } = {}) {
  return new Promise((resolve) => {
    let stdout = '', stderr = '', settled = false;
    const done = (r) => { if (!settled) { settled = true; resolve(r); } };
    let child;
    try { child = spawn(pythonPath, args); } catch (e) { done({ ok: false, error: msg(e), stdout, stderr }); return; }
    const killer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch {}
      done({ ok: false, timedOut: true, error: 'sidecar exceeded its hard kill budget (' + timeoutMs + 'ms) and was force-killed', stdout, stderr });
    }, Math.max(1000, timeoutMs || 60000));
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => { clearTimeout(killer); done({ ok: false, error: msg(e), stdout, stderr }); });
    child.on('close', (code) => { clearTimeout(killer); done({ ok: true, status: code, stdout, stderr }); });
  });
}

// The --no-ride transport: the wafbypass ensureGhost doctrine, browser-flavored (a
// proxy, not agents). Private/range is always direct; a public target with no armed
// chain is refused fail-closed under ghost 'required', direct-with-a-note under
// off|on; a multi-hop chain is refused (a browser rides exactly ONE hop). Never throws.
async function noRideTransport({ ghost, ghostMode, hostname }) {
  const mode = ghostMode || (ghost && ghost.mode) || 'off';
  try {
    if (isPrivateDest(hostname)) {
      return { ok: true, proxy: null, transport: 'direct (private/range destination -- ghost doctrine: lab traffic never leaves the lab)' };
    }
    if (!ghost || mode === 'off' || !ghost.chain || !ghost.chain.length) {
      if (mode === 'required') {
        return { ok: false, reason: 'ghost mode is REQUIRED but no proxy chain is configured -- even a cookieless render of a public target would expose the operator egress. Render REFUSED (fail-closed). Configure ghost.mode + ghost.chain, or keep the ride (drop --no-ride).' };
      }
      return { ok: true, proxy: null, transport: 'direct (cookieless --no-ride render; ghost ' + mode + (mode === 'on' ? ' is best-effort with no chain configured' : ', no chain') + ' -- operator egress, honestly labeled)' };
    }
    if (ghost.chain.length > 1) {
      return { ok: false, reason: 'the armed ghost chain has ' + ghost.chain.length + ' hops but a browser rides exactly ONE proxy hop (Chrome accepts a single --proxy-server) -- render REFUSED (fail-closed): configure a single-hop chain' };
    }
    if (mode === 'required' && !ghost.verifiedOk()) {
      try { await ghost.verify(); } catch { /* verify failure is handled below */ }
      if (!ghost.verifiedOk()) {
        return { ok: false, reason: 'ghost mode is required but the chain exit is NOT verified (exit != operator IP unproven) -- public egress REFUSED (fail-closed). Run the ghost self-check first.' };
      }
    }
    const hop = ghost.chain[0];
    return { ok: true, proxy: hop.scheme + '://' + hop.host + ':' + hop.port, transport: 'ghost chain (1 hop, cookieless --no-ride render)' };
  } catch (e) {
    return { ok: false, reason: 'no-ride transport resolution failed (' + msg(e) + ') -- refusing (fail-closed)' };
  }
}

// ---------------------------------------------------------------------------
// renderCheck(url, opts) -> the governed visual confirmation. NEVER throws -- every
// refusal/failure is data. opts:
//   expect, deny                      assertion specs (text, or re:<pattern>)
//   out                               screenshot path (default data/evidence/rendercheck-<ts>-<rand>.png)
//   scope (REQUIRED), resolve         signed engagement scope + injectable resolver
//   ride !== false                    ride the vault clearance (default); false = --no-ride cookieless
//   jarPath | jar                     optional session jar (the sessride sess_jar.json shape)
//   egressId, ghost, ghostMode,       the cfride/sessride seams (defaults read the same
//     engagement, vaultPath           Settings via ghostRideState)
//   clearanceLookup                   vault seam (tests)
//   timeoutMs, settleMs               render budget / readable-document wait
//   sidecarRun, env, exists,          sidecar + Chrome detection seams (the broker's)
//     spawnSync, chromePath
//   rand, now                         determinism seams (tests)
// ---------------------------------------------------------------------------
export async function renderCheck(url, {
  expect, deny, out, scope, resolve, engagement, egressId: egressOpt,
  ghost, ghostMode, vaultPath, ride = true, jarPath, jar: jarInline,
  clearanceLookup, timeoutMs = DEFAULT_TIMEOUT_MS, settleMs = DEFAULT_SETTLE_MS,
  sidecarRun, env, exists, spawnSync: injectedSpawnSync, chromePath,
  rand, now = () => Date.now(),
} = {}) {
  // The throwaway browser profile (and the cookie file inside it) ALWAYS dies here.
  let profileDir = null;
  try {
    let u;
    try {
      u = new URL(String(url || ''));
      if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('scheme');
    } catch { return { ok: false, verdict: 'REFUSED', reason: 'usage: url must be an absolute http(s) URL, got ' + JSON.stringify(url) }; }

    // -- assertions parse up front: a bad regex is a usage refusal BEFORE any request --
    const expA = expect != null ? parseAssertion(expect) : null;
    if (expA && expA.error) return { ok: false, verdict: 'REFUSED', reason: expA.error };
    const denyA = deny != null ? parseAssertion(deny) : null;
    if (denyA && denyA.error) return { ok: false, verdict: 'REFUSED', reason: denyA.error };

    // -- the session jar (optional). --no-ride forces cookieless: a jar contradicts it --
    let jarPairs = [];
    let jarNote = null;
    if (ride === false && (jarPath || Array.isArray(jarInline))) {
      return { ok: false, verdict: 'REFUSED', reason: '--no-ride forces a COOKIELESS render but a session jar was supplied -- contradictory. Drop --no-ride to ride the jar, or drop the jar for the anonymous-visitor view.' };
    }
    if (ride !== false) {
      if (Array.isArray(jarInline)) {
        jarPairs = jarInline.map((p) => [String(p[0]), String(p[1])]);
      } else if (jarPath) {
        const j = readJar(jarPath); // the sessride jar contract -- same shape, same honesty
        if (!j.ok) return { ok: false, verdict: 'REFUSED', reason: j.error };
        jarPairs = j.entries;
        jarNote = j.note || null;
      }
    }

    // -- governance gate 1: signed scope (BEFORE any request; refusal prints the CIDRs) --
    const scopeRes = await scopeCheck(u, scope, resolve || defaultResolve);
    if (!scopeRes.ok) return { ok: false, verdict: 'REFUSED', reason: scopeRes.reason, scope: scopeRes.scope || [], resolved: scopeRes.resolved };

    // -- governance gate 2: the ride + egress parity (the cfride/sessride wiring) --
    const st = ghost ? { ghost, ghostMode: ghostMode || ghost.mode } : ghostRideState(engagement);
    let egressId = 'direct';
    if (egressOpt) egressId = String(egressOpt);
    else if (st.ghostMode !== 'off' && st.ghost && st.ghost.chain && st.ghost.chain.length) {
      try { egressId = chainEgressId(st.ghost.chain); } catch { egressId = 'direct'; }
    }
    let clearance = null;
    let proxy = null;
    let transport;
    if (ride !== false) {
      const lookup = clearanceLookup || clearanceFor;
      clearance = await lookup(u.href, { egressId, ...(vaultPath ? { vaultPath } : {}) }).catch(() => null);
      if (!clearance) return { ok: false, verdict: 'REFUSED', reason: 'no valid clearance in the vault for this zone -- mint (clearance mint) or provide operator clearance first (or --no-ride for the anonymous-visitor view)', scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
      const t = await resolveRideTransport({ ghost: st.ghost, ghostMode: st.ghostMode, egressId, hostname: u.hostname });
      if (!t.ok) return { ok: false, verdict: 'REFUSED', reason: t.reason, scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
      if (t.multiHop) {
        return { ok: false, verdict: 'REFUSED', reason: 'the vaulted clearance is bound to a multi-hop ghost chain (egressId "' + egressId + '") but a browser rides exactly ONE proxy hop -- launching through only the first hop would bind the render to the WRONG exit IP. REFUSED (fail-closed): configure a single-hop chain, or re-mint with --direct-egress.' };
      }
      proxy = t.proxy;
      transport = t.transport;
    } else {
      const t = await noRideTransport({ ghost: st.ghost, ghostMode: st.ghostMode, hostname: u.hostname });
      if (!t.ok) return { ok: false, verdict: 'REFUSED', reason: t.reason, scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
      proxy = t.proxy;
      transport = t.transport;
    }

    // -- the sidecar + a REAL Chrome binary: honest UNSUPPORTED when absent --
    const ndOpts = (env !== undefined || exists !== undefined || injectedSpawnSync !== undefined) ? { env, exists, spawnSync: injectedSpawnSync } : undefined;
    const nd = detectNodriver(ndOpts);
    if (!nd.available) {
      return { ok: false, verdict: 'UNSUPPORTED', supported: false, reason: 'rendercheck needs the nodriver raw-CDP sidecar and it is unavailable: ' + (nd.reason || 'probe failed'), scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
    }
    const chrome = (env !== undefined || exists !== undefined) ? resolveChrome({ chromePath, env, exists }) : resolveChrome({ chromePath });
    if (!chrome) {
      return { ok: false, verdict: 'UNSUPPORTED', supported: false, reason: 'no REAL Chrome/Edge binary found (checked opts.chromePath, env CHROME_PATH, both well-known Chrome paths, both well-known Edge paths) -- a render as a real visitor needs a real browser, not a bundled Chromium; install Chrome or pass chromePath', scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
    }

    // -- the render URL: unique cache-buster, always (the core lesson) --
    const token = rand ? String(rand) : crypto.randomBytes(6).toString('hex');
    const renderUrl = cacheBust(u.href, token);

    // -- the session, seeded: jar base + clearance overlay (values go to a temp FILE) --
    const seeded = sidecarCookies({
      jarPairs,
      clearanceCookies: clearance ? (clearance.cookies || []) : [],
      zoneHost: u.hostname,
    });

    // -- the screenshot: the operator's --out, else the evidence dir. Path only, ever. --
    const ts = new Date(now()).toISOString().replace(/[:.]/g, '-');
    const shotPath = out ? path.resolve(String(out)) : path.join(EVIDENCE_DIR, 'rendercheck-' + ts + '-' + token + '.png');
    try { fs.mkdirSync(path.dirname(shotPath), { recursive: true }); } catch {}

    // -- the THROWAWAY profile: nothing carries between runs; a render can never
    //    deadlock on the profile lock of a live mint/cfbrowser window --
    profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'varvel-rendercheck-'));
    let cookieFile = null;
    if (seeded.cookies.length) {
      cookieFile = path.join(profileDir, 'cookies.json');
      fs.writeFileSync(cookieFile, JSON.stringify(seeded.cookies));
    }

    const secs = Math.max(5, Math.ceil(timeoutMs / 1000));
    const args = [NDMINT_PY, renderUrl, '--chrome', chrome.p, '--profile', profileDir, '--timeout-s', String(secs), '--render', '--settle-s', String(Math.max(1, Math.ceil(settleMs / 1000))), '--shot-out', shotPath];
    if (proxy) args.push('--proxy', proxy); // the ghost chain rides at LAUNCH, before any window opens
    if (cookieFile) args.push('--cookies', cookieFile); // live credentials ride a FILE, never argv

    const run = sidecarRun || defaultSidecarRun;
    const res = await run(nd.pythonPath, args, { timeoutMs: timeoutMs + SIDECAR_GRACE_MS }).catch((e) => ({ ok: false, error: msg(e), stdout: '', stderr: '' }));
    const stderrTail = String((res && res.stderr) || '').trim().split(/\r?\n/).filter(Boolean).slice(-3).join(' | ').slice(0, 300);
    if (!res || res.ok !== true) {
      return { ok: false, verdict: 'RENDER-FAILED', reason: 'nodriver render sidecar did not complete (' + ((res && (res.error || ('exit ' + res.status))) || 'spawn failed') + (stderrTail ? '; stderr tail: ' + stderrTail : '') + ') -- honestly reported, nothing claimed', scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
    }
    const parsed = parseSidecarJson(res.stdout);
    if (!parsed.ok) {
      return { ok: false, verdict: 'RENDER-FAILED', reason: 'nodriver render sidecar produced no parseable JSON verdict on stdout (exit ' + res.status + (stderrTail ? '; stderr tail: ' + stderrTail : '') + ') -- honestly reported, nothing claimed', scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
    }
    const facts = parsed.facts;
    if (facts.ok !== true) {
      return { ok: false, verdict: 'RENDER-FAILED', reason: 'nodriver render sidecar failed: ' + String(facts.reason || 'unknown sidecar error'), scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved } };
    }

    // -- the evidence block shared by every outcome below --
    const status = Number.isFinite(facts.status) ? facts.status : 0;
    const headers = (facts.headers && typeof facts.headers === 'object') ? facts.headers : {};
    const reportHeaders = { ...headers };
    if (reportHeaders['set-cookie'] || reportHeaders['Set-Cookie']) {
      const k = reportHeaders['set-cookie'] ? 'set-cookie' : 'Set-Cookie';
      reportHeaders[k] = String(reportHeaders[k]).split(/\n/).map((line) => String(line).split(';')[0].split('=')[0].trim() + '=<redacted -- live session credential; never in a report>');
    }
    const screenshot = facts.screenshot && typeof facts.screenshot === 'object'
      ? (facts.screenshot.error ? { error: String(facts.screenshot.error), path: shotPath } : { path: String(facts.screenshot.path || shotPath), bytes: facts.screenshot.bytes })
      : null;
    const cache = cacheRead(headers);
    const base = {
      tool: 'rendercheck',
      url: u.href,
      renderUrl, // the cache-busted URL actually rendered -- reported, never hidden
      finalUrl: String(facts.finalUrl || ''),
      title: String(facts.title || ''),
      status,
      headers: reportHeaders,
      cache,
      screenshot, // path + byte size ONLY -- image bytes never ride a report
      truncated: facts.truncated || { wire: false, dom: false, text: false },
      settle: facts.settle || null,
      documentResponses: Array.isArray(facts.documentResponses) ? facts.documentResponses : [],
      cookies: ride !== false
        ? { seeded: seeded.names, fromJar: seeded.fromJar, fromClearance: seeded.fromClearance, note: 'names only -- cookie VALUES are live credentials and never appear in a report' }
        : { seeded: [], note: '--no-ride: COOKIELESS render (the anonymous-visitor view); the vault was never read' },
      ride: ride !== false
        ? { egressId, engine: clearance.engine || 'operator-provided', expiresAt: clearance.expiresAt, transport }
        : null,
      transport,
      scope: { cidrs: scopeRes.scope, resolved: scopeRes.resolved },
      sidecar: { python: nd.pythonPath, nodriver: nd.version || 'unknown', mode: 'render (headless one-shot)' },
      at: new Date(now()).toISOString(),
    };
    if (jarNote) base.jarNote = jarNote;

    // -- the browser-tier redirect honesty: a real browser follows redirects ITSELF.
    //    The FINAL landed host is re-checked against the signed scope AFTER the fact
    //    and reported loudly (per-hop gating is not enforceable on a real browser --
    //    the deliberate deviation from sessride, documented in the header). --
    if (base.finalUrl && base.finalUrl !== renderUrl) {
      let finalHost = null;
      try { finalHost = new URL(base.finalUrl).hostname; } catch {}
      const hops = base.documentResponses.slice(0, -1).map((d) => d.status + ' ' + d.url);
      base.redirect = { finalUrl: base.finalUrl, hops, crossHost: !!(finalHost && finalHost !== u.hostname) };
      if (base.redirect.crossHost) {
        const g = await scopeCheck(new URL(base.finalUrl), scopeRes.scope, resolve || defaultResolve);
        base.redirect.finalHostInScope = g.ok;
        base.redirect.note = 'the browser followed a CROSS-HOST redirect (' + u.hostname + ' -> ' + finalHost + ') -- a real browser does this; per-hop gating is sessride\'s cheap-HTTP doctrine and is not enforceable on a real browser. The ridden cookies were domain-scoped to ' + u.hostname + ' (CDP cookie scoping) and never rode to the new host. The final host is reported, not hidden' + (g.ok ? '; it IS inside the signed scope.' : '; it resolves OUTSIDE the signed scope -- ' + g.reason);
      }
    }

    // -- HONESTY GATE: a challenge-dominated render is CHALLENGED with evidence --
    const detection = detectChallenge({ status, headers, body: String(facts.domHtml || facts.wireHtml || '') });
    base.detection = detection;
    if (detection.present) {
      return {
        ...base,
        ok: false,
        verdict: 'CHALLENGED',
        reason: 'the render was CHALLENGED (detection: ' + detection.kind + ') -- expired/drifted clearance (IP+UA bound), or a headless render is simply weaker against the bot gate. Re-mint or refresh the operator session. NOTHING about this page can be claimed as the change under test; the screenshot is the challenge page itself, kept as evidence.',
      };
    }
    if (!status && !facts.domHtml) {
      return {
        ...base,
        ok: false,
        verdict: 'RENDER-FAILED',
        reason: 'the sidecar ran but produced no Document response and no DOM (settle: ' + ((facts.settle && facts.settle.lastKind) || 'unknown') + ') -- the page never rendered; nothing can be claimed',
      };
    }

    // -- the assertions: rendered DOM text + rendered DOM HTML + raw wire HTML --
    const assertions = runAssertions({
      expect: expA, deny: denyA,
      surfaces: { domText: facts.visibleText, domHtml: facts.domHtml, wireHtml: facts.wireHtml },
    });
    base.assertions = assertions;
    const expectGiven = !!expA;
    base.reading = composeReading(cache, { expectGiven, expectPass: expA ? assertions.checks.find((c) => c.which === 'expect').pass : null });

    if (!assertions.pass) {
      const failedExpect = assertions.checks.some((c) => c.which === 'expect' && !c.pass);
      return {
        ...base,
        ok: false,
        verdict: failedExpect ? 'EXPECT-FAILED' : 'DENY-HIT',
        reason: assertions.failures.join('; '),
      };
    }
    return { ...base, ok: true, verdict: 'CONFIRMED' };
  } catch (e) {
    return { ok: false, verdict: 'RENDER-FAILED', reason: 'rendercheck failed: ' + msg(e) };
  } finally {
    if (profileDir) { try { fs.rmSync(profileDir, { recursive: true, force: true }); } catch {} }
  }
}

// ---------------------------------------------------------------------------
// CLI surface (registered by the orchestrator in tools/cli.mjs):
//   rendercheck <url> [--expect <text|re:...>] [--deny <text|re:...>]
//               [--out <screenshot.png>] [--jar <file.json>] --scope <cidrCsv>
//               [--engagement <id>] [--egress-id <id>] [--no-ride]
// ---------------------------------------------------------------------------
export const RENDERCHECK_USAGE = "rendercheck <url> --scope <cidrCsv> [--expect <text|re:...>] [--deny <text|re:...>] [--out <screenshot.png>] [--jar <file.json>] [--engagement <id>] [--egress-id <id>] [--no-ride] -- VISUAL confirmation of a target-side change: renders the page in a REAL headless browser (nodriver raw-CDP sidecar) riding the vault clearance + ghost chain exactly like cfride/sessride. Cache-aware: cf-cache-status distinguishes 'live at origin' from 'visitors see a cached copy' -- a change behind a HIT is real-but-cloaked and the verdict says exactly that. A missing --expect is a FAIL, never a soft pass. Screenshot (PNG viewport) goes to --out (default data/evidence/); path only, never bytes";

export async function cli(args, deps = {}) {
  const a = Array.isArray(args) ? args.slice() : String(args || '').split(/\s+/).filter(Boolean);
  const flag = (name) => {
    const i = a.indexOf('--' + name);
    return i >= 0 && i + 1 < a.length ? a[i + 1] : null;
  };
  const opts = { ...deps };
  opts.expect = flag('expect') || undefined;
  opts.deny = flag('deny') || undefined;
  opts.out = flag('out') || undefined;
  opts.jarPath = flag('jar') || undefined;
  opts.scope = flag('scope') || undefined;
  opts.engagement = flag('engagement') || undefined;
  opts.egressId = flag('egress-id') || undefined;
  if (a.includes('--no-ride')) opts.ride = false;
  const url = flag('url') || a[0];
  return renderCheck(url, opts);
}
