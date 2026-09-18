// rendercheck.test.mjs -- hermetic pins for the visual-confirmation tool: NO real
// browser, NO network. The browser side is the mocked nodriver sidecar (the
// nodriver.test.mjs fakeSidecar pattern: an injected sidecarRun replies with scripted
// facts); the clearance side is an injected clearanceLookup; DNS is an injected
// resolve; ghost is an injected Ghost (off, or armed with a chain) so runs stay
// hermetic on any host. Covers: (a) the signed-scope gate BEFORE anything, (b) the
// ride/egress-parity gates (no clearance, multi-hop chain, chain proxy reaching the
// sidecar args, --no-ride cookieless), (c) the cache-aware verdict language (the four
// origin-live/cached-copy x expect-pass/fail cases -- the tool's core lesson), (d)
// assertions (expect/deny, text + re:, never a soft pass), (e) challenge honesty
// (CHALLENGED with evidence), (f) sidecar/Chrome UNSUPPORTED honesty, (g) the
// redirect block, (h) the pure pieces (parseAssertion/runAssertions/cacheRead/
// composeReading/cacheBust/sidecarCookies), (i) the CLI flag mapping.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Ghost, chainEgressId, parseChain } from '../engine/ghost.mjs';
import {
  renderCheck,
  scopeCheck,
  parseAssertion,
  runAssertions,
  cacheRead,
  composeReading,
  cacheBust,
  sidecarCookies,
  cli,
} from '../tools/rendercheck.mjs';

const THIS_FILE = fileURLToPath(import.meta.url); // an existing file: stands in for chrome.exe at resolution time
const FAKE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const URL1 = 'https://zone-one.example/changed-page';
const SCOPE = '127.0.0.0/8';
const GHOST_CHAIN = 'socks5://10.64.0.1:1080';

const MARKER = 'varvel-rc-9f2c71aa';
const CLEAN_DOM = '<html><head><title>Zone One</title></head><body><main><h1>Zone One</h1><p>'
  + 'served page, no challenge here '.repeat(8) + '</p><div id="change">' + MARKER + '</div></main></body></html>';
const CLEAN_TEXT = 'Zone One served page, no challenge here ' + MARKER;
const CF_CHALLENGE_BODY = '<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>';

const CLEARANCE = {
  cookies: [{ name: 'cf_clearance', value: 'VAULT-FRESH-SECRET', domain: 'zone-one.example', path: '/', expires: -1 }],
  ua: FAKE_UA,
  expiresAt: '2027-01-01T00:00:00Z',
  engine: 'nodriver (raw-CDP sidecar)',
};

// --- detection seams (the nodriver.test.mjs pattern) ------------------------------
const existsOk = (p) => String(p) === THIS_FILE || /\.venv[\\/]Scripts[\\/]python/.test(String(p));
const existsNoVenv = (p) => String(p) === THIS_FILE; // chrome "exists", the venv does not
const spawnOk = () => ({ status: 0, stdout: '0.50.3\n', stderr: '' });

// A scripted sidecarRun seam: records (pythonPath, args, opts), reads the --cookies
// file if one was passed (it exists for the duration of the call), replies with
// `reply` (object -> JSON stringified, or a function of the recorded call).
function fakeSidecar(reply) {
  const state = { calls: [] };
  const run = async (pythonPath, args, opts) => {
    const call = { pythonPath, args, opts, cookies: null };
    const ci = args.indexOf('--cookies');
    if (ci >= 0) {
      try { call.cookies = JSON.parse(fs.readFileSync(args[ci + 1], 'utf8')); } catch (e) { call.cookies = 'UNREADABLE: ' + e.message; }
    }
    state.calls.push(call);
    const r = typeof reply === 'function' ? reply(call) : reply;
    return { ok: true, status: 0, stdout: typeof r === 'string' ? r : JSON.stringify(r), stderr: '' };
  };
  return { state, run };
}

const renderFacts = (over = {}) => ({
  ok: true,
  engine: 'nodriver',
  mode: 'render',
  requestedUrl: 'https://zone-one.example/changed-page?__varvel_rc=deadbeefcafe',
  finalUrl: 'https://zone-one.example/changed-page?__varvel_rc=deadbeefcafe',
  title: 'Zone One',
  status: 200,
  headers: { server: 'cloudflare', 'cf-ray': '9-LHR', 'cf-cache-status': 'DYNAMIC' },
  documentResponses: [{ url: 'https://zone-one.example/changed-page?__varvel_rc=deadbeefcafe', status: 200 }],
  wireHtml: CLEAN_DOM,
  domHtml: CLEAN_DOM,
  visibleText: CLEAN_TEXT,
  truncated: { wire: false, dom: false, text: false },
  settle: { readable: true, lastKind: 'readable' },
  cookiesSeeded: 1,
  screenshot: { path: 'C:/evidence/shot.png', bytes: 4096 },
  ...over,
});

// Wire a fully-injected renderCheck call. ghost OFF keeps every run hermetic (the
// default ghost state reads the real Settings store); scope DNS is injected.
function injected(opts = {}) {
  const sidecar = fakeSidecar(opts.facts !== undefined ? opts.facts : renderFacts());
  const lookups = [];
  const run = renderCheck(opts.url || URL1, {
    scope: opts.scope === undefined ? SCOPE : opts.scope,
    resolve: opts.resolve || (async () => ['127.0.0.1']),
    clearanceLookup: opts.clearanceLookup || (async (u, o) => { lookups.push({ u, o }); return CLEARANCE; }),
    ghost: opts.ghost || new Ghost(),
    chromePath: THIS_FILE,
    env: {}, exists: opts.exists || existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run,
    rand: 'deadbeefcafe',
    now: () => Date.parse('2026-08-11T12:00:00Z'),
    expect: opts.expect,
    deny: opts.deny,
    out: opts.out,
    jar: opts.jar,
    ride: opts.ride,
    egressId: opts.egressId,
    timeoutMs: 5000,
  });
  return { run, sidecar, lookups };
}

// --- (a) the signed-scope gate BEFORE anything -------------------------------------

test('scope gate: no --scope is a fail-closed refusal; the sidecar is never spawned', async () => {
  const sidecar = fakeSidecar(renderFacts());
  const r = await renderCheck(URL1, {
    resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => CLEARANCE,
    ghost: new Ghost(),
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run,
  });
  assert.equal(r.ok, false);
  assert.equal(r.verdict, 'REFUSED');
  assert.match(r.reason, /no signed engagement scope/);
  assert.equal(sidecar.state.calls.length, 0);
});

test('scope gate: a host resolving OUTSIDE the signed CIDRs is refused, and the refusal prints the scope', async () => {
  const sidecar = fakeSidecar(renderFacts());
  const r = await renderCheck(URL1, {
    scope: SCOPE,
    resolve: async () => ['203.0.113.9'],
    clearanceLookup: async () => CLEARANCE,
    ghost: new Ghost(),
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /outside the signed engagement scope/);
  assert.match(r.reason, /127\.0\.0\.0\/8/); // the refusal prints the signed scope
  assert.equal(sidecar.state.calls.length, 0);
});

test('usage: a non-absolute URL and a bad regex are REFUSED before anything runs', async () => {
  const bad1 = await renderCheck('zone-one.example', { scope: SCOPE, resolve: async () => ['127.0.0.1'] });
  assert.equal(bad1.ok, false);
  assert.match(bad1.reason, /absolute http\(s\) URL/);
  const sidecar = fakeSidecar(renderFacts());
  const bad2 = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => CLEARANCE, ghost: new Ghost(),
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run, expect: 're:([',
  });
  assert.equal(bad2.ok, false);
  assert.match(bad2.reason, /invalid regex/);
  assert.equal(sidecar.state.calls.length, 0);
});

test('--no-ride with a session jar is a contradiction refusal, never a silent pick', async () => {
  const r = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    ghost: new Ghost(), ride: false, jar: [['wordpress_logged_in_x', 'u|t']],
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: async () => { throw new Error('must never spawn'); },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /COOKIELESS.*contradictory/i);
});

// --- (b) the ride + egress-parity gates ---------------------------------------------

test('no valid clearance: honest refusal, the browser is never launched', async () => {
  const sidecar = fakeSidecar(renderFacts());
  const r = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => null,
    ghost: new Ghost(),
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no valid clearance/);
  assert.equal(sidecar.state.calls.length, 0);
});

test('multi-hop chain-keyed clearance: refused fail-closed BEFORE the sidecar is spawned', async () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: 'socks5://10.64.0.1:1080,http://proxy.example:8080' });
  const sidecar = fakeSidecar(renderFacts());
  const r = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => CLEARANCE,
    ghost, // egressId defaults to the armed multi-hop chain's canonical id
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /multi-hop ghost chain/);
  assert.equal(sidecar.state.calls.length, 0);
});

test('chain-keyed ride: the ghost chain reaches the sidecar as --proxy and the lookup uses the canonical egress id', async () => {
  const ghost = new Ghost();
  ghost.configure({ mode: 'on', chain: GHOST_CHAIN });
  const { run, sidecar, lookups } = injected({ ghost });
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(lookups.length, 1);
  assert.equal(lookups[0].o.egressId, chainEgressId(parseChain(GHOST_CHAIN)));
  const call = sidecar.state.calls[0];
  const pi = call.args.indexOf('--proxy');
  assert.ok(pi >= 0, 'the sidecar args must carry --proxy');
  assert.equal(call.args[pi + 1], GHOST_CHAIN); // Chrome --proxy-server, applied at launch
  assert.match(r.transport, /ghost chain/);
});

test('--no-ride: cookieless render, the vault is NEVER consulted, no --cookies file is passed', async () => {
  const sidecar = fakeSidecar(renderFacts({ cookiesSeeded: 0 }));
  const r = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => { throw new Error('the vault must never be read under --no-ride'); },
    ghost: new Ghost(), ride: false,
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run,
    rand: 'deadbeefcafe', now: () => Date.parse('2026-08-11T12:00:00Z'),
  });
  assert.equal(r.ok, true);
  assert.equal(r.ride, null);
  assert.match(r.cookies.note, /COOKIELESS/);
  assert.equal(sidecar.state.calls[0].args.includes('--cookies'), false);
});

test('--no-ride under ghost required + no chain: fail-closed refusal', async () => {
  const ghost = new Ghost(); // off object, but the raw mode is forced required
  const r = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    ghost, ghostMode: 'required', ride: false,
    clearanceLookup: async () => null,
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: async () => { throw new Error('must never spawn'); },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /ghost mode is REQUIRED/);
});

// --- the happy path: render args, cache-buster, cookie seeding, credential hygiene ---

test('happy path: --render + cache-busted URL + seeded cookies reach the sidecar; values never in the report', async () => {
  const { run, sidecar } = injected({
    expect: MARKER,
    jar: [['wordpress_logged_in_abc', 'JAR-SESSION-SECRET'], ['cf_clearance', 'STALE-JAR-COPY']],
    out: 'C:/evidence/shot.png',
  });
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(r.verdict, 'CONFIRMED');
  const call = sidecar.state.calls[0];
  // the sidecar contract: one-shot render mode, headless, args array (never a shell string)
  assert.ok(Array.isArray(call.args));
  assert.match(call.args[0], /ndmint\.py$/);
  assert.ok(call.args.includes('--render'));
  assert.ok(call.args.includes('https://zone-one.example/changed-page?__varvel_rc=deadbeefcafe')); // the cache-buster rides
  assert.equal(call.args.includes('--proxy'), false); // ghost off => direct ride
  const si = call.args.indexOf('--shot-out');
  assert.equal(call.args[si + 1], 'C:\\evidence\\shot.png'); // --out wins, resolved
  // the seeded session: jar base, vault clearance OVERLAYS the stale jar copy (sessride merge order)
  assert.deepEqual(call.cookies.map((c) => c.name), ['wordpress_logged_in_abc', 'cf_clearance']);
  assert.equal(call.cookies[1].value, 'VAULT-FRESH-SECRET');
  assert.equal(call.cookies[0].domain, '.zone-one.example'); // dot-prefixed zone (cfbrowser doctrine)
  assert.equal(call.cookies[1].expires, undefined); // session-cookie expires:-1 dropped
  // credential hygiene: names only in the report, VALUES never
  assert.deepEqual(r.cookies.seeded, ['wordpress_logged_in_abc', 'cf_clearance']);
  assert.deepEqual(r.cookies.fromJar, ['wordpress_logged_in_abc', 'cf_clearance']);
  assert.deepEqual(r.cookies.fromClearance, ['cf_clearance']);
  const serialized = JSON.stringify(r);
  assert.ok(!serialized.includes('VAULT-FRESH-SECRET'));
  assert.ok(!serialized.includes('JAR-SESSION-SECRET'));
  assert.ok(!serialized.includes('STALE-JAR-COPY'));
  // the screenshot is path + size ONLY -- never bytes
  assert.deepEqual(r.screenshot, { path: 'C:/evidence/shot.png', bytes: 4096 });
  assert.ok(!/base64/i.test(serialized));
  // ride + cache + scope metadata ride the report
  assert.equal(r.ride.egressId, 'direct');
  assert.equal(r.cache.classification, 'origin-live');
  assert.deepEqual(r.scope.cidrs, [SCOPE]);
  assert.equal(r.detection.present, false);
});

// --- (c) the cache-aware verdict language (the core lesson) -------------------------

test('expect passes + DYNAMIC: CONFIRMED LIVE AT ORIGIN', async () => {
  const { run } = injected({ expect: MARKER });
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(r.verdict, 'CONFIRMED');
  assert.match(r.reading, /CONFIRMED LIVE AT ORIGIN/);
});

test('expect passes + HIT: CONFIRMED VISIBLE TO VISITORS (the cached copy carries it)', async () => {
  const { run } = injected({ expect: MARKER, facts: renderFacts({ headers: { server: 'cloudflare', 'cf-cache-status': 'HIT', age: '300' } }) });
  const r = await run;
  assert.equal(r.ok, true);
  assert.match(r.reading, /CONFIRMED VISIBLE TO VISITORS/);
  assert.match(r.reading, /age 300s/);
});

test('expect ABSENT + HIT: FAIL with the real-but-cloaked language -- visitors see the stale page', async () => {
  const { run } = injected({
    expect: 'varvel-rc-NOT-ON-THE-PAGE',
    facts: renderFacts({ headers: { server: 'cloudflare', 'cf-cache-status': 'HIT', age: '812' } }),
  });
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.verdict, 'EXPECT-FAILED');
  assert.equal(r.cache.classification, 'cached-copy');
  assert.equal(r.cache.ageSeconds, 812);
  assert.match(r.reading, /REAL-BUT-CLOAKED/);
  assert.match(r.reading, /what VISITORS see \(the stale page\)/);
  assert.match(r.reading, /purge the cache or await expiry/);
});

test('expect ABSENT + DYNAMIC: FAIL with NOT LIVE AT ORIGIN -- refutes the cached-browser alibi', async () => {
  const { run } = injected({ expect: 'varvel-rc-NOT-ON-THE-PAGE' });
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.verdict, 'EXPECT-FAILED');
  assert.match(r.reading, /NOT LIVE AT ORIGIN/);
  assert.match(r.reading, /REFUTES the "your browser is just showing a cached page" explanation/);
});

test('no cf-cache-status: the cache state is reported UNOBSERVABLE, never assumed', async () => {
  const { run } = injected({ expect: MARKER, facts: renderFacts({ headers: { server: 'nginx' } }) });
  const r = await run;
  assert.equal(r.ok, true);
  assert.equal(r.cache.observed, false);
  assert.equal(r.cache.classification, 'unknown');
  assert.match(r.reading, /UNOBSERVABLE/);
});

// --- (d) assertions -----------------------------------------------------------------

test('assertions run against ALL THREE surfaces: an expect found only in the wire HTML still passes, and says where', async () => {
  const wireOnly = '<html><body><script>var v = "varvel-rc-wire-only";</script>' + 'padding '.repeat(20) + '</body></html>';
  const { run } = injected({
    expect: 'varvel-rc-wire-only',
    facts: renderFacts({ wireHtml: wireOnly, domHtml: CLEAN_DOM.replace(MARKER, ''), visibleText: 'no marker in the text' }),
  });
  const r = await run;
  assert.equal(r.ok, true);
  assert.deepEqual(r.assertions.checks[0].matchedSurfaces, ['wireHtml']);
});

test('a deny hit is a FAIL (DENY-HIT) naming the surfaces; a regex deny works', async () => {
  const { run } = injected({ deny: 're:varvel-rc-[0-9a-f]+' });
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.verdict, 'DENY-HIT');
  assert.match(r.reason, /IS PRESENT/);
  assert.ok(r.assertions.checks[0].matchedSurfaces.length > 0);
});

test('regex expect matches; no assertions at all renders with the proves-nothing note', async () => {
  const { run: r1 } = injected({ expect: 're:varvel-rc-[0-9a-f]{8}' });
  assert.equal((await r1).ok, true);
  const { run: r2 } = injected();
  const plain = await r2;
  assert.equal(plain.ok, true);
  assert.match(plain.reading, /proves NOTHING about a change/);
});

// --- (e) challenge honesty ------------------------------------------------------------

test('a challenge-dominated render is ok:false CHALLENGED with evidence -- the screenshot still rides as evidence', async () => {
  const { run } = injected({
    expect: MARKER,
    facts: renderFacts({
      status: 403,
      headers: { server: 'cloudflare', 'cf-mitigated': 'challenge', 'cf-ray': '9-LHR' },
      domHtml: CF_CHALLENGE_BODY,
      wireHtml: CF_CHALLENGE_BODY,
      visibleText: 'Just a moment...',
    }),
  });
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.verdict, 'CHALLENGED');
  assert.match(r.reason, /CHALLENGED/);
  assert.equal(r.detection.kind, 'managed-js');
  assert.deepEqual(r.screenshot, { path: 'C:/evidence/shot.png', bytes: 4096 }); // evidence, never a claim
});

// --- (f) sidecar / Chrome UNSUPPORTED honesty ------------------------------------------

test('no sidecar venv: honest UNSUPPORTED, never a silent fallback', async () => {
  const { run } = injected({ exists: existsNoVenv });
  const r = await run;
  assert.equal(r.ok, false);
  assert.equal(r.verdict, 'UNSUPPORTED');
  assert.equal(r.supported, false);
  assert.match(r.reason, /nodriver raw-CDP sidecar.*unavailable/);
});

test('no real Chrome: honest UNSUPPORTED', async () => {
  const venvOnly = (p) => /\.venv[\\/]Scripts[\\/]python/.test(String(p)); // the sidecar exists; no browser binary does
  const r = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => CLEARANCE, ghost: new Ghost(),
    chromePath: 'C:/no/such/chrome-' + process.pid + '.exe',
    env: {}, exists: venvOnly, spawnSync: spawnOk,
    sidecarRun: async () => { throw new Error('must never spawn'); },
  });
  assert.equal(r.ok, false);
  assert.equal(r.verdict, 'UNSUPPORTED');
  assert.match(r.reason, /no REAL Chrome\/Edge binary found/);
});

test('garbage sidecar stdout and sidecar-internal failures are honest RENDER-FAILEDs', async () => {
  const garbage = fakeSidecar('all noise, no verdict\n');
  const r1 = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => CLEARANCE, ghost: new Ghost(),
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: garbage.run,
  });
  assert.equal(r1.ok, false);
  assert.equal(r1.verdict, 'RENDER-FAILED');
  assert.match(r1.reason, /no parseable JSON/);
  const crashed = fakeSidecar({ ok: false, engine: 'nodriver', reason: 'sidecar crashed: TimeoutError: boom' });
  const r2 = await renderCheck(URL1, {
    scope: SCOPE, resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => CLEARANCE, ghost: new Ghost(),
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: crashed.run,
  });
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /sidecar crashed: TimeoutError: boom/);
});

// --- (g) the redirect block (browser-tier honesty) -------------------------------------

test('a cross-host final landing is reported with a post-hoc scope re-check (never hidden)', async () => {
  const crossHost = renderFacts({
    finalUrl: 'https://cdn-other.example/changed-page?__varvel_rc=deadbeefcafe',
    documentResponses: [
      { url: 'https://zone-one.example/changed-page?__varvel_rc=deadbeefcafe', status: 302 },
      { url: 'https://cdn-other.example/changed-page?__varvel_rc=deadbeefcafe', status: 200 },
    ],
  });
  const inScope = await injected({ facts: crossHost, expect: MARKER }).run;
  assert.equal(inScope.ok, true);
  assert.equal(inScope.redirect.crossHost, true);
  assert.equal(inScope.redirect.finalHostInScope, true); // the mock resolver lands it in 127/8
  assert.match(inScope.redirect.note, /CROSS-HOST redirect/);
  assert.match(inScope.redirect.note, /domain-scoped/); // the credential-leak guard, stated
  const outScope = await injected({
    facts: crossHost, expect: MARKER,
    resolve: async (host) => (host === 'cdn-other.example' ? ['203.0.113.9'] : ['127.0.0.1']),
  }).run;
  assert.equal(outScope.redirect.finalHostInScope, false);
  assert.match(outScope.redirect.note, /OUTSIDE the signed scope/);
});

// --- (h) the pure pieces ----------------------------------------------------------------

test('parseAssertion: text vs re:, empty and bad-regex errors', () => {
  assert.deepEqual(parseAssertion('hello'), { kind: 'text', text: 'hello', label: '"hello"' });
  const re = parseAssertion('re:a+b');
  assert.equal(re.kind, 'regex');
  assert.ok(re.re.test('caab'));
  assert.match(parseAssertion('re:([').error, /invalid regex/);
  assert.match(parseAssertion('').error, /empty assertion/);
});

test('runAssertions: expect per-surface pass/fail; deny; a missing expect is a FAIL', () => {
  const surfaces = { domText: 'alpha', domHtml: '<p>beta</p>', wireHtml: 'gamma' };
  const pass = runAssertions({ expect: parseAssertion('beta'), surfaces });
  assert.equal(pass.pass, true);
  assert.deepEqual(pass.checks[0].matchedSurfaces, ['domHtml']);
  const miss = runAssertions({ expect: parseAssertion('delta'), surfaces });
  assert.equal(miss.pass, false);
  assert.match(miss.failures[0], /NOT FOUND/);
  assert.match(miss.failures[0], /never a soft pass/);
  const denyOk = runAssertions({ deny: parseAssertion('delta'), surfaces });
  assert.equal(denyOk.pass, true);
  const denyHit = runAssertions({ deny: parseAssertion('alpha'), surfaces });
  assert.equal(denyHit.pass, false);
  assert.match(denyHit.failures[0], /domText/);
});

test('cacheRead: the HIT/MISS/DYNAMIC/none/unknown-token classification + the buster-ignored language', () => {
  const hit = cacheRead({ 'CF-Cache-Status': 'hit', Age: '42', 'cf-ray': 'x' }); // header case-insensitive
  assert.equal(hit.classification, 'cached-copy');
  assert.equal(hit.ageSeconds, 42);
  assert.match(hit.note, /cache key IGNORES query strings/);
  assert.equal(cacheRead({ 'cf-cache-status': 'DYNAMIC' }).classification, 'origin-live');
  const miss = cacheRead({ 'cf-cache-status': 'MISS' });
  assert.equal(miss.classification, 'origin-live');
  assert.match(miss.note, /NEXT visitor/); // the honest MISS caveat
  assert.equal(cacheRead({ 'cf-cache-status': 'BYPASS' }).classification, 'origin-live');
  assert.equal(cacheRead({ 'cf-cache-status': 'STALE' }).classification, 'cached-copy');
  const none = cacheRead({});
  assert.equal(none.observed, false);
  assert.match(none.note, /never assumed/);
  const weird = cacheRead({ 'cf-cache-status': 'FROBNICATED' });
  assert.equal(weird.classification, 'unknown');
  assert.match(weird.note, /FROBNICATED/); // reported verbatim
});

test('composeReading: the four live cases never blur', () => {
  const cached = { classification: 'cached-copy', status: 'HIT', ageSeconds: 10, note: 'N' };
  const fresh = { classification: 'origin-live', status: 'DYNAMIC', ageSeconds: null, note: 'N' };
  assert.match(composeReading(cached, { expectGiven: true, expectPass: true }), /CONFIRMED VISIBLE TO VISITORS/);
  assert.match(composeReading(fresh, { expectGiven: true, expectPass: true }), /CONFIRMED LIVE AT ORIGIN/);
  assert.match(composeReading(cached, { expectGiven: true, expectPass: false }), /REAL-BUT-CLOAKED/);
  assert.match(composeReading(fresh, { expectGiven: true, expectPass: false }), /NOT LIVE AT ORIGIN/);
  assert.match(composeReading(cached, { expectGiven: false }), /proves NOTHING/);
});

test('cacheBust: a unique param is appended (query preserved); sidecarCookies: merge order + shaping', () => {
  assert.equal(cacheBust('https://z.example/p?a=1', 'tok'), 'https://z.example/p?a=1&__varvel_rc=tok');
  assert.equal(cacheBust('https://z.example/p', 'tok'), 'https://z.example/p?__varvel_rc=tok');
  const s = sidecarCookies({
    jarPairs: [['sess', 'jar-value'], ['cf_clearance', 'stale']],
    clearanceCookies: [{ name: 'cf_clearance', value: 'fresh', domain: 'zone-one.example', expires: -1 }],
    zoneHost: 'zone-one.example',
  });
  assert.deepEqual(s.names, ['sess', 'cf_clearance']);
  assert.equal(s.cookies[1].value, 'fresh'); // the vault overlays the stale jar copy
  assert.equal(s.cookies[0].domain, '.zone-one.example');
  assert.equal(s.cookies[1].expires, undefined);
  assert.deepEqual(s.fromJar, ['sess', 'cf_clearance']);
  assert.deepEqual(s.fromClearance, ['cf_clearance']);
});

test('scopeCheck (pure): literal IPs skip DNS; empty resolution refuses fail-closed', async () => {
  const ok = await scopeCheck(new URL('http://127.0.0.1:8080/x'), SCOPE, async () => { throw new Error('DNS must not run for a literal'); });
  assert.equal(ok.ok, true);
  const empty = await scopeCheck(new URL(URL1), SCOPE, async () => []);
  assert.equal(empty.ok, false);
  assert.match(empty.reason, /no addresses/);
});

// --- (i) the CLI flag mapping -----------------------------------------------------------

test('cli: flags map onto renderCheck opts (wafbypass cli pattern; deps are the seam)', async () => {
  const sidecar = fakeSidecar(renderFacts());
  const r = await cli([
    URL1, '--expect', MARKER, '--deny', 'never-present', '--out', 'C:/evidence/cli.png',
    '--scope', SCOPE, '--engagement', 'eng-1', '--no-ride',
  ], {
    resolve: async () => ['127.0.0.1'],
    clearanceLookup: async () => { throw new Error('--no-ride must not read the vault'); },
    ghost: new Ghost(),
    chromePath: THIS_FILE, env: {}, exists: existsOk, spawnSync: spawnOk,
    sidecarRun: sidecar.run,
    rand: 'deadbeefcafe',
    now: () => Date.parse('2026-08-11T12:00:00Z'),
  });
  assert.equal(r.ok, true);
  assert.equal(r.ride, null); // --no-ride mapped
  assert.equal(r.assertions.checks.length, 2); // expect + deny both mapped
  const call = sidecar.state.calls[0];
  assert.equal(call.args[call.args.indexOf('--shot-out') + 1], 'C:\\evidence\\cli.png');
});
