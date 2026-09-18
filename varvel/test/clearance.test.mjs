// clearance.test.mjs — hermetic pins for the clearance broker: NO real browser, NO
// network. Covers (a) vault key derivation + TTL pruning under an injected now(),
// (b) sticky-egress keying (same zone, different egressId => different entries),
// (c) launch-failure honesty via an injected rejecting launcher, and (d) the pure
// post-mint proof gate (challenge-present => minted:false; clean 200 => minted:true) —
// plus the full mint flow end to end through a scripted fake browser context.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { vaultKey, readVault, writeVault, clearanceFor, proofGate, mintClearance, resolveChrome, waitForResolution, resolveMintEgress, rideEgressId } from '../tools/clearance/broker.mjs';
import { chainEgressId } from '../engine/ghost.mjs';

const THIS_FILE = fileURLToPath(import.meta.url); // an existing file: stands in for chrome.exe at resolution time
const FAKE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const URL1 = 'https://zone-one.example/path';
const T0 = Date.parse('2026-08-05T12:00:00Z');

const CF_CHALLENGE = {
  status: 403,
  headers: { server: 'cloudflare', 'cf-mitigated': 'challenge', 'cf-ray': '97abc123-LHR' },
  body: '<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>',
};

function tmpVault() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'varvel-clearance-')), 'vault.json');
}

const entry = (val, expiresAt) => ({
  cookies: [{ name: 'cf_clearance', value: val, domain: 'zone-one.example', path: '/' }],
  ua: FAKE_UA,
  mintedAt: new Date(T0).toISOString(),
  expiresAt,
});

// A scripted BrowserContext stand-in: first goto "loads" the challenge, the second goto
// is the confirmation fetch of the zone root and returns `proof`.
function fakeContext({ dom, cookies, proof, resolveAfter }) {
  const state = { gotos: [], closed: false };
  let domProbes = 0;
  // resolveAfter models a REAL solve: the challenged DOM gives way to clean content
  // after N DOM probes (2026-08-10: resolution is page-state-decided; the cookie never
  // decides — cf_clearance can arrive a tick early while the challenge is still up).
  const cleanDom = '<html><title>Zone One</title><body>' + 'real content '.repeat(20) + '</body></html>';
  const page = {
    async evaluate(fn) {
      if (/navigator/.test(String(fn))) return FAKE_UA;
      domProbes += 1;
      return (resolveAfter != null && domProbes > resolveAfter) ? cleanDom : dom;
    },
    async goto(u) {
      state.gotos.push(u);
      return state.gotos.length === 1
        ? { status: () => 403, headers: () => ({}), text: async () => dom }
        : proof;
    },
  };
  return {
    state,
    pages: () => [page],
    newPage: async () => page,
    cookies: async () => cookies,
    close: async () => { state.closed = true; },
  };
}

test('vault key derivation: zone|egressId|sha256(ua)[:12], deterministic and UA-sensitive', () => {
  const digest = crypto.createHash('sha256').update(FAKE_UA).digest('hex').slice(0, 12);
  const k = vaultKey('zone-one.example', 'direct', FAKE_UA);
  assert.equal(k, 'zone-one.example|direct|' + digest);
  assert.equal(vaultKey('zone-one.example', 'direct', FAKE_UA), k);
  assert.notEqual(vaultKey('zone-one.example', 'direct', FAKE_UA + ' '), k);
});

test('TTL pruning: readVault drops expired (and malformed) entries under an injected now()', () => {
  const vaultPath = tmpVault();
  const live = entry('live-cookie', new Date(T0 + 45 * 60000).toISOString());
  const dead = entry('dead-cookie', new Date(T0 - 1000).toISOString());
  const w = writeVault({ 'a|direct|x': live, 'b|direct|y': dead, 'c|direct|z': { broken: true } }, { vaultPath });
  assert.equal(w.ok, true);
  assert.equal(w.count, 3);
  const v = readVault({ vaultPath, now: () => T0 });
  assert.equal(v.ok, true);
  assert.equal(v.pruned, 2);
  assert.deepEqual(Object.keys(v.entries), ['a|direct|x']);
  const vLater = readVault({ vaultPath, now: () => T0 + 46 * 60000 });
  assert.deepEqual(vLater.entries, {}); // past the 45min TTL, nothing survives
  const missing = readVault({ vaultPath: tmpVault(), now: () => T0 });
  assert.deepEqual(missing, { ok: true, entries: {}, pruned: 0 }); // no vault file = empty vault, not an error
});

test('sticky egress: same zone, different egressId => different entries; clearanceFor matches exactly', async () => {
  const vaultPath = tmpVault();
  writeVault({
    [vaultKey('zone-one.example', 'direct', FAKE_UA)]: entry('direct-cookie', new Date(T0 + 45 * 60000).toISOString()),
    [vaultKey('zone-one.example', 'exit-de-1', FAKE_UA)]: entry('de-cookie', new Date(T0 + 45 * 60000).toISOString()),
  }, { vaultPath });
  const at = () => T0 + 60000;
  const direct = await clearanceFor(URL1, { egressId: 'direct', ua: FAKE_UA, vaultPath, now: at });
  const de = await clearanceFor(URL1, { egressId: 'exit-de-1', ua: FAKE_UA, vaultPath, now: at });
  assert.equal(direct.cookies[0].value, 'direct-cookie');
  assert.equal(de.cookies[0].value, 'de-cookie');
  assert.equal(direct.ua, FAKE_UA);
  assert.equal(direct.expiresAt, new Date(T0 + 45 * 60000).toISOString());
  // unknown egress, wrong UA, expired entry, missing vault: all honestly null
  assert.equal(await clearanceFor(URL1, { egressId: 'exit-fr-9', ua: FAKE_UA, vaultPath, now: at }), null);
  assert.equal(await clearanceFor(URL1, { egressId: 'direct', ua: 'Some Other UA', vaultPath, now: at }), null);
  assert.equal(await clearanceFor(URL1, { egressId: 'direct', ua: FAKE_UA, vaultPath, now: () => T0 + 46 * 60000 }), null);
  assert.equal(await clearanceFor(URL1, { egressId: 'direct', ua: FAKE_UA, vaultPath: tmpVault(), now: at }), null);
  assert.equal(await clearanceFor('not-a-url', { egressId: 'direct', ua: FAKE_UA, vaultPath, now: at }), null);
});

test('mint honesty: a rejecting launcher resolves { minted:false }, never throws', async () => {
  const r = await mintClearance(URL1, {
    chromePath: THIS_FILE, // exists -> passes real-binary resolution
    launcher: async () => { throw new Error('spawn exploded'); },
    timeoutMs: 1000,
    vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.match(r.reason, /browser launch failed/);
  assert.match(r.reason, /spawn exploded/);
});

test('mint honesty: no real Chrome anywhere is an honest failure, not a crash', async () => {
  const r = await mintClearance(URL1, {
    chromePath: path.join(os.tmpdir(), 'no-such-chrome-' + process.pid + '.exe'),
    env: {}, // injected: CHROME_PATH unset
    exists: () => false, // injected: nothing on disk — deterministic on any host
    launcher: async () => { throw new Error('must never be called'); },
    vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.match(r.reason, /no REAL Chrome\/Edge binary found/);
  assert.deepEqual(resolveChrome({ env: {}, exists: () => false }), null);
  // Edge fallback: when Chrome is absent but Edge exists, Edge is selected WITH its
  // honest unverified-parity label attached (never silently treated as proven-equivalent).
  const edgeOnly = (p) => /msedge\.exe$/i.test(String(p));
  const edge = resolveChrome({ env: {}, exists: edgeOnly });
  assert.ok(edge && /Edge/.test(edge.via) && /UNVERIFIED/.test(edge.via));
});

test('proofGate: a challenge-present confirmation yields minted:false with the honest reason', () => {
  const g = proofGate(CF_CHALLENGE);
  assert.equal(g.minted, false);
  assert.equal(g.reason, 'cf_clearance minted but zone still challenges — unproven passage, honestly reported');
  assert.equal(g.detection.kind, 'managed-js');
});

test('proofGate: a clean 200 through CF yields minted:true', () => {
  const g = proofGate({ status: 200, headers: { server: 'cloudflare', 'cf-ray': '1-LHR' }, body: '<html>the real zone root</html>' });
  assert.equal(g.minted, true);
  assert.equal(g.detection.present, false);
});

test('full mint, proven: scripted context => minted:true, vault persisted under the sticky key, context closed', async () => {
  const vaultPath = tmpVault();
  const ctx = fakeContext({
    dom: '<title>Just a moment...</title>', // challenged first…
    resolveAfter: 1, // …then a REAL solve: the page goes clean (the cookie never decides — 2026-08-10)
    cookies: [{ name: 'cf_clearance', value: 'minted-value', domain: 'zone-one.example', path: '/' }],
    proof: { status: () => 200, headers: () => ({ server: 'cloudflare', 'cf-ray': '2-LHR' }), text: async () => '<html>the real zone root</html>' },
  });
  const r = await mintClearance(URL1, {
    chromePath: THIS_FILE,
    launcher: async () => ctx,
    egressId: 'test-egress',
    timeoutMs: 5000,
    vaultPath,
    now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.zone, 'zone-one.example');
  assert.equal(r.ua, FAKE_UA);
  assert.equal(r.postStatus, 200);
  assert.equal(r.mintedAt, '2026-08-05T12:00:00.000Z');
  assert.equal(r.expiresAt, new Date(T0 + 45 * 60000).toISOString());
  assert.equal(r.cookies[0].value, 'minted-value');
  assert.match(r.egressNote, /sticky egress/i);
  assert.equal(r.vault.ok, true);
  assert.equal(ctx.state.closed, true); // the browser is always closed
  assert.deepEqual(ctx.state.gotos, [URL1, 'https://zone-one.example/']); // the proof fetch hit the zone root, same context
  // persisted and retrievable under the SAME egress + UA — gone under another egress
  const got = await clearanceFor(URL1, { egressId: 'test-egress', ua: FAKE_UA, vaultPath, now: () => T0 + 60000 });
  assert.equal(got.cookies[0].value, 'minted-value');
  assert.equal(await clearanceFor(URL1, { egressId: 'other-egress', ua: FAKE_UA, vaultPath, now: () => T0 + 60000 }), null);
});

test('full mint, gate holds: cf_clearance present but the zone still challenges => minted:false, nothing vaulted', async () => {
  const vaultPath = tmpVault();
  const ctx = fakeContext({
    dom: '<title>Just a moment...</title>',
    resolveAfter: 1, // resolve clean first, THEN the proof fetch re-challenges — the proofGate layer stays under test
    cookies: [{ name: 'cf_clearance', value: 'minted-value', domain: 'zone-one.example', path: '/' }],
    proof: { status: () => 403, headers: () => ({ server: 'cloudflare', 'cf-mitigated': 'challenge' }), text: async () => CF_CHALLENGE.body },
  });
  const r = await mintClearance(URL1, { chromePath: THIS_FILE, launcher: async () => ctx, timeoutMs: 5000, vaultPath });
  assert.equal(r.minted, false);
  assert.equal(r.reason, 'cf_clearance minted but zone still challenges — unproven passage, honestly reported');
  assert.equal(r.postStatus, 403);
  assert.equal(r.postKind, 'managed-js');
  assert.equal(ctx.state.closed, true);
  const v = readVault({ vaultPath });
  assert.equal(v.ok, true);
  assert.deepEqual(v.entries, {}); // unproven clearance is NEVER vaulted
});

test('mint honesty: an unresolvable challenge burns the budget and fails honestly', async () => {
  const ctx = fakeContext({
    dom: '<title>Just a moment...</title>',
    cookies: [], // no cf_clearance ever appears
    proof: { status: () => 200, headers: () => ({}), text: async () => 'never reached' },
  });
  const r = await mintClearance(URL1, { chromePath: THIS_FILE, launcher: async () => ctx, timeoutMs: 60, vaultPath: tmpVault() });
  assert.equal(r.minted, false);
  assert.match(r.reason, /did not resolve/);
  assert.equal(ctx.state.closed, true);
});

// --- waitForResolution: the 2026-08-05 flash-close regression pins (manhuaus attempt 3:
// the poll treated an EMPTY/loading DOM as 'no challenge markers' = resolved, closed the
// window instantly, and robbed the operator's interactive tick) ---
function fakePage({ url = 'https://zone-one.example/', html } = {}) {
  return { url: () => url, evaluate: async () => html };
}
const noCookies = { cookies: async () => [] };
const withClearance = { cookies: async () => [{ name: 'cf_clearance', value: 'x' }] };
const SOON = () => Date.now() + 400;

test('waitForResolution: about:blank counts as STILL challenged, never resolved', async () => {
  const r = await waitForResolution(fakePage({ url: 'about:blank', html: '' }), noCookies, 'https://zone-one.example', SOON());
  assert.equal(r.ok, false);
});

test('waitForResolution: a nearly-empty DOM on the real URL is a loading state, not resolution', async () => {
  const r = await waitForResolution(fakePage({ html: '<html><head></head><body></body></html>' }), noCookies, 'https://zone-one.example', SOON());
  assert.equal(r.ok, false);
});

test('waitForResolution: a real non-challenge document resolves', async () => {
  const r = await waitForResolution(fakePage({ html: '<html><title>Zone One</title><body>' + 'real content '.repeat(20) + '</body></html>' }), noCookies, 'https://zone-one.example', Date.now() + 3000);
  assert.equal(r.ok, true);
});

test('waitForResolution: challenge markers keep it waiting until the deadline', async () => {
  const r = await waitForResolution(fakePage({ html: CF_CHALLENGE.body }), noCookies, 'https://zone-one.example', SOON());
  assert.equal(r.ok, false);
});

test('waitForResolution: cf_clearance while the DOM still challenges is NOT resolved -- the cookie can arrive a tick EARLY (2026-08-10 manhuaus rematch, operator-observed: the window closed before the second tick)', async () => {
  const r = await waitForResolution(fakePage({ html: CF_CHALLENGE.body }), withClearance, 'https://zone-one.example', SOON());
  assert.equal(r.ok, false);
  assert.equal(r.sawClearance, true);
  assert.match(r.reason, /still looks challenged/);
});

test('clearanceFor without a UA: zone+egress lookup returns the most recent unexpired entry', async () => {
  const vaultPath = tmpVault();
  const older = { cookies: [{ name: 'cf_clearance', value: 'old' }], ua: FAKE_UA + ' old', mintedAt: '2026-08-05T10:00:00Z', expiresAt: '2027-01-01T00:00:00Z' };
  const newer = { cookies: [{ name: 'cf_clearance', value: 'new' }], ua: FAKE_UA, mintedAt: '2026-08-05T11:00:00Z', expiresAt: '2027-01-01T00:00:00Z' };
  const entries = {};
  entries[vaultKey('zone-one.example', 'direct', older.ua)] = older;
  entries[vaultKey('zone-one.example', 'direct', newer.ua)] = newer;
  entries[vaultKey('zone-one.example', 'vpn', newer.ua)] = { ...newer, cookies: [{ name: 'cf_clearance', value: 'other-egress' }] };
  writeVault(entries, { vaultPath });
  const r = await clearanceFor('https://zone-one.example/', { vaultPath });
  assert.equal(r.cookies[0].value, 'new');         // newest wins
  const exact = await clearanceFor('https://zone-one.example/', { vaultPath, ua: older.ua });
  assert.equal(exact.cookies[0].value, 'old');     // exact-UA lookup still precise
  const none = await clearanceFor('https://other.example/', { vaultPath });
  assert.equal(none, null);
});

// --- 2026-08-10 ghost-chain mint egress (the live-proven bug: mints launched DIRECT
// while ghost-governed tools rode the SOCKS chain; the IP-bound cf_clearance was
// challenged on every chain-ridden probe -- 24/24 wasted at the edge) ---
const GHOST_CHAIN = 'socks5://10.64.0.1:1080';
const GHOST_ID = 'socks5://10.64.0.1:1080'; // the canonical egress id (creds-stripped scheme://host:port)

test('chainEgressId: canonical creds-stripped id; empty chain is direct; bad spec throws', () => {
  assert.equal(chainEgressId(GHOST_CHAIN), GHOST_ID);
  assert.equal(chainEgressId('socks5://user:pass@10.64.0.1:1080'), GHOST_ID); // creds never ride the id
  assert.equal(chainEgressId(''), 'direct');
  assert.equal(chainEgressId([]), 'direct');
  assert.equal(chainEgressId('socks://10.64.0.1:1080'), GHOST_ID); // scheme normalized like parseChain
  assert.throws(() => chainEgressId('not-a-url'), TypeError);
});

test('resolveMintEgress: ghost off mints direct with no warning', () => {
  const p = resolveMintEgress({ ghostMode: 'off', ghostChain: GHOST_CHAIN });
  assert.deepEqual(p, { ok: true, proxy: null, proxyAuth: null, egressId: 'direct' });
});

test('resolveMintEgress: ghost armed + chain => the mint rides the chain, egressId is the canonical chain id', () => {
  for (const mode of ['on', 'required']) {
    const p = resolveMintEgress({ ghostMode: mode, ghostChain: GHOST_CHAIN });
    assert.equal(p.ok, true);
    assert.equal(p.proxy, GHOST_ID);
    assert.equal(p.proxyAuth, null);
    assert.equal(p.egressId, GHOST_ID);
    assert.equal(p.warning, undefined);
  }
});

test('resolveMintEgress: ghost REQUIRED + no chain => fail-closed refusal (never a default direct mint)', () => {
  const p = resolveMintEgress({ ghostMode: 'required', ghostChain: '' });
  assert.equal(p.ok, false);
  assert.equal(p.proxy, null);
  assert.match(p.reason, /REQUIRED but no proxy chain/);
  assert.match(p.reason, /REFUSED \(fail-closed\)/);
  assert.match(p.reason, /--direct-egress/); // the honest way out is named
});

test('resolveMintEgress: ghost ON + no chain => direct mint WITH a loud warning', () => {
  const p = resolveMintEgress({ ghostMode: 'on', ghostChain: '' });
  assert.equal(p.ok, true);
  assert.equal(p.proxy, null);
  assert.equal(p.egressId, 'direct');
  assert.match(p.warning, /WARNING: ghost mode is ON but no proxy chain/);
});

test('resolveMintEgress: --direct-egress override mints direct WITH the loud warning, even under required+chain', () => {
  const p = resolveMintEgress({ ghostMode: 'required', ghostChain: GHOST_CHAIN, directEgress: true });
  assert.equal(p.ok, true);
  assert.equal(p.proxy, null);
  assert.equal(p.egressId, 'direct');
  assert.match(p.warning, /WARNING: --direct-egress/);
  assert.match(p.warning, /OPERATOR egress/);
});

test('resolveMintEgress: multi-hop chain is refused fail-closed (a browser rides exactly ONE hop; first-hop-only would bind the WRONG exit)', () => {
  const p = resolveMintEgress({ ghostMode: 'required', ghostChain: 'socks5://10.64.0.1:1080,http://proxy.example:8080' });
  assert.equal(p.ok, false);
  assert.match(p.reason, /2 hops/);
  assert.match(p.reason, /WRONG exit/);
});

test('resolveMintEgress: an unparseable chain is refused fail-closed, never thrown', () => {
  const p = resolveMintEgress({ ghostMode: 'required', ghostChain: 'not-a-url' });
  assert.equal(p.ok, false);
  assert.match(p.reason, /could not be parsed/);
});

test('resolveMintEgress: credentialed hop strips creds from proxy+egressId and hands them to proxyAuth', () => {
  const p = resolveMintEgress({ ghostMode: 'on', ghostChain: 'http://alice:s3cret@proxy.example:8080' });
  assert.equal(p.ok, true);
  assert.equal(p.proxy, 'http://proxy.example:8080');
  assert.equal(p.egressId, 'http://proxy.example:8080');
  assert.deepEqual(p.proxyAuth, { username: 'alice', password: 's3cret' });
  assert.ok(!JSON.stringify([p.proxy, p.egressId]).includes('s3cret')); // secrets never ride the vault key
});

test('mint/ride egress PARITY: a chain mint vaults under the SAME id the ride side looks up (and direct lookups miss)', async () => {
  const vaultPath = tmpVault();
  const settings = { ghostMode: 'required', ghostChain: GHOST_CHAIN };
  const plan = resolveMintEgress(settings);
  const launchArgs = [];
  const ctx = fakeContext({
    dom: '<title>Just a moment...</title>',
    resolveAfter: 1,
    cookies: [{ name: 'cf_clearance', value: 'chain-minted', domain: 'zone-one.example', path: '/' }],
    proof: { status: () => 200, headers: () => ({ server: 'cloudflare' }), text: async () => '<html>the real zone root</html>' },
  });
  const r = await mintClearance(URL1, {
    chromePath: THIS_FILE,
    launcher: async (a) => { launchArgs.push(a); return ctx; },
    proxy: plan.proxy,
    proxyAuth: plan.proxyAuth,
    egressId: plan.egressId,
    timeoutMs: 5000,
    vaultPath,
    now: () => T0,
  });
  assert.equal(r.minted, true);
  // the proxy reached the patchright leg's launcher
  assert.equal(launchArgs.length, 1);
  assert.equal(launchArgs[0].proxy, GHOST_ID);
  assert.equal(launchArgs[0].proxyAuth, null);
  // mint-side egress id == lookup-side egress id == the chain's canonical id
  assert.equal(r.egressId, GHOST_ID);
  assert.equal(plan.egressId, chainEgressId(GHOST_CHAIN));
  assert.equal(rideEgressId(settings), plan.egressId);
  const rode = await clearanceFor(URL1, { egressId: rideEgressId(settings), ua: FAKE_UA, vaultPath, now: () => T0 + 60000 });
  assert.equal(rode.cookies[0].value, 'chain-minted');
  // ...and the OLD bug shape (direct mint vs chain ride) provably misses both ways
  assert.equal(await clearanceFor(URL1, { egressId: 'direct', ua: FAKE_UA, vaultPath, now: () => T0 + 60000 }), null);
});

test('mintClearance: proxy given without an explicit egressId defaults the vault key to the chain canonical id', async () => {
  const vaultPath = tmpVault();
  const ctx = fakeContext({
    dom: '<title>Just a moment...</title>',
    resolveAfter: 1,
    cookies: [{ name: 'cf_clearance', value: 'auto-id', domain: 'zone-one.example', path: '/' }],
    proof: { status: () => 200, headers: () => ({}), text: async () => '<html>clean</html>' },
  });
  const r = await mintClearance(URL1, {
    chromePath: THIS_FILE, launcher: async () => ctx,
    proxy: GHOST_CHAIN, // no egressId given
    timeoutMs: 5000, vaultPath, now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.egressId, GHOST_ID);
  const v = readVault({ vaultPath, now: () => T0 });
  assert.ok(v.entries[vaultKey('zone-one.example', GHOST_ID, FAKE_UA)]);
});

test('mintClearance: no proxy => the launcher gets none and the egress stays direct (legacy behavior unchanged)', async () => {
  const launchArgs = [];
  const ctx = fakeContext({
    dom: '<title>Just a moment...</title>',
    resolveAfter: 1,
    cookies: [{ name: 'cf_clearance', value: 'direct-minted', domain: 'zone-one.example', path: '/' }],
    proof: { status: () => 200, headers: () => ({}), text: async () => '<html>clean</html>' },
  });
  const r = await mintClearance(URL1, {
    chromePath: THIS_FILE, launcher: async (a) => { launchArgs.push(a); return ctx; },
    timeoutMs: 5000, vaultPath: tmpVault(), now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.egressId, 'direct');
  assert.equal(launchArgs[0].proxy, undefined);
});

test('mintClearance: a multi-hop or unparseable proxy is an honest fail-closed refusal, browser never launches', async () => {
  let launched = false;
  const launcher = async () => { launched = true; return fakeContext({ dom: '', cookies: [], proof: null }); };
  const multi = await mintClearance(URL1, { chromePath: THIS_FILE, launcher, proxy: 'socks5://10.64.0.1:1080,http://proxy.example:8080', vaultPath: tmpVault() });
  assert.equal(multi.minted, false);
  assert.match(multi.reason, /exactly ONE hop/);
  const bad = await mintClearance(URL1, { chromePath: THIS_FILE, launcher, proxy: 'not-a-url', vaultPath: tmpVault() });
  assert.equal(bad.minted, false);
  assert.match(bad.reason, /could not be parsed/);
  assert.equal(launched, false);
});
