// nodriver.test.mjs — hermetic pins for the nodriver sidecar engine: NO real browser, NO
// network. Covers (a) detectNodriver honesty absent vs present (injected exists/spawnSync),
// (b) the engine cascade ('auto' picks nodriver when the probe is healthy, patchright
// otherwise; an injected launcher pins patchright), (c) sidecar stdout parsing (log lines
// around the JSON tolerated; unparseable output = honest failure), and (d) the proofGate
// on scripted sidecar facts (challenge-present proof => minted:false, never vaulted;
// clean => minted:true with the engine recorded in the vault entry).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { detectNodriver, parseSidecarJson, mintClearance, readVault, clearanceFor, vaultKey, normalizeTick, manualTickRequested } from '../tools/clearance/broker.mjs';

const THIS_FILE = fileURLToPath(import.meta.url); // an existing file: stands in for chrome.exe at resolution time
const FAKE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36';
const URL1 = 'https://zone-one.example/path';
const T0 = Date.parse('2026-08-05T12:00:00Z');
const ND = 'nodriver (raw-CDP sidecar)';
const PR = 'patchright (stealth Playwright + real Chrome)';

const CF_CHALLENGE_BODY = '<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>';

function tmpVault() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'varvel-nodriver-')), 'vault.json');
}

// exists stub: the fake Chrome binary always "exists"; the venv python only when venvPresent.
const existsWith = (venvPresent) => (p) => String(p) === THIS_FILE || (venvPresent && /\.venv[\\/]Scripts[\\/]python/.test(String(p)));
const spawnOk = () => ({ status: 0, stdout: '0.50.3\n', stderr: '' });
const spawnFail = () => ({ status: 1, stdout: '', stderr: "ModuleNotFoundError: No module named 'nodriver'" });

// A scripted sidecarRun seam: records (pythonPath, args, opts), replies with `reply`.
function fakeSidecar(reply) {
  const state = { calls: [] };
  const run = async (pythonPath, args, opts) => {
    state.calls.push({ pythonPath, args, opts });
    return typeof reply === 'function' ? reply(state.calls[state.calls.length - 1]) : reply;
  };
  return { state, run };
}

const solvedFacts = (over = {}) => JSON.stringify({
  ok: true,
  solved: true,
  engine: 'nodriver',
  cookies: [{ name: 'cf_clearance', value: 'nd-minted-value', domain: 'zone-one.example', path: '/' }],
  ua: FAKE_UA,
  proofStatus: 200,
  proofHeaders: { server: 'cloudflare', 'cf-ray': '9-LHR' },
  proofBody: '<html><title>Zone One</title><body>the real zone root, served clean</body></html>',
  ...over,
});

// A scripted BrowserContext stand-in for the patchright leg (same shape as clearance.test).
function fakePatchrightContext() {
  let domProbes = 0;
  const page = {
    // challenge first, then a REAL solve -- page-state-decided resolution (2026-08-10:
    // the cookie alone never resolves; it can arrive a tick early)
    evaluate: async (fn) => {
      if (/navigator/.test(String(fn))) return FAKE_UA;
      domProbes += 1;
      return domProbes > 1
        ? '<html><title>Zone One</title><body>' + 'real content '.repeat(20) + '</body></html>'
        : '<title>Just a moment...</title>';
    },
    goto: async (u) => ({ status: () => 200, headers: () => ({ server: 'cloudflare' }), text: async () => '<html>the real zone root</html>' }),
  };
  return { pages: () => [page], newPage: async () => page, cookies: async () => [{ name: 'cf_clearance', value: 'pr-minted' }], close: async () => {} };
}

// --- (a) detectNodriver: honest absent vs present ---

test('detectNodriver: no venv python anywhere => available:false with the install hint, never throws', () => {
  const d = detectNodriver({ env: {}, exists: () => false, spawnSync: () => { throw new Error('must never spawn'); } });
  assert.equal(d.available, false);
  assert.equal(d.pythonPath, null);
  assert.equal(d.version, null);
  assert.match(d.reason, /no nodriver sidecar venv/);
  assert.match(d.reason, /pip install nodriver/);
});

test('detectNodriver: venv python exists but import fails => available:false, stderr carried in the reason', () => {
  const d = detectNodriver({ env: {}, exists: existsWith(true), spawnSync: spawnFail });
  assert.equal(d.available, false);
  assert.ok(/\.venv[\\/]Scripts[\\/]python/.test(d.pythonPath));
  assert.equal(d.version, null);
  assert.match(d.reason, /import nodriver.*failed/);
  assert.match(d.reason, /ModuleNotFoundError/);
});

test('detectNodriver: spawnSync throwing (missing binary at exec) => available:false, never throws', () => {
  const d = detectNodriver({ env: {}, exists: existsWith(true), spawnSync: () => { throw new Error('ENOENT spawn'); } });
  assert.equal(d.available, false);
  assert.match(d.reason, /ENOENT spawn/);
});

test('detectNodriver: venv python + clean import => available:true with the pinned version', () => {
  const seen = [];
  const d = detectNodriver({
    env: {},
    exists: existsWith(true),
    spawnSync: (p, args) => { seen.push({ p, args }); return spawnOk(); },
  });
  assert.equal(d.available, true);
  assert.ok(/\.venv[\\/]Scripts[\\/]python\.exe$/.test(d.pythonPath)); // Windows venv layout probed first
  assert.equal(d.version, '0.50.3');
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0].args.slice(0, 1), ['-c']); // a -c import probe, never a shell string
});

// --- (b) engine cascade ---

test('cascade: auto + healthy sidecar probe => the nodriver engine runs (args array, never a shell string)', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts(), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto',
    chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run,
    vaultPath: tmpVault(),
    now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.engine, ND);
  assert.equal(r.sidecar.nodriver, '0.50.3');
  const call = sidecar.state.calls[0];
  assert.ok(/\.venv[\\/]Scripts[\\/]python\.exe$/.test(call.pythonPath));
  assert.ok(Array.isArray(call.args));
  assert.match(call.args[0], /ndmint\.py$/);
  assert.ok(call.args.includes(URL1) && call.args.includes('--chrome') && call.args.includes(THIS_FILE));
  assert.ok(!call.args.includes('--headless')); // headed is doctrine unless asked
});

test('cascade: auto + unhealthy probe => patchright runs (and the engine label says so)', async () => {
  let sidecarTouched = false;
  const r = await mintClearance(URL1, {
    engine: 'auto',
    chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnFail,
    sidecarRun: async () => { sidecarTouched = true; throw new Error('must never run'); },
    launcher: async () => fakePatchrightContext(),
    timeoutMs: 3000,
    vaultPath: tmpVault(),
    now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.engine, PR);
  assert.equal(sidecarTouched, false);
});

test('cascade: an injected launcher pins auto to patchright even with a healthy probe', async () => {
  let probes = 0;
  const r = await mintClearance(URL1, {
    chromePath: THIS_FILE, // engine omitted => auto
    env: {}, exists: existsWith(true),
    spawnSync: () => { probes++; return spawnOk(); },
    launcher: async () => fakePatchrightContext(),
    timeoutMs: 3000,
    vaultPath: tmpVault(),
    now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.engine, PR);
  assert.equal(probes, 0); // pinned before the probe: the seam IS the driver
});

test('cascade: nodriver requested but unavailable => honest failure, never a silent weak fallback', async () => {
  const r = await mintClearance(URL1, {
    engine: 'nodriver',
    chromePath: THIS_FILE,
    env: {}, exists: existsWith(false), spawnSync: spawnOk,
    launcher: async () => { throw new Error('must never launch patchright'); },
    vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.equal(r.engine, ND);
  assert.match(r.reason, /requested but the sidecar is unavailable/);
  assert.match(r.reason, /no nodriver sidecar venv/);
});

test('cascade: unknown engine token is an honest failure', async () => {
  const r = await mintClearance(URL1, { engine: 'selenium', chromePath: THIS_FILE, vaultPath: tmpVault() });
  assert.equal(r.minted, false);
  assert.match(r.reason, /unknown engine/);
});

// --- (c) sidecar stdout parsing ---

test('parseSidecarJson: leading log lines are tolerated — the last JSON line wins', () => {
  const stdout = 'INFO:nodriver:browser started\n{"ok": false, "engine": "nodriver", "reason": "boom"}\n';
  const p = parseSidecarJson(stdout);
  assert.equal(p.ok, true);
  assert.equal(p.facts.ok, false);
  assert.equal(p.facts.reason, 'boom');
});

test('parseSidecarJson: trailing interpreter-shutdown noise after the JSON is tolerated', () => {
  // the real 0.50.3 emits "Exception ignored ..." deallocator noise AFTER the verdict
  const stdout = '{"ok": true, "solved": true}\nException ignored while calling deallocator:\nValueError: I/O operation on closed pipe\n';
  const p = parseSidecarJson(stdout);
  assert.equal(p.ok, true);
  assert.equal(p.facts.solved, true);
});

test('parseSidecarJson: wholly unparseable output is an honest not-ok', () => {
  assert.deepEqual(parseSidecarJson('garbage\nmore garbage\n'), { ok: false });
  assert.deepEqual(parseSidecarJson(''), { ok: false });
  assert.deepEqual(parseSidecarJson(null), { ok: false });
});

test('sidecar path: garbage stdout => minted:false with an honest reason, nothing vaulted', async () => {
  const vaultPath = tmpVault();
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: 'all noise, no verdict\n', stderr: 'some warning' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath,
  });
  assert.equal(r.minted, false);
  assert.equal(r.engine, ND);
  assert.match(r.reason, /no parseable JSON verdict/);
  assert.deepEqual(readVault({ vaultPath }).entries, {});
});

test('sidecar path: a dead/crashed sidecar process is an honest failure', async () => {
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: async () => ({ ok: false, error: 'sidecar exceeded its hard kill budget', stdout: '', stderr: '' }),
    vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.equal(r.engine, ND);
  assert.match(r.reason, /did not complete/);
});

test('sidecar path: ok:false facts (sidecar-internal failure) surface the sidecar reason', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: JSON.stringify({ ok: false, engine: 'nodriver', reason: 'sidecar crashed: TimeoutError: boom' }), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.match(r.reason, /nodriver sidecar failed: sidecar crashed/);
});

test('sidecar path: solved:false (challenge never resolved) is minted:false with the budget reason', async () => {
  const sidecar = fakeSidecar({
    ok: true, status: 0, stderr: '',
    stdout: solvedFacts({ solved: false, proofStatus: 0, proofHeaders: {}, proofBody: '', reason: 'managed challenge did not resolve before the time budget ran out (last DOM classification: challenge-markers; no cf_clearance observed)' }),
  });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.equal(r.engine, ND);
  assert.match(r.reason, /did not resolve/);
});

// --- (d) proofGate on scripted sidecar facts ---

test('gate holds: solved but the proof still challenges => minted:false, nothing vaulted', async () => {
  const vaultPath = tmpVault();
  const sidecar = fakeSidecar({
    ok: true, status: 0, stderr: '',
    stdout: solvedFacts({
      proofStatus: 403,
      proofHeaders: { server: 'cloudflare', 'cf-mitigated': 'challenge' },
      proofBody: CF_CHALLENGE_BODY,
    }),
  });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath,
  });
  assert.equal(r.minted, false);
  assert.equal(r.engine, ND);
  assert.equal(r.reason, 'cf_clearance minted but zone still challenges — unproven passage, honestly reported');
  assert.equal(r.postStatus, 403);
  assert.equal(r.postKind, 'managed-js');
  assert.deepEqual(readVault({ vaultPath }).entries, {}); // unproven clearance is NEVER vaulted
});

test('proven mint: clean proof => minted:true, engine recorded in the vault entry, cookies retrievable', async () => {
  const vaultPath = tmpVault();
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts(), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run,
    egressId: 'test-egress',
    vaultPath,
    now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.engine, ND);
  assert.equal(r.postStatus, 200);
  assert.equal(r.ua, FAKE_UA);
  assert.equal(r.cookies[0].value, 'nd-minted-value');
  assert.equal(r.mintedAt, '2026-08-05T12:00:00.000Z');
  assert.match(r.egressNote, /sticky egress/i);
  const v = readVault({ vaultPath, now: () => T0 });
  const entry = v.entries[vaultKey('zone-one.example', 'test-egress', FAKE_UA)];
  assert.ok(entry);
  assert.equal(entry.engine, ND); // the vault records which engine minted
  const got = await clearanceFor(URL1, { egressId: 'test-egress', ua: FAKE_UA, vaultPath, now: () => T0 + 60000 });
  assert.equal(got.cookies[0].value, 'nd-minted-value');
});

test('proven mint: log lines around the sidecar JSON do not break the mint', async () => {
  const sidecar = fakeSidecar({
    ok: true, status: 0, stderr: '',
    stdout: 'INFO: launching chrome\nWARNING: sandbox\n' + solvedFacts() + '\nException ignored: shutdown noise\n',
  });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(), now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.engine, ND);
});

test('honesty: solved but UA unreadable => minted:false (the vault key embeds sha256(ua))', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts({ ua: null }), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.equal(r.engine, ND);
  assert.match(r.reason, /User-Agent/);
});

// --- 2026-08-10 ghost-chain mint egress, nodriver leg: the proxy must reach the sidecar
// args (applied by ndmint.py as Chrome --proxy-server) and the egressId must be the
// chain's canonical id so the ride side's lookup hits ---
const GHOST_CHAIN = 'socks5://10.64.0.1:1080';

test('chain mint via nodriver: --proxy reaches the sidecar args and the egressId is the chain canonical id', async () => {
  const vaultPath = tmpVault();
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts(), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run,
    proxy: GHOST_CHAIN, // no explicit egressId: defaults to the chain canonical id
    vaultPath,
    now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.engine, ND);
  assert.equal(r.egressId, 'socks5://10.64.0.1:1080');
  const call = sidecar.state.calls[0];
  const i = call.args.indexOf('--proxy');
  assert.ok(i >= 0, 'sidecar args must carry --proxy');
  assert.equal(call.args[i + 1], GHOST_CHAIN); // ndmint.py applies it as Chrome --proxy-server
  // mint-side vs lookup-side parity: the ride egress id for the same ghost settings hits
  const { resolveMintEgress, rideEgressId } = await import('../tools/clearance/broker.mjs');
  const settings = { ghostMode: 'required', ghostChain: GHOST_CHAIN };
  assert.equal(resolveMintEgress(settings).egressId, r.egressId);
  assert.equal(rideEgressId(settings), r.egressId);
  const v = readVault({ vaultPath, now: () => T0 });
  assert.ok(v.entries[vaultKey('zone-one.example', 'socks5://10.64.0.1:1080', FAKE_UA)]);
  const got = await clearanceFor(URL1, { egressId: rideEgressId(settings), ua: FAKE_UA, vaultPath, now: () => T0 + 60000 });
  assert.equal(got.cookies[0].value, 'nd-minted-value');
  assert.equal(await clearanceFor(URL1, { egressId: 'direct', ua: FAKE_UA, vaultPath, now: () => T0 + 60000 }), null);
});

test('no proxy: the sidecar args carry no --proxy (legacy behavior unchanged)', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts(), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run,
    vaultPath: tmpVault(),
    now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.egressId, 'direct');
  assert.equal(sidecar.state.calls[0].args.includes('--proxy'), false);
});

test('nodriver leg: a multi-hop proxy is refused fail-closed BEFORE the sidecar is spawned', async () => {
  let spawned = false;
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: async () => { spawned = true; return { ok: true, status: 0, stdout: solvedFacts(), stderr: '' }; },
    proxy: 'socks5://10.64.0.1:1080,http://proxy.example:8080',
    vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.match(r.reason, /exactly ONE hop/);
  assert.equal(spawned, false);
});

// --- 2026-08-11 OS-level auto-tick: the Turnstile checkbox is ticked by a real OS
// input event from the sidecar (ctypes user32), NEVER a CDP-synthesized click. These
// pins cover the Node side of the contract: the manual override reaches the sidecar
// args, the auto path is the default, and the tick-path provenance is surfaced
// honestly in the mint report + vault. The click itself (humanization bounds, attempt
// cap, fallback) is pinned in Python (tools/clearance/py/test_ndtick.py), run below
// under the venv when present. NO live Cloudflare contact anywhere here. ---

const TICK_AUTO = { path: 'auto-os-click', attempts: 1, clicks: 1, sawCheckbox: true, auto: true, manual: false };
const TICK_MANUAL = { path: 'operator-manual', attempts: 3, clicks: 3, sawCheckbox: true, auto: true, manual: false };

test('manualTickRequested: only 1|true (any case) pin the manual path', () => {
  assert.equal(manualTickRequested({ VARVEL_CF_MANUAL_TICK: '1' }), true);
  assert.equal(manualTickRequested({ VARVEL_CF_MANUAL_TICK: 'TRUE' }), true);
  assert.equal(manualTickRequested({}), false);
  assert.equal(manualTickRequested({ VARVEL_CF_MANUAL_TICK: '0' }), false);
  assert.equal(manualTickRequested({ VARVEL_CF_MANUAL_TICK: 'yes' }), false);
});

test('normalizeTick: known fields coerced, garbage/absent tolerated honestly', () => {
  assert.deepEqual(normalizeTick(TICK_AUTO), TICK_AUTO);
  assert.equal(normalizeTick(null), null);
  assert.equal(normalizeTick('auto-os-click'), null);
  const thin = normalizeTick({ path: 'operator-manual' });
  assert.deepEqual(thin, { path: 'operator-manual', attempts: 0, clicks: 0, sawCheckbox: false, auto: false, manual: false });
  assert.equal(normalizeTick({ attempts: 2 }).path, 'unknown'); // a pathless record never claims a path
});

test('auto-tick plumbing: VARVEL_CF_MANUAL_TICK=1 reaches the sidecar args as --manual-tick', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts({ tick: { ...TICK_MANUAL, auto: false, manual: true, attempts: 0, clicks: 0 } }), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: { VARVEL_CF_MANUAL_TICK: '1' }, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(), now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.ok(sidecar.state.calls[0].args.includes('--manual-tick')); // the operator override is on the wire contract
  assert.equal(r.tick.manual, true);
});

test('auto-tick plumbing: the auto path is the DEFAULT (no --manual-tick without the env)', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts(), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(), now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(sidecar.state.calls[0].args.includes('--manual-tick'), false);
});

test('tick provenance: auto-os-click surfaces in the mint report, the vault entry, and clearanceFor', async () => {
  const vaultPath = tmpVault();
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts({ tick: TICK_AUTO }), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, egressId: 'test-egress', vaultPath, now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.deepEqual(r.tick, TICK_AUTO); // the report states HOW the challenge was passed
  const v = readVault({ vaultPath, now: () => T0 });
  const entry = v.entries[vaultKey('zone-one.example', 'test-egress', FAKE_UA)];
  assert.deepEqual(entry.tick, TICK_AUTO); // recorded for detectability accounting
  const got = await clearanceFor(URL1, { egressId: 'test-egress', ua: FAKE_UA, vaultPath, now: () => T0 + 60000 });
  assert.deepEqual(got.tick, TICK_AUTO); // the ride side can see it too
});

test('tick provenance: operator-manual fallback after exhausted auto attempts is reported, never dressed up as auto', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts({ tick: TICK_MANUAL }), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(), now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.tick.path, 'operator-manual');
  assert.equal(r.tick.attempts, 3); // the retry cap the sidecar enforced is visible in the report
});

test('tick provenance: an old sidecar without tick facts reports tick:null (absent, never invented)', async () => {
  const sidecar = fakeSidecar({ ok: true, status: 0, stdout: solvedFacts(), stderr: '' });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(), now: () => T0,
  });
  assert.equal(r.minted, true);
  assert.equal(r.tick, null);
});

test('tick provenance: an UNSOLVED mint still carries the tick facts (which path was tried)', async () => {
  const sidecar = fakeSidecar({
    ok: true, status: 0, stderr: '',
    stdout: solvedFacts({
      solved: false, proofStatus: 0, proofHeaders: {}, proofBody: '',
      tick: { path: 'unresolved', attempts: 3, clicks: 3, sawCheckbox: true, auto: true, manual: false },
      reason: 'managed challenge did not resolve before the time budget ran out (last DOM classification: challenge-markers; no cf_clearance observed; tick: unresolved, 3 attempt(s), 3 OS click(s))',
    }),
  });
  const r = await mintClearance(URL1, {
    engine: 'auto', chromePath: THIS_FILE,
    env: {}, exists: existsWith(true), spawnSync: spawnOk,
    sidecarRun: sidecar.run, vaultPath: tmpVault(),
  });
  assert.equal(r.minted, false);
  assert.equal(r.tick.path, 'unresolved');
  assert.equal(r.tick.clicks, 3);
  assert.match(r.reason, /tick: unresolved, 3 attempt/); // the sidecar's reason carries the tick summary
});

// The Python side of the contract (click humanization bounds, the 3-attempt retry
// cap, fresh-locate-per-attempt, the provenance matrix): tools/clearance/py/
// test_ndtick.py, hermetic (injected user32/clock/RNG, no browser, no input events).
// Runs under the sidecar venv when present; skips cleanly where it is not.
const ndProbe = detectNodriver();
test('python auto-tick unit tests (venv-gated)', { skip: !ndProbe.available && 'no nodriver sidecar venv on this host' }, async () => {
  const { spawnSync } = await import('node:child_process');
  const testFile = fileURLToPath(new URL('../tools/clearance/py/test_ndtick.py', import.meta.url));
  const r = spawnSync(ndProbe.pythonPath, [testFile], { encoding: 'utf8', timeout: 120000 });
  assert.equal(r.status, 0, 'python tick tests failed:\n' + String(r.stdout || '') + '\n' + String(r.stderr || ''));
});
