// ghost-egress.test.mjs — hermetic tests for engine/egresscheck.mjs + Ghost.exitCheck().
// The exit sampler, the ipinfo fetch, and sleep are ALL dependency-injected; nothing
// leaves the test process, no sockets are opened, no wall-clock waiting happens.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Ghost } from '../engine/ghost.mjs';
import { runEgressCheck, classifyEgressOrg, ipinfoClassify } from '../engine/egresscheck.mjs';

delete process.env.VARVEL_GHOST_EXPECT_EXIT; // env must never leak into a test

const noSleep = () => Promise.resolve(); // injected: the 1s spacing costs 0ms here
const okFetch = (org, ip = '203.0.113.7') => async () => ({ ok: true, status: 200, json: async () => ({ ip, org }) });
const offFetch = async () => { const e = new Error('aborted'); e.name = 'AbortError'; throw e; };

function armedGhost() {
  const g = new Ghost();
  // dead hop + loopback checkUrl: sampler is injected, and verify() stays hermetic
  g.configure({ mode: 'required', chain: 'http://127.0.0.1:1', checkUrl: 'http://127.0.0.1:1/' });
  return g;
}

test('classifyEgressOrg: vpn/datacenter/residential-ish heuristics, unknown fail-closed', () => {
  assert.equal(classifyEgressOrg('AS1234 Mullvad VPN AB'), 'vpn');
  assert.equal(classifyEgressOrg('AS9009 M247 Ltd'), 'datacenter');
  assert.equal(classifyEgressOrg('AS16509 Amazon.com, Inc.'), 'datacenter');
  assert.equal(classifyEgressOrg('AS7922 Comcast Cable Communications'), 'residential-ish');
  assert.equal(classifyEgressOrg('AS0000 Inscrutable Networks'), 'unknown');
  assert.equal(classifyEgressOrg(''), 'unknown');
  assert.equal(classifyEgressOrg(null), 'unknown');
});

test('exitCheck: stable verdict when all N samples agree', async () => {
  const g = armedGhost();
  let calls = 0;
  const r = await g.exitCheck({
    sampler: async () => { calls++; return '203.0.113.7'; },
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
  });
  assert.equal(calls, 3, 'default is 3 samples');
  assert.equal(r.ok, true);
  assert.equal(r.verdict, 'stable');
  assert.deepEqual(r.distinct, ['203.0.113.7']);
  assert.deepEqual(r.exits, ['203.0.113.7', '203.0.113.7', '203.0.113.7']);
  assert.equal(r.warnings.length, 0);
  assert.equal(r.egress.ok, true);
  assert.equal(r.egress.class, 'vpn');
  assert.equal(r.egress.heuristic, true, 'class result is labelled a heuristic');
});

test('exitCheck: rotating verdict lists distinct exits + the cf_clearance warning', async () => {
  const g = armedGhost();
  const ips = ['203.0.113.7', '198.51.100.9', '192.0.2.44'];
  let i = 0;
  const r = await g.exitCheck({
    sampler: async () => ips[i++ % ips.length],
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
  });
  assert.equal(r.ok, true, 'rotation warns, it does not fail the check');
  assert.equal(r.verdict, 'rotating');
  assert.deepEqual(r.distinct, ['203.0.113.7', '198.51.100.9', '192.0.2.44']);
  const w = r.warnings.find((x) => /ROTATING/.test(x));
  assert.ok(w, 'rotating warning present');
  assert.match(w, /cf_clearance binds to exit IP \+ User-Agent/);
  assert.match(w, /pin ONE specific Mullvad server/i);
});

test('exitCheck: datacenter class raises the CF advisory, labelled heuristic', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '203.0.113.7',
    sleep: noSleep, fetchImpl: okFetch('AS9009 M247 Ltd'),
  });
  assert.equal(r.egress.class, 'datacenter');
  const w = r.warnings.find((x) => /DATACENTER/.test(x));
  assert.ok(w, 'datacenter advisory present');
  assert.match(w, /Cloudflare-class/);
  assert.match(w, /zero-spend boundary/);
});

test('exitCheck: expect-exit mismatch in default (warn) mode — loud warning, ok stays true', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '198.51.100.9',
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '203.0.113.7',
  });
  assert.equal(r.ok, true, 'warn mode never closes the gate');
  assert.equal(r.pinMatch, false);
  const w = r.warnings.find((x) => /EXIT MISMATCH/.test(x));
  assert.ok(w, 'mismatch warning present');
  assert.match(w, /203\.0\.113\.7/);
  assert.match(w, /198\.51\.100\.9/);
  assert.equal(g.verifiedOk(), false, 'never verified in the first place — unchanged');
});

test('exitCheck: pinStrict mismatch FAILS CLOSED and drops verification', async () => {
  const g = armedGhost();
  g._verified = { ok: true, baselineIp: '192.0.2.1', exitIp: '198.51.100.9', at: 'then' }; // was verified
  const r = await g.exitCheck({
    sampler: async () => '198.51.100.9',
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '203.0.113.7', pinStrict: true,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /pinStrict/);
  assert.match(r.reason, /203\.0\.113\.7/); // expected named
  assert.match(r.reason, /198\.51\.100\.9/); // actual named
  assert.equal(g.verifiedOk(), false, 'verification dropped — the gate is closed');
  await assert.rejects(() => g.assertEgress('https://example.com/'), (e) => e.ghostRefused === true);
});

test('exitCheck: pin match (strict) passes and touches nothing', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '203.0.113.7',
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '203.0.113.7', pinStrict: true,
  });
  assert.equal(r.ok, true);
  assert.equal(r.pinMatch, true);
  assert.equal(r.warnings.length, 0);
});

test('exitCheck: VARVEL_GHOST_EXPECT_EXIT env is honored when no option is passed', async () => {
  process.env.VARVEL_GHOST_EXPECT_EXIT = '203.0.113.7';
  try {
    const g = armedGhost();
    const r = await g.exitCheck({
      sampler: async () => '198.51.100.9',
      sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    });
    assert.equal(r.expectExit, '203.0.113.7');
    assert.equal(r.pinMatch, false);
    assert.ok(r.warnings.some((x) => /EXIT MISMATCH/.test(x)));
  } finally { delete process.env.VARVEL_GHOST_EXPECT_EXIT; }
});

test('exitCheck: offline everything NEVER throws — unknown verdict, class skipped silently', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => { throw new Error('chain dead'); }, // even a throwing sampler
    sleep: noSleep, fetchImpl: offFetch,
  });
  assert.equal(r.ok, true);
  assert.equal(r.verdict, 'unknown');
  assert.equal(r.sampled, 0);
  assert.equal(r.failed, 3);
  assert.deepEqual(r.distinct, []);
  assert.equal(r.egress.ok, false);
  assert.match(r.egress.error, /timed out/);
  assert.equal(r.warnings.some((x) => /DATACENTER|ROTATING|MISMATCH/.test(x)), false, 'no class/pin noise when offline');
});

test('exitCheck: partial sampling (1 of 3 answered) is reported honestly', async () => {
  const g = armedGhost();
  let i = 0;
  const r = await g.exitCheck({
    sampler: async () => (i++ === 1 ? '203.0.113.7' : null),
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
  });
  assert.equal(r.verdict, 'stable', 'one distinct answer is stable…');
  assert.equal(r.failed, 2);
  assert.ok(r.warnings.some((x) => /2 of 3 exit samples failed/.test(x)), '…but the gap is said plainly');
});

test('exitCheck: v6 exits are canonicalized — mixed case/compression dedupe to a stable verdict', async () => {
  const g = armedGhost();
  const forms = ['2001:DB8::7', '2001:0db8:0000:0000:0000:0000:0000:0007', '2001:db8::7'];
  let i = 0;
  const r = await g.exitCheck({
    sampler: async () => forms[i++ % forms.length],
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
  });
  assert.equal(r.verdict, 'stable', 'three spellings of ONE v6 exit are stable, not rotating');
  assert.deepEqual(r.distinct, ['2001:db8::7'], 'canonical form reported');
  assert.equal(r.warnings.length, 0);
});

test('exitCheck: v4-mapped v6 exit collapses to its embedded v4 (mapped 127.0.0.1 can NEVER read as public)', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '::ffff:203.0.113.7',
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '203.0.113.7', pinStrict: true,
  });
  assert.deepEqual(r.distinct, ['203.0.113.7'], 'the mapped exit IS the v4 address');
  assert.equal(r.pinMatch, true, 'a v4 pin matches the mapped form of the same address');
  assert.equal(r.ok, true);
});

test('exitCheck: pin in mapped/expanded form matches the canonical sample (both directions)', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '203.0.113.7',
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '::ffff:cb00:7107', pinStrict: true, // '::ffff:203.0.113.7' in hex notation
  });
  assert.equal(r.pinMatch, true, 'pin spelling does not matter — the ADDRESS does');
  assert.equal(r.ok, true);
  assert.equal(r.expectExit, '::ffff:cb00:7107', 'the report still shows what the operator pinned');
});

test('exitCheck: a non-IP "exit" sample is a FAILED measurement — never a stable claim (fail-closed)', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => 'redacted-by-proxy', // a check endpoint answering garbage must not read as coverage
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
  });
  assert.equal(r.verdict, 'unknown', 'garbage exits say unknown, never stable');
  assert.equal(r.sampled, 0);
  assert.equal(r.failed, 3);
  assert.ok(r.warnings.some((x) => /not a parseable IP literal/.test(x)), 'the garbage is named in the warnings');
});

test('exitCheck: v6 pinStrict mismatch fails closed and names both canonical ends', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '2001:db8::6',
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '2001:db8::5', pinStrict: true,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /pinStrict/);
  assert.match(r.reason, /2001:db8::5/);
  assert.match(r.reason, /2001:db8::6/);
  assert.equal(g.verifiedOk(), false);
});

test('exitCheck: v4 regression — raw dotted-quad samples/pins behave exactly as before', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '198.51.100.9',
    sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '203.0.113.7',
  });
  assert.equal(r.pinMatch, false, 'v4 mismatch still mismatches');
  assert.deepEqual(r.exits, ['198.51.100.9', '198.51.100.9', '198.51.100.9'], 'valid v4 samples pass through untouched');
  assert.equal(r.ok, true, 'warn mode unchanged for v4');
});

test('ipinfoClassify: 3s-cap shape, non-200 and garbage never throw', async () => {
  const bad = await ipinfoClassify({ fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({}) }) });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /503/);
  const garbage = await ipinfoClassify({ fetchImpl: async () => ({ ok: true, status: 200, json: async () => { throw new Error('not json'); } }) });
  assert.equal(garbage.ok, false);
  const asn = await ipinfoClassify({ fetchImpl: okFetch('AS1234 Mullvad VPN AB') });
  assert.equal(asn.asn, 'AS1234');
  assert.equal(asn.heuristic, true);
});

test('runEgressCheck: spacing is honored via injected sleep, samples option wins', async () => {
  const gaps = [];
  let last = -1;
  let calls = 0;
  const r = await runEgressCheck({
    samples: 5,
    sampler: async () => { calls++; return '203.0.113.7'; },
    sleep: async () => { gaps.push(++last); },
    classify: false,
  });
  assert.equal(calls, 5);
  assert.equal(gaps.length, 4, 'no sleep before the first sample');
  assert.equal(r.egress, null, 'classify:false skips the feed entirely');
});

test('existing fail-closed semantics untouched: verify() and the required gate', async () => {
  const g = armedGhost();
  // dead chain: verify fails honestly, required refuses public egress
  const v = await g.verify();
  assert.equal(v.ok, false);
  await assert.rejects(() => g.assertEgress('https://example.com/'), (e) => e.ghostRefused === true && /REFUSED/.test(e.message));
  assert.equal(await g.assertEgress('http://192.168.50.130/'), true, 'range destinations still direct');
  // an exitCheck without pinStrict must never open or close the gate
  await g.exitCheck({ sampler: async () => '203.0.113.7', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB') });
  assert.equal(g.verifiedOk(), false);
  await assert.rejects(() => g.assertEgress('https://example.com/'), (e) => e.ghostRefused === true);
});

test('status(): exitCheck field is additive and null before the first check', async () => {
  const g = armedGhost();
  assert.equal(g.status().exitCheck, null);
  await g.exitCheck({ sampler: async () => '203.0.113.7', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB') });
  assert.equal(g.status().exitCheck.verdict, 'stable');
});

// ---------- rotation-set policy (2026-09-01): the operator marks a SET of expected
// exits; exitCheck verifies the chain exits INSIDE it; a pin must be a member.

test('exitCheck: rotation SET — a stable exit inside the operator set matches (setMatch true)', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '203.0.113.7', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    exitSet: ['203.0.113.7', '198.51.100.9'],
  });
  assert.equal(r.ok, true);
  assert.equal(r.setMatch, true);
  assert.deepEqual(r.expectExitSet, ['203.0.113.7', '198.51.100.9']);
  assert.equal(r.warnings.some((x) => /ROTATION SET/.test(x)), false, 'in-policy is quiet');
});

test('exitCheck: exit OUTSIDE the set — warn mode is LOUD, ok stays true', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '192.0.2.44', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    exitSet: ['203.0.113.7', '198.51.100.9'],
  });
  assert.equal(r.ok, true, 'warn mode never closes the gate');
  assert.equal(r.setMatch, false);
  const w = r.warnings.find((x) => /OUTSIDE THE ROTATION SET/.test(x));
  assert.ok(w, 'out-of-set warning present');
  assert.match(w, /192\.0\.2\.44/);
});

test('exitCheck: pinStrict + exit outside the set FAILS CLOSED and drops verification', async () => {
  const g = armedGhost();
  g._verified = { ok: true, baselineIp: '192.0.2.1', exitIp: '192.0.2.44', at: 'then' };
  const r = await g.exitCheck({
    sampler: async () => '192.0.2.44', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    exitSet: ['203.0.113.7', '198.51.100.9'], pinStrict: true,
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /pinStrict/);
  assert.match(r.reason, /192\.0\.2\.44/);
  assert.equal(g.verifiedOk(), false, 'gate closed');
  await assert.rejects(() => g.assertEgress('https://example.com/'), (e) => e.ghostRefused === true);
});

test('exitCheck: rotation INSIDE the set is in-policy (setMatch true) — the rotating warning still fires for cf_clearance ops', async () => {
  const g = armedGhost();
  const ips = ['203.0.113.7', '198.51.100.9', '203.0.113.7'];
  let i = 0;
  const r = await g.exitCheck({
    sampler: async () => ips[i++ % ips.length], sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    exitSet: ['203.0.113.7', '198.51.100.9'],
  });
  assert.equal(r.verdict, 'rotating');
  assert.equal(r.setMatch, true, 'both observed exits are operator-approved');
  assert.ok(r.warnings.some((x) => /ROTATING/.test(x)), 'rotation itself is still surfaced honestly');
});

test('exitCheck: a PIN outside the operator set is named — strict mode fails closed', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '192.0.2.44', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '192.0.2.44', exitSet: ['203.0.113.7', '198.51.100.9'],
  });
  assert.equal(r.ok, true);
  const w = r.warnings.find((x) => /NOT A MEMBER OF THE ROTATION SET/.test(x));
  assert.ok(w, 'pin-outside-set is named even when the pin itself matches');
  const g2 = armedGhost();
  const r2 = await g2.exitCheck({
    sampler: async () => '192.0.2.44', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '192.0.2.44', exitSet: ['203.0.113.7'], pinStrict: true,
  });
  assert.equal(r2.ok, false, 'strict: a pin outside policy fails closed even when the exit equals the pin');
  assert.match(r2.reason, /NOT A MEMBER OF THE ROTATION SET/);
});

test('exitCheck: unparseable set entries are DROPPED and named — a dropped entry can never match', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => '203.0.113.7', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    exitSet: ['203.0.113.7', 'garbage-entry'],
  });
  assert.equal(r.setMatch, true);
  assert.deepEqual(r.setDropped, ['garbage-entry']);
  assert.ok(r.warnings.some((x) => /DROPPED/.test(x) && /garbage-entry/.test(x)));
});

test('exitCheck: strict + set configured but NO samples = UNPROVEN, fail-closed (mirrors pin doctrine)', async () => {
  const g = armedGhost();
  const r = await g.exitCheck({
    sampler: async () => null, sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    exitSet: ['203.0.113.7'], pinStrict: true,
  });
  assert.equal(r.ok, false);
  assert.equal(r.setMatch, null);
  assert.match(r.reason, /UNPROVEN/);
});

test('exitCheck: VARVEL_GHOST_EXIT_SET env and Ghost.setExitSet both feed the check (option wins)', async () => {
  process.env.VARVEL_GHOST_EXIT_SET = '203.0.113.7,198.51.100.9';
  try {
    const g = armedGhost();
    const r = await g.exitCheck({ sampler: async () => '198.51.100.9', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB') });
    assert.equal(r.setMatch, true, 'env-configured set honored');
    const g2 = armedGhost();
    g2.setExitSet(['192.0.2.44']);
    const r2 = await g2.exitCheck({ sampler: async () => '192.0.2.44', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB') });
    assert.equal(r2.setMatch, true, 'engine-configured set honored');
    const r3 = await g2.exitCheck({ sampler: async () => '192.0.2.44', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'), exitSet: ['192.0.2.44', '203.0.113.7'] });
    assert.deepEqual(r3.expectExitSet, ['192.0.2.44', '203.0.113.7'], 'explicit option wins over engine/env');
  } finally { delete process.env.VARVEL_GHOST_EXIT_SET; }
});

test('exitCheck: the engagement pin record is kept for the audit ledger (campaign ghost.engagement reads ghost._pin)', async () => {
  const g = armedGhost();
  await g.exitCheck({
    sampler: async () => '203.0.113.7', sleep: noSleep, fetchImpl: okFetch('AS1234 Mullvad VPN AB'),
    expectExit: '203.0.113.7', exitSet: ['203.0.113.7'],
  });
  assert.equal(g._pin.expectExit, '203.0.113.7');
  assert.deepEqual(g._pin.exitSet, ['203.0.113.7']);
  assert.ok(g._pin.at);
});
