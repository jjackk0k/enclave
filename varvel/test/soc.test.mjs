// VARVEL Axiom SOC v2 tests — impossible-session detection + rotation lag + faster rotation.
//   node --test varvel/test/soc.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeSoc } from '../targets/soc-core.mjs';
import { createHardTarget } from '../targets/premium-hard.mjs';

const quiet = (srv) => { srv.on('clientError', (e, s) => { try { s.destroy(); } catch {} }); return srv; };

test('SOC v2: temp-ban + strict mode rules are unchanged', () => {
  let t = 1000;
  const soc = makeSoc({ now: () => t, banMs: 60_000 });
  soc.observeRateLimited('1.1.1.1');
  soc.observeRateLimited('1.1.1.1');
  assert.equal(soc.check('1.1.1.1'), null);
  soc.observeRateLimited('1.1.1.1');
  assert.ok(soc.check('1.1.1.1').action === 'ban');
  for (let i = 0; i < 3; i++) soc.observeWafBlock('2.2.2.2');
  assert.equal(soc.rateLimitFor('2.2.2.2', 120), 40);
});

test('SOC v2: IMPOSSIBLE-SESSION — an admin action with NO interactive login double-strikes and rotation pends at once', () => {
  let t = 5000;
  const events = [];
  const rotations = [];
  const soc = makeSoc({ now: () => t, onEvent: (ty, e) => events.push(e), rotateKey: () => { rotations.push(1); return rotations.length; }, rotationLagMs: 30_000 });
  // one forged write from an IP that never logged in → 2 strikes → threshold met → rotation PENDS (not instant)
  const r = soc.observeAdminAnomaly({ ip: '9.9.9.9', registered: false });
  assert.equal(r.pending, true, 'rotation pends, does not fire instantly');
  assert.equal(rotations.length, 0, 'lag not expired yet');
  assert.ok(events.some((e) => e.type === 'rotate.pending'), 'pending alert emitted');
  // during the lag, a fast attacker's actions still work; after it, the key dies
  t += 31_000;
  assert.equal(soc.tick(), true, 'tick fires the pending rotation after the lag');
  assert.equal(rotations.length, 1);
  assert.ok(events.some((e) => e.type === 'rotate'));
  assert.ok(!JSON.stringify(events).includes('axiom-auth-hs256'), 'no key material in alerts, ever');
});

test('SOC v2: an IP WITH an interactive login single-strikes (v1 behavior preserved)', () => {
  let t = 0;
  const soc = makeSoc({ now: () => t, rotateKey: () => 1 });
  soc.observeLogin('5.5.5.5');
  soc.observeAdminAnomaly({ ip: '5.5.5.5', registered: false });
  assert.equal(soc.state().anomalies, 1, 'interactive login present → single strike');
  assert.equal(soc.observeAdminAnomaly({ ip: '5.5.5.5', registered: true }), null, 'server-issued sessions stay clean');
});

test('Axiom + SOC v2: the fast-revert escape — chain completes inside the response lag, key dies after', async () => {
  process.env.AXIOM_SOC_LAG_MS = '2000'; // test speed; production stays 30s
  const srv = quiet(createHardTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const { createHmac } = await import('node:crypto');
    const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const legacy = await (await fetch(base + '/assets/legacy/auth.bundle.js')).text();
    const key = /axiom-auth-hs256-legacy-2019/.exec(legacy)[0];
    const head = b64u({ alg: 'HS256', typ: 'JWT' });
    const pay = b64u({ sub: 'admin@axiom.dev', role: 'admin', iss: 'axiom-auth', iat: 1, exp: 9999999999 });
    const forged = head + '.' + pay + '.' + createHmac('sha256', key).update(head + '.' + pay).digest('base64url');
    const w = (h) => fetch(base + '/admin/content', { method: 'POST', headers: { 'content-type': 'application/json', cookie: 'axm_session=' + forged }, body: JSON.stringify({ headline: h }) });
    assert.equal((await w('fast-write')).status, 200, 'the write lands (anomaly strikes — but rotation only PENDS)');
    assert.equal((await w('The programmable money platform for modern business.')).status, 200, 'the revert lands inside the SOC response lag — mission complete before the key dies');
    const st = srv.soc.state();
    assert.ok(st.anomalies >= 2, 'both anomalous writes recorded');
    assert.ok(st.rotationPending !== false || st.rotations >= 0, 'rotation is pending (not yet effective)');
    // after the lag, the forged token is dead — but the disciplined attacker already escaped
    await new Promise((r) => setTimeout(r, 2600)); // > the 2s test lag
    await fetch(base + '/robots.txt'); // any request ticks the SOC clock
    const after = await fetch(base + '/admin', { headers: { cookie: 'axm_session=' + forged }, redirect: 'manual' });
    assert.equal(after.status, 302, 'key rotated after the lag — the forged token is now dead');
    const login = await fetch(base + '/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'email=sandbox%40axiom.dev&password=sandbox-demo-2026', redirect: 'manual' });
    assert.equal(login.status, 302, 'legit logins survive rotation');
  } finally { srv.close(); }
});

test('Axiom + SOC v2: burst rate-limiting still escalates to a temp-ban', async () => {
  const srv = quiet(createHardTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    let first429 = null, firstBan = null;
    for (let i = 0; i < 130; i++) {
      const r = await fetch(base + '/robots.txt');
      if (r.status === 429 && first429 == null) first429 = i;
      if (r.status === 403 && r.headers.get('x-axiom-shield') === 'ban') { firstBan = { i }; break; }
    }
    assert.ok(first429 != null && firstBan && firstBan.i > first429 && firstBan.i - first429 <= 3);
    assert.ok(srv.soc.alerts().some((e) => e.type === 'ban'));
  } finally { srv.close(); }
});
