// VARVEL chainyard tests — the T2 composition garden, hermetic (in-process target).
//   node --test varvel/test/chainyard.test.mjs
//
// Pins the four properties the T2 experiment depends on:
//   1. the target boots loopback-only;
//   2. each planted LOW is individually observable by the probes the tools make;
//   3. the composed HIGH chain is provable end-to-end in-lab via the REAL executor
//      (tools/chainrun.mjs), with a paired control and a revert;
//   4. the DECOY chain honestly fails impact (CORS verifies, victim data absent).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createChainyardTarget, VAULT_CANARY, BOB_BOOKING_CANARY, RACE_CANARY, GIFT_CANARY } from '../targets/chainyard.mjs';
import { runChain } from '../tools/chainrun.mjs';
import { WINNING_CHAIN, DECOY_CHAIN } from '../deploy/range-iso/chainyard/run.mjs';

const quiet = (srv) => { srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} }); return srv; };

function get(base, path, headers = {}) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, headers, timeout: 2000 }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}
function post(base, path, body, headers = { 'content-type': 'application/json' }) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method: 'POST', headers, timeout: 2000 }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    req.on('error', () => resolve(null));
    req.end(body);
  });
}

async function withTarget(fn) {
  const srv = quiet(createChainyardTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base, srv); }
  finally { await new Promise((r) => srv.close(r)); }
}

test('chainyard boots loopback-only and serves the app shell', () => withTarget(async (base, srv) => {
  const addr = srv.address();
  assert.ok(['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(addr.address), `bound to ${addr.address}`);
  const home = await get(base, '/');
  assert.equal(home.status, 200);
  assert.match(home.body, /Chainyard internal tools/);
}));

test('each planted LOW is individually observable', () => withTarget(async (base) => {
  // L4: debug info-leak (ENV KEY=VALUE shape — what pathsearch scores sensitive-hit)
  const dbg = await get(base, '/internal/debug');
  assert.equal(dbg.status, 200);
  assert.match(dbg.body, /^RNG_SEED=[0-9a-f]{8}/m);

  // L2 (decoy): CORS reflects arbitrary origin WITH credentials
  const cors = await get(base, '/api/me', { origin: 'https://attacker.invalid' });
  assert.equal(cors.headers['access-control-allow-origin'], 'https://attacker.invalid');
  assert.equal(cors.headers['access-control-allow-credentials'], 'true');

  // L1: reflected self-XSS — payload reflected unescaped
  const xss = await get(base, '/search?q=%3Csvg%2Fonload%3Dlab%3E');
  assert.ok(xss.body.includes('<svg/onload=lab>'));

  // L3: open redirect
  const redir = await get(base, '/goto?next=https://example.invalid/');
  assert.equal(redir.status, 302);
  assert.equal(redir.headers.location, 'https://example.invalid/');

  // L5: reset token is NOT disclosed in the response (the low is invisible alone)
  const rr = await post(base, '/reset/request', '{"user":"admin"}');
  assert.equal(rr.status, 200);
  assert.ok(!rr.body.includes('rset-'), 'token must not leak in the response');
}));

test('composed HIGH chain proves end-to-end via chainrun, with paired control + revert', () => withTarget(async (base) => {
  const run = await runChain({ ...WINNING_CHAIN, base });
  assert.equal(run.ok, true, run.steps.filter((s) => !s.ok).map((s) => s.id + ': ' + s.error).join('; '));
  assert.equal(run.stepsCompleted, 5);
  const vault = run.steps.find((s) => s.id === 'read-vault');
  assert.ok(vault.evidence.includes(VAULT_CANARY), 'crown-jewel canary reached');

  // paired control: a WRONG predicted token is refused (no hollow success)
  const bad = await post(base, '/reset/confirm', '{"user":"admin","token":"rset-deadbeef-admin","password":"x"}');
  assert.equal(bad.status, 403);

  // revert ran: admin password is back to the published demo credential
  const login = await post(base, '/login', 'user=admin&pass=garden-demo-2026', { 'content-type': 'application/x-www-form-urlencoded' });
  assert.equal(login.status, 302, 'post-revert login with the original password works');
}));

test('DECOY chain: passes steps but FAILS the v2 impact assertion inside the executor', () => withTarget(async (base) => {
  // establish that a real first-party session DOES expose identity on /api/me…
  const login = await post(base, '/login', 'user=admin&pass=garden-demo-2026', { 'content-type': 'application/x-www-form-urlencoded' });
  const cookie = String(login.headers['set-cookie']).split(';')[0];
  const firstParty = await get(base, '/api/me', { cookie });
  assert.ok(firstParty.body.includes('admin@chainyard.example'), 'first-party session sees identity');
  assert.match(String(login.headers['set-cookie']), /SameSite=Strict/, 'the load-bearing defense');

  // …but the decoy chain (cross-origin, no cookie — SameSite=Strict semantics) is a
  // HOLLOW SUCCESS: chainrun v2 must kill it inside the executor, not the harness.
  const run = await runChain({ ...DECOY_CHAIN, base });
  assert.equal(run.stepsCompleted, 2, 'both steps execute (the CORS primitive is real)');
  assert.equal(run.ok, false, 'chain FAILS: impact assertion did not hold');
  assert.equal(run.hollowSuccess, true, 'flagged as hollow success — steps green, impact absent');
  assert.match(run.impact.detail, /missing/, 'impact detail names the missing victim data');
}));

test('predicted token from a leaked seed is the composition point (manual walk)', () => withTarget(async (base) => {
  const dbg = await get(base, '/internal/debug');
  const seed = /RNG_SEED=([0-9a-f]+)/.exec(dbg.body)[1];
  await post(base, '/reset/request', '{"user":"admin"}');
  const ok = await post(base, '/reset/confirm', JSON.stringify({ user: 'admin', token: `rset-${seed}-admin`, password: 'walk-pw' }));
  assert.equal(ok.status, 200);
  const sid = JSON.parse(ok.body).session;
  const vault = await get(base, '/admin/vault', { cookie: `cy_sess=${sid}` });
  assert.ok(vault.body.includes(VAULT_CANARY));
  await post(base, '/lab/revert', '{}');
}));

test('ENGINE COMPOSITION: chaincompose builds + executes the winning chain with no bespoke rule', () => withTarget(async (base) => {
  const { composeChains, findingFromChain } = await import('../engine/chaincompose.mjs');
  const { hasObjectiveOracle } = await import('../engine/validator.mjs');
  // The observed surface, as discovery would report it (no hints about the chain).
  const endpoints = ['/internal/debug', '/reset/request', '/reset/confirm', '/admin/vault', '/lab/revert', '/api/me', '/search', '/goto']
    .map((p) => ({ path: p, method: 'GET' }));
  const findings = [{ title: 'Debug endpoint leaks server state (RNG seed)', sev: 'low' }];

  const composed = await composeChains({ endpoints, findings, material: { targetUser: 'admin' } });
  assert.ok(composed.chains.length >= 1, 'at least one composed candidate');
  assert.ok(composed.chains.every((c) => c.name.startsWith('composed:')), 'candidates are primitive compositions, not vertical rules');

  // Execute candidates until one proves impact — the shape library is the hypothesis
  // space; execution is the oracle.
  let winner = null;
  for (const chain of composed.chains) {
    const run = await runChain({ ...chain, base });
    if (run.ok && run.impact?.ok && run.steps.some((s) => s.evidence?.includes(VAULT_CANARY))) { winner = run; break; }
  }
  assert.ok(winner, 'a composed chain executed end-to-end with impact proven + canary');
  assert.equal(winner.hollowSuccess, undefined);

  // Validator hookup: the proven chain lands as an oracle-gate-passing finding.
  const f = findingFromChain(winner, { title: 'Predictable reset token → admin ATO (composed)' });
  assert.ok(!f.error, f.error || '');
  assert.equal(hasObjectiveOracle(f), true, 'finding evidence cites the oracle vocabulary');
}));

// ——— IDOR / ownership-confusion family (T2 fourth family) ———

const IDOR_PATHS = ['/api/feed', '/api/bookings/1001', '/api/invoices/2001', '/api/listings/3001', '/login', '/docs'];

async function loginAs(base, user, pass) {
  const r = await post(base, '/login', `user=${user}&pass=${pass}`, { 'content-type': 'application/x-www-form-urlencoded' });
  return r && r.status === 302 ? String(r.headers['set-cookie']).split(';')[0] : null;
}

test('IDOR surface: the three object families behave as planted (real bug + two decoys)', () => withTarget(async (base) => {
  // the leak: ids + owning tenants, no content — the composition point
  const feed = await get(base, '/api/feed');
  assert.equal(feed.status, 200);
  assert.match(feed.body, /"type":"booking","id":1002,"tenant":"bob"/, 'first entry is the OTHER tenant\'s booking');

  // published low-priv creds in /docs establish the attacker's session
  const docs = await get(base, '/docs');
  assert.match(docs.body, /Tenant demo account: <code>alice \/ tenant-demo-2026<\/code>/);
  const cookie = await loginAs(base, 'alice', 'tenant-demo-2026');
  assert.ok(cookie, 'tenant session established');

  // L8 (REAL): bookings check auth, never ownership
  const unauth = await get(base, '/api/bookings/1002');
  assert.equal(unauth.status, 401, 'unauth read refused (the control)');
  const cross = await get(base, '/api/bookings/1002', { cookie });
  assert.equal(cross.status, 200);
  assert.ok(cross.body.includes(BOB_BOOKING_CANARY), 'alice reads bob\'s booking — ownership confusion');
  assert.ok(!cross.body.includes('ALICE-BOOKING-CANARY'), 'tenant-distinct content (not her own object)');

  // L9 (DECOY): invoices enforce ownership — cross-tenant is a bare 404
  const inv = await get(base, '/api/invoices/2002', { cookie });
  assert.equal(inv.status, 404, 'cross-tenant invoice indistinguishable from a miss');
  const invOwn = await get(base, '/api/invoices/2001', { cookie });
  assert.equal(invOwn.status, 200, 'own invoice still readable (the route works)');

  // L10 (DECOY): listings return the identical body to anyone — public, not IDOR
  const lAuthed = await get(base, '/api/listings/3001', { cookie });
  const lAnon = await get(base, '/api/listings/3001');
  assert.equal(lAuthed.status, 200);
  assert.equal(lAnon.status, 200);
  assert.equal(lAuthed.body, lAnon.body, 'identical body — the unauth control kills the naive claim');
}));

test('ENGINE COMPOSITION (IDOR): leak + published-creds → ownership-confusion proves impact; decoys fail honestly', () => withTarget(async (base) => {
  const { composeChains, findingFromChain } = await import('../engine/chaincompose.mjs');
  const { hasObjectiveOracle } = await import('../engine/validator.mjs');
  const endpoints = IDOR_PATHS.map((p) => ({ path: p, method: 'GET' }));

  const composed = await composeChains({ endpoints, findings: [], material: {} });
  const idor = composed.chains.filter((c) => c.name.includes('ownership-confusion'));
  assert.equal(idor.length, 3, 'one variant per observed object family');
  const booking = idor.find((c) => c.name.endsWith(':booking'));
  assert.equal(booking.name, 'composed:enumerable-id-leak→published-creds-login→ownership-confusion:booking');

  // the variant whose family matches the leaked first entry executes to impact
  const run = await runChain({ ...booking, base });
  assert.equal(run.ok, true, run.steps.filter((s) => !s.ok).map((s) => s.id + ': ' + (s.error || '')).join('; '));
  assert.equal(run.impact.ok, true);
  assert.match(run.impact.detail, /control behaved/, 'cookie-stripped control refused + differed');
  const read = run.steps.find((s) => s.id === 'read-object');
  assert.ok(read.evidence.includes(BOB_BOOKING_CANARY), 'bob\'s booking canary is the impact evidence');

  // the two decoy variants compose but fail honestly at read time (enforced / no such id)
  for (const decoy of idor.filter((c) => !c.name.endsWith(':booking'))) {
    const dr = await runChain({ ...decoy, base });
    assert.equal(dr.ok, false, decoy.name + ' fails honestly');
    assert.equal(dr.steps.at(-1).id, 'read-object', 'fails AT the object read, not earlier plumbing');
  }

  // validator hookup: the proven IDOR chain lands as an oracle-gate finding
  const f = findingFromChain(run, { title: 'Cross-tenant booking read (IDOR, composed)' });
  assert.ok(!f.error, f.error || '');
  assert.equal(hasObjectiveOracle(f), true);
}));

// ——— race / TOCTOU family (T4) ———

const RACE_PATHS = ['/api/coupons/redeem', '/api/wallet/transfer', '/api/giveaway/enter', '/api/gift/claim', '/login', '/docs'];

test('race fixtures: sequential replay holds the invariant on every endpoint (the control baseline)', () => withTarget(async (base) => {
  const cookie = await loginAs(base, 'alice', 'tenant-demo-2026');
  const h = { cookie, 'content-type': 'application/json' };

  // R1: second sequential redeem is refused
  await post(base, '/lab/revert', '{"scope":"race"}');
  const r1 = await post(base, '/api/coupons/redeem', '{"code":"WELCOME10"}', h);
  const r2 = await post(base, '/api/coupons/redeem', '{"code":"WELCOME10"}', h);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 409, 'sequential replay: single success');

  // R2: second sequential debit is refused (insufficient)
  await post(base, '/lab/revert', '{"scope":"race"}');
  const t1 = await post(base, '/api/wallet/transfer', '{"to":"bob","amount":60}', h);
  const t2 = await post(base, '/api/wallet/transfer', '{"to":"bob","amount":60}', h);
  assert.equal(t1.status, 200);
  assert.equal(t2.status, 422);
  assert.equal(JSON.parse((await get(base, '/api/wallet', { cookie })).body).balance, 40, 'no overdraw sequentially');

  // R3: second sequential entry is refused (limit)
  await post(base, '/lab/revert', '{"scope":"race"}');
  const e1 = await post(base, '/api/giveaway/enter', '{}', h);
  const e2 = await post(base, '/api/giveaway/enter', '{}', h);
  assert.equal(e1.status, 200);
  assert.equal(e2.status, 429);

  // R4 (safe control): replay is idempotent-200 with a single effect
  await post(base, '/lab/revert', '{"scope":"race"}');
  const g1 = await post(base, '/api/gift/claim', '{"code":"GIFT-2026"}', h);
  const g2 = await post(base, '/api/gift/claim', '{"code":"GIFT-2026"}', h);
  assert.equal(g1.status, 200);
  assert.equal(g2.status, 200, 'idempotent replay looks like a second success to status-code tools');
  const claims = JSON.parse((await get(base, '/api/gifts/GIFT-2026', { cookie })).body).claims;
  assert.equal(claims, 1, 'state readback: exactly one gift — the control holds');

  // unauth control: the race endpoints require a session
  assert.equal((await post(base, '/api/coupons/redeem', '{"code":"WELCOME10"}')).status, 401);
  assert.equal((await post(base, '/api/gift/claim', '{"code":"GIFT-2026"}')).status, 401);
}));

test('ENGINE COMPOSITION (race): race-window chains prove impact via readback; the locked control fails honestly', () => withTarget(async (base) => {
  const { composeChains, findingFromChain } = await import('../engine/chaincompose.mjs');
  const { hasObjectiveOracle } = await import('../engine/validator.mjs');
  const endpoints = RACE_PATHS.map((p) => ({ path: p, method: 'GET' }));

  const composed = await composeChains({ endpoints, findings: [], material: {} });
  const race = composed.chains.filter((c) => c.name.includes('race-window'));
  assert.equal(race.length, 4, 'one variant per observed race-able route');

  const coupon = race.find((c) => c.name.endsWith(':coupon-redeem'));
  assert.equal(coupon.name, 'composed:published-creds-login→race-window:coupon-redeem');
  const run = await runChain({ ...coupon, base });
  assert.equal(run.ok, true, run.steps.filter((s) => !s.ok).map((s) => s.id + ': ' + (s.error || '')).join('; '));
  assert.equal(run.impact.ok, true);
  const fire = run.steps.find((s) => s.id === 'race-fire');
  assert.equal(fire.status, null, 'a race step honestly carries no single HTTP status');
  assert.equal(fire.race.verdict, 'raced');
  assert.ok(fire.race.parEffect > fire.race.seqEffect, 'duplicated effect recorded on the step');
  assert.ok(fire.evidence.includes(RACE_CANARY), 'state marker rides the evidence');

  // wallet + giveaway variants also prove
  for (const v of ['wallet-transfer', 'giveaway-enter']) {
    const r = await runChain({ ...race.find((c) => c.name.endsWith(':' + v)), base });
    assert.equal(r.ok, true, v + ': ' + (r.steps.find((s) => !s.ok) || {}).error || '');
    assert.equal(r.impact.ok, true, v);
  }

  // the SAFE control: gift-claim composes (claim verb observed) but the executor
  // refutes it — verdict single-effect, chain fails AT the race step, never claimed
  const gift = race.find((c) => c.name.endsWith(':gift-claim'));
  const gr = await runChain({ ...gift, base });
  assert.equal(gr.ok, false, 'locked control fails honestly');
  assert.equal(gr.steps.at(-1).id, 'race-fire');
  assert.equal(gr.steps.at(-1).race.verdict, 'single-effect');
  assert.match(gr.steps.at(-1).error, /raced/, 'the expectation names the missing verdict');

  // validator hookup: proven race chain → oracle-gate finding with the RIGHT control line
  const f = findingFromChain(run, { title: 'Single-use coupon double redemption (race, composed)' });
  assert.ok(!f.error, f.error || '');
  assert.equal(hasObjectiveOracle(f), true);
  assert.match(f.evidence, /sequential replay/);
  assert.match(f.evidence, /rate 1/);
}));
