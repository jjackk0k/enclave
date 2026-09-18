// VARVEL logiclab tests — the T3 invariant garden, hermetic (in-process target).
//   node --test varvel/test/logiclab.test.mjs
//
// Pins: (1) the fixture plants what it claims (8 violations observable by hand),
// (2) the extractor derives candidates from the SPEC alone (violation values from
// schema bounds/enums/flows — never hard-coded), (3) the prover's verdict oracle
// (control + readback) sorts violated/enforced/inconclusive while the naive
// status-code heuristic flags the enforced decoy, (4) composed invariant chains
// execute through chainrun to oracle-gate findings, safe variants fail honestly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createLogiclabTarget, TENANT_USER, TENANT_PASS, LOGIC_CANARY } from '../targets/logiclab.mjs';
import { extractInvariants, findCandidate } from '../engine/logicinvariants.mjs';
import { runLogicProbe, classifyLogic, naiveLogicFlag } from '../tools/logicprobe.mjs';
import { runChain } from '../tools/chainrun.mjs';

const quiet = (srv) => { srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} }); return srv; };

function req(base, method, path, { body, cookie } = {}) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const headers = {};
    if (cookie) headers.cookie = cookie;
    if (body != null) headers['content-type'] = 'application/json';
    const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, timeout: 2000 }, (res) => {
      let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: b }));
    });
    r.on('error', () => resolve(null));
    if (body != null) r.write(typeof body === 'string' ? body : JSON.stringify(body));
    r.end();
  });
}

async function withLab(fn) {
  const srv = quiet(createLogiclabTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base, srv); }
  finally { await new Promise((r) => srv.close(r)); }
}

async function login(base) {
  const r = await req(base, 'POST', '/login', { body: new URLSearchParams({ user: TENANT_USER, pass: TENANT_PASS }).toString() });
  return r && r.status === 302 ? String(r.headers['set-cookie']).split(';')[0] : null;
}

const SPEC_CACHE = new Map();
async function specOf(base) {
  if (!SPEC_CACHE.has(base)) SPEC_CACHE.set(base, JSON.parse((await req(base, 'GET', '/openapi.json')).body));
  return SPEC_CACHE.get(base);
}

// ——— pure extractor ———

test('extractor derives violation values from the schema/spec, not from the fixture', () => withLab(async (base) => {
  const ex = extractInvariants(await specOf(base));
  assert.equal(ex.candidates.length, 16, '8 vuln + 8 safe candidates');
  assert.equal(ex.dropped.length, 0);
  const byId = Object.fromEntries(ex.candidates.map((c) => [c.id, c]));
  assert.equal(byId.createPayment.derived.values[0], -100, 'bounds-min: derived below schema minimum 1 (zero-magnitude escalated)');
  assert.equal(byId.createBooking.derived.values[0], 5, 'bounds-max: schema maximum 4 → 5');
  assert.equal(byId.createOrder.derived.values[0], 0.01, 'server-authoritative: near-zero tamper derived');
  assert.equal(byId.applyCoupon.derived.values[0], 'SAVE20', 'usage-limit: the OTHER enum operand');
  assert.equal(byId.setRideStatus.derived.values[0], 'completed', 'role-gate: terminal enum state');
  assert.equal(byId.createReferral.derived.values[0], '{{self}}', 'actor-separation: own operand resolved at runtime');
  assert.equal(byId.cancelOrder.derived.toState, 'cancelled');
  assert.equal(byId.cancelOrder.derived.preState, 'delivered', 'setup drives the order to delivered');
  assert.deepEqual([...new Set(ex.candidates.map((c) => c.kind))].sort(),
    ['actor-separation', 'bounds-max', 'bounds-min', 'flow-order', 'role-gate', 'server-authoritative', 'state-machine', 'usage-limit']);
}));

test('extractor honestly drops a candidate the spec cannot motivate', () => {
  // a cancel transition whose setup stays within the allowed from-states is NOT a violation
  const ex = extractInvariants({
    openapi: '3.0.3', info: { title: 't' },
    'x-state-machines': { order: { states: ['pending', 'paid', 'cancelled'], transitions: [{ name: 'cancel', from: ['pending', 'paid'], to: 'cancelled' }, { name: 'pay', from: ['pending'], to: 'paid' }] } },
    paths: {
      '/api/orders/{id}/cancel': {
        post: {
          operationId: 'cancelOrder',
          'x-invariant': {
            kind: 'state-machine', machine: 'order', transition: 'cancel',
            setup: [{ method: 'POST', path: '/api/orders', body: {}, save: { orderId: '"id":"(\\w+)"' } }, { method: 'POST', path: '/api/orders/{{orderId}}/pay', body: {} }],
            controlSetup: [], control: {}, violationPath: '/api/orders/{{orderId}}/cancel',
            readback: { method: 'GET', path: '/api/orders/{{orderId}}', fields: { status: '"status":"(\\w+)"' }, expect: { status: 'cancelled' } },
          },
        },
      },
    },
  });
  assert.equal(ex.candidates.length, 0, 'setup reaches "paid" — an allowed from-state — so no probe is emitted');
  assert.match(ex.dropped[0].reason, /allowed from-state/);
});

test('classifyLogic: the verdict vocabulary, incl. the accepted-but-ineffective decoy', () => {
  assert.equal(classifyLogic({ controlOk: true, violationStatus: 200, effectMatch: 'attacker' }).verdict, 'violated');
  assert.equal(classifyLogic({ controlOk: true, violationStatus: 422, effectMatch: 'unchanged' }).verdict, 'enforced');
  const decoy = classifyLogic({ controlOk: true, violationStatus: 200, effectMatch: 'server' });
  assert.equal(decoy.verdict, 'enforced', '200 + server-side value in the readback = enforced, not violated');
  assert.match(decoy.detail, /accepted-but-ineffective/);
  assert.equal(classifyLogic({ controlOk: false, violationStatus: 200, effectMatch: 'attacker' }).verdict, 'inconclusive', 'no working control = no claim');
  assert.equal(classifyLogic({ controlOk: true, violationStatus: 200, effectMatch: null }).verdict, 'inconclusive', 'unreadable readback = no claim');
  assert.equal(naiveLogicFlag({ violationStatus: 200 }), true);
  assert.equal(naiveLogicFlag({ violationStatus: 422 }), false);
});

// ——— fixture behavior, by hand ———

test('fixture plants the eight violations (manual spot-checks) and the safe surface enforces them', () => withLab(async (base) => {
  const cookie = await login(base);
  assert.ok(cookie);

  // V1 negative payment credits the wallet; safe refuses
  await req(base, 'POST', '/lab/revert', { body: '{}' });
  assert.equal((await req(base, 'POST', '/api/payments', { body: { amount: -100 }, cookie })).status, 200);
  assert.equal(JSON.parse((await req(base, 'GET', '/api/wallet', { cookie })).body).balance, 200);
  assert.equal((await req(base, 'POST', '/api/safe/payments', { body: { amount: -100 }, cookie })).status, 422);

  // V2 client price trusted; the DECOY accepts but ignores
  await req(base, 'POST', '/lab/revert', { body: '{}' });
  const o = await req(base, 'POST', '/api/orders', { body: { itemId: 'ITEM1', qty: 2, price: 0.01 }, cookie });
  const oid = JSON.parse(o.body).id;
  assert.equal(JSON.parse((await req(base, 'GET', `/api/orders/${oid}`, { cookie })).body).unitPrice, 0.01, 'tampered price materialized');
  const so = await req(base, 'POST', '/api/safe/orders', { body: { itemId: 'ITEM1', qty: 2, price: 0.01 }, cookie });
  assert.equal(so.status, 200, 'decoy ACCEPTS the request (status-only tools claim here)');
  const soid = JSON.parse(so.body).id;
  assert.equal(JSON.parse((await req(base, 'GET', `/api/safe/orders/${soid}`, { cookie })).body).unitPrice, 25, 'but the readback shows the catalog price');

  // V4 step-skip: confirm an unpaid order; safe demands the payment step
  await req(base, 'POST', '/lab/revert', { body: '{}' });
  const c = JSON.parse((await req(base, 'POST', '/api/orders', { body: { itemId: 'ITEM1', qty: 1, price: 25 }, cookie })).body).id;
  assert.equal((await req(base, 'POST', '/api/checkout/confirm', { body: { orderId: c }, cookie })).status, 200);
  const co = JSON.parse((await req(base, 'GET', `/api/orders/${c}`, { cookie })).body);
  assert.equal(co.status, 'confirmed');
  assert.equal(co.paymentStatus, 'unpaid', 'confirmed WITHOUT paying — the flow invariant is broken');
  const sc = JSON.parse((await req(base, 'POST', '/api/safe/orders', { body: { itemId: 'ITEM1', qty: 1, price: 25 }, cookie })).body).id;
  assert.equal((await req(base, 'POST', '/api/safe/checkout/confirm', { body: { orderId: sc }, cookie })).status, 409);

  // V7 backward cancel of a delivered order; safe refuses
  await req(base, 'POST', '/lab/revert', { body: '{}' });
  const d = JSON.parse((await req(base, 'POST', '/api/orders', { body: { itemId: 'ITEM2', qty: 1, price: 40 }, cookie })).body).id;
  for (const a of ['pay', 'ship', 'deliver']) await req(base, 'POST', `/api/orders/${d}/${a}`, { body: {}, cookie });
  assert.equal((await req(base, 'POST', `/api/orders/${d}/cancel`, { body: {}, cookie })).status, 200);
  assert.equal(JSON.parse((await req(base, 'GET', `/api/orders/${d}`, { cookie })).body).status, 'cancelled', 'delivered → cancelled (backward)');
  const sd = JSON.parse((await req(base, 'POST', '/api/safe/orders', { body: { itemId: 'ITEM2', qty: 1, price: 40 }, cookie })).body).id;
  for (const a of ['pay', 'ship', 'deliver']) await req(base, 'POST', `/api/safe/orders/${sd}/${a}`, { body: {}, cookie });
  assert.equal((await req(base, 'POST', `/api/safe/orders/${sd}/cancel`, { body: {}, cookie })).status, 409);

  // unauth control on the write surface
  assert.equal((await req(base, 'POST', '/api/payments', { body: { amount: 5 } })).status, 401);
}));

// ——— the prover, live ———

test('runLogicProbe: 8/8 violated on the vuln surface, 0 claims on the safe surface', () => withLab(async (base) => {
  const cookie = await login(base);
  const ex = extractInvariants(await specOf(base));
  let hit = 0, claims = 0;
  const verdicts = {};
  for (const cand of ex.candidates) {
    const r = await runLogicProbe(base, cand, { headers: { cookie }, resetPath: '/lab/revert' });
    verdicts[cand.id] = r.verdict;
    if (cand.path.startsWith('/api/safe/')) { if (r.verdict === 'violated') claims++; }
    else if (r.verdict === 'violated') hit++;
  }
  assert.equal(hit, 8, 'recall: every planted violation proven — ' + JSON.stringify(verdicts));
  assert.equal(claims, 0, 'zero fabrications on the clean control surface');
}));

test('runLogicProbe: the decoy discrimination is pinned (naive flags, oracle clears)', () => withLab(async (base) => {
  const cookie = await login(base);
  const ex = extractInvariants(await specOf(base));
  const decoy = ex.candidates.find((c) => c.id === 'createSafeOrder');
  const r = await runLogicProbe(base, decoy, { headers: { cookie }, resetPath: '/lab/revert' });
  assert.equal(r.naiveWouldFlag, true, 'status-code heuristic claims the enforced decoy');
  assert.equal(r.verdict, 'enforced', 'readback oracle clears it');
  assert.equal(r.effectMatch, 'server');
}));

test('runLogicProbe never throws (unreachable base → honest inconclusive)', async () => {
  const r = await runLogicProbe('http://127.0.0.1:1', { kind: 'bounds-min', id: 'x', derived: { values: [-1] }, violation: { body: {} }, control: { body: {} }, readback: { effect: '"a":(\\d)' } }, { timeout: 250 });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.naiveWouldFlag, false);
});

// ——— composed chains through the real executor ———

const LOGIC_PATHS = ['/login', '/docs', '/openapi.json',
  '/api/payments', '/api/orders', '/api/bookings', '/api/checkout/confirm',
  '/api/coupons/apply', '/api/rides/RIDE1/status', '/api/orders/ORD-x/cancel', '/api/referrals',
  '/api/safe/orders'];

test('ENGINE COMPOSITION (invariants): all eight kinds prove impact; the safe variant fails honestly', () => withLab(async (base) => {
  const { composeChains, findingFromChain } = await import('../engine/chaincompose.mjs');
  const { hasObjectiveOracle } = await import('../engine/validator.mjs');
  const endpoints = LOGIC_PATHS.map((p) => ({ path: p, method: 'GET' }));

  const composed = await composeChains({ endpoints, findings: [], material: {} });
  const inv = composed.chains.filter((c) => c.name.includes('invariant-violation'));
  assert.equal(inv.length, 9, '8 vuln variants + the safe decoy variant: ' + inv.map((c) => c.name).join(' | '));

  let proved = 0;
  for (const chain of inv) {
    const run = await runChain({ ...chain, base });
    const step = run.steps.find((s) => s.invariant);
    if (chain.name.endsWith(':safe')) {
      assert.equal(run.ok, false, 'safe variant fails honestly');
      assert.equal(step.invariant.verdict, 'enforced');
      continue;
    }
    assert.equal(run.ok, true, chain.name + ': ' + ((run.steps.find((s) => !s.ok) || {}).error || ''));
    assert.equal(run.impact.ok, true, chain.name);
    assert.equal(step.invariant.verdict, 'violated');
    assert.equal(step.status, null, 'an invariant step honestly carries no single HTTP status');
    proved++;
  }
  assert.equal(proved, 8, 'all eight invariant kinds proved through composed chains');

  // validator hookup on one proven chain
  const winner = await runChain({ ...inv.find((c) => c.name.endsWith(':payment-negative')), base });
  const f = findingFromChain(winner, { title: 'Negative-amount payment credits wallet (composed)' });
  assert.ok(!f.error, f.error || '');
  assert.equal(hasObjectiveOracle(f), true);
  assert.match(f.evidence, /spec-valid control request/, 'the finding cites the control that actually ran');
}));
