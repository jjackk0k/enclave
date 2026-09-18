// VARVEL logicdiscover tests — T3b: source-level invariant discovery from OBSERVED
// HTTP TRAFFIC alone (no x-invariant annotations, no spec fetch), calibrated
// against logiclab.
//   node --test varvel/test/logicdiscover.test.mjs
//
// Pins: (1) discovery derives the full 8-kind candidate set per surface from a
// realistic traffic recording (values from correlations/vocab, never hard-coded
// per-target), with an honest dropped list; (2) thin traffic yields honest drops,
// not fabricated candidates; (3) CALIBRATION — every discovered candidate is
// PROBED against a fresh logiclab: ≥6/8 planted violations rediscovered from
// traffic alone (measured: see the assertion message), ZERO violated-claims on
// the /api/safe/* mirror, the accepted-but-ineffective decoy sorted 'enforced';
// (4) discovered candidates feed the chaincompose invariant-violation family
// with NO spec endpoint observed and execute through chainrun to oracle-gated
// findings.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createLogiclabTarget, TENANT_USER, TENANT_PASS } from '../targets/logiclab.mjs';
import { recordLogicTraffic } from './fixtures/logictraffic.mjs';
import { discoverInvariants } from '../engine/logicdiscover.mjs';
import { runLogicProbe } from '../tools/logicprobe.mjs';
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

// One shared recording for the pure-discovery tests (hermetic, in-process).
async function recorded() {
  const { observations, close } = await recordLogicTraffic();
  try { return { observations, result: discoverInvariants(observations) }; }
  finally { await close(); }
}

const EXPECTED_KINDS = ['server-authoritative', 'bounds-min', 'bounds-max', 'flow-order', 'usage-limit', 'role-gate', 'state-machine', 'actor-separation'];

// ——— 1. discovery from traffic alone ———

test('DISCOVERY: the 8-kind candidate set is derived per surface from traffic alone', async () => {
  const { observations, result } = await recorded();
  const { candidates, dropped } = result;

  assert.ok(observations.length > 40, 'a realistic recording (journeys, not single calls)');
  assert.ok(!observations.some((o) => /openapi|swagger|api-docs/i.test(o.path)), 'the recording NEVER touches a spec document');

  assert.equal(candidates.length, 16, '8 kinds × 2 surfaces: ' + candidates.map((c) => c.kind + '@' + c.path).join(' | '));
  for (const surface of ['/api', '/api/safe']) {
    const kinds = new Set(candidates.filter((c) => (surface === '/api/safe' ? c.path.startsWith('/api/safe/') : !c.path.startsWith('/api/safe/'))).map((c) => c.kind));
    assert.deepEqual([...kinds].sort(), [...EXPECTED_KINDS].sort(), surface + ' surface derives all 8 kinds');
  }
  for (const c of candidates) {
    assert.equal(c.source, 'traffic-discovery');
    assert.ok(c.violation && c.violation.method && c.violation.path, c.id + ' carries a violation request');
    assert.ok(c.readback && c.readback.path, c.id + ' carries a state readback oracle');
    assert.ok(c.derived && Array.isArray(c.derived.values) && typeof c.derived.basis === 'string', c.id + ' carries derived values + basis');
    assert.ok(c.evidence, c.id + ' carries an evidence trail');
  }

  // derived VALUES come from the traffic correlations/vocabulary, not the fixture
  const at = (kind, path) => candidates.find((c) => c.kind === kind && c.path === path);
  assert.equal(at('bounds-min', '/api/payments').derived.values[0], -100, 'negative probe = −10× the max observed debit');
  assert.equal(at('server-authoritative', '/api/orders').derived.values[0], 0.01, 'price tamper to 0.01');
  assert.equal(at('bounds-max', '/api/bookings').derived.values[0], 5, 'cap(4)+1 from the observed constant capacity field');
  assert.equal(at('usage-limit', '/api/coupons/apply').derived.values[0], 'SAVE20', 'the second distinct observed code');
  assert.equal(at('role-gate', '/api/rides/RIDE1/status').derived.values[0], 'completed', 'the unobserved canonical terminal state');
  assert.equal(at('state-machine', '/api/orders/{{id}}/cancel').derived.toState, 'cancelled');
  assert.equal(at('state-machine', '/api/orders/{{id}}/cancel').derived.preState, 'delivered', 'probe from an entity\'s FINAL observed state');
  assert.equal(at('actor-separation', '/api/referrals').derived.values[0], '{{self}}', 'own operand resolved at runtime via selfFrom');
  assert.equal(at('actor-separation', '/api/referrals').selfFrom.path, '/api/me');

  // honesty: flows that were never observed end-to-end are DROPPED with reasons
  assert.ok(dropped.length >= 2, 'honest drops recorded');
  assert.ok(dropped.every((d) => typeof d.reason === 'string' && d.reason.length > 10));
});

test('DISCOVERY HONESTY: thin traffic yields drops, not fabricated candidates', () => {
  const thin = [
    { seq: 0, session: 's', method: 'POST', path: '/api/thing', status: 200, req: { amount: 5 }, res: { ok: true } },
    { seq: 1, session: 's', method: 'POST', path: '/api/thing', status: 200, req: { amount: 3 }, res: { ok: true } },
  ];
  const { candidates, dropped } = discoverInvariants(thin);
  assert.equal(candidates.length, 0, 'no candidate without a derivable control+readback oracle');
  assert.ok(dropped.length >= 1, 'the attempt is honestly recorded');
  assert.ok(dropped.some((d) => /readback|oracle|observ/i.test(d.reason)), 'drop reasons cite the missing oracle: ' + JSON.stringify(dropped));
});

// ——— 2. calibration against a fresh logiclab ———

test('CALIBRATION: ≥6/8 planted violations rediscovered from traffic alone; ZERO violated-claims on the safe mirror', async () => {
  const { result } = await recorded();
  const { candidates } = result;
  await withLab(async (base) => {
    const cookie = await login(base);
    assert.ok(cookie);
    const verdicts = new Map();
    for (const c of candidates) {
      const pr = await runLogicProbe(base, c, { headers: { cookie }, resetPath: '/lab/revert', timeout: 4000 });
      verdicts.set(c.kind + ' ' + c.path, pr.verdict + (pr.naiveWouldFlag ? ' (naive flags)' : ''));
    }
    const vuln = candidates.filter((c) => !c.path.startsWith('/api/safe/'));
    const safe = candidates.filter((c) => c.path.startsWith('/api/safe/'));
    const vViol = vuln.filter((c) => verdicts.get(c.kind + ' ' + c.path).startsWith('violated')).length;
    const sViol = safe.filter((c) => verdicts.get(c.kind + ' ' + c.path).startsWith('violated')).length;
    const map = [...verdicts.entries()].map(([k, v]) => k + ' → ' + v).join('\n  ');
    assert.ok(vViol >= 6, `GATE: ≥6/8 planted violations rediscovered from traffic alone — measured ${vViol}/8\n  ${map}`);
    assert.equal(vViol, 8, `full recall on the lab (all 8 kinds prove from traffic-derived candidates)\n  ${map}`);
    assert.equal(sViol, 0, `ZERO violated-claims on the /api/safe/* mirror\n  ${map}`);
    const decoy = verdicts.get('server-authoritative /api/safe/orders');
    assert.ok(decoy && decoy.startsWith('enforced'), 'the accepted-but-ineffective decoy sorts enforced: ' + decoy);
    assert.ok(decoy.includes('naive flags'), '…while the naive status-code heuristic would flag it');
  });
});

// ——— 3. discovered candidates feed composed chains ———

test('CHAIN INTEGRATION: invariant chains compose with NO spec observed and execute to oracle-gated findings', async () => {
  const { observations, result } = await recorded();
  const { candidates } = result;
  const { composeChains, findingFromChain } = await import('../engine/chaincompose.mjs');
  const { hasObjectiveOracle } = await import('../engine/validator.mjs');

  const seen = new Set();
  const endpoints = [];
  for (const o of observations) {
    const k = o.method + ' ' + o.path;
    if (seen.has(k)) continue;
    seen.add(k);
    endpoints.push({ method: o.method, path: o.path });
  }
  assert.ok(!endpoints.some((e) => /openapi|swagger|api-docs/i.test(e.path)), 'no spec endpoint in the observed surface');

  const composed = await composeChains({ endpoints, findings: [], material: { discoveredInvariants: candidates }, maxChains: 40 });
  const inv = composed.chains.filter((c) => c.name.includes('invariant-violation'));
  assert.equal(inv.length, 16, '8 kinds × 2 surfaces compose from discovered candidates alone: ' + inv.map((c) => c.name).join(' | '));

  await withLab(async (base) => {
    const winner = await runChain({ ...inv.find((c) => c.name.endsWith(':payment-negative')), base });
    assert.equal(winner.ok, true, 'payment-negative chain runs: ' + ((winner.steps.find((s) => !s.ok) || {}).error || ''));
    assert.equal(winner.impact.ok, true);
    assert.equal(winner.steps.find((s) => s.invariant).invariant.verdict, 'violated');
    const f = findingFromChain(winner, { title: 'Negative-amount payment credits wallet (traffic-discovered)' });
    assert.ok(!f.error, f.error || '');
    assert.equal(hasObjectiveOracle(f), true, 'the finding is oracle-gated');

    const decoy = await runChain({ ...inv.find((c) => c.name.endsWith(':order-price-tamper:safe')), base });
    assert.equal(decoy.ok, false, 'safe variant fails honestly');
    assert.equal(decoy.steps.find((s) => s.invariant).invariant.verdict, 'enforced');
  });
});
