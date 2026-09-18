// VARVEL chaincompose + tokenshape tests — pure, hermetic (no network).
//   node --test varvel/test/chaincompose.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { composeChains, findingFromChain, PRIMITIVES } from '../engine/chaincompose.mjs';
import { analyzeSamples, TOKEN_SHAPES, SEED_EXTRACT_REGEXES } from '../engine/tokenshape.mjs';
import { hasObjectiveOracle } from '../engine/validator.mjs';

const CHAINYARD_SURFACE = {
  endpoints: ['/internal/debug', '/reset/request', '/reset/confirm', '/admin/vault', '/lab/revert', '/api/me', '/search', '/goto']
    .map((p) => ({ path: p, method: 'GET' })),
  findings: [{ title: 'Debug endpoint leaks server state (RNG seed)', sev: 'low' }],
};

test('composition compiles the leak→predict→read chain from primitives (no bespoke rule)', async () => {
  const out = await composeChains({ ...CHAINYARD_SURFACE, material: { targetUser: 'admin' } });
  assert.ok(out.chains.length >= 1, out.honest);
  const names = out.chains.map((c) => c.name);
  assert.ok(names.some((n) => n.includes('leaked-token-material→predictable-reset-token:prefix-seed-user→protected-data-read')),
    'the winning typed path is among the candidates: ' + names.join(' | '));
  // one candidate per token shape — the shape is the hypothesis, execution the oracle
  assert.equal(out.chains.length, TOKEN_SHAPES.length);
  for (const c of out.chains) {
    assert.ok(c.impact && c.impact.control, 'every candidate carries the impact assertion with a paired control');
    assert.equal(c.impact.step, 'read-protected');
    // revert hygiene is LAST, never before the impact read
    const ids = c.steps.map((s) => s.id);
    assert.ok(ids.indexOf('revert') > ids.indexOf('read-protected'), 'revert after impact read');
  }
});

test('composition honestly empties when the surface lacks a link', async () => {
  // no debug/leak endpoint → the token-material root cannot be satisfied
  const out = await composeChains({
    endpoints: [{ path: '/reset/request' }, { path: '/reset/confirm' }, { path: '/admin/vault' }],
    findings: [],
  });
  assert.equal(out.chains.length, 0, 'no leak → no chain (honest empty)');
  assert.match(out.honest, /honest empty/);
  assert.ok(out.gaps.some((g) => g.primitive === 'leaked-token-material'));
});

test('typed compatibility is enforced: protected-data-read cannot root a chain', async () => {
  const out = await composeChains({
    endpoints: [{ path: '/admin/vault' }],
    findings: [],
  });
  assert.equal(out.chains.length, 0);
  // protected-data-read consumes auth-as-user; nothing provides it → never composed
  assert.ok(!out.chains.some((c) => c.primitives[0] === 'protected-data-read'));
});

test('composed steps are chainrun-shaped (declarative, extractable, expectation-checked)', async () => {
  const out = await composeChains({ ...CHAINYARD_SURFACE, material: {} });
  const c = out.chains[0];
  for (const s of c.steps) {
    assert.ok(s.id && s.path, 'step identity');
    assert.ok(s.expect && s.expect.status, 'every step has an expectation');
  }
  const consume = c.steps.find((s) => s.id === 'consume-token');
  assert.match(consume.body, /\{\{seed\}\}/, 'token renders from the threaded seed var');
  assert.ok(consume.extract && consume.extract.authcookie, 'session capture is generic (Set-Cookie header, no app-specific name)');
});

test('findingFromChain: refuses unproven chains, produces oracle-gate findings for proven ones', () => {
  const refuse = findingFromChain({ ok: true, steps: [], impact: { ok: false } });
  assert.ok(refuse.error, 'unproven impact → honest refusal');
  const refuse2 = findingFromChain({ ok: false, steps: [] });
  assert.ok(refuse2.error);

  const proven = findingFromChain({
    ok: true, chain: 'composed:x', base: 'http://127.0.0.1:9',
    stepsCompleted: 5, stepsTotal: 5,
    steps: [{ id: 'read-protected', method: 'GET', path: '/admin/vault', status: 200 }],
    impact: { ok: true, step: 'read-protected', detail: 'impact proven (assertions held, control behaved)' },
  }, { title: 't' });
  assert.ok(!proven.error);
  assert.equal(hasObjectiveOracle(proven), true, 'evidence cites chainrun reproduction + control — passes the ingest gate');
  const bare = { title: 't', sev: 'high', evidence: 'looks vulnerable', ref: 'F-01' };
  assert.equal(hasObjectiveOracle(bare), false, 'control: bare claims still fail the gate');
});

test('tokenshape.analyzeSamples: sequential detected, random is an honest negative', () => {
  const seq = analyzeSamples(['1001', '1002', '1003', '1004']);
  assert.equal(seq.predictable, true);
  assert.equal(seq.pattern, 'sequential');

  const ts = analyzeSamples(['1724800000123', '1724800000456', '1724800000999']);
  assert.equal(ts.predictable, true);
  assert.equal(ts.pattern, 'timestamp');

  const rand = analyzeSamples(['9f2a1c88', '04bd77e1', 'ccee0011']);
  assert.equal(rand.predictable, false, 'random hex is a negative result, not a guess');

  const thin = analyzeSamples(['1001', '1002']);
  assert.equal(thin.predictable, false);
  assert.match(thin.detail, /inconclusive/);
});

test('tokenshape: seed extract regex hits KEY=VALUE leaks, rejects bare noise', () => {
  const re = new RegExp(SEED_EXTRACT_REGEXES[0]);
  assert.equal(re.exec('RNG_SEED=deadbeef\nUPTIME_MS=412')[1], 'deadbeef');
  assert.equal(re.exec('UPTIME_MS=41242\nBUILD=x'), null, 'no seed key → no false extraction');
  assert.equal(TOKEN_SHAPES.find((s) => s.id === 'prefix-seed-user').render({ seed: 'abc123', user: 'admin' }), 'rset-abc123-admin');
});

test('primitive library shape: typed slots declared, observes/build present', () => {
  for (const p of PRIMITIVES) {
    assert.ok(Array.isArray(p.provides) && Array.isArray(p.consumes), p.id);
    assert.equal(typeof p.observes, 'function');
    assert.equal(typeof p.build, 'function');
  }
  assert.ok(PRIMITIVES.some((p) => p.provides.includes('impact-data')), 'a terminal primitive exists');
});

// ——— IDOR / ownership-confusion family (T2 fourth family) ———

const IDOR_SURFACE = {
  endpoints: ['/api/feed', '/api/bookings/1001', '/api/invoices/2001', '/api/listings/3001', '/login', '/docs']
    .map((p) => ({ path: p, method: 'GET' })),
  findings: [],
};

test('IDOR composition: leak + published-creds → ownership-confusion, one variant per observed family', async () => {
  const out = await composeChains({ ...IDOR_SURFACE, material: {} });
  const idor = out.chains.filter((c) => c.name.includes('ownership-confusion'));
  assert.equal(idor.length, 3, 'one composed variant per observed object family: ' + out.chains.map((c) => c.name).join(' | '));
  const names = idor.map((c) => c.name);
  for (const fam of ['booking', 'invoice', 'listing']) {
    assert.ok(names.some((n) => n === `composed:enumerable-id-leak→published-creds-login→ownership-confusion:${fam}`), fam + ' variant: ' + names.join(' | '));
  }

  const booking = idor.find((c) => c.name.endsWith(':booking'));
  // consumes-ordering: providers before the terminal read (leak/login relative order is free)
  const ids = booking.steps.map((s) => s.id);
  assert.ok(ids.indexOf('read-object') > ids.indexOf('leak-ids'), 'leaked ids before the object read');
  assert.ok(ids.indexOf('read-object') > ids.indexOf('login'), 'session before the object read');
  assert.equal(ids[ids.length - 1], 'read-object', 'terminal read is last (no revert hygiene in this family)');

  // the read renders the leaked id + session generically, never a hard-coded victim
  const read = booking.steps.find((s) => s.id === 'read-object');
  assert.equal(read.path, '/api/bookings/{{oid}}');
  assert.equal(read.headers.cookie, '{{authcookie}}');
  assert.equal(read.expect.contains, '{{owner}}', 'the OTHER tenant identity is the expectation, extracted at runtime');

  // impact assertion: victim identity in the body + paired stripped-auth control
  assert.equal(booking.impact.step, 'read-object');
  assert.equal(booking.impact.contains, '{{owner}}');
  assert.deepEqual(booking.impact.control, { stripHeaders: ['cookie', 'authorization'], refuseStatus: [401, 403], mustDiffer: true });
});

test('IDOR composition honestly empties when a link is missing', async () => {
  // no /docs → published-creds-login cannot establish a session → no chain
  const noDocs = await composeChains({
    endpoints: ['/api/feed', '/api/bookings/1001', '/login'].map((p) => ({ path: p })),
    findings: [],
  });
  assert.equal(noDocs.chains.filter((c) => c.name.includes('ownership-confusion')).length, 0, 'no session link → no IDOR chain');
  assert.ok(noDocs.gaps.some((g) => g.primitive === 'published-creds-login'), 'the missing link is reported');

  // feed + login + docs but no numeric-id object route → ownership-confusion unfit
  const noObjects = await composeChains({
    endpoints: ['/api/feed', '/login', '/docs'].map((p) => ({ path: p })),
    findings: [],
  });
  assert.equal(noObjects.chains.filter((c) => c.name.includes('ownership-confusion')).length, 0);
  assert.ok(noObjects.gaps.some((g) => g.primitive === 'ownership-confusion'));
});

test('IDOR family composes alongside the token family on the full chainyard surface', async () => {
  const out = await composeChains({
    endpoints: [...CHAINYARD_SURFACE.endpoints, ...IDOR_SURFACE.endpoints],
    findings: CHAINYARD_SURFACE.findings,
    material: { targetUser: 'admin' },
  });
  const idor = out.chains.filter((c) => c.name.includes('ownership-confusion'));
  const token = out.chains.filter((c) => c.name.includes('predictable-reset-token'));
  assert.equal(idor.length, 3, 'three IDOR variants');
  assert.equal(token.length, TOKEN_SHAPES.length, 'token shapes untouched');
  // distinct terminal typing: IDOR provides impact-data from a low-priv session;
  // the token family escalates to auth-as-user — the two never cross-consume
  assert.ok(!out.chains.some((c) => c.name.includes('predictable-reset-token') && c.name.includes('ownership-confusion')),
    'no cross-family chimera chains');
});

// ——— race / TOCTOU family (T4) ———

const RACE_SURFACE = {
  endpoints: ['/api/coupons/redeem', '/api/wallet/transfer', '/api/giveaway/enter', '/api/gift/claim', '/login', '/docs']
    .map((p) => ({ path: p, method: 'GET' })),
  findings: [],
};

test('race composition: authenticated-session + observed single-use route → race-window variant per route', async () => {
  const out = await composeChains({ ...RACE_SURFACE, material: {} });
  const race = out.chains.filter((c) => c.name.includes('race-window'));
  assert.equal(race.length, 4, 'one variant per observed race-able route: ' + out.chains.map((c) => c.name).join(' | '));
  for (const v of ['coupon-redeem', 'wallet-transfer', 'giveaway-enter', 'gift-claim']) {
    assert.ok(race.some((c) => c.name === `composed:published-creds-login→race-window:${v}`), v);
  }

  const coupon = race.find((c) => c.name.endsWith(':coupon-redeem'));
  const ids = coupon.steps.map((s) => s.id);
  assert.ok(ids.indexOf('race-fire') > ids.indexOf('login'), 'session before the burst');
  assert.ok(ids.indexOf('race-fire') > ids.indexOf('read-resource'), 'resource ref extracted before the burst');
  assert.equal(ids[ids.length - 1], 'race-fire', 'terminal');

  // the race step is a governed probe spec, parameterized by templates — nothing hard-coded
  const fire = coupon.steps.find((s) => s.id === 'race-fire');
  assert.equal(fire.race.headers.cookie, '{{authcookie}}');
  assert.equal(fire.race.body, '{"code":"{{rc}}"}');
  assert.equal(fire.race.resetPath, '/lab/revert');
  assert.ok(fire.race.readback && fire.race.readback.effect, 'the verdict requires a state readback metric');
  assert.deepEqual(fire.expect, { contains: '"verdict":"raced"' });
  assert.deepEqual(coupon.impact, { step: 'race-fire', contains: '"verdict":"raced"' },
    'the duplicated effect IS the impact; the sequential control lives inside the race step');

  // the giveaway variant needs no resource step (no docs dependency)
  const giveaway = race.find((c) => c.name.endsWith(':giveaway-enter'));
  assert.ok(!giveaway.steps.some((s) => s.id === 'read-resource'));
});

test('race composition honestly empties without a session provider or an observed route', async () => {
  // routes but no /login → nothing provides authenticated-session
  const noLogin = await composeChains({
    endpoints: ['/api/coupons/redeem', '/docs'].map((p) => ({ path: p })), findings: [],
  });
  assert.equal(noLogin.chains.filter((c) => c.name.includes('race-window')).length, 0);
  assert.ok(noLogin.gaps.some((g) => g.primitive === 'published-creds-login'));

  // session surface but no single-use route → race-window unfit
  const noRoutes = await composeChains({
    endpoints: ['/login', '/docs'].map((p) => ({ path: p })), findings: [],
  });
  assert.equal(noRoutes.chains.filter((c) => c.name.includes('race-window')).length, 0);
  assert.ok(noRoutes.gaps.some((g) => g.primitive === 'race-window'));

  // resource-bearing route without a docs surface → that variant is withheld honestly
  // (the chain could only hard-code a victim resource otherwise)
  const noDocs = await composeChains({
    endpoints: ['/api/coupons/redeem', '/login'].map((p) => ({ path: p })),
    findings: [{ title: 'Published demo creds on the login page', sev: 'info' }], // lets published-creds-login fit via its fallback — isolating the race-variant filter
  });
  assert.equal(noDocs.chains.filter((c) => c.name.endsWith(':coupon-redeem')).length, 0, 'no docs surface → resource variant withheld');
  const withDocs = await composeChains({
    endpoints: ['/api/coupons/redeem', '/login', '/docs'].map((p) => ({ path: p })), findings: [],
  });
  assert.ok(withDocs.chains.some((c) => c.name.endsWith(':coupon-redeem')), 'control: with /docs the coupon variant composes');
});

test('findingFromChain describes the race control that ACTUALLY ran', () => {
  const f = findingFromChain({
    ok: true, chain: 'composed:published-creds-login→race-window:coupon-redeem', base: 'http://127.0.0.1:9',
    stepsCompleted: 4, stepsTotal: 4,
    steps: [
      { id: 'login', method: 'POST', path: '/login', status: 302 },
      { id: 'race-fire', method: 'POST', path: '/api/coupons/redeem', status: null, race: { verdict: 'raced', rate: 1, seqEffect: 1, parEffect: 6 } },
    ],
    impact: { ok: true, step: 'race-fire', detail: 'impact proven (assertions held)' },
  }, { title: 't' });
  assert.ok(!f.error, f.error || '');
  assert.match(f.evidence, /sequential replay/, 'the control line describes the sequential-replay control');
  assert.ok(!/without auth headers/.test(f.evidence), 'never claims an auth-strip control that did not run');
  assert.equal(hasObjectiveOracle(f), true, 'race findings pass the ingest oracle gate');
});

// ——— business-logic invariant family (T3) ———

const LOGIC_SURFACE = {
  endpoints: ['/login', '/docs', '/openapi.json',
    '/api/payments', '/api/orders', '/api/bookings', '/api/checkout/confirm',
    '/api/coupons/apply', '/api/rides/RIDE1/status', '/api/orders/ORD-x/cancel', '/api/referrals']
    .map((p) => ({ path: p, method: 'GET' })),
  findings: [],
};

test('invariant composition: one variant per observed logic-bearing route, spec-driven at execution', async () => {
  const out = await composeChains({ ...LOGIC_SURFACE, material: {} });
  const inv = out.chains.filter((c) => c.name.includes('invariant-violation'));
  assert.equal(inv.length, 8, 'eight variants from the observed routes: ' + inv.map((c) => c.name).join(' | '));
  for (const c of inv) {
    assert.ok(c.name.startsWith('composed:published-creds-login→invariant-violation:'), 'rides the low-priv session primitive');
    const step = c.steps.find((s) => s.id === 'probe-invariant');
    assert.ok(step.invariant && step.invariant.specPath === '/openapi.json', 'spec extraction happens at execution, nothing hard-coded');
    assert.equal(step.invariant.headers.cookie, '{{authcookie}}');
    assert.deepEqual(c.impact, { step: 'probe-invariant', contains: '"verdict":"violated"' }, 'the materialized effect IS the impact');
    const ids = c.steps.map((s) => s.id);
    assert.ok(ids.indexOf('probe-invariant') > ids.indexOf('login'), 'session before the probe');
  }
});

test('invariant composition honestly empties without a spec document or a session provider', async () => {
  const noSpec = await composeChains({
    endpoints: ['/login', '/docs', '/api/payments'].map((p) => ({ path: p })), findings: [],
  });
  assert.equal(noSpec.chains.filter((c) => c.name.includes('invariant-violation')).length, 0, 'no spec observed → withheld honestly');
  assert.ok(noSpec.gaps.some((g) => g.primitive === 'invariant-violation' && /spec/.test(g.missing.join(' '))));

  const noLogin = await composeChains({
    endpoints: ['/openapi.json', '/api/payments'].map((p) => ({ path: p })), findings: [],
  });
  assert.equal(noLogin.chains.filter((c) => c.name.includes('invariant-violation')).length, 0, 'no authenticated-session provider → no chain');
});

test('no chimera chains across the four families on a combined surface', async () => {
  const out = await composeChains({
    endpoints: [
      // chainyard (token + IDOR + race) and logiclab (invariants) surfaces together
      ...['/internal/debug', '/reset/request', '/reset/confirm', '/admin/vault', '/lab/revert',
        '/api/feed', '/api/bookings/1001', '/login', '/docs',
        '/api/coupons/redeem', '/api/wallet/transfer', '/api/giveaway/enter', '/api/gift/claim',
        '/openapi.json', '/api/payments', '/api/orders', '/api/referrals']
        .map((p) => ({ path: p, method: 'GET' })),
    ],
    findings: [{ title: 'Debug endpoint leaks server state (RNG seed)', sev: 'low' }],
    material: { targetUser: 'admin' },
    maxChains: 24, // see ALL families, not the default budget's first twelve
  });
  const TERMINALS = ['protected-data-read', 'ownership-confusion', 'race-window', 'invariant-violation'];
  for (const c of out.chains) {
    const terminals = TERMINALS.filter((t) => c.primitives.some((p) => p.startsWith(t)));
    assert.equal(terminals.length, 1, `exactly one terminal family per chain — ${c.name} has ${terminals.join('+') || 'none'}`);
  }
  // every family is present on the combined surface
  for (const t of TERMINALS) assert.ok(out.chains.some((c) => c.primitives.some((p) => p.startsWith(t))), t + ' composes');
  // and no family borrows another family's proof type mid-chain
  assert.ok(!out.chains.some((c) => /invariant-violation/.test(c.name) && /race-window|ownership-confusion|predictable-reset-token/.test(c.name)));
});
