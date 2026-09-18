// VARVEL chainforge tests — the deterministic exploit-chain compiler, proven end-to-end.
//   node --test varvel/test/chainforge.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chainforge, RULES } from '../engine/chainforge.mjs';
import { runChain } from '../tools/chainrun.mjs';
import { createHardTarget } from '../targets/premium-hard.mjs';

const quiet = (srv) => { srv.on('clientError', (e, s) => { try { s.destroy(); } catch {} }); return srv; };

const AXIOM_SURFACE = {
  endpoints: [
    { path: '/assets/legacy/auth.bundle.js', method: 'GET' },
    { path: '/login', method: 'GET' },
    { path: '/admin', method: 'GET' },
    { path: '/admin/content', method: 'POST' },
  ],
  findings: [],
  material: {
    keyRegex: '(axiom-auth-hs256-[\\w-]+)',
    lowPrivCreds: { email: 'sandbox@axiom.dev', password: 'sandbox-demo-2026' },
    claims: { sub: 'admin@axiom.dev', role: 'admin', org: 'org_axiom', iss: 'axiom-auth', iat: 1, exp: 9999999999 },
  },
};

test('chainforge: an Axiom-shaped surface compiles the full JWT-forge chain', () => {
  const { plans, gaps } = chainforge(AXIOM_SURFACE);
  const forge = plans.find((p) => p.rule === 'jwt-forge-chain');
  assert.ok(forge, 'the forge chain compiled');
  assert.equal(forge.steps.length, 6);
  const ids = forge.steps.map((s) => s.id);
  assert.deepEqual(ids, ['leak-key', 'login', 'forge', 'verify-admin', 'prove-write', 'revert']);
  assert.ok(forge.confidence.includes('confirmed'));
  assert.ok(!gaps.some((g) => g.rule === 'jwt-forge-chain'), 'no gaps for the complete case');
});

test('chainforge: missing prerequisites produce honest gaps, not hallucinated steps', () => {
  const { plans, gaps } = chainforge({ endpoints: [], findings: [], material: {} });
  assert.equal(plans.length, 0, 'nothing compiles on an empty surface');
  assert.ok(gaps.length >= 3, 'every rule reports its gaps');
  const forgeGaps = gaps.find((g) => g.rule === 'jwt-forge-chain');
  assert.ok(forgeGaps.missing.some((m) => /login endpoint/.test(m)) && forgeGaps.missing.some((m) => /admin endpoint/.test(m)), 'hard prerequisites reported; creds are a runtime note, not a blocker');
});

test('chainforge→chainrun: the compiled chain BREACHES the real Axiom target and reverts', async () => {
  const srv = quiet(createHardTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const { plans } = chainforge(AXIOM_SURFACE);
    const chain = { name: 'chainforge-compiled', base, steps: plans.find((p) => p.rule === 'jwt-forge-chain').steps };
    const res = await runChain(chain, { timeout: 2500 });
    assert.equal(res.ok, true, 'the compiled chain executed end-to-end');
    assert.equal(res.stepsCompleted, 6);
    assert.ok(res.vars.jwt.includes('…'), 'forged token redacted in the record');
    const home = await (await fetch(base + '/')).text();
    assert.ok(home.includes('The programmable money platform for modern business.'), 'revert restored the original headline');
  } finally { srv.close(); }
});

test('chainforge: exposed-secrets + cors-theft rules compile on matching evidence', () => {
  const { plans } = chainforge({
    endpoints: [{ path: '/api/users', method: 'GET' }],
    findings: [
      { id: 'git-head', title: 'Exposed .git repository' },
      { id: 'cors', title: 'CORS reflects an arbitrary Origin WITH credentials' },
    ],
    material: {},
  });
  assert.ok(plans.some((p) => p.rule === 'exposed-secrets'), 'secrets rule compiled');
  assert.ok(plans.some((p) => p.rule === 'cors-theft'), 'cors rule compiled');
  assert.ok(plans.every((p) => p.requestsEstimate > 0));
});

test('rule hygiene: every rule has id/title/needs/build and honest confidence', () => {
  for (const r of RULES) {
    assert.ok(r.id && r.title && typeof r.needs === 'function' && typeof r.build === 'function');
    assert.ok(/confirmed|firm/.test(r.confidence));
    const n = r.needs({ endpoints: [], findings: [], material: {} });
    assert.ok(Array.isArray(n.gaps), r.id + ' gaps array');
  }
});

test('teardown grace (win32)', async () => { await new Promise((r) => setTimeout(r, 400)); });
