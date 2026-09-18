// VARVEL logic-campaign test — logiclab through the REAL phase path.
//   node --test varvel/test/logic-campaign.test.mjs
//
// Proves the T3 wiring end-to-end with a scripted runAgent (no LLM):
//   recon+validate land the surface → the campaign composes invariant-violation
//   chains (published-creds-login → invariant-violation:<kind>) → gated execution
//   via campaign.runComposedChain (chainrun invariant step: spec fetch → extract →
//   control → violation → state readback) proves impact → a confirmed finding that
//   passes the validator's objective-oracle gate. And the decoy: the enforced
//   safe-orders variant composes (route observed) but fails honestly — never claimed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Campaign } from '../engine/campaign.mjs';
import { PHASES } from '../engine/phases.mjs';
import { createLogiclabTarget, LOGIC_CANARY } from '../targets/logiclab.mjs';
import { hasObjectiveOracle } from '../engine/validator.mjs';

const quiet = (srv) => { srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} }); return srv; };
const phase = (id) => PHASES.find((p) => p.id === id);

const LOGICLAB_PATHS = ['/', '/login', '/docs', '/openapi.json', '/api/me', '/lab/revert',
  '/api/payments', '/api/orders', '/api/bookings', '/api/checkout/confirm',
  '/api/coupons/apply', '/api/rides/RIDE1/status', '/api/orders/ORD-x/cancel', '/api/referrals',
  '/api/safe/orders'];

async function withCampaign(fn) {
  const srv = quiet(createLogiclabTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const prompts = [];
  const runAgent = async ({ system, messages }) => {
    const content = messages[0].content;
    prompts.push({ system, content });
    if (/validation operator/.test(system)) {
      return { text: '```json\n' + JSON.stringify({
        findings: [
          { host: '127.0.0.1', title: 'API spec document exposed at /openapi.json', sev: 'info', ref: 'F-1', confidence: 'confirmed', evidence: 'GET /openapi.json returned an OpenAPI 3 document (read-back observed)' },
        ],
      }) + '\n```', steps: 3 };
    }
    if (/recon/i.test(system) || prompts.length === 1) {
      return { text: '```json\n' + JSON.stringify({
        hosts: [{ ip: '127.0.0.1', label: 'logiclab', endpoints: LOGICLAB_PATHS.map((p) => ({ url: p, method: 'GET' })), services: [{ port: srv.address().port, proto: 'http', name: 'http' }] }],
      }) + '\n```', steps: 3 };
    }
    return { text: '{"exploits":[]}', steps: 1 }; // exploit: the deterministic executor does the work
  };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'logic-campaign-test', signedBy: 'test', cidrs: ['127.0.0.0/8'] },
    runAgent, targets: [base], hooks: { approve: async () => true },
  });
  try { return await fn(c, base, prompts, srv); }
  finally { await new Promise((r) => srv.close(r)); }
}

test('validate phase composes invariant-violation candidates from the live surface', () => withCampaign(async (c) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');

  assert.ok(c.composedChains && c.composedChains.chains.length >= 1, 'composed chains exist after validate');
  const names = c.composedChains.chains.map((x) => x.name);
  assert.ok(names.some((n) => n === 'composed:published-creds-login→invariant-violation:payment-negative'), 'the negative-payment composition is among them');
  assert.ok(names.some((n) => n.endsWith(':order-price-tamper:safe')), 'the enforced decoy composes too (route observed) — execution is its oracle');
  assert.ok(c.activity.some((e) => e.kind === 'chain.composed'), 'composition logged');
}));

test('gated execution: invariant chain proves impact → confirmed finding (oracle gate)', () => withCampaign(async (c, base) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');

  const idx = c.composedChains.chains.findIndex((x) => x.name.includes('invariant-violation:payment-negative') && !x.name.endsWith(':safe'));
  assert.ok(idx >= 0, 'payment-negative variant composed');
  const r = await c.runComposedChain(idx, { base });
  assert.equal(r.ok, true, `invariant chain executed: ${r.error || ''}`);
  assert.ok(r.run.impact && r.run.impact.ok);
  const probe = r.run.steps.find((s) => s.id === 'probe-invariant');
  assert.equal(probe.invariant.verdict, 'violated');
  assert.equal(probe.status, null, 'no fabricated HTTP status on a probe step');
  assert.ok(probe.evidence.includes('"violated"'), 'verdict body rides the evidence');

  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && /invariant-violation:payment-negative/.test(n.label));
  assert.ok(f, 'invariant finding on the surface');
  assert.equal(f.confidence, 'confirmed');
  assert.equal(hasObjectiveOracle(f), true, 'passes the ingest oracle gate');
  assert.match(f.evidence, /spec-valid control request/, 'cites the control that actually ran');

  const node = [...c.surface.nodes.values()].find((n) => n.type === 'exploit' && n.composed && n.label === r.chain);
  assert.equal(node.state, 'proved');
  assert.ok(c.activity.some((e) => e.kind === 'chain.proved'));
}));

test('decoy: the enforced safe-orders variant composes but fails honestly (never claimed)', () => withCampaign(async (c, base) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');

  const idx = c.composedChains.chains.findIndex((x) => x.name.endsWith(':order-price-tamper:safe'));
  assert.ok(idx >= 0, 'safe variant composed');
  const r = await c.runComposedChain(idx, { base });
  assert.equal(r.ok, false, 'enforced endpoint fails honestly');
  const probe = r.run.steps.find((s) => s.id === 'probe-invariant');
  assert.equal(probe.invariant.verdict, 'enforced', 'accepted-but-ignored: the readback shows the catalog price');
  assert.equal(probe.invariant.operation, 'createSafeOrder');
  const node = [...c.surface.nodes.values()].find((n) => n.type === 'exploit' && n.composed && n.label === r.chain);
  assert.equal(node.state, 'failed');
  assert.ok(c.activity.some((e) => e.kind === 'chain.failed'), 'honest failure on the record');
  // and NO finding landed for it
  assert.ok(![...c.surface.nodes.values()].some((n) => n.type === 'finding' && /:safe/.test(n.label)), 'no finding for the enforced endpoint');
}));

test('runComposedChain refuses out-of-scope bases for invariant chains (fail-closed)', () => withCampaign(async (c) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');
  const idx = c.composedChains.chains.findIndex((x) => x.name.includes('invariant-violation:payment-negative') && !x.name.endsWith(':safe'));
  const r = await c.runComposedChain(idx, { base: 'http://10.203.0.9/' });
  assert.equal(r.ok, false);
  assert.match(r.error, /outside the signed scope/);
  assert.ok(c.activity.some((e) => e.kind === 'chain.refused'));
}));

void LOGIC_CANARY; // the canary is asserted at the harness layer (readback bodies)
