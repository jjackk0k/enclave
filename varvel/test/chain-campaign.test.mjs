// VARVEL chain-campaign test — chainyard through the REAL phase path.
//   node --test varvel/test/chain-campaign.test.mjs
//
// Proves the v2 wiring end-to-end with a scripted runAgent (no LLM):
//   recon+validate phases land the surface → the campaign COMPOSES candidate chains
//   post-validate (chain.composed) → the exploit prompt carries the [chains] doctrine
//   → gated execution via campaign.runComposedChain (chainrun v2) proves impact →
//   a validated finding lands with chain evidence. Plus the honesty inverses:
//   hollow chains are failures, out-of-scope execution is refused, scratchTools is
//   tolerated-and-logged.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Campaign } from '../engine/campaign.mjs';
import { PHASES } from '../engine/phases.mjs';
import { createChainyardTarget, VAULT_CANARY, BOB_BOOKING_CANARY, RACE_CANARY } from '../targets/chainyard.mjs';
import { hasObjectiveOracle } from '../engine/validator.mjs';

const quiet = (srv) => { srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} }); return srv; };
const phase = (id) => PHASES.find((p) => p.id === id);

const CHAINYARD_PATHS = ['/', '/search', '/goto', '/login', '/docs', '/admin/vault', '/api/me', '/internal/debug', '/reset/request', '/reset/confirm', '/lab/revert',
  '/api/feed', '/api/bookings/1001', '/api/invoices/2001', '/api/listings/3001',
  '/api/coupons/redeem', '/api/wallet/transfer', '/api/giveaway/enter', '/api/gift/claim'];

async function withCampaign(fn) {
  const srv = quiet(createChainyardTarget());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const prompts = [];
  const runAgent = async ({ system, messages }) => {
    const content = messages[0].content;
    prompts.push({ system, content });
    if (/validation operator/.test(system)) {
      return { text: '```json\n' + JSON.stringify({
        findings: [
          { host: '127.0.0.1', title: 'Debug endpoint leaks server state (RNG seed)', sev: 'low', ref: 'F-1', confidence: 'confirmed', evidence: 'GET /internal/debug returned RNG_SEED material (read-back observed)' },
          { host: '127.0.0.1', title: 'CORS reflects arbitrary origin with credentials on /api/me', sev: 'low', ref: 'F-2', confidence: 'confirmed', evidence: 'GET /api/me responded with reflected Access-Control-Allow-Origin' },
          { host: '127.0.0.1', title: 'Open redirect on /goto', sev: 'low', ref: 'F-3', confidence: 'suspected' },
        ],
        scratchTools: ['token-shape-probe.mjs'],
      }) + '\n```', steps: 4 };
    }
    if (/recon/i.test(system) || prompts.length === 1) {
      return { text: '```json\n' + JSON.stringify({
        hosts: [{ ip: '127.0.0.1', label: 'chainyard', endpoints: CHAINYARD_PATHS.map((p) => ({ url: p, method: 'GET' })), services: [{ port: srv.address().port, proto: 'http', name: 'http' }] }],
      }) + '\n```', steps: 3 };
    }
    return { text: '{"exploits":[]}', steps: 1 }; // exploit: the deterministic executor does the work
  };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'chain-campaign-test', signedBy: 'test', cidrs: ['127.0.0.0/8'] },
    runAgent, targets: [base], hooks: { approve: async () => true },
  });
  try { return await fn(c, base, prompts, srv); }
  finally { await new Promise((r) => srv.close(r)); }
}

test('validate phase composes candidate chains from validated primitives (chain.composed)', () => withCampaign(async (c) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');

  assert.ok(c.composedChains && c.composedChains.chains.length >= 1, 'composed chains exist after validate');
  assert.ok(c.composedChains.chains.some((x) => x.name.includes('leaked-token-material→predictable-reset-token')), 'the token-prediction composition is among them');
  assert.ok(c.activity.some((e) => e.kind === 'chain.composed'), 'composition logged to the activity feed');

  // parked on the surface as proposed exploit nodes with the chain document attached
  const nodes = [...c.surface.nodes.values()].filter((n) => n.type === 'exploit' && n.composed);
  assert.ok(nodes.length >= 1, 'composed chains are surface nodes');
  assert.equal(nodes[0].state, 'proposed');
  assert.ok(nodes[0].chain && nodes[0].chain.impact, 'the chain doc + impact assertion ride the node');
}));

test('scratchTools output is tolerated and logged, never an ingest failure', () => withCampaign(async (c) => {
  await c.runPhase(phase('validate'), '');
  assert.ok(c.activity.some((e) => e.kind === 'scratch-tools' && /token-shape-probe/.test(JSON.stringify(e))), 'scratch tool declaration logged');
}));

test('exploit prompt carries the [chains] doctrine when composed chains exist', () => withCampaign(async (c, base, prompts) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');
  await c.runPhase(phase('exploit'), ''); // gate auto-approved by hooks.approve
  const exploitPrompt = prompts.find((p) => /exploitation operator/.test(p.system));
  assert.ok(exploitPrompt, 'exploit phase ran');
  assert.ok(exploitPrompt.content.includes('[chains]'), 'composed chains ride the prompt');
  assert.ok(exploitPrompt.content.includes('chainrun'), 'the executor contract is named');
  assert.ok(exploitPrompt.content.includes('never "proved"'), 'the hollow-success doctrine is in the prompt');
}));

test('gated execution: runComposedChain proves impact → validated finding with chain evidence', () => withCampaign(async (c, base) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');

  let proved = null;
  for (let i = 0; i < c.composedChains.chains.length && !proved; i++) {
    const r = await c.runComposedChain(i, { base });
    if (r.ok) proved = r;
  }
  assert.ok(proved, 'one composed chain executed end-to-end with impact proven');
  assert.ok(proved.run.impact && proved.run.impact.ok);
  assert.ok(
    proved.run.steps.some((s) => s.evidence && (s.evidence.includes(VAULT_CANARY) || s.evidence.includes(BOB_BOOKING_CANARY) || s.evidence.includes(RACE_CANARY))),
    'canary evidence captured (vault via token chain, bob booking via IDOR chain, or race marker)');

  // the finding lands at confirmed tier with validator-oracle-citing evidence
  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && /composed:/.test(n.label));
  assert.ok(f, 'chain finding on the surface');
  assert.equal(f.confidence, 'confirmed');
  assert.equal(hasObjectiveOracle(f), true, 'chain evidence passes the ingest oracle gate');

  // the chain node flips to proved; the activity feed records chain.proved
  const node = [...c.surface.nodes.values()].find((n) => n.type === 'exploit' && n.composed && n.label === proved.chain);
  assert.equal(node.state, 'proved');
  assert.ok(c.activity.some((e) => e.kind === 'chain.proved'));

  // wrong-shape candidates that ran first are honest failures, not silent drops
  assert.ok(c.activity.some((e) => e.kind === 'chain.failed') || proved.chain === c.composedChains.chains[0].name,
    'either earlier candidates failed honestly or the first candidate won outright');
}));

test('runComposedChain refuses out-of-scope bases (fail-closed, no request)', () => withCampaign(async (c) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');
  const r = await c.runComposedChain(0, { base: 'http://10.203.0.9/' });
  assert.equal(r.ok, false);
  assert.match(r.error, /outside the signed scope/);
  assert.ok(c.activity.some((e) => e.kind === 'chain.refused'), 'refusal is on the record');
}));

test('runComposedChain on a hollow chain = failure (node failed, failure ledger fed)', () => withCampaign(async (c, base) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');
  // graft a hollow candidate (steps pass, impact absent) onto the composed set — the
  // decoy shape: CORS verify + cross-origin read that can only return anonymous data.
  c.composedChains.chains.unshift({
    name: 'composed:hollow-decoy', primitives: ['test-fixture'],
    steps: [
      { id: 'verify-cors', path: '/api/me', headers: { origin: 'https://attacker.invalid' }, expect: { status: 200 } },
      { id: 'fetch-data', path: '/api/me', headers: { origin: 'https://attacker.invalid' }, expect: { status: 200 } },
    ],
    impact: { step: 'fetch-data', contains: 'admin@' },
    requestsEstimate: 2, confidence: 'test-fixture',
  });
  c.surface.exploit(c.surface.root, { title: 'composed:hollow-decoy', state: 'proposed' });
  const node = [...c.surface.nodes.values()].find((n) => n.label === 'composed:hollow-decoy');
  node.composed = true;

  const r = await c.runComposedChain(0, { base });
  assert.equal(r.ok, false, 'hollow chain fails');
  assert.equal(r.run.hollowSuccess, true);
  assert.equal(node.state, 'failed');
  assert.ok(c.activity.some((e) => e.kind === 'chain.failed' && /hollow/.test(JSON.stringify(e))), 'hollow failure logged');
  assert.ok(c.failures.some((f) => /hollow/.test(f.approach)), 'failure ledger carries it forward');
}));

test('IDOR chain composes and executes through the campaign path (impact = bob canary)', () => withCampaign(async (c, base) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');

  // the ownership-confusion family composes per observed object family
  const idorIdx = c.composedChains.chains.findIndex((x) => x.name.includes('ownership-confusion:booking'));
  assert.ok(idorIdx >= 0, 'booking IDOR variant composed');
  assert.ok(c.composedChains.chains.some((x) => x.name.includes('enumerable-id-leak→published-creds-login→ownership-confusion')),
    'the full IDOR primitive triple is named in the chain');

  const r = await c.runComposedChain(idorIdx, { base });
  assert.equal(r.ok, true, `IDOR chain executed: ${r.error || ''}`);
  assert.ok(r.run.impact && r.run.impact.ok);
  assert.ok(r.run.steps.some((s) => s.evidence && s.evidence.includes(BOB_BOOKING_CANARY)),
    "bob's booking canary captured as impact evidence");
  // control honesty: the cookie-stripped re-fire was refused and differed (else impact.ok would be false)
  assert.match(r.run.impact.detail, /control behaved/, 'impact detail records the stripped-auth control behaving');

  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && /ownership-confusion/.test(n.label));
  assert.ok(f, 'IDOR finding on the surface');
  assert.equal(f.confidence, 'confirmed');
  assert.equal(hasObjectiveOracle(f), true, 'IDOR evidence passes the ingest oracle gate');
}));

test('race chain composes and executes through the campaign path (impact = duplicated effect via readback)', () => withCampaign(async (c, base) => {
  await c.runPhase(phase('recon'), '');
  await c.runPhase(phase('validate'), '');

  const raceIdx = c.composedChains.chains.findIndex((x) => x.name.includes('race-window:coupon-redeem'));
  assert.ok(raceIdx >= 0, 'coupon race variant composed from the live surface');

  const r = await c.runComposedChain(raceIdx, { base });
  assert.equal(r.ok, true, `race chain executed: ${r.error || ''}`);
  assert.ok(r.run.impact && r.run.impact.ok);
  const fire = r.run.steps.find((s) => s.id === 'race-fire');
  assert.equal(fire.race.verdict, 'raced');
  assert.equal(fire.race.rate, 1, 'deterministic in-lab (rate reported, not assumed)');
  assert.ok(fire.evidence.includes(RACE_CANARY), 'state marker from the readback rides the evidence');

  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && /race-window/.test(n.label));
  assert.ok(f, 'race finding on the surface');
  assert.equal(f.confidence, 'confirmed');
  assert.equal(hasObjectiveOracle(f), true, 'race evidence passes the ingest oracle gate');
  assert.match(f.evidence, /sequential replay/, 'the finding cites the control that actually ran');

  // and the SAFE control's composed variant fails honestly through the same path
  const giftIdx = c.composedChains.chains.findIndex((x) => x.name.includes('race-window:gift-claim'));
  assert.ok(giftIdx >= 0, 'the locked endpoint composed a variant (claim verb observed)');
  const g = await c.runComposedChain(giftIdx, { base });
  assert.equal(g.ok, false, 'locked/idempotent endpoint refuted, not claimed');
  assert.equal(g.run.steps.at(-1).race.verdict, 'single-effect');
}));
