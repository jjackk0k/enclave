// VARVEL chainforge campaign wiring test — the campaign compiles from its own surface.
//   node --test varvel/test/chainforge-campaign.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'] });

test('compileChains: the campaign compiles chains from its LIVE surface', () => {
  const c = new Campaign({ engine: {}, scope: scope('FORGE-C'), runAgent: mockAgent });
  const hid = c.surface.host('10.0.0.5', { label: 'target' });
  c.surface.endpoint(hid, '/assets/legacy/auth.bundle.js', 'GET');
  c.surface.endpoint(hid, '/login', 'GET');
  c.surface.endpoint(hid, '/admin', 'GET');
  c.surface.endpoint(hid, '/admin/content', 'POST');
  const r = c.compileChains();
  assert.ok(r && r.plans.length >= 1, 'a chain compiled from the surface');
  const forge = r.plans.find((p) => p.rule === 'jwt-forge-chain');
  assert.ok(forge, 'jwt-forge-chain compiled');
  assert.equal(forge.steps.filter((s) => !s.jwt).length > 0, true);
  assert.equal(c.chainPlans, r, 'stored on the campaign');
  const st = c.getState();
  assert.ok(st.chainPlans && st.chainPlans.plans.length, 'exposed in getState for the console');
  assert.ok(c.activity.some((e) => e.kind === 'chainforge'), 'compile logged');
});

test('compileChains: an empty surface yields honest gaps, never throws', () => {
  const c = new Campaign({ engine: {}, scope: scope('FORGE-E'), runAgent: mockAgent });
  const r = c.compileChains();
  assert.ok(r && r.plans.length === 0);
  assert.ok(r.gaps.length >= 1, 'gaps reported');
});

test('compileChains: the exploit prompt carries the compiled plan (forgeNote path)', async () => {
  let sent = '';
  const agent = async ({ messages }) => { sent = messages[0].content; return { text: '{"findings":[]}', steps: 1 }; };
  const c = new Campaign({ engine: {}, scope: scope('FORGE-P'), runAgent: agent, targets: [], hooks: { approve: async () => true } });
  const hid = c.surface.host('10.0.0.5', { label: 't' });
  c.surface.endpoint(hid, '/assets/legacy/auth.bundle.js', 'GET');
  c.surface.endpoint(hid, '/login', 'GET');
  c.surface.endpoint(hid, '/admin', 'GET');
  c.surface.endpoint(hid, '/admin/content', 'POST');
  c.surface.finding(hid, { title: 'leaked key in legacy bundle', sev: 'high', ref: 'F-1', confidence: 'confirmed' }); // the progression gate needs a confirmed finding
  c.compileChains();
  const phase = (await import('../engine/phases.mjs')).PHASES.find((p) => p.id === 'exploit');
  await c.runPhase(phase, '');
  assert.ok(sent.includes('[chainforge]'), 'the compiled plan rides the exploit prompt');
  assert.ok(sent.includes('jwt-forge-chain'));
});
