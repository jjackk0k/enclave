// VARVEL confidence-gated exploitation tests — VARVEL only exploits CONFIRMED findings.
//   node --test varvel/test/confidence.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { Surface, CONFIRM_AT, toConf } from '../engine/surface.mjs';

const jb = (o) => '```json\n' + JSON.stringify(o) + '\n```';
const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['10.0.0.0/8'] });

test('numeric confidence (0-100): >= CONFIRM_AT is confirmed, below is suspected', () => {
  const s = new Surface(scope('NUM'));
  const h = s.host('10.0.0.1', {});
  const hi = s.finding(h, { title: 'strong', confidence: 90 });
  const lo = s.finding(h, { title: 'weak', confidence: 55 });
  const ev = s.finding(h, { title: 'evidenced', confidence: 'confirmed' }); // string maps to a confirmed tier
  const nodes = s.toJSON().nodes;
  const byRef = (label) => nodes.find((n) => n.label === label);
  assert.equal(byRef('strong').conf, 90);
  assert.equal(byRef('strong').confidence, 'confirmed');
  assert.equal(byRef('weak').confidence, 'suspected', `55 < ${CONFIRM_AT}`);
  assert.equal(byRef('evidenced').confidence, 'confirmed');
  assert.equal(s.toJSON().counts.confirmed, 2, 'only the two >= threshold count as confirmed');
  assert.equal(toConf(200), 100, 'clamped'); assert.equal(toConf(-5), 0, 'clamped');
});

test('confirmed findings are exploited', async () => {
  const st = await new Campaign({ engine: {}, scope: scope('CONF'), runAgent: mockAgent, hooks: { approve: async () => true } }).run();
  assert.ok(st.surface.counts.confirmed >= 2, 'confirmed findings counted');
  assert.ok(st.surface.counts.exploits >= 1, 'confirmed findings exploited');
});

test('SUSPECTED-only findings are NOT exploited (exploit phase skipped)', async () => {
  const agent = async (opts) => {
    const c = opts.messages[0].content;
    if (c.startsWith('Enumerate')) return { text: jb({ hosts: [{ ip: '10.0.0.1', label: 'h', services: [{ port: 80, proto: 'tcp', name: 'http' }] }] }), steps: 1 };
    if (c.startsWith('Vet')) return { text: jb({ findings: [{ host: 'h', title: 'maybe-vuln', sev: 'high', ref: 'S1' }] }), steps: 1 }; // no confidence -> suspected
    return { text: 'ok', steps: 1 };
  };
  const st = await new Campaign({ engine: {}, scope: scope('SUSP'), runAgent: agent, maxReplan: 0, hooks: { approve: async () => true } }).run();
  assert.equal(st.surface.counts.findings, 1);
  assert.equal(st.surface.counts.confirmed, 0, 'the finding is suspected, not confirmed');
  assert.equal(st.surface.counts.exploits, 0, 'suspected findings are NOT exploited');
  assert.ok(st.activity.some((a) => a.kind === 'phase.skip' && a.data.phase === 'exploit'), 'exploit skipped for lack of a confirmed finding');
});

test('an evidence field promotes a finding to confirmed', async () => {
  const agent = async (opts) => {
    const c = opts.messages[0].content;
    if (c.startsWith('Enumerate')) return { text: jb({ hosts: [{ ip: '10.0.0.1', label: 'h' }] }), steps: 1 };
    if (c.startsWith('Vet')) return { text: jb({ findings: [{ host: 'h', title: 'real vuln', sev: 'high', ref: 'E1', evidence: 'PoC returned 200 with the admin console' }] }), steps: 1 };
    return { text: 'ok', steps: 1 };
  };
  const st = await new Campaign({ engine: {}, scope: scope('EVID'), runAgent: agent, maxReplan: 0, hooks: { approve: async () => true } }).run();
  assert.equal(st.surface.counts.confirmed, 1, 'evidence promotes suspected -> confirmed');
});
