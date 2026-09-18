// VARVEL honesty/productivity auditor tests — the autonomy differentiator.
//   node --test varvel/test/auditor.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessProgress, replanHint, productivity } from '../engine/auditor.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['10.0.0.0/8'] });

test('assessProgress: real surface growth -> productive/honest', () => {
  const a = assessProgress({ findings: 0 }, { findings: 2, hosts: 1 }, 'found 2 admin panels');
  assert.equal(a.verdict, 'productive');
  assert.equal(a.realDelta, 3);
  assert.equal(a.honest, true);
});

test('assessProgress: claims progress but ZERO delta -> dishonest', () => {
  const a = assessProgress({ findings: 1 }, { findings: 1 }, 'I discovered a critical RCE and exploited it');
  assert.equal(a.honest, false);
  assert.equal(a.verdict, 'dishonest-or-stalled');
});

test('assessProgress: no claim + no delta -> no-progress (still honest)', () => {
  const a = assessProgress({ hosts: 2 }, { hosts: 2 }, 'nothing further of note this round');
  assert.equal(a.verdict, 'no-progress');
  assert.equal(a.honest, true);
});

test('productivity: rolls up counts + honesty rate', () => {
  const p = productivity([{ verdict: 'productive', realDelta: 3 }, { verdict: 'dishonest-or-stalled', realDelta: 0 }, { verdict: 'no-progress', realDelta: 0 }]);
  assert.equal(p.phases, 3);
  assert.equal(p.productive, 1);
  assert.equal(p.dishonest, 1);
  assert.equal(p.noProgress, 1);
  assert.ok(p.honestyRate < 1 && p.honestyRate > 0);
  assert.ok(replanHint('recon', 2).includes('re-plan'));
});

test('replanHint escalates: tier 1 = change approach, tier ≥2 = deep-think hypotheses', () => {
  const t1 = replanHint('recon', 0, 1);
  assert.match(t1, /change approach/i);
  assert.doesNotMatch(t1, /hypothes/i);
  const t2 = replanHint('validate', 0, 2);
  assert.match(t2, /deep-think/i);
  assert.match(t2, /two competing hypotheses|TWO competing/i);
});

test('productivity.stuckStreak: longest consecutive no-growth run (deterministic stuck signal)', () => {
  const p = productivity([
    { verdict: 'productive', realDelta: 2 },
    { verdict: 'no-progress', realDelta: 0 },
    { verdict: 'dishonest-or-stalled', realDelta: 0 },
    { verdict: 'no-progress', realDelta: 0 },
    { verdict: 'productive', realDelta: 1 },
  ]);
  assert.equal(p.stuckStreak, 3, 'three consecutive non-growth phases');
  const clean = productivity([{ verdict: 'productive', realDelta: 1 }, { verdict: 'productive', realDelta: 2 }]);
  assert.equal(clean.stuckStreak, 0);
});

test('campaign: the stuck counter tracks consecutive no-growth phases', async () => {
  const agent = async (opts) => {
    if (opts.messages[0].content.startsWith('Enumerate')) return { text: 'the range is silent, nothing responded', steps: 1 };
    return { text: 'nothing of note', steps: 1 };
  };
  const c = new Campaign({ engine: {}, scope: scope('STUCK'), runAgent: agent, maxReplan: 0, hooks: { approve: async () => true } });
  const st = await c.run();
  assert.ok(c.stuck >= 1, 'campaign registered a no-growth streak');
  assert.ok(st.productivity.stuckStreak >= 1, 'stuckStreak surfaced in productivity');
});

test('campaign: hallucinated progress is flagged, not trusted (BUG-class RedAmon calls "dishonest progress")', async () => {
  const liar = async () => ({ text: 'I found and exploited a critical vulnerability and recovered admin credentials!', steps: 1 });
  const st = await new Campaign({ engine: {}, scope: scope('LIAR'), runAgent: liar, maxReplan: 0, hooks: { approve: async () => true } }).run();
  assert.ok(st.activity.some((a) => a.kind === 'progress.flag'), 'dishonest progress flagged');
  assert.ok(st.productivity.dishonest >= 1);
  assert.ok(st.productivity.honestyRate < 1);
});

test('campaign: a no-progress recon triggers a bounded re-plan (deny/stall backout)', async () => {
  let reconCalls = 0;
  const agent = async (opts) => {
    if (opts.messages[0].content.startsWith('Enumerate')) { reconCalls++; return { text: 'scanned the range, nothing responded', steps: 1 }; }
    return { text: 'ok', steps: 1 };
  };
  const st = await new Campaign({ engine: {}, scope: scope('REPLAN'), runAgent: agent, maxReplan: 1, hooks: { approve: async () => true } }).run();
  assert.equal(reconCalls, 2, 'recon retried once on no progress');
  assert.ok(st.activity.some((a) => a.kind === 'replan' && a.data.phase === 'recon'));
});

test('campaign: an honest, productive run has zero dishonest flags', async () => {
  const st = await new Campaign({ engine: {}, scope: scope('HONEST'), runAgent: mockAgent, hooks: { approve: async () => true } }).run();
  assert.equal(st.productivity.dishonest, 0, 'mock output matches its claims');
  assert.ok(st.productivity.productive >= 2);
});
