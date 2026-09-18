// VARVEL cross-session FAILURE memory (EvoGraph-class) — a new session inherits the
// approaches that already failed and is told not to repeat them.
//   node --test varvel/test/failmemory.test.mjs

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmSync } from 'node:fs';
import { Campaign } from '../engine/campaign.mjs';
import { recordFailures, priorFailures } from '../engine/store.mjs';

// Isolate persistence to this process (parallel test files must not share the dir).
const DATA = join(tmpdir(), 'varvel-fail-' + process.pid);
process.env.VARVEL_DATA_DIR = DATA;
const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['10.0.0.0/8'] });

test('store: recordFailures dedups; priorFailures reads back', () => {
  const eng = 'FAIL-STORE';
  recordFailures(eng, [{ phase: 'recon', kind: 'held', approach: 'egress:8.8.8.8' }, { phase: 'recon', kind: 'held', approach: 'egress:8.8.8.8' }]);
  recordFailures(eng, [{ phase: 'exploit', kind: 'failed-exploit', approach: 'SQLi on /login' }]);
  const f = priorFailures(eng);
  assert.equal(f.length, 2, 'the repeat was deduped, the distinct one kept');
  assert.ok(f.some((x) => /egress/.test(x.approach)) && f.some((x) => /SQLi/.test(x.approach)));
  assert.ok(recordFailures(eng, [{ approach: '' }]).length === 2, 'empty approaches are ignored');
});

test('campaign records held actions AND a no-progress phase as failures, then persists them', async () => {
  const agent = async (opts) => {
    const c = opts.messages[0].content;
    if (c.startsWith('Enumerate')) return { text: 'swept the range, nothing responded', denials: ['egress:1.2.3.4'], steps: 1 };
    return { text: 'nothing further of note', steps: 1 };
  };
  const c = new Campaign({ engine: {}, scope: scope('FAIL-REC'), runAgent: agent, maxReplan: 0, hooks: { approve: async () => true } });
  await c.run();
  assert.ok(c.failures.some((f) => f.kind === 'held' && /egress/.test(f.approach)), 'held action recorded as a failure');
  assert.ok(c.failures.some((f) => f.kind === 'no-progress'), 'a dead-end phase recorded as a failure');
  assert.ok(priorFailures('FAIL-REC').length >= 1, 'failures persisted for the next session');
});

test('a new session inherits failures and injects them into the agent context', async () => {
  const eng = 'FAIL-INHERIT';
  recordFailures(eng, [{ phase: 'exploit', kind: 'failed-exploit', approach: 'default creds on admin panel' }]);
  let seen = '';
  const agent = async (opts) => { seen += opts.messages[0].content + '\n'; return { text: 'ok', steps: 1 }; };
  const c = new Campaign({ engine: {}, scope: scope(eng), runAgent: agent, maxReplan: 0, hooks: { approve: async () => true } });
  assert.ok(c.priorFail.length >= 1, 'inherited prior failures at construction');
  const st = await c.run();
  assert.equal(st.inheritedFailures, c.priorFail.length, 'surfaced in getState');
  assert.match(seen, /FAILED these approaches/, 'the agent was warned');
  assert.match(seen, /default creds on admin panel/, 'the specific failed approach was named');
});

after(() => { try { rmSync(DATA, { recursive: true, force: true }); } catch {} });
