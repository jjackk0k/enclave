// VARVEL EvoGraph-class cross-session memory tests — a new session inherits the
// prior engagement's attack surface (opt-in), marked as carried-forward.
//   node --test varvel/test/evograph.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';

// Isolate this file's persistence: parallel test processes must not share the
// on-disk data dir (this test rmSyncs it, which would race the others on Windows).
const DATA = join(tmpdir(), 'varvel-evo-' + process.pid);
process.env.VARVEL_DATA_DIR = DATA;
const jb = (o) => '```json\n' + JSON.stringify(o) + '\n```';
const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['10.0.0.0/8'] });
const nodes = (c) => [...c.surface.nodes.values()];

test('carryForward: a new session inherits the prior engagement surface (EvoGraph)', async () => {
  rmSync(DATA, { recursive: true, force: true });
  const s1 = async (opts) => {
    const c = opts.messages[0].content;
    if (c.startsWith('Enumerate')) return { text: jb({ hosts: [{ ip: '10.9.9.9', label: 'legacy-web' }] }), steps: 1 };
    if (c.startsWith('Vet')) return { text: jb({ findings: [{ host: 'legacy-web', title: 'F-PRIOR', sev: 'high', ref: 'P1', confidence: 'confirmed', evidence: 'x' }] }), steps: 1 };
    return { text: 'ok', steps: 1 };
  };
  await new Campaign({ engine: {}, scope: scope('EVO'), runAgent: s1, hooks: { approve: async () => true } }).run();

  const c2 = new Campaign({ engine: {}, scope: scope('EVO'), runAgent: mockAgent, carryForward: true, hooks: { approve: async () => true } });
  assert.ok(nodes(c2).some((n) => n.ip === '10.9.9.9' && n.inherited), 'prior host seeded + marked inherited before running');
  assert.ok(nodes(c2).some((n) => n.type === 'finding' && n.label === 'F-PRIOR' && n.inherited), 'prior confirmed finding seeded');
  assert.ok(c2.activity.some((a) => a.kind === 'surface.inherit'), 'inherit event logged');

  const st = await c2.run();
  assert.ok(st.surface.nodes.some((n) => n.label === 'F-PRIOR' && n.inherited), 'prior finding persists');
  assert.ok(st.surface.nodes.some((n) => n.type === 'finding' && !n.inherited), 'new-session findings added on top');
});

test('carryForward off (default): a session does NOT inherit the surface', () => {
  const c = new Campaign({ engine: {}, scope: scope('EVO'), runAgent: mockAgent, hooks: { approve: async () => true } });
  assert.ok(!nodes(c).some((n) => n.ip === '10.9.9.9'), 'no inherited host without carryForward');
});
