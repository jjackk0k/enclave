// campaign-persist.test.mjs — restart-resilience (2026-08-29, Jack's rule):
// a restart must never cost us findings, even if the agent/process loses memory mid-run.
// Covers (1) write-through snapshots BEFORE the done path and (2) carryForward restore
// into the next campaign on the same engagement.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';

process.env.VARVEL_DATA_DIR = mkdtempSync(join(tmpdir(), 'varvel-persist-'));

const { Campaign } = await import('../engine/campaign.mjs');
const { mockAgent } = await import('../mock-agent.mjs');
const { loadSurface, priorFindings } = await import('../engine/store.mjs');

const SCOPE = { engagement: 'T-persist', signedBy: 'x', cidrs: ['127.0.0.0/8'] };
const FINDING = 'TLS: overly broad wildcard certificate';

test('write-through: a mid-run finding hits disk inside the debounce window (no done required)', async () => {
  const c = new Campaign({ engine: {}, scope: SCOPE, runAgent: mockAgent, targets: ['127.0.0.1'] });
  const hid = c.surface.host('127.0.0.1', { label: 't' });
  c.surface.finding(hid, { title: FINDING, sev: 'medium', ref: 'TLS-WILDCARD-BROAD', confidence: 'confirmed' });
  await new Promise((r) => setTimeout(r, 2600)); // write-through debounce is 2s
  const snap = loadSurface(SCOPE.engagement);
  assert.ok(snap, 'surface snapshot exists WITHOUT the campaign reaching done');
  const labels = (snap.nodes || []).map((n) => n.label);
  assert.ok(labels.includes(FINDING), 'finding persisted mid-run');
  assert.ok(priorFindings(SCOPE.engagement).some((f) => f.ref === 'TLS-WILDCARD-BROAD'), 'findings ledger updated mid-run');
});

test('carryForward: a fresh campaign after a simulated restart inherits the persisted surface', async () => {
  const c2 = new Campaign({ engine: {}, scope: SCOPE, runAgent: mockAgent, targets: ['127.0.0.1'], carryForward: true });
  const labels = [...c2.surface.nodes.values()].map((n) => n.label);
  assert.ok(labels.includes(FINDING), 'finding survived the simulated restart');
});

test('deliberately fresh look: carryForward:false starts empty (only the root node)', async () => {
  const c3 = new Campaign({ engine: {}, scope: SCOPE, runAgent: mockAgent, targets: ['127.0.0.1'], carryForward: false });
  const labels = [...c3.surface.nodes.values()].map((n) => n.label);
  assert.ok(!labels.includes(FINDING), 'opt-out stays fresh');
});
