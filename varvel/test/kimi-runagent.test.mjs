// VARVEL governed Kimi backend — governance-integration tests (real local hook, no Kimi API).
//   node --test varvel/test/kimi-runagent.test.mjs
// These prove the Kimi runAgent enforces the SAME Enclave hook the Claude path does: a tool
// call is only executed if the signed-scope / workspace-confinement policy allows it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { hookDecision, kimiConfig, isKimiModel, makeKimiAgent, KIMI_MODELS, KIMI_EFFORTS } from '../engine/kimi-runagent.mjs';
import { DEMO_SESSION } from '../engine/live.mjs';

const ws = mkdtempSync(join(tmpdir(), 'varvel-kimi-ws-'));
writeFileSync(join(ws, 'note.txt'), 'in-workspace file');
const ctx = { sessionFile: DEMO_SESSION, wsDir: ws, container: '' };

test('model catalog: k3 + kimi-k2.7-code selectable, effort scale present', () => {
  assert.ok(KIMI_MODELS.includes('k3') && KIMI_MODELS.includes('kimi-k2.7-code'));
  assert.deepEqual(KIMI_EFFORTS, ['low', 'medium', 'high']);
  assert.equal(isKimiModel('k3'), true);
  assert.equal(isKimiModel('kimi-k2.7-code'), true);
  assert.equal(isKimiModel('claude-opus-5'), false);
});

test('GOVERNANCE: a Read INSIDE the signed workspace is allowed', () => {
  const d = hookDecision('Read', { file_path: join(ws, 'note.txt') }, ctx);
  assert.equal(d.allow, true, d.reason);
});

test('GOVERNANCE: a Read OUTSIDE the workspace tree is denied (workspace escape)', () => {
  const d = hookDecision('Read', { file_path: 'C:/Windows/System32/drivers/etc/hosts' }, ctx);
  assert.equal(d.allow, false);
  assert.match(d.reason, /workspace|outside|escape/i);
});

test('GOVERNANCE: a Bash command reaching a credential path is denied (host-tier confinement)', () => {
  const d = hookDecision('Bash', { command: 'cat ~/.ssh/id_rsa' }, ctx);
  assert.equal(d.allow, false);
  assert.match(d.reason, /workspace|home|off-limits|outside/i);
});

test('GOVERNANCE: a scan/curl of an OUT-OF-SCOPE target is denied (signed scope enforced)', () => {
  // demo session is scoped to 127.0.0.0/8 only; 10.0.0.1 is outside it.
  const d = hookDecision('Bash', { command: 'curl -s http://10.0.0.1/' }, ctx);
  assert.equal(d.allow, false);
  assert.match(d.reason, /scope|outside|clearance|approval|held/i);
});

test('GOVERNANCE: fail-closed on a bad session path', () => {
  const d = hookDecision('Read', { file_path: join(ws, 'note.txt') }, { sessionFile: 'C:/nonexistent-session.json', wsDir: ws });
  assert.equal(d.allow, false);
});

test('makeKimiAgent builds a runAgent function when a Kimi key is configured', () => {
  const c = kimiConfig();
  if (!c.ok) { assert.ok(true, 'no key configured — skipped'); return; }
  const agent = makeKimiAgent({ sessionFile: DEMO_SESSION, wsDir: ws, model: 'k3', effort: 'high' });
  assert.equal(typeof agent, 'function');
});
