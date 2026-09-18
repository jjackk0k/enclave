// VARVEL autogate tests — the operator pre-authorization doctrine, proven fail-closed.
//   node --test varvel/test/autogate.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGrant, saveGrant, loadGrant, revokeGrant, decide, autoApprove, statusGrant, MAX_HOURS, MAX_GRANTS, GATED_PHASES } from '../engine/autogate.mjs';
import { Campaign } from '../engine/campaign.mjs';

const SIGNED = { engagement: 't-eng', signedBy: 'operator', cidrs: ['127.0.0.0/8'] };
const UNSIGNED = { engagement: 't-eng', signedBy: null, cidrs: [] };
const HOUR = 3600000;

function tmp() {
  const dir = mkdtempSync(join(tmpdir(), 'autogate-'));
  return { file: join(dir, 'autogate.json'), log: join(dir, 'log.jsonl') };
}
function auditLines(log) {
  try { return readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l)); } catch { return []; }
}
// Point the module's lazy env-overridden paths at a tmp pair for the duration of fn.
async function withEnv(t, fn) {
  process.env.VARVEL_AUTOGATE_FILE = t.file;
  process.env.VARVEL_AUTOGATE_LOG = t.log;
  try { return await fn(); } finally { delete process.env.VARVEL_AUTOGATE_FILE; delete process.env.VARVEL_AUTOGATE_LOG; }
}

test('createGrant: doctrine bounds enforced at creation — never a silent clamp', () => {
  const g = createGrant({ hours: 12, max: 8 });
  assert.ok(g.id.startsWith('ag-'));
  assert.deepEqual(g.phases, GATED_PHASES);
  assert.equal(g.used, 0);
  assert.throws(() => createGrant({ hours: 0 }), RangeError);
  assert.throws(() => createGrant({ hours: MAX_HOURS + 1 }), /TODAY mechanism/);
  assert.throws(() => createGrant({ max: 0 }), RangeError);
  assert.throws(() => createGrant({ max: MAX_GRANTS + 1 }), RangeError);
  assert.throws(() => createGrant({ phases: ['exploit', 'recon'] }), /not sigil-gated/);
  assert.throws(() => createGrant({ phases: [] }), TypeError);
  assert.throws(() => createGrant({ principal: '  ' }), TypeError);
});

test('loadGrant: missing, malformed, and mis-shaped files all read as NO grant', () => {
  const t = tmp();
  assert.equal(loadGrant(t.file), null); // missing
  saveGrant(createGrant({}), t.file);
  assert.ok(loadGrant(t.file)); // roundtrip
  for (const bad of ['not json', '{}', '{"id":"x"}', JSON.stringify({ id: 'a', principal: 'b', expiresAt: 'nope', phases: ['exploit'], maxGrants: 1, used: 0 }), JSON.stringify({ id: 'a', principal: 'b', expiresAt: new Date().toISOString(), phases: [], maxGrants: 1, used: 0 }), JSON.stringify({ id: 'a', principal: 'b', expiresAt: new Date().toISOString(), phases: ['exploit'], maxGrants: 0, used: 0 })]) {
    writeFileSync(t.file, bad);
    assert.equal(loadGrant(t.file), null, 'malformed: ' + bad.slice(0, 40));
  }
});

test('decide: every refusal reason, in doctrine order', () => {
  const now = Date.now();
  const g = createGrant({ hours: 1, max: 2, now });
  assert.equal(decide(g, 'recon', SIGNED, { now }).reason, 'phase-not-allowlisted');
  assert.equal(decide(g, 'exploit', SIGNED, { now: now + 2 * HOUR }).reason, 'expired');
  g.used = 2;
  assert.equal(decide(g, 'exploit', SIGNED, { now }).reason, 'exhausted');
  g.used = 0;
  assert.equal(decide(g, 'exploit', UNSIGNED, { now }).reason, 'unsigned-scope');
  assert.equal(decide(g, 'exploit', SIGNED, { now }).ok, true);
  assert.equal(decide(g, 'postex', SIGNED, { now }).ok, true);
});

test('autoApprove: no grant on file is the silent default — nothing audited', async () => {
  const t = tmp();
  await withEnv(t, async () => {
    const r = autoApprove('exploit', SIGNED);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'no-grant');
    assert.equal(auditLines(t.log).length, 0, 'the default state writes no audit noise');
  });
});

test('autoApprove: approval spends the cap on disk and audits; refusal with a grant audits too', async () => {
  const t = tmp();
  await withEnv(t, async () => {
    saveGrant(createGrant({ hours: 1, max: 1, note: 'test' }), t.file);
    const r = autoApprove('exploit', SIGNED);
    assert.equal(r.ok, true);
    assert.equal(r.remaining, 0);
    assert.equal(loadGrant(t.file).used, 1, 'the spend persisted');
    const r2 = autoApprove('postex', SIGNED);
    assert.equal(r2.ok, false);
    assert.equal(r2.reason, 'exhausted');
    const lines = auditLines(t.log);
    assert.equal(lines.length, 2);
    assert.equal(lines[0].decision, 'approved');
    assert.equal(lines[1].decision, 'refused');
    assert.equal(lines[1].reason, 'exhausted');
  });
});

test('Campaign._approve: a live grant countersigns without any human hook', async () => {
  const t = tmp();
  await withEnv(t, async () => {
    saveGrant(createGrant({ hours: 1, max: 2 }), t.file);
    const c = new Campaign({ scope: SIGNED }); // NO hooks.approve — human path would return false
    assert.equal(await c._approve({ id: 'exploit' }), true);
    assert.ok(c.activity.some((e) => e.kind === 'gate.auto'), 'gate.auto hit the operator feed');
  });
});

test('Campaign._approve: refusal falls through to the human gate UNCHANGED', async () => {
  const t = tmp();
  await withEnv(t, async () => {
    const g = createGrant({ hours: 1, max: 1 });
    g.used = 1; // exhausted
    saveGrant(g, t.file);
    const humanSays = new Campaign({ scope: SIGNED, hooks: { approve: async () => true } });
    assert.equal(await humanSays._approve({ id: 'exploit' }), true, 'exhausted grant → the human hook still decides');
    assert.ok(humanSays.activity.some((e) => e.kind === 'gate.auto.refused' && e.data.reason === 'exhausted'));
    const noHuman = new Campaign({ scope: SIGNED });
    assert.equal(await noHuman._approve({ id: 'exploit' }), false, 'no hook, no grant headroom → hold (fail closed)');
  });
});

test('Campaign._approve: an UNSIGNED scope is never auto-approved, grant or no', async () => {
  const t = tmp();
  await withEnv(t, async () => {
    saveGrant(createGrant({ hours: 1, max: 2 }), t.file);
    const c = new Campaign({ scope: UNSIGNED });
    assert.equal(await c._approve({ id: 'exploit' }), false);
    assert.ok(c.activity.some((e) => e.kind === 'gate.auto.refused' && e.data.reason === 'unsigned-scope'));
  });
});

test('statusGrant + revokeGrant: honest states, instant revocation', async () => {
  const t = tmp();
  await withEnv(t, async () => {
    assert.equal(statusGrant({ file: t.file }).state, 'none');
    saveGrant(createGrant({ hours: 1, max: 2 }), t.file);
    const s = statusGrant({ file: t.file });
    assert.equal(s.state, 'active');
    assert.equal(s.remaining, 2);
    assert.match(s.read, /signed scope only/);
    assert.equal(statusGrant({ now: Date.now() + 2 * HOUR, file: t.file }).state, 'expired');
    assert.equal(revokeGrant(t.file), true);
    assert.equal(loadGrant(t.file), null);
    assert.equal(revokeGrant(t.file), false, 'revoking nothing is reported, not faked');
  });
});
