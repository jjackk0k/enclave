// lateralexec.test.mjs — the GOVERNED AD TIER, rung 2 (LATERAL EXEC ADAPTERS).
// Hermetic: the pure LateralStore runs over an INJECTED fake backend (a Map standing
// in for the range's services/files/shares), so the per-adapter plan, the artifact
// manifest, the cleanup-proof (incl. its LOUD failure path), the foreign-clobber
// refusal, the gate matrix, the out-of-scope refusal, and the secret-negative
// contract all pin without touching a network, a service manager, or a share.
//
// HOUSE RULE: everything this suite writes lives under repo-local varvel/.tmp —
// never os.tmpdir(). VARVEL_SETTINGS_FILE points under .tmp; engagement names unique.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CallbackChannel } from '../engine/callback.mjs';
import {
  LATERAL_KINDS, LATERAL_ADAPTERS, LATERAL_REGISTRY, lateralTag,
  parseLateralSpec, lateralGate, lateralScopeCheck, lateralSpecSha256,
  LateralStore, parseLateralEvidence, assessLateralClean, lateralGraphItems,
} from '../engine/lateralexec.mjs';
import { Settings } from '../engine/settings.mjs';

const TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });
const WORK = mkdtempSync(join(TMP_ROOT, 'lateral-test-'));
process.env.VARVEL_SETTINGS_FILE = join(WORK, 'settings.json');

let engSeq = 0;
const freshEng = () => 'lateral-' + (engSeq++) + '-' + Date.now();
const TAG = 'vx-test0001';
const SECRET = 'Sup3rS3cret!RangePW';

// A Map-backed fake backend standing in for the range: services, files, shares.
function fakeBackend({ preExisting = [], dropKinds = null } = {}) {
  const key = (a) => a.kind + '|' + (a.name || a.path) + '|' + String(a.host || '').toLowerCase();
  const world = new Set(preExisting.map(key));
  return {
    world, key, runs: [], dropKinds,
    run(job) {
      this.runs.push({ adapter: job.adapter, target: job.target, command: job.command, user: job.user, hasPassword: job.password != null });
      for (const a of job.artifacts) if (a.kind !== 'share') world.add(key(a)); // the adapter creates its artifacts
      return { code: 0, output: 'nt authority\\system\r\n' };
    },
    probe(a) { return { present: world.has(key(a)) }; },
    remove(a) { if (this.dropKinds && this.dropKinds.has(a.kind)) return; /* the cleanup FAILURE knob: leaves it present */ world.delete(key(a)); },
  };
}
const specFor = (adapter, over = {}) => ({
  kind: 'lateral-exec', target: '10.0.0.9', adapter, command: 'whoami /all',
  user: 'rangeadmin', domain: 'CORP', password: SECRET, ...over,
});

// ——— ADAPTER PLANS (the pure registry) ———
test('the three adapters plan their honest artifact sets', () => {
  const wmi = LATERAL_REGISTRY.wmi.artifacts(TAG);
  assert.deepEqual(wmi.map((a) => a.kind), ['file', 'share']);
  assert.ok(wmi[0].path.includes(TAG));
  const psexec = LATERAL_REGISTRY.psexec.artifacts(TAG);
  assert.deepEqual(psexec.map((a) => a.kind), ['service', 'file', 'share']);
  assert.equal(psexec[0].name, TAG); // the temporary service name
  assert.equal(LATERAL_REGISTRY.winrm.artifacts(TAG).length, 0); // no persistent artifacts — said plainly
  assert.equal(LATERAL_REGISTRY.psexec.runsAs, 'SYSTEM');
  assert.equal(LATERAL_REGISTRY.wmi.runsAs, 'supplied-user');
});

// ——— EXEC + CLEANUP-PROOF over the fake backend ———
test('wmi exec: ran, result captured, artifacts created then verified-removed, manifest recorded', () => {
  const be = fakeBackend();
  const store = new LateralStore({ backend: be, name: TAG });
  const ev = store.exec(specFor('wmi'));
  assert.equal(ev.state, 'ran');
  assert.equal(be.runs.length, 1);
  assert.equal(be.runs[0].hasPassword, true); // the secret reached ONLY the injected backend (the agent-side seam)
  const file = ev.artifacts.find((a) => a.kind === 'file');
  assert.equal(file.removalVerified, true);
  assert.equal(file.present, false);
  const share = ev.artifacts.find((a) => a.kind === 'share');
  assert.equal(share.present, null); // a touch record, never probed
  const entry = store.manifest.entries[TAG];
  assert.equal(entry.removalVerified, true);
  assert.equal(entry.commandSha256.length, 64);
  assert.ok(!('command' in entry), 'the manifest pins the command by hash, never the raw line');
  const audit = store.audit();
  assert.equal(audit.clean, true);
});

test('psexec exec: service + file + share, all verified removed; winrm: ran with zero artifacts', () => {
  const be = fakeBackend();
  const ps = new LateralStore({ backend: be, name: TAG });
  const ev = ps.exec(specFor('psexec'));
  assert.equal(ev.state, 'ran');
  assert.ok(ev.artifacts.every((a) => a.kind === 'share' || a.removalVerified === true));
  const wr = new LateralStore({ backend: fakeBackend(), name: TAG });
  const ev2 = wr.exec(specFor('winrm'));
  assert.equal(ev2.state, 'ran');
  assert.equal(ev2.artifacts.length, 0);
  assert.equal(wr.audit().clean, true);
});

test('CLEANUP-PROOF FAILURE is loud: removal-failed, escalated, sweep unclean — then remove closes it', () => {
  const be = fakeBackend({ dropKinds: new Set(['file']) }); // the file refuses to die
  const store = new LateralStore({ backend: be, name: TAG });
  const ev = store.exec(specFor('psexec'));
  assert.equal(ev.state, 'removal-failed');
  assert.match(ev.error, /CLEANUP-PROOF FAILED/);
  assert.equal(store.manifest.entries[TAG].removalVerified, false);
  assert.equal(store.audit().clean, false);
  assert.match(store.audit().note, /CANNOT be called clean/);
  // the standing cleanup leg: fix the world, remove, verify
  be.dropKinds = null;
  const rm = store.remove();
  assert.equal(rm.state, 'removed');
  assert.equal(store.audit().clean, true);
});

test('a foreign artifact at the planned name is a loud refusal — never a takeover, never executed', () => {
  const plannedFile = { kind: 'file', path: '%SystemRoot%\\Temp\\' + TAG + '.out', host: '10.0.0.9' };
  const be = fakeBackend({ preExisting: [plannedFile] });
  const store = new LateralStore({ backend: be, name: TAG });
  const ev = store.exec(specFor('wmi'));
  assert.equal(ev.state, 'refused-clobber');
  assert.match(ev.error, /REFUSED to clobber/);
  assert.equal(be.runs.length, 0, 'nothing executed');
});

test('our own previously-recorded artifact does not trigger the clobber refusal', () => {
  const be = fakeBackend();
  const store = new LateralStore({ backend: be, name: TAG });
  store.exec(specFor('wmi'));
  // simulate a leftover from ourselves (manifest knows it): re-add to the world
  const leftover = { kind: 'file', path: '%SystemRoot%\\Temp\\' + TAG + '.out', host: '10.0.0.9' };
  be.world.add(be.key(leftover));
  const ev = store.exec(specFor('wmi'));
  assert.equal(ev.state, 'ran'); // reused and re-cleaned, not refused
});

test('status() is a live re-read; remove() on an empty handle is verified-clean', () => {
  const be = fakeBackend();
  const store = new LateralStore({ backend: be, name: TAG });
  assert.equal(store.status().state, 'absent');
  assert.equal(store.remove().state, 'removed');
  store.exec(specFor('wmi'));
  assert.equal(store.status().state, 'clean');
  be.world.add(be.key({ kind: 'file', path: '%SystemRoot%\\Temp\\' + TAG + '.out', host: '10.0.0.9' })); // out-of-band leftover
  assert.equal(store.status().state, 'present');
  assert.equal(store.remove().state, 'removed');
  assert.equal(store.status().state, 'clean');
});

// ——— SPEC GATE + SCOPE ———
test('spec parse matrix: IP-literal targets only, adapter allowlist, unambiguous remove scope', () => {
  assert.throws(() => parseLateralSpec('lateral-yolo', '{}'), /unknown kind/);
  assert.throws(() => parseLateralSpec('lateral-exec', '{}'), /target is required/);
  assert.throws(() => parseLateralSpec('lateral-exec', '{"target":"web01.corp.local","adapter":"wmi","command":"whoami"}'), /not an IP literal/);
  assert.throws(() => parseLateralSpec('lateral-exec', '{"target":"10.0.0.9","adapter":"smbexec","command":"whoami"}'), /unknown adapter/);
  assert.throws(() => parseLateralSpec('lateral-exec', '{"target":"10.0.0.9","adapter":"wmi"}'), /command is required/);
  assert.throws(() => parseLateralSpec('lateral-exec', JSON.stringify({ target: '10.0.0.9', adapter: 'wmi', command: 'x'.repeat(801) })), /cap/);
  const ok = parseLateralSpec('lateral-exec', JSON.stringify(specFor('wmi')));
  assert.equal(ok.target, '10.0.0.9');
  assert.equal(ok.password, SECRET); // the spec carries it for the agent; the audit trail never does
  assert.throws(() => parseLateralSpec('lateral-remove', '{}'), /explicit scope/);
  assert.throws(() => parseLateralSpec('lateral-remove', '{"name":"vx-a","all":true}'), /not both/);
  assert.deepEqual(parseLateralSpec('lateral-status', ''), { kind: 'lateral-status', name: null });
});

test('lateralScopeCheck: in-ring passes, out-of-ring and hostnames refuse loudly', () => {
  assert.equal(lateralScopeCheck('10.0.0.9', ['10.0.0.0/8']).ok, true);
  const out = lateralScopeCheck('192.168.50.9', ['10.0.0.0/8']);
  assert.equal(out.ok, false);
  assert.match(out.reason, /OUTSIDE the signed scope ring/);
  assert.equal(lateralScopeCheck('web01', ['10.0.0.0/8']).ok, false);
  assert.equal(lateralGate('off-' + Date.now()).ok, false);
});

// ——— CHANNEL GATE MATRIX + SECRET-NEGATIVE ———
function gatedChannel(eng) {
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['10.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'gated' });
  return { ch, events, agentId };
}

test('the gate is fail-closed for every lateral kind (GOVERNANCE, audited task.refused)', () => {
  const { ch, events, agentId } = gatedChannel(freshEng());
  for (const kind of LATERAL_KINDS) {
    let err = null;
    try { ch.task(agentId, kind, kind === 'lateral-exec' ? JSON.stringify(specFor('wmi')) : '{"all":true}'); } catch (e) { err = e; }
    assert.ok(err && err.code === 'GOVERNANCE', kind + ' refused with GOVERNANCE');
    assert.match(err.message, /ad\.lateral.*OFF/s);
  }
  assert.ok(events.filter((e) => e.type === 'task.refused').length >= 3);
});

test('gate on: queues with the audit pin; out-of-scope target refused even then; the SECRET never reaches the audit stream', () => {
  const eng = freshEng();
  Settings.for(eng).set('ad.lateral', true);
  const { ch, events, agentId } = gatedChannel(eng);
  const taskId = ch.task(agentId, 'lateral-exec', JSON.stringify(specFor('psexec')));
  assert.ok(taskId);
  const ev = events.find((e) => e.type === 'lateral.task');
  assert.ok(ev, 'lateral.task audited');
  assert.equal(ev.adapter, 'psexec');
  assert.equal(ev.target, '10.0.0.9');
  assert.equal(ev.user, 'rangeadmin');
  assert.ok(ev.specSha256);
  // THE SECRET-NEGATIVE SWEEP: the password appears NOWHERE in the audit stream.
  assert.ok(!JSON.stringify(events).includes(SECRET), 'the audit stream never carries the password');
  // the pin is the ORDER, not the secret: same spec modulo password -> same pin
  const a = parseLateralSpec('lateral-exec', JSON.stringify(specFor('wmi', { password: 'pw-one' })));
  const b = parseLateralSpec('lateral-exec', JSON.stringify(specFor('wmi', { password: 'pw-two' })));
  assert.equal(lateralSpecSha256(a), lateralSpecSha256(b));
  // out-of-scope refused loudly even with the gate on
  let err = null;
  try { ch.task(agentId, 'lateral-exec', JSON.stringify(specFor('wmi', { target: '192.168.50.9' }))); } catch (e) { err = e; }
  assert.ok(err && err.code === 'GOVERNANCE');
  assert.match(err.message, /OUTSIDE the signed scope ring/);
  assert.ok(events.some((e) => e.type === 'task.refused' && /OUTSIDE/.test(e.reason)));
});

// ——— INTAKE + CLEAN SWEEP over the audit stream ———
test('lateral.ran / removed / remove-failed / status events; the output tail never enters audit', () => {
  const eng = freshEng();
  Settings.for(eng).set('ad.lateral', true);
  const { ch, events, agentId } = gatedChannel(eng);
  const t1 = ch.task(agentId, 'lateral-exec', JSON.stringify(specFor('psexec')));
  const ranBody = JSON.stringify({
    op: 'ran', pid: 44, state: 'ran',
    names: {
      [TAG]: {
        state: 'ran', adapter: 'psexec', target: '10.0.0.9', exitCode: null,
        outputTail: 'nt authority\\system', outputSha256: 'ab'.repeat(32),
        artifacts: [
          { kind: 'service', role: 'exec-host', name: TAG, host: '10.0.0.9', present: false, removalVerified: true },
          { kind: 'file', role: 'result-capture', path: '%SystemRoot%\\Temp\\' + TAG + '.out', host: '10.0.0.9', present: false, removalVerified: true },
          { kind: 'share', role: 'result-read', name: 'ADMIN$', host: '10.0.0.9', present: null, removalVerified: null },
        ],
        removalVerified: true,
      },
    },
    at: new Date().toISOString(),
  });
  ch._intakeResult(ch.agents.get(agentId), t1, Buffer.from(ranBody));
  const ran = events.find((e) => e.type === 'lateral.ran');
  assert.ok(ran);
  assert.equal(ran.names[TAG].artifacts.length, 3);
  assert.ok(!JSON.stringify(ran).includes('nt authority'), 'the output tail is stripped from the audit stream');
  assert.ok(!JSON.stringify(events).includes(SECRET));
  assert.equal(assessLateralClean(events).clean, true, 'verified-autoclean closes the engagement');

  // a removal-failed exec keeps the engagement UNCLEAN until a verified removal lands
  const t2 = ch.task(agentId, 'lateral-exec', JSON.stringify(specFor('wmi')));
  const failBody = JSON.stringify({
    op: 'ran', pid: 44, state: 'removal-failed',
    names: { 'vx-leak01': { state: 'removal-failed', adapter: 'wmi', target: '10.0.0.9', exitCode: null, artifacts: [{ kind: 'file', role: 'result-capture', path: '%SystemRoot%\\Temp\\vx-leak01.out', host: '10.0.0.9', present: true, removalVerified: false }], removalVerified: false } },
    at: new Date().toISOString(),
  });
  ch._intakeResult(ch.agents.get(agentId), t2, Buffer.from(failBody));
  let assess = assessLateralClean(events);
  assert.equal(assess.clean, false);
  assert.equal(assess.open[0].name, 'vx-leak01');
  const t3 = ch.task(agentId, 'lateral-remove', '{"name":"vx-leak01"}');
  ch._intakeResult(ch.agents.get(agentId), t3, Buffer.from(JSON.stringify({
    op: 'remove', pid: 44, state: 'removed',
    names: { 'vx-leak01': { state: 'removed', adapter: 'wmi', target: '10.0.0.9', artifacts: [{ kind: 'file', role: 'result-capture', path: '%SystemRoot%\\Temp\\vx-leak01.out', host: '10.0.0.9', present: false, removalVerified: true }], removalVerified: true } },
    at: new Date().toISOString(),
  })));
  assess = assessLateralClean(events);
  assert.equal(assess.clean, true);
  assert.ok(events.some((e) => e.type === 'lateral.removed'));
});

test('an escalated remove-failed event flips the type and carries escalated:true', () => {
  const eng = freshEng();
  Settings.for(eng).set('ad.lateral', true);
  const { ch, events, agentId } = gatedChannel(eng);
  const t = ch.task(agentId, 'lateral-remove', '{"name":"vx-stuck1"}');
  ch._intakeResult(ch.agents.get(agentId), t, Buffer.from(JSON.stringify({
    op: 'remove', pid: 1, state: 'removal-failed',
    names: { 'vx-stuck1': { state: 'removal-failed', adapter: 'psexec', target: '10.0.0.9', artifacts: [{ kind: 'service', name: 'vx-stuck1', host: '10.0.0.9', present: true, removalVerified: false }], removalVerified: false } },
    at: new Date().toISOString(),
  })));
  const ev = events.find((e) => e.type === 'lateral.remove-failed');
  assert.ok(ev, 'the escalation is the event TYPE, never a buried boolean');
  assert.equal(ev.escalated, true);
  assert.equal(parseLateralEvidence('lateral-exec REFUSED: ...'), null);
});

test('lateralGraphItems normalizes a ran-exec for the attack-path graph', () => {
  const item = lateralGraphItems(TAG, { state: 'ran', adapter: 'wmi', target: '10.0.0.9', exitCode: 0 }, '10.0.0.4');
  assert.deepEqual(item, { srcHost: '10.0.0.4', target: '10.0.0.9', adapter: 'wmi', ok: true, exitCode: 0 });
});

test('the deterministic tag matches the agent-side derivation', () => {
  assert.match(lateralTag('agent|url'), /^vx-[0-9a-f]{8}$/);
});
