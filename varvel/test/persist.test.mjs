// persist.test.mjs — the GOVERNED PERSISTENCE TIER (roadmap #8): cleanup-proof user-land
// persistence for the Windows range agent. Hermetic by default: the PS-host layer is an
// injected runner and the technique backends are injected stores, so the spec parse
// matrix, BOTH gate halves (default-OFF refusals), the install manifest shape, the
// clobber-refusal + journal, remove-verifies, the cleanup-proof FAILURE path (loud +
// escalated), the engagement sweep, and the audit hash assertions are all pinned
// without spawning a process or touching the real registry/scheduler/Startup folder.
//
// HOUSE RULE (absolute): payload-class test artifacts live under repo-local varvel/.tmp/
// (created with mkdirSync recursive) — NEVER os.tmpdir().
//
// The LAST test is the GUARDED LIVE path (opt-in): set VARVEL_LIVE_PERSIST=1 to spawn a
// THROWAWAY powershell child running the real persist host, install the STARTUP-FOLDER
// technique ONLY (the least invasive) pointing at a harmless inert line, verify
// presence, then verify absence after remove — self-cleaning even on failure
// (try/finally). Default: SKIP. On THIS machine, user-context only.
//
// Settings discipline (house pattern): VARVEL_SETTINGS_FILE points under .tmp for THIS
// process and every engagement name is unique.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CallbackChannel } from '../engine/callback.mjs';
import {
  PERSIST_KINDS, PERSIST_TECHNIQUES, PERSIST_RUNKEY_PATH,
  parsePersistSpec, persistGate, persistTag, persistLocation, persistSpecSha256,
  PersistStore, parsePersistEvidence, assessEngagementClean,
} from '../engine/persist.mjs';
import { runPersistTask, powerShellPersistRunner, PERSIST_HOST_PATH } from '../agents/persist.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { Settings } from '../engine/settings.mjs';
import { assessPersist, parsePersistResult } from '../tools/persist.mjs';
import { buildSnapshotCommand } from '../tools/detoracle.mjs';
import { spawnSync } from 'node:child_process';

// HOUSE RULE: everything this suite writes lives under repo-local .tmp (gitignored,
// Defender-excluded) — never os.tmpdir().
const TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });
const WORK = mkdtempSync(join(TMP_ROOT, 'persist-test-'));
process.env.VARVEL_SETTINGS_FILE = join(WORK, 'settings.json');

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
let engSeq = 0;
const freshEng = () => 'persist-' + (engSeq++) + '-' + Date.now();

const TAG = 'VARVEL-test01';
const TARGET = '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\\range\\varvel-agent.ps1" -Url "http://127.0.0.1:8971" -AgentId "a1" -Token "deadbeef"';

// A Map-backed fake store standing in for the registry / Task Scheduler / Startup
// folder — the technique implementations never touch the real ones from Node.
function mapBackend(seed = {}) {
  const m = new Map(Object.entries(seed));
  return {
    map: m,
    probe: (loc) => (m.has(loc) ? { present: true, value: m.get(loc) } : { present: false, value: null }),
    apply: (loc, v) => { m.set(loc, String(v)); },
    remove: (loc) => { m.delete(loc); },
  };
}

// The evidence JSON a REAL agent-side op returns (mirrors the PS host's shape), built
// by running the REAL state machine (PersistStore) over the fake store — the same
// contract the ==PERSIST-LIB== block fulfills against Windows.
function hostFromStore(backend) {
  const stores = new Map();
  return async (jobJson) => {
    const job = JSON.parse(jobJson);
    const target = job.target || TARGET;
    const tag = job.name || persistTag(target);
    if (!stores.has(tag)) stores.set(tag, new PersistStore({ backend, tag, target }));
    const store = stores.get(tag);
    if (job.op === 'audit') {
      const a = store.audit();
      return { stdout: JSON.stringify({ op: 'audit', pid: 4321, state: a.clean ? 'clean' : 'unclean', clean: a.clean, entries: a.entries, open: a.open, note: a.note, at: new Date().toISOString() }), stderr: '' };
    }
    const techniques = {};
    const techs = job.techniques && job.techniques.length ? job.techniques : PERSIST_TECHNIQUES;
    for (const t of techs) {
      techniques[t] = job.op === 'install' ? store.install(t, { overwrite: job.overwrite === true })
        : job.op === 'remove' ? store.remove(t)
        : store.status(t);
    }
    const states = Object.values(techniques).map((e) => e.state);
    const agg = states.some((s) => s === 'failed' || s === 'removal-failed') ? 'failed'
      : states.some((s) => s === 'refused-clobber' || s === 'refused-foreign') ? 'refused'
      : job.op === 'install' ? 'installed' : job.op === 'remove' ? 'removed'
      : states.every((s) => s === 'installed') ? 'installed' : states.every((s) => s === 'absent' || s === 'removed') ? 'absent' : 'mixed';
    return { stdout: JSON.stringify({ op: job.op, pid: 4321, state: agg, techniques, at: new Date().toISOString() }), stderr: '' };
  };
}

// ---------------- spec parse (the pre-queue / pre-exec refusal layer) ----------------
test('parsePersistSpec: the valid matrix parses (dedup + case-fold + defaults)', () => {
  assert.deepEqual(parsePersistSpec('persist-install', '{"techniques":["RUNKEY","runkey","schtask"]}'),
    { kind: 'persist-install', techniques: ['runkey', 'schtask'], name: null, overwrite: false });
  assert.deepEqual(parsePersistSpec('persist-install', '{"techniques":["startup"],"name":"MyOp-2026","overwrite":true}'),
    { kind: 'persist-install', techniques: ['startup'], name: 'MyOp-2026', overwrite: true });
  assert.deepEqual(parsePersistSpec('persist-status', ''), { kind: 'persist-status', techniques: null, name: null });
  assert.deepEqual(parsePersistSpec('persist-status', '{}'), { kind: 'persist-status', techniques: null, name: null });
  assert.deepEqual(parsePersistSpec('persist-status', '{"techniques":["runkey"]}'), { kind: 'persist-status', techniques: ['runkey'], name: null });
  assert.deepEqual(parsePersistSpec('persist-remove', '{"techniques":["startup"]}'), { kind: 'persist-remove', techniques: ['startup'], all: false, name: null });
  assert.deepEqual(parsePersistSpec('persist-remove', '{"all":true}'), { kind: 'persist-remove', techniques: null, all: true, name: null });
  assert.deepEqual(parsePersistSpec('persist-audit', ''), { kind: 'persist-audit', techniques: null });
  assert.deepEqual(parsePersistSpec('persist-audit', '{}'), { kind: 'persist-audit', techniques: null });
});

test('parsePersistSpec: every malformed spec refuses loudly (nothing installs)', () => {
  assert.throws(() => parsePersistSpec('persist-install', 'not json'), /not valid JSON/);
  assert.throws(() => parsePersistSpec('persist-install', '{}'), /techniques must be an array/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":[]}'), /empty/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["runkey","wmi"]}'), /unknown technique "wmi"/, 'WMI event subscription is NOT this wave (documented boundary)');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["kernel"]}'), /unknown technique/, 'kernel anything: out of scope permanently');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["hklm-run"]}'), /unknown technique/, 'machine-wide hives: out of scope this wave');
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["runkey"],"name":"bad name!"}'), /not a safe persistence handle/);
  assert.throws(() => parsePersistSpec('persist-install', '{"techniques":["runkey"],"overwrite":"yes"}'), /overwrite must be a boolean/);
  assert.throws(() => parsePersistSpec('persist-remove', ''), /explicit scope/, 'remove is never ambiguous');
  assert.throws(() => parsePersistSpec('persist-remove', '{}'), /explicit scope/);
  assert.throws(() => parsePersistSpec('persist-remove', '{"all":true,"techniques":["runkey"]}'), /not both/);
  assert.throws(() => parsePersistSpec('persist-remove', '{"all":false}'), /explicit scope/);
  assert.throws(() => parsePersistSpec('persist-audit', '{"techniques":["runkey"]}'), /takes no task data/);
  assert.throws(() => parsePersistSpec('persist-x', '{}'), /unknown kind/);
});

// ---------------- governance: the engagement gate (default OFF) + audit ----------------
test('channel gate: persist.enabled defaults OFF — all four kinds refuse LOUDLY + audited; other kinds unaffected', () => {
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: freshEng(), signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'gated' });
  const dataFor = (k) => (k === 'persist-install' ? '{"techniques":["startup"]}' : k === 'persist-remove' ? '{"all":true}' : '');
  for (const kind of PERSIST_KINDS) {
    let err = null;
    try { ch.task(agentId, kind, dataFor(kind)); } catch (e) { err = e; }
    assert.ok(err, kind + ' must throw');
    assert.equal(err.code, 'GOVERNANCE');
    assert.match(err.message, /persist\.enabled.*OFF/);
    assert.match(err.message, /Nothing installed/);
    assert.ok(events.some((e) => e.type === 'task.refused' && e.kind === kind), kind + ' refusal is audited');
  }
  assert.ok(!events.some((e) => e.type === 'task.queued' && PERSIST_KINDS.has(e.kind)), 'a refused task never queues');
  assert.ok(!events.some((e) => e.type === 'persist.task'), 'no audit event without a queue');
  assert.throws(() => ch.taskWhere({ all: true }, 'persist-install', '{"techniques":["startup"]}'), (e) => e.code === 'GOVERNANCE', 'broadcast refuses identically');
  assert.ok(ch.task(agentId, 'shell', 'hostname'), 'the gate never touches ordinary kinds');
  assert.equal(persistGate('persist-never-enabled-xyz').ok, false, 'the gate fails CLOSED on an unreadable/unknown engagement');
});

test('channel gate ON: the task queues and the spec sha256 lands in audit (the hash pins what was ordered)', () => {
  const eng = freshEng();
  Settings.for(eng).set('persist.enabled', true);
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'allowed' });
  const taskId = ch.task(agentId, 'persist-install', '{"techniques":["runkey","startup"],"overwrite":true}');
  assert.ok(taskId);
  const ev = events.find((e) => e.type === 'persist.task');
  assert.ok(ev, 'the queue-time audit event exists');
  assert.equal(ev.taskId, taskId);
  assert.deepEqual(ev.techniques, ['runkey', 'startup']);
  assert.equal(ev.overwrite, true);
  assert.equal(ev.specSha256, persistSpecSha256(parsePersistSpec('persist-install', '{"techniques":["runkey","startup"],"overwrite":true}')), 'the audit hash pins exactly the normalized spec that was ordered');
  assert.match(ev.specSha256, /^[0-9a-f]{64}$/);
  // remove-all: techniques null + all:true
  ch.task(agentId, 'persist-remove', '{"all":true}');
  const ev2 = events.filter((e) => e.type === 'persist.task')[1];
  assert.equal(ev2.techniques, null);
  assert.equal(ev2.all, true);
  // the spec gate still bites with the engagement gate open
  assert.throws(() => ch.task(agentId, 'persist-install', '{"techniques":["svc"]}'), (e) => e.code === 'GOVERNANCE' && /unknown technique/.test(e.message));
});

// ---------------- PersistStore: the cleanup-proof state machine over a fake store ----------------
test('PersistStore install: manifest shape, locations, target hash, install verified by re-read', () => {
  const backend = mapBackend();
  const store = new PersistStore({ backend, tag: TAG, target: TARGET });
  const ev = store.install('runkey');
  assert.equal(ev.state, 'installed');
  assert.equal(ev.installVerified, true, 'the write was re-read and proven');
  assert.equal(ev.preExisted, false);
  assert.equal(ev.location, PERSIST_RUNKEY_PATH + '\\' + TAG);
  assert.equal(ev.targetSha256, sha256(TARGET), 'the audit hash pins the exact relaunch line');
  assert.equal(backend.probe(ev.location).value, TARGET);
  // manifest shape — the removal record
  const entry = store.manifest.entries.runkey;
  assert.equal(entry.technique, 'runkey');
  assert.equal(entry.location, ev.location);
  assert.equal(entry.targetSha256, sha256(TARGET));
  assert.deepEqual(entry.preInstall, { present: false, value: null, valueSha256: null }, 'pre-install snapshot recorded (nothing was there)');
  assert.equal(entry.overwriteJournaled, false);
  assert.equal(entry.state, 'installed');
  assert.ok(entry.installedAt);
  assert.equal(entry.removalVerified, null);
  assert.equal(store.manifest.tag, TAG);
  assert.equal(store.manifest.target, TARGET);
  // all three canonical locations
  assert.equal(persistLocation('schtask', TAG), '\\' + TAG);
  assert.equal(persistLocation('startup', TAG), '%STARTUP%\\' + TAG + '.lnk');
  // idempotent re-install: present+intact re-verified, nothing rewritten
  const ev2 = store.install('runkey');
  assert.equal(ev2.state, 'installed');
  assert.match(ev2.note, /idempotent/);
  // the constructor refuses to run without an injected backend / tag / target
  assert.throws(() => new PersistStore({ tag: TAG, target: TARGET }), /injected backend/);
  assert.throws(() => new PersistStore({ backend, tag: 'bad tag!', target: TARGET }), /valid tag/);
  assert.throws(() => new PersistStore({ backend, tag: TAG, target: '' }), /target relaunch line/);
});

test('PersistStore clobber: foreign values refuse silently-clobbering; overwrite journals; remove RESTORES the journal', () => {
  const loc = persistLocation('runkey', TAG);
  const OLD = 'C:\\Users\\range\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\old-agent.lnk /quiet';
  const backend = mapBackend({ [loc]: OLD });
  const store = new PersistStore({ backend, tag: TAG, target: TARGET });
  // 1. refusal: nothing written, loud reason
  const ref = store.install('runkey');
  assert.equal(ref.state, 'refused-clobber');
  assert.match(ref.note, /REFUSED to clobber/);
  assert.equal(backend.probe(loc).value, OLD, 'the foreign value was NOT touched');
  // 2. overwrite: the old value is JOURNALED, the write verified
  const ins = store.install('runkey', { overwrite: true });
  assert.equal(ins.state, 'installed');
  assert.equal(ins.preExisted, true);
  assert.equal(ins.overwriteJournaled, true);
  const entry = store.manifest.entries.runkey;
  assert.equal(entry.preInstall.present, true);
  assert.equal(entry.preInstall.value, OLD, 'the journal carries the exact pre-install value');
  assert.equal(entry.preInstall.valueSha256, sha256(OLD));
  assert.equal(backend.probe(loc).value, TARGET);
  // 3. remove RESTORES the journaled value and re-verifies (not a bare delete)
  const rem = store.remove('runkey');
  assert.equal(rem.state, 'removed');
  assert.equal(rem.journalRestored, true);
  assert.equal(rem.removalVerified, true);
  assert.equal(backend.probe(loc).value, OLD, 'the location provably holds what it held BEFORE install');
  assert.equal(store.manifest.entries.runkey.state, 'removed');
  assert.equal(store.manifest.entries.runkey.removalVerified, true);
});

test('PersistStore remove VERIFIES absence; foreign locations are never deleted; status is a live re-read', () => {
  const backend = mapBackend();
  const store = new PersistStore({ backend, tag: TAG, target: TARGET });
  store.install('startup');
  const loc = persistLocation('startup', TAG);
  assert.equal(backend.probe(loc).present, true);
  // status: installed + intact (live)
  const st = store.status('startup');
  assert.equal(st.state, 'installed');
  assert.equal(st.installVerified, true);
  // tamper: the value changes under us — status says so honestly
  backend.apply(loc, 'C:\\evil\\other.exe /x');
  assert.equal(store.status('startup').state, 'tampered');
  backend.apply(loc, TARGET);
  // remove: verified absent
  const rem = store.remove('startup');
  assert.equal(rem.state, 'removed');
  assert.equal(rem.removalVerified, true);
  assert.equal(backend.probe(loc).present, false);
  // status after: removed (verified), still absent at a fresh re-read
  const st2 = store.status('startup');
  assert.equal(st2.state, 'removed');
  assert.equal(st2.removalVerified, true);
  // idempotent remove of an absent location: verified clean, not an error
  const rem2 = store.remove('schtask');
  assert.equal(rem2.state, 'removed');
  assert.equal(rem2.removalVerified, true);
  assert.match(rem2.note, /verified clean|already absent/);
  // a FOREIGN value we never installed is REFUSED (we never delete what we did not write)
  const foreignLoc = persistLocation('schtask', TAG);
  backend.apply(foreignLoc, 'C:\\someone-else\\thing.exe');
  const rem3 = store.remove('schtask');
  assert.equal(rem3.state, 'refused-foreign');
  assert.match(rem3.note, /REFUSED to remove what we did not write/);
  assert.equal(backend.probe(foreignLoc).present, true, 'the foreign value survived');
});

test('PersistStore cleanup-proof FAILURE path: an unverifiable removal is LOUD, kept, and escalated — the sweep never calls it clean', () => {
  const loc = persistLocation('runkey', TAG);
  // a store whose deletes never take (an EDR/permissions wall): probe still shows present
  const sticky = {
    probe: (l) => (l === loc ? { present: true, value: TARGET } : { present: false, value: null }),
    apply: () => {},
    remove: () => {}, // the delete silently does nothing
  };
  const store = new PersistStore({ backend: sticky, tag: TAG, target: TARGET });
  const ins = store.install('runkey');
  assert.equal(ins.state, 'installed');
  const rem = store.remove('runkey');
  assert.equal(rem.state, 'removal-failed', 'the unverifiable removal is a first-class loud failure');
  assert.equal(rem.removalVerified, false);
  assert.match(rem.error, /CLEANUP-PROOF FAILED|STILL PRESENT/);
  // the entry STAYS in the manifest as an open loose end
  assert.equal(store.manifest.entries.runkey.state, 'removal-failed');
  assert.equal(store.manifest.entries.runkey.removalVerified, false);
  // the sweep: unclean, with the entry open
  const sweep = store.audit();
  assert.equal(sweep.clean, false);
  assert.equal(sweep.state, 'unclean');
  assert.equal(sweep.open.length, 1);
  assert.equal(sweep.open[0].technique, 'runkey');
  assert.match(sweep.note, /CANNOT be called clean/);
});

test('PersistStore audit sweep: empty is clean; installed is unclean; verified removal closes it (measured live, not remembered)', () => {
  const backend = mapBackend();
  const store = new PersistStore({ backend, tag: TAG, target: TARGET });
  const s0 = store.audit();
  assert.equal(s0.clean, true);
  assert.equal(s0.entries.length, 0);
  store.install('runkey');
  store.install('startup');
  const s1 = store.audit();
  assert.equal(s1.clean, false);
  assert.equal(s1.open.length, 2, 'both installs are open (present, never removed)');
  store.remove('runkey');
  const s2 = store.audit();
  assert.equal(s2.clean, false, 'startup still present');
  assert.equal(s2.open.length, 1);
  // out-of-band removal of the lnk: the sweep MEASURES absence live and closes it
  backend.remove(persistLocation('startup', TAG));
  const s3 = store.audit();
  assert.equal(s3.clean, true, 'live-verified absent at sweep — measured now, not remembered');
  assert.equal(s3.entries.every((e) => e.removalVerified === true), true);
});

// ---------------- evidence parse + engagement sweep (channel-side audit) ----------------
test('parsePersistEvidence: install/remove/status/sweep map to the right events; remove-failed escalates; refusal text emits NOTHING', async () => {
  const backend = mapBackend();
  const runner = hostFromStore(backend);
  // install
  const inRaw = await runPersistTask('persist-install', '{"techniques":["runkey"]}', { runner, target: TARGET, defaultName: TAG, manifestPath: join(WORK, 'm1.json') });
  const ev1 = parsePersistEvidence(inRaw);
  assert.equal(ev1.event, 'persist.installed');
  assert.equal(ev1.fields.techniques.runkey.state, 'installed');
  assert.equal(ev1.fields.techniques.runkey.targetSha256, sha256(TARGET));
  assert.equal(ev1.fields.techniques.runkey.installVerified, true);
  assert.equal(ev1.fields.escalated, false);
  // remove (verified)
  const reRaw = await runPersistTask('persist-remove', '{"techniques":["runkey"]}', { runner, target: TARGET, defaultName: TAG, manifestPath: join(WORK, 'm1.json') });
  const ev2 = parsePersistEvidence(reRaw);
  assert.equal(ev2.event, 'persist.removed');
  assert.equal(ev2.fields.techniques.runkey.removalVerified, true);
  // status
  const stRaw = await runPersistTask('persist-status', '', { runner, target: TARGET, defaultName: TAG, manifestPath: join(WORK, 'm1.json') });
  const ev3 = parsePersistEvidence(stRaw);
  assert.equal(ev3.event, 'persist.status');
  // audit sweep
  const auRaw = await runPersistTask('persist-audit', '', { runner, target: TARGET, defaultName: TAG, manifestPath: join(WORK, 'm1.json') });
  const ev4 = parsePersistEvidence(auRaw);
  assert.equal(ev4.event, 'persist.sweep');
  assert.equal(ev4.fields.clean, true);
  // a remove that CANNOT verify flips the event + escalates
  const stickyRunner = async () => ({ stdout: JSON.stringify({ op: 'remove', pid: 1, state: 'failed', techniques: { runkey: { state: 'removal-failed', location: 'L', removalVerified: false, error: 'STILL PRESENT' } }, at: new Date().toISOString() }), stderr: '' });
  const ev5 = parsePersistEvidence(await runPersistTask('persist-remove', '{"techniques":["runkey"]}', { runner: stickyRunner, target: TARGET, defaultName: TAG }));
  assert.equal(ev5.event, 'persist.remove-failed');
  assert.equal(ev5.fields.escalated, true, 'the escalation flag rides the audit event — never a buried boolean');
  // refusal text / garbage / empty techniques: NO event is fabricated
  assert.equal(parsePersistEvidence('persist-install REFUSED: agent-side persistence is OFF'), null);
  assert.equal(parsePersistEvidence('not json at all'), null);
  assert.equal(parsePersistEvidence(JSON.stringify({ op: 'install', state: 'failed', techniques: {} })), null, 'a runner-level failure envelope carries no per-technique truth — no event');
});

test('assessEngagementClean: the platform refuses to call an engagement clean while unverified persistence exists', () => {
  const A = 'agent-1';
  const loc = PERSIST_RUNKEY_PATH + '\\' + TAG;
  const events = [
    { type: 'persist.installed', agentId: A, techniques: { runkey: { state: 'installed', technique: 'runkey', location: loc, targetSha256: 'x' } } },
  ];
  let r = assessEngagementClean(events);
  assert.equal(r.clean, false, 'installed and never removed: UNCLEAN');
  assert.equal(r.open.length, 1);
  // a removal that did NOT verify keeps it open + escalated
  r = assessEngagementClean([...events, { type: 'persist.remove-failed', agentId: A, escalated: true, techniques: { runkey: { state: 'removal-failed', location: loc, removalVerified: false } } }]);
  assert.equal(r.clean, false);
  assert.equal(r.open[0].escalated, true, 'the failed removal is escalated in the sweep');
  // a verified removal closes it
  r = assessEngagementClean([...events, { type: 'persist.removed', agentId: A, techniques: { runkey: { state: 'removed', location: loc, removalVerified: true } } }]);
  assert.equal(r.clean, true);
  assert.equal(r.closed.length, 1);
  // a clean agent-side sweep also closes what that agent had open
  r = assessEngagementClean([...events, { type: 'persist.sweep', agentId: A, clean: true, entries: [], open: [] }]);
  assert.equal(r.clean, true, 'a live clean sweep from the agent closes its open entries');
  // an unclean sweep re-asserts open entries
  r = assessEngagementClean([{ type: 'persist.sweep', agentId: A, clean: false, open: [{ technique: 'startup', location: '%STARTUP%\\VARVEL-x.lnk', state: 'installed' }], entries: [] }]);
  assert.equal(r.clean, false);
  assert.equal(r.open[0].escalated, true);
  // no persistence at all: clean
  assert.equal(assessEngagementClean([]).clean, true);
});

// ---------------- agent-side executor (injected runner — the hermetic seam) ----------------
test('runPersistTask: refusal texts are loud; install requires the captured target; an attempt is op-FIRST evidence JSON', async () => {
  const bad = await runPersistTask('persist-install', 'garbage', { runner: async () => ({ stdout: '{}' }), target: TARGET });
  assert.match(bad, /^persist-install REJECTED: /);
  const none = await runPersistTask('persist-install', '{"techniques":["runkey"]}', { target: TARGET });
  assert.match(none, /^persist-install REFUSED: /);
  const noTarget = await runPersistTask('persist-install', '{"techniques":["runkey"]}', { runner: async () => ({ stdout: '{}' }) });
  assert.match(noTarget, /^persist-install REJECTED: no relaunch target/, 'persistence must relaunch the SAME agent with the SAME config — no captured line, no install');
  let jobSeen = null;
  const runner = async (jobJson) => { jobSeen = jobJson; return { stdout: JSON.stringify({ op: 'install', pid: 77, state: 'installed', techniques: { runkey: { state: 'installed', location: 'L', targetSha256: sha256(TARGET), installVerified: true } }, at: new Date().toISOString() }), stderr: '' }; };
  const res = JSON.parse(await runPersistTask('persist-install', '{"techniques":["runkey"],"overwrite":true,"name":"OpX"}', { runner, target: TARGET, manifestPath: join(WORK, 'm2.json'), defaultName: TAG }));
  assert.deepEqual(Object.keys(res).slice(0, 3), ['op', 'pid', 'state'], 'op leads — the 120-char ledger preview always carries it');
  assert.equal(res.op, 'install');
  assert.equal(res.state, 'installed');
  const job = JSON.parse(jobSeen);
  assert.equal(job.op, 'install');
  assert.deepEqual(job.techniques, ['runkey']);
  assert.equal(job.target, TARGET, 'the agent-side captured relaunch line rides the job (never the channel)');
  assert.equal(job.overwrite, true);
  assert.equal(job.name, 'OpX');
  assert.equal(job.manifestPath, join(WORK, 'm2.json'));
  // remove-all job shape
  let job2 = null;
  await runPersistTask('persist-remove', '{"all":true}', { runner: async (j) => { job2 = j; return { stdout: JSON.stringify({ op: 'remove', pid: 77, state: 'removed', techniques: { runkey: { state: 'removed', removalVerified: true } }, at: new Date().toISOString() }), stderr: '' }; }, target: TARGET, defaultName: TAG });
  assert.equal(JSON.parse(job2).all, true);
  assert.equal(JSON.parse(job2).techniques, null);
});

test('runPersistTask: runner failures stay honest (failed state, never a dressed-up win)', async () => {
  const timeout = JSON.parse(await runPersistTask('persist-install', '{"techniques":["runkey"]}', { runner: async () => ({ stdout: '', stderr: '', error: 'persist host op timeout after 50ms — host killed' }), target: TARGET }));
  assert.equal(timeout.state, 'failed');
  assert.match(timeout.error, /timeout/i);
  const garbage = JSON.parse(await runPersistTask('persist-status', '', { runner: async () => ({ stdout: 'host noise, no json', stderr: '' }), target: TARGET, defaultName: TAG }));
  assert.equal(garbage.state, 'failed');
  assert.match(garbage.error, /unparseable/);
  const threw = JSON.parse(await runPersistTask('persist-remove', '{"all":true}', { runner: async () => { throw new Error('boom'); }, target: TARGET, defaultName: TAG }));
  assert.equal(threw.state, 'failed');
  assert.match(threw.error, /boom/);
});

// ---------------- the default runner's plumbing (fake child process — still hermetic) ----------------
function fakePersistChild({ hang = false } = {}) {
  const c = new EventEmitter();
  c.stdin = new PassThrough();
  c.stdout = new PassThrough();
  c.stderr = new PassThrough();
  c.killed = false;
  c.kill = () => { c.killed = true; setImmediate(() => c.emit('close')); };
  const host = hostFromStore(mapBackend());
  let buf = '';
  c.stdin.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const job = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      c.jobs = c.jobs || [];
      c.jobs.push(job);
      if (hang || !job) continue;
      host(job).then((r) => c.stdout.write(r.stdout + '\n'));
    }
  });
  return c;
}

test('powerShellPersistRunner: one PERSISTENT host serves ordered ops against ONE store; timeout kills; spawn failure is honest', async () => {
  const child = fakePersistChild();
  const runner = powerShellPersistRunner({ spawnFn: () => child, timeoutMs: 5000 });
  const r1 = JSON.parse(await runPersistTask('persist-install', '{"techniques":["startup"]}', { runner, target: TARGET, defaultName: TAG }));
  assert.equal(r1.state, 'installed');
  const r2 = JSON.parse(await runPersistTask('persist-status', '{"techniques":["startup"]}', { runner, target: TARGET, defaultName: TAG }));
  assert.equal(r2.state, 'installed');
  assert.equal(r2.techniques.startup.installVerified, true, 'status is a live re-read against the same store');
  const r3 = JSON.parse(await runPersistTask('persist-remove', '{"techniques":["startup"]}', { runner, target: TARGET, defaultName: TAG }));
  assert.equal(r3.state, 'removed');
  assert.equal(r3.techniques.startup.removalVerified, true);
  assert.equal(child.jobs.length, 3, 'ONE persistent child served all three ops (install/status/remove observe ONE store)');
  runner.close();
  assert.ok(child.killed, 'close() kills the host');

  const hung = fakePersistChild({ hang: true });
  const slow = powerShellPersistRunner({ spawnFn: () => hung, timeoutMs: 50 });
  const r4 = JSON.parse(await runPersistTask('persist-install', '{"techniques":["startup"]}', { runner: slow, target: TARGET, defaultName: TAG }));
  assert.equal(r4.state, 'failed');
  assert.match(r4.error, /timeout/);
  assert.ok(hung.killed, 'a wedged host is killed — the task loop survives');

  const dead = powerShellPersistRunner({ spawnFn: () => { throw new Error('ENOENT'); } });
  const r5 = JSON.parse(await runPersistTask('persist-install', '{"techniques":["startup"]}', { runner: dead, target: TARGET, defaultName: TAG }));
  assert.equal(r5.state, 'failed');
  assert.match(r5.error, /spawn failed/);
});

// ---------------- end-to-end over a REAL channel + REAL SimAgent (fake runner) ----------------
async function wiredAgent({ persist, persistRunner }) {
  const eng = freshEng();
  Settings.for(eng).set('persist.enabled', true); // channel half of the gate: OPEN
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  await ch.arm(0);
  const { agentId, token } = ch.registerAgent({ label: 'persist-e2e' });
  const dir = mkdtempSync(join(WORK, 'sbx-'));
  const agent = new SimAgent({ url: 'http://127.0.0.1:' + ch.port, agentId, token, dir, interval: 200, jitter: 0, persist, persistRunner });
  return { ch, agent, agentId, events, dir };
}

test('e2e: install -> status -> remove -> audit routes channel -> agent -> audit; hashes + verification evidence land; the sweep closes clean', async () => {
  const persistRunner = hostFromStore(mapBackend());
  const { ch, agent, agentId, events } = await wiredAgent({ persist: true, persistRunner });
  try {
    // INSTALL
    const t1 = ch.task(agentId, 'persist-install', '{"techniques":["runkey","startup"]}');
    assert.equal(await agent.tick(), true);
    const r1 = ch.results(agentId, { taskId: t1 });
    assert.equal(JSON.parse(r1[0].data).state, 'installed');
    const installed = events.find((e) => e.type === 'persist.installed');
    assert.ok(installed, 'the intake audited the install');
    assert.equal(installed.taskId, t1);
    assert.equal(installed.techniques.runkey.state, 'installed');
    assert.equal(installed.techniques.runkey.installVerified, true);
    assert.ok(installed.techniques.runkey.location.includes(PERSIST_RUNKEY_PATH));
    const relaunch = agent._relaunchLine();
    assert.equal(installed.techniques.runkey.targetSha256, sha256(relaunch), 'audit pins the sha256 of the agent-captured relaunch line (same agent, same config)');
    assert.ok(relaunch.includes(agentId) && relaunch.includes('sim-agent.mjs'), 'the installed line relaunches THIS agent binary/script with THIS config');
    const queued = events.find((e) => e.type === 'persist.task' && e.taskId === t1);
    assert.match(queued.specSha256, /^[0-9a-f]{64}$/, 'queue-time audit pins the spec hash');
    // STATUS
    const t2 = ch.task(agentId, 'persist-status', '{"techniques":["runkey"]}');
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t2 });
    assert.ok(events.some((e) => e.type === 'persist.status' && e.techniques.runkey.state === 'installed'), 'status audited honestly');
    // REMOVE
    const t3 = ch.task(agentId, 'persist-remove', '{"all":true}');
    assert.equal(await agent.tick(), true);
    const r3 = ch.results(agentId, { taskId: t3 });
    assert.equal(JSON.parse(r3[0].data).state, 'removed');
    const removed = events.find((e) => e.type === 'persist.removed');
    assert.ok(removed, 'the intake audited the removal');
    assert.equal(removed.techniques.runkey.removalVerified, true, 'audit carries verified absence');
    assert.equal(removed.techniques.startup.removalVerified, true);
    assert.ok(!events.some((e) => e.type === 'persist.remove-failed'), 'no escalation on a verified cleanup');
    // AUDIT SWEEP — the engagement-end gate
    const t4 = ch.task(agentId, 'persist-audit', '');
    assert.equal(await agent.tick(), true);
    const sweep = events.find((e) => e.type === 'persist.sweep');
    assert.ok(sweep, 'the sweep audited');
    assert.equal(sweep.clean, true, 'every installed persistence is verified removed');
    // the platform-level engagement-clean verdict over the whole event stream
    const verdict = assessEngagementClean(events);
    assert.equal(verdict.clean, true, 'the engagement MAY be called clean — all persistence verified removed');
    // the full lifecycle event set
    for (const t of ['task.queued', 'persist.task', 'task.delivered', 'result.received', 'persist.installed', 'persist.removed', 'persist.sweep']) {
      assert.ok(events.some((e) => e.type === t), 'audited: ' + t);
    }
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: an unverifiable removal escalates LOUDLY end-to-end and the engagement stays UNCLEAN', async () => {
  // a host whose startup delete never takes
  const loc = persistLocation('startup', persistTag('x'));
  const stickyRunner = async (jobJson) => {
    const job = JSON.parse(jobJson);
    if (job.op === 'install') {
      return { stdout: JSON.stringify({ op: 'install', pid: 9, state: 'installed', techniques: { startup: { state: 'installed', technique: 'startup', location: '%STARTUP%\\x.lnk', targetSha256: 't', installVerified: true } }, at: new Date().toISOString() }), stderr: '' };
    }
    if (job.op === 'remove') {
      return { stdout: JSON.stringify({ op: 'remove', pid: 9, state: 'failed', techniques: { startup: { state: 'removal-failed', technique: 'startup', location: '%STARTUP%\\x.lnk', removalVerified: false, error: 'remove executed but the location is STILL PRESENT on re-read — CLEANUP-PROOF FAILED' } }, at: new Date().toISOString() }), stderr: '' };
    }
    return { stdout: JSON.stringify({ op: job.op, pid: 9, state: 'installed', techniques: {}, entries: [], clean: false, open: [{ technique: 'startup', location: '%STARTUP%\\x.lnk', state: 'installed' }], at: new Date().toISOString() }), stderr: '' };
  };
  const { ch, agent, agentId, events } = await wiredAgent({ persist: true, persistRunner: stickyRunner });
  try {
    const t1 = ch.task(agentId, 'persist-install', '{"techniques":["startup"]}');
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t1 });
    const t2 = ch.task(agentId, 'persist-remove', '{"all":true}');
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t2 });
    const failed = events.find((e) => e.type === 'persist.remove-failed');
    assert.ok(failed, 'the intake escalated the unverifiable removal as its OWN loud event type');
    assert.equal(failed.escalated, true);
    assert.equal(failed.techniques.startup.state, 'removal-failed');
    assert.ok(!events.some((e) => e.type === 'persist.removed'), 'no removal claim without verification');
    const verdict = assessEngagementClean(events);
    assert.equal(verdict.clean, false, 'the engagement CANNOT be called clean while the removal is unverified');
    assert.equal(verdict.open.length, 1);
    assert.equal(verdict.open[0].escalated, true);
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: a refusal text emits NO evidence event (audit is never fabricated from unverifiable data)', async () => {
  const { ch, agent, agentId, events } = await wiredAgent({ persist: true, persistRunner: async () => ({ stdout: 'persist-install REFUSED: simulated agent-side refusal', stderr: '' }) });
  try {
    const t1 = ch.task(agentId, 'persist-install', '{"techniques":["startup"]}');
    assert.equal(await agent.tick(), true);
    const rs = ch.results(agentId, { taskId: t1 });
    assert.match(rs[0].data, /REFUSED/);
    assert.ok(!events.some((e) => e.type === 'persist.installed'), 'no installed event for a refusal');
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: agent-side gate OFF refuses even when the engagement gate is OPEN (both halves must say yes)', async () => {
  let ran = false;
  const { ch, agent, agentId } = await wiredAgent({ persist: false, persistRunner: async () => { ran = true; return { stdout: '{}' }; } });
  try {
    for (const kind of PERSIST_KINDS) {
      const data = kind === 'persist-install' ? '{"techniques":["startup"]}' : kind === 'persist-remove' ? '{"all":true}' : '';
      const taskId = ch.task(agentId, kind, data);
      assert.equal(await agent.tick(), true);
      const rs = ch.results(agentId, { taskId });
      assert.equal(rs.length, 1);
      assert.match(rs[0].data, new RegExp('^' + kind + ' REFUSED: '));
      assert.match(rs[0].data, /--persist/);
    }
    assert.equal(ran, false, 'the runner never fires on a refusal');
  } finally { agent.stop(); await ch.disarm(); }
});

// ---------------- the detoracle pairing loop (scripted taskAgent — the detoracle pattern) ----------------
test('assessPersist: install -> detoracle verdict on the install moment -> VERIFIED remove -> status; refusal and cleanup-failure paths stay loud', async () => {
  // full clean loop
  const calls = [];
  const backend = mapBackend();
  const host = hostFromStore(backend);
  const taskAgent = async (agentId, kind, data) => {
    calls.push(kind);
    if (kind === 'shell') return 'DETOR T1 D2 B0 R1'; // identical snapshots -> 'clean' diff
    const r = await host(JSON.stringify({ op: kind.slice('persist-'.length), ...(JSON.parse(data || '{}')), target: TARGET, name: TAG }));
    return r.stdout;
  };
  const v = await assessPersist({ taskAgent, agentId: 'agent-x', techniques: ['startup'], settleMs: 5 });
  assert.equal(v.refused, false);
  assert.equal(v.verdict, 'clean', 'no detection observed in the install window (never a claim of undetectability)');
  assert.equal(v.cleanupVerified, true, 'the removal leg verified absence for every installed technique');
  assert.equal(v.installed.techniques.startup.installVerified, true);
  assert.equal(v.removed.techniques.startup.removalVerified, true);
  assert.equal(v.statusAfter.techniques.startup.state, 'removed');
  assert.match(v.note, /provably back to its pre-install state/);
  assert.deepEqual(calls, ['shell', 'persist-install', 'shell', 'persist-remove', 'persist-status'], 'snapshot -> install -> snapshot -> remove -> status');
  // a measured DETECTION on install passes through as detected
  let snaps = 0;
  const taskAgent2 = async (agentId, kind, data) => {
    if (kind === 'shell') { snaps++; return snaps === 1 ? 'DETOR T1 D2 B0 R1' : 'DETOR T1 D3 B0 R1'; }
    const r = await host(JSON.stringify({ op: kind.slice('persist-'.length), ...(JSON.parse(data || '{}')), target: TARGET, name: TAG }));
    return r.stdout;
  };
  const v2 = await assessPersist({ taskAgent: taskAgent2, agentId: 'agent-x', techniques: ['runkey'], settleMs: 5 });
  assert.equal(v2.verdict, 'detected', 'Defender logging the Run-key write is reported as a detection — honest both ways');
  assert.equal(v2.cleanupVerified, true, 'cleanup still ran and verified');
  // governance refusal: verdict unknown, refused, nothing probed/removed
  const calls3 = [];
  const v3 = await assessPersist({ taskAgent: async (a, kind) => { calls3.push(kind); return "persist-install refused: engagement setting 'persist.enabled' is OFF ..."; }, agentId: 'agent-x', techniques: ['startup'], settleMs: 5 });
  assert.equal(v3.refused, true);
  assert.equal(v3.verdict, 'unknown');
  assert.deepEqual(calls3, ['shell', 'persist-install'], 'a refusal stops the loop — no remove theater');
  // cleanup-proof FAILURE: loud loose end, never a quiet pass
  const backend4 = mapBackend();
  const host4 = hostFromStore(backend4);
  const taskAgent4 = async (agentId, kind, data) => {
    if (kind === 'shell') return 'DETOR T1 D2 B0 R1';
    const job = JSON.parse(data || '{}');
    if (kind === 'persist-remove') {
      return JSON.stringify({ op: 'remove', pid: 1, state: 'failed', techniques: { startup: { state: 'removal-failed', removalVerified: false, error: 'STILL PRESENT' } }, at: new Date().toISOString() });
    }
    const r = await host4(JSON.stringify({ op: kind.slice('persist-'.length), ...job, target: TARGET, name: TAG }));
    return r.stdout;
  };
  const v4 = await assessPersist({ taskAgent: taskAgent4, agentId: 'agent-x', techniques: ['startup'], settleMs: 5 });
  assert.equal(v4.cleanupVerified, false);
  assert.match(v4.note, /STILL PERSISTED|cannot be called clean/i);
  // spec gate: bad technique lists throw BEFORE any task rides the wire
  await assert.rejects(() => assessPersist({ taskAgent: async () => '', agentId: 'x', techniques: ['wmi-sub'] }), /unknown technique/);
  // parsePersistResult: refusal text is not evidence
  assert.equal(parsePersistResult('persist-install REFUSED: ...'), null);
});

// ---------------- GUARDED LIVE: real PS host, real Startup folder, startup technique ONLY ----------------
// Opt-in ONLY (VARVEL_LIVE_PERSIST=1). Installs the LEAST invasive technique (a
// shell:startup .lnk) pointing at a harmless inert line, on THIS machine, user-context,
// self-cleaning even on failure (try/finally remove; the runner dies with the test).
// The manifest + all artifacts live under repo-local .tmp (house rule).
const LIVE = process.env.VARVEL_LIVE_PERSIST === '1';

test('LIVE (guarded): startup technique — install verified present, status intact, remove verified ABSENT (self-cleaning)', async (t) => {
  if (!LIVE) return t.skip('guarded live test — set VARVEL_LIVE_PERSIST=1 to run (writes+removes ONE user-context startup .lnk on this machine)');
  if (process.platform !== 'win32') return t.skip('windows-only (user-land registry/scheduler/startup techniques)');
  const ps = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], { windowsHide: true });
  if (ps.error || ps.status !== 0) return t.skip('powershell.exe unavailable on this host');
  if (!existsSync(PERSIST_HOST_PATH)) return t.skip('agents/persist-host.ps1 missing');

  const liveName = ('VARVEL-LIVE-' + Date.now().toString(36)).slice(0, 32);
  const liveTarget = '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -WindowStyle Hidden -Command "exit 0"'; // inert by construction
  const manifestPath = join(WORK, 'live-manifest.json');
  const lnkPath = join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', liveName + '.lnk');
  const runner = powerShellPersistRunner({ timeoutMs: 60000 });
  try {
    // INSTALL: verified by re-read
    const ins = JSON.parse(await runPersistTask('persist-install', JSON.stringify({ techniques: ['startup'], name: liveName }), { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    assert.equal(ins.state, 'installed', JSON.stringify(ins.techniques.startup));
    assert.equal(ins.techniques.startup.installVerified, true);
    assert.equal(existsSync(lnkPath), true, 'the .lnk really landed in shell:startup (user-context)');
    assert.equal(existsSync(manifestPath), true, 'the removal manifest was recorded under .tmp');
    // STATUS: present + intact + pointing at the right target line (live re-read)
    const st = JSON.parse(await runPersistTask('persist-status', JSON.stringify({ techniques: ['startup'], name: liveName }), { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    assert.equal(st.techniques.startup.state, 'installed');
    // REMOVE: verified ABSENT
    const rem = JSON.parse(await runPersistTask('persist-remove', JSON.stringify({ techniques: ['startup'], name: liveName }), { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    assert.equal(rem.state, 'removed', JSON.stringify(rem.techniques.startup));
    assert.equal(rem.techniques.startup.removalVerified, true, 'cleanup-proof: absence proven by re-read');
    assert.equal(existsSync(lnkPath), false, 'the .lnk is really gone');
    // AUDIT: the sweep closes clean
    const au = JSON.parse(await runPersistTask('persist-audit', '', { runner, target: liveTarget, manifestPath, defaultName: liveName }));
    assert.equal(au.clean, true, JSON.stringify(au.open));
  } finally {
    // self-cleaning even on failure: best-effort remove, then the host dies
    try { await runPersistTask('persist-remove', JSON.stringify({ all: true, name: liveName }), { runner, target: liveTarget, manifestPath, defaultName: liveName }); } catch {}
    runner.close();
    try { rmSync(lnkPath, { force: true }); } catch {}
  }
});
