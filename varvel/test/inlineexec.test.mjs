// inlineexec.test.mjs — the in-memory execution tier (gap #4 remainder): governed
// 'inline-dotnet'. Hermetic by default: the PS-execution layer is an injected runner, so
// task routing, BOTH gate halves, the size cap, the audit hash, the output shape, and the
// no-disk-bytes property are all pinned without spawning a process. The LAST test is the
// privilege-aware LIVE path (house pattern: icmpbridge-live): a real csc compile + a real
// PowerShell CLR round trip, skipped precisely when this box lacks the prerequisites.
//
// Settings discipline (house pattern from settings.test.mjs): VARVEL_SETTINGS_FILE points
// at a temp file for THIS process and every engagement name is unique — the module-level
// settings registry caches per engagement for the process lifetime.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { CallbackChannel } from '../engine/callback.mjs';
import { MAX_INLINE_ASSEMBLY_BYTES, parseInlineSpec, inlineDotnetGate } from '../engine/inlineexec.mjs';
import { runInlineDotnet, powerShellHelperRunner } from '../agents/inlineexec.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { Settings } from '../engine/settings.mjs';
import { assessInlineExec } from '../tools/execasm.mjs';
import { buildSnapshotCommand } from '../tools/detoracle.mjs';

process.env.VARVEL_SETTINGS_FILE = join(mkdtempSync(join(tmpdir(), 'vinline-')), 'settings.json');

// Defender-exclusion discipline (house rule 2026-08-12): payload-class artifacts (the
// csc-built probe .exe below) must land INSIDE the repo tree — the enclave/varvel dirs
// carry the operator's Defender exclusion; %TEMP% does not, and compiling there trips AV.
const REPO_TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(REPO_TMP, { recursive: true });

const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
let engSeq = 0;
const freshEng = () => 'inline-' + (engSeq++) + '-' + Date.now();
const specFor = (bytes, extra = {}) => JSON.stringify({ assemblyB64: Buffer.from(bytes).toString('base64'), ...extra });

// Recursively hash every file under dir; return true if ANY file's content hash matches.
function dirContainsHash(dir, hash) {
  let hit = false;
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (sha256(readFileSync(p)) === hash) hit = true;
    }
  };
  walk(dir);
  return hit;
}

// ---------------- pure spec parse (the pre-queue / pre-exec refusal layer) ----------------
test('parseInlineSpec: valid spec parses with hash + stringified args; entryPoint optional', () => {
  const bytes = Buffer.from('MZ-fake-assembly-bytes');
  const s = parseInlineSpec(specFor(bytes, { args: [1, 'two', true], entryPoint: 'Ns.Type.Main' }));
  assert.equal(s.sha256, sha256(bytes));
  assert.deepEqual(s.args, ['1', 'two', 'true']);
  assert.equal(s.entryPoint, 'Ns.Type.Main');
  assert.equal(s.bytes.length, bytes.length);
  assert.equal(parseInlineSpec(specFor(bytes)).entryPoint, '');
  assert.deepEqual(parseInlineSpec(specFor(bytes)).args, []);
});

test('parseInlineSpec: every malformed spec refuses loudly (nothing executes)', () => {
  assert.throws(() => parseInlineSpec('not json'), TypeError);
  assert.throws(() => parseInlineSpec('{"args":[]}'), /assemblyB64 is required/);
  assert.throws(() => parseInlineSpec('{"assemblyB64":"!!!"}'), /not valid base64/);
  assert.throws(() => parseInlineSpec('{"assemblyB64":""}'), /assemblyB64 is required/);
  assert.throws(() => parseInlineSpec('{"assemblyB64":"AA==","args":"nope"}'), /args must be an array/);
  const big = Buffer.alloc(MAX_INLINE_ASSEMBLY_BYTES + 1, 0x41);
  assert.throws(() => parseInlineSpec(specFor(big)), /over the \d+-byte cap/);
  assert.ok(parseInlineSpec(specFor(Buffer.alloc(MAX_INLINE_ASSEMBLY_BYTES, 0x41))).bytes.length === MAX_INLINE_ASSEMBLY_BYTES); // exactly AT the cap passes
});

// ---------------- governance: the engagement gate (default OFF) + audit ----------------
test('channel gate: exec.inMemory defaults OFF — inline-dotnet refuses LOUDLY + audited; other kinds unaffected', () => {
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: freshEng(), signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'gated' });
  const spec = specFor('MZ-payload');
  let err = null;
  try { ch.task(agentId, 'inline-dotnet', spec); } catch (e) { err = e; }
  assert.ok(err, 'the task must throw');
  assert.equal(err.code, 'GOVERNANCE');
  assert.match(err.message, /exec\.inMemory.*OFF/);
  assert.match(err.message, /Nothing executed/);
  assert.ok(events.some((e) => e.type === 'task.refused' && e.kind === 'inline-dotnet'));
  assert.ok(!events.some((e) => e.type === 'task.queued' && e.kind === 'inline-dotnet'), 'a refused task never queues');
  assert.ok(!events.some((e) => e.type === 'exec.inline-dotnet'));
  // broadcast refuses identically (no partial tasking: the first refusal throws before any queue)
  assert.throws(() => ch.taskWhere({ all: true }, 'inline-dotnet', spec), (e) => e.code === 'GOVERNANCE');
  // and the gate never touches ordinary kinds
  assert.ok(ch.task(agentId, 'shell', 'hostname'));
  // the gate fails CLOSED on an unreadable settings layer too
  assert.equal(inlineDotnetGate('inline-never-enabled-xyz').ok, false);
});

test('channel gate ON: the task queues and the assembly sha256 lands in audit (the hash IS the trail)', () => {
  const eng = freshEng();
  Settings.for(eng).set('exec.inMemory', true);
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'allowed' });
  const bytes = Buffer.from('MZ-audited-assembly');
  const taskId = ch.task(agentId, 'inline-dotnet', specFor(bytes, { args: ['a'] }));
  assert.ok(taskId);
  const ev = events.find((e) => e.type === 'exec.inline-dotnet');
  assert.ok(ev, 'the exec audit event exists');
  assert.equal(ev.taskId, taskId);
  assert.equal(ev.sha256, sha256(bytes));
  assert.equal(ev.bytes, bytes.length);
  // the spec gate still bites when the engagement gate is open: over-cap refuses pre-queue
  assert.throws(() => ch.task(agentId, 'inline-dotnet', specFor(Buffer.alloc(MAX_INLINE_ASSEMBLY_BYTES + 1, 0x42))), (e) => e.code === 'GOVERNANCE' && /over the \d+-byte cap/.test(e.message));
});

// ---------------- agent-side executor (injected runner — the hermetic seam) ----------------
test('runInlineDotnet: refusal texts are loud; an execution is hash-FIRST JSON', async () => {
  // spec refusal (no runner call at all)
  const bad = await runInlineDotnet('garbage', { runner: async () => ({ stdout: '{}' }) });
  assert.match(bad, /^inline-dotnet REJECTED: /);
  // no runner configured: REFUSED, and the hash of what did NOT run is named
  const bytes = Buffer.from('MZ-no-runner');
  const none = await runInlineDotnet(specFor(bytes), {});
  assert.match(none, /^inline-dotnet REFUSED: /);
  assert.ok(none.includes(sha256(bytes)), 'the refusal names the hash of what did NOT run');
  // a real execution shape
  let jobSeen = null;
  const runner = async (jobJson) => { jobSeen = jobJson; return { stdout: JSON.stringify({ exitCode: 3, timedOut: false, stdout: 'OUT-TEXT', stderr: 'ERR-TEXT' }), stderr: '' }; };
  const res = JSON.parse(await runInlineDotnet(specFor(bytes, { args: ['x', 'y'], entryPoint: 'T.M' }), { runner }));
  assert.deepEqual(Object.keys(res).slice(0, 3), ['sha256', 'bytes', 'entryPoint'], 'hash leads — the 120-char ledger preview always carries it');
  assert.equal(res.sha256, sha256(bytes));
  assert.equal(res.bytes, bytes.length);
  assert.equal(res.entryPoint, 'T.M');
  assert.equal(res.exitCode, 3);
  assert.equal(res.timedOut, false);
  assert.equal(res.stdout, 'OUT-TEXT');
  assert.equal(res.stderr, 'ERR-TEXT');
  // the runner contract: a JSON string carrying the BYTES — there is no path field anywhere
  const job = JSON.parse(jobSeen);
  assert.equal(Buffer.from(job.assemblyB64, 'base64').toString(), bytes.toString());
  assert.deepEqual(job.args, ['x', 'y']);
  assert.ok(!('path' in job) && !('file' in job), 'no disk path exists in the runner contract');
});

test('runInlineDotnet: runner failures stay honest (timeout flag, unparseable output)', async () => {
  const bytes = Buffer.from('MZ-failure-modes');
  const timeout = JSON.parse(await runInlineDotnet(specFor(bytes), { runner: async () => ({ stdout: '', stderr: '', error: 'helper timeout after 50ms — process tree killed' }) }));
  assert.equal(timeout.exitCode, -1);
  assert.equal(timeout.timedOut, true);
  assert.match(timeout.stderr, /timeout/i);
  const garbage = JSON.parse(await runInlineDotnet(specFor(bytes), { runner: async () => ({ stdout: 'not json at all', stderr: 'host noise' }) }));
  assert.equal(garbage.exitCode, -1);
  assert.match(garbage.stderr, /unparseable/);
  const threw = JSON.parse(await runInlineDotnet(specFor(bytes), { runner: async () => { throw new Error('boom'); } }));
  assert.equal(threw.exitCode, -1);
  assert.match(threw.stderr, /boom/);
});

// ---------------- the default runner's plumbing (fake child process — still hermetic) ----------------
function fakePsChild({ emitJson, hang = false } = {}) {
  const c = new EventEmitter();
  c.stdin = new PassThrough();
  c.stdout = new PassThrough();
  c.stderr = new PassThrough();
  c.killed = false;
  c.kill = () => { c.killed = true; setImmediate(() => c.emit('close')); };
  let buf = '';
  c.stdin.on('data', (d) => { buf += d; });
  c.stdin.on('end', () => {
    c.jobJson = buf;
    if (hang) return;
    if (emitJson) c.stdout.write('powershell host noise line\n' + JSON.stringify(emitJson) + '\n');
    setImmediate(() => c.emit('close'));
  });
  return c;
}

test('powerShellHelperRunner: job rides stdin, result parses past host noise, timeout kills', async () => {
  const ok = fakePsChild({ emitJson: { exitCode: 0, timedOut: false, stdout: 'helper-stdout', stderr: '' } });
  const runner = powerShellHelperRunner({ spawnFn: () => ok, timeoutMs: 5000 });
  const bytes = Buffer.from('MZ-runner-plumbing');
  const res = JSON.parse(await runInlineDotnet(specFor(bytes), { runner }));
  assert.equal(res.exitCode, 0);
  assert.equal(res.stdout, 'helper-stdout'); // the last JSON line wins over host noise
  assert.ok(JSON.parse(ok.jobJson).assemblyB64.length > 0);

  const hung = fakePsChild({ hang: true });
  const slow = powerShellHelperRunner({ spawnFn: () => hung, timeoutMs: 50 });
  const res2 = JSON.parse(await runInlineDotnet(specFor(bytes), { runner: slow }));
  assert.equal(res2.timedOut, true);
  assert.equal(res2.exitCode, -1);
  assert.ok(hung.killed, 'a wedged helper is killed — the task loop survives');

  const spawnDead = powerShellHelperRunner({ spawnFn: () => { throw new Error('ENOENT'); } });
  const res3 = JSON.parse(await runInlineDotnet(specFor(bytes), { runner: spawnDead }));
  assert.equal(res3.exitCode, -1);
  assert.match(res3.stderr, /spawn failed/);
});

// ---------------- end-to-end over a REAL channel + REAL SimAgent (fake runner) ----------------
async function wiredAgent({ execInMemory, inlineRunner }) {
  const eng = freshEng();
  Settings.for(eng).set('exec.inMemory', true); // channel half of the gate: OPEN
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  await ch.arm(0);
  const { agentId, token } = ch.registerAgent({ label: 'inline-e2e' });
  const dir = mkdtempSync(join(tmpdir(), 'vinline-sbx-'));
  const agent = new SimAgent({ url: 'http://127.0.0.1:' + ch.port, agentId, token, dir, interval: 200, jitter: 0, execInMemory, inlineRunner });
  return { ch, agent, agentId, events, dir };
}

test('e2e: inline-dotnet routes channel -> agent -> result, hash audited, output captured, NO BYTES ON DISK', async () => {
  const bytes = crypto.randomBytes(2048); // stands in for a real assembly
  const hash = sha256(bytes);
  let jobSeen = null;
  const inlineRunner = async (jobJson) => {
    jobSeen = jobJson;
    return { stdout: JSON.stringify({ exitCode: 0, timedOut: false, stdout: 'VV-SIM-STDOUT', stderr: 'VV-SIM-STDERR' }), stderr: '' };
  };
  const { ch, agent, agentId, events, dir } = await wiredAgent({ execInMemory: true, inlineRunner });
  try {
    const taskId = ch.task(agentId, 'inline-dotnet', specFor(bytes, { args: ['recon'] }));
    assert.ok(taskId);
    assert.equal(await agent.tick(), true); // one governed cycle: pull -> execute -> push
    const rs = ch.results(agentId, { taskId });
    assert.equal(rs.length, 1);
    const res = JSON.parse(rs[0].data);
    assert.equal(res.sha256, hash);
    assert.equal(res.exitCode, 0);
    assert.equal(res.stdout, 'VV-SIM-STDOUT');
    assert.equal(res.stderr, 'VV-SIM-STDERR');
    // the runner saw the exact bytes, in-memory only
    assert.equal(sha256(Buffer.from(JSON.parse(jobSeen).assemblyB64, 'base64')), hash);
    // the audit trail: queued + exec hash + delivered + result intake, all present
    // (the HTTP /r path emits 'result.received'; 'task.resulted' is the codec-path name)
    for (const t of ['task.queued', 'exec.inline-dotnet', 'task.delivered', 'result.received']) assert.ok(events.some((e) => e.type === t), t);
    assert.equal(events.find((e) => e.type === 'exec.inline-dotnet').sha256, hash);
    // NO-DISK-BYTES: the agent's whole world (its sandbox) holds no file with these bytes
    assert.equal(dirContainsHash(dir, hash), false, 'no file in the agent sandbox may contain the assembly bytes');
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: agent-side gate OFF refuses even when the engagement gate is OPEN (both halves must say yes)', async () => {
  const bytes = Buffer.from('MZ-agent-gate');
  let ran = false;
  const { ch, agent, agentId } = await wiredAgent({ execInMemory: false, inlineRunner: async () => { ran = true; return { stdout: '{}' }; } });
  try {
    const taskId = ch.task(agentId, 'inline-dotnet', specFor(bytes));
    assert.equal(await agent.tick(), true);
    const rs = ch.results(agentId, { taskId });
    assert.equal(rs.length, 1);
    assert.match(rs[0].data, /^inline-dotnet REFUSED: /);
    assert.match(rs[0].data, /--exec-in-memory/);
    assert.equal(ran, false, 'the runner never fires on a refusal');
  } finally { agent.stop(); await ch.disarm(); }
});

// ---------------- the detoracle pairing (scripted taskAgent — the detoracle pattern) ----------------
test('assessInlineExec: snapshots bracket the inline execution; verdict + execution fields surface', async () => {
  const snapGood = 'DETOR T1 D2 B0 R1';
  const snapHit = 'DETOR T1 D3 B0 R1';
  const calls = [];
  const execJson = JSON.stringify({ sha256: 'ab'.repeat(32), bytes: 100, entryPoint: null, exitCode: 0, timedOut: false, stdout: 'probe-out', stderr: '' });
  const taskAgent = async (agentId, kind, data) => {
    calls.push({ kind, data });
    if (kind === 'shell') return calls.filter((c) => c.kind === 'shell').length === 1 ? snapGood : snapHit;
    return execJson;
  };
  const v = await assessInlineExec({ taskAgent, agentId: 'agent-x', spec: { assemblyB64: 'QQ==', args: [] }, settleMs: 5 });
  assert.equal(v.verdict, 'detected');
  assert.equal(v.newDetections, 1);
  assert.equal(v.refused, false);
  assert.equal(v.execution.sha256, 'ab'.repeat(32));
  assert.equal(v.execution.exitCode, 0);
  // ordering: snapshot BEFORE, the inline-dotnet probe, snapshot AFTER
  assert.deepEqual(calls.map((c) => c.kind), ['shell', 'inline-dotnet', 'shell']);
  assert.equal(calls[0].data, buildSnapshotCommand());
  assert.equal(JSON.parse(calls[1].data).assemblyB64, 'QQ==');
});

test('assessInlineExec: a governance refusal is verdict unknown + refused — NEVER a clean reading', async () => {
  const calls = [];
  const taskAgent = async (agentId, kind) => {
    calls.push(kind);
    if (kind === 'shell') return 'DETOR T0 D0 B0 R1';
    return "inline-dotnet refused: engagement setting 'exec.inMemory' is OFF ...";
  };
  const v = await assessInlineExec({ taskAgent, agentId: 'agent-x', spec: { assemblyB64: 'QQ==' }, settleMs: 5 });
  assert.equal(v.refused, true);
  assert.equal(v.verdict, 'unknown');
  assert.match(v.note, /REFUSED|refused/);
  assert.deepEqual(calls, ['shell', 'inline-dotnet'], 'no AFTER snapshot — nothing ran, nothing to measure');
  await assert.rejects(() => assessInlineExec({ agentId: 'x', spec: {} }), TypeError);
});

// ---------------- LIVE: a REAL PowerShell CLR round trip (privilege/capability-aware) ----------------
// The honesty boundary (icmpbridge-live pattern): whatever this host permits is what we
// claim. No powershell or no csc -> precise skips; the hermetic layers above stay proven.
const CSC_CANDIDATES = [
  'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe',
  'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe',
];
function livePrereqs() {
  const ps = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], { windowsHide: true });
  if (ps.error || ps.status !== 0) return { ok: false, reason: 'powershell.exe unavailable on this host' };
  const csc = CSC_CANDIDATES.find((p) => existsSync(p));
  if (!csc) return { ok: false, reason: 'no .NET Framework csc.exe on this host — cannot build the probe assembly' };
  return { ok: true, csc };
}

test('LIVE: real csc-built assembly executes in-memory via the real PS helper (bytes deleted BEFORE execution)', async (t) => {
  const pre = livePrereqs();
  if (!pre.ok) return t.skip(pre.reason);
  const work = mkdtempSync(join(REPO_TMP, 'vinline-live-'));
  const src = join(work, 'probe.cs');
  const exe = join(work, 'probe.exe');
  writeFileSync(src, [
    'using System;',
    'public class VvInlineProbe {',
    '  public static int Main(string[] args) {',
    '    Console.WriteLine("VV-INLINE-OK args=" + string.Join("|", args));',
    '    Console.Error.WriteLine("VV-INLINE-ERR");',
    '    return 42;',
    '  }',
    '}',
  ].join('\r\n'));
  const build = spawnSync(pre.csc, ['/nologo', '/target:exe', '/out:' + exe, src], { windowsHide: true });
  if (build.status !== 0 || !existsSync(exe)) return t.skip('csc compile failed: ' + String(build.stderr || build.stdout).slice(0, 200));
  const bytes = readFileSync(exe);
  const hash = sha256(bytes);
  // THE NO-DISK PROOF: the build artifacts are deleted BEFORE execution — the helper
  // receives the bytes on stdin and the assembly loads from memory only.
  rmSync(exe); rmSync(src);
  const res = JSON.parse(await runInlineDotnet(specFor(bytes, { args: ['alpha', 'beta'] }), { runner: powerShellHelperRunner({ timeoutMs: 60000 }) }));
  assert.equal(res.sha256, hash);
  assert.equal(res.exitCode, 42, String(res.stderr));
  assert.match(res.stdout, /VV-INLINE-OK args=alpha\|beta/);
  assert.match(res.stderr, /VV-INLINE-ERR/);
  assert.equal(res.timedOut, false);
  assert.equal(dirContainsHash(work, hash), false, 'the helper wrote nothing to disk');
  rmSync(work, { recursive: true, force: true });
});

test('LIVE: the SimAgent default path (no injected runner) really spawns the helper', async (t) => {
  const pre = livePrereqs();
  if (!pre.ok) return t.skip(pre.reason);
  // A tiny prebuilt probe is not shipped in the repo — build one here, then delete it.
  const work = mkdtempSync(join(REPO_TMP, 'vinline-live2-'));
  const src = join(work, 'p.cs');
  const exe = join(work, 'p.exe');
  writeFileSync(src, 'using System; public class P { public static void Main() { Console.WriteLine("VV-SIM-LIVE-OK"); } }');
  const build = spawnSync(pre.csc, ['/nologo', '/target:exe', '/out:' + exe, src], { windowsHide: true });
  if (build.status !== 0 || !existsSync(exe)) return t.skip('csc compile failed');
  const bytes = readFileSync(exe);
  const hash = sha256(bytes);
  rmSync(exe); rmSync(src);
  const agent = new SimAgent({ url: 'http://127.0.0.1:9', agentId: 'liveinline', token: 't', dir: join(work, 'sbx'), execInMemory: true });
  try {
    const res = JSON.parse(await agent._exec({ kind: 'inline-dotnet', data: specFor(bytes) }));
    assert.match(res.stdout, /VV-SIM-LIVE-OK/);
    assert.equal(res.sha256, hash);
    assert.equal(dirContainsHash(work, hash), false);
  } finally { agent.stop(); rmSync(work, { recursive: true, force: true }); }
});
