// execproxy.test.mjs — the SIGNED-PROXY EXECUTION TIER (the governed answer to
// application allowlisting): run the agent's DLL form through Microsoft-signed
// hosts (rundll32 / regsvr32 / sideload-copy). Hermetic by default: the PS-host
// layer is an injected runner and the filesystem/process backend is an injected
// store, so the spec parse matrix, BOTH gate halves (default-OFF refusals), the
// plan/manifest shape, the foreign-clobber refusal, remove-verifies, the
// cleanup-proof FAILURE path (loud + escalated), the engagement sweep, the audit
// hash assertions, and the discovery-rank classifier are all pinned without
// spawning a process or touching the real filesystem.
//
// HOUSE RULE (absolute): payload-class test artifacts live under repo-local
// varvel/.tmp/ (created with mkdirSync recursive) — NEVER os.tmpdir().
//
// The LAST test is the GUARDED LIVE path (opt-in, VARVEL_LIVE_PROXY=1): build the
// Go DLL for real with the CONTAINED toolchain (never %LOCALAPPDATA%), then drive
// the REAL execproxy host (agents/execproxy-host.ps1) to invoke
// `rundll32 <dll>,VarvelStatus <out>` — proving a Microsoft-signed binary really
// loaded and ran our code (marker JSON + Valid signature evidence) — then
// execproxy-remove + execproxy-status verify the plant set absent. Self-cleaning
// even on failure (try/finally). Default: SKIP.
//
// Settings discipline (house pattern): VARVEL_SETTINGS_FILE points under .tmp for
// THIS process and every engagement name is unique.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CallbackChannel } from '../engine/callback.mjs';
import {
  EXECPROXY_KINDS, EXECPROXY_TECHNIQUES, EXECPROXY_EXPORTS, EXECPROXY_HIJACK_NAMES,
  parseExecProxySpec, execProxyGate, execProxyTag, execProxyPlantDir, execProxySpecSha256,
  ExecProxyStore, parseExecProxyEvidence, assessExecProxyClean, rankHostCandidates,
} from '../engine/execproxy.mjs';
import { runExecProxyTask, powerShellExecProxyRunner, EXECPROXY_HOST_PATH } from '../agents/execproxy.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { Settings } from '../engine/settings.mjs';
import { buildDiscoveryCommand, parseDiscoveryExport, assessExecProxy, parseExecProxyResult } from '../tools/execproxy.mjs';

// HOUSE RULE: everything this suite writes lives under repo-local .tmp (gitignored,
// Defender-excluded) — never os.tmpdir().
const TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });
const WORK = mkdtempSync(join(TMP_ROOT, 'execproxy-test-'));
process.env.VARVEL_SETTINGS_FILE = join(WORK, 'settings.json');

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
let engSeq = 0;
const freshEng = () => 'execproxy-' + (engSeq++) + '-' + Date.now();

const SANDBOX = 'C:\\sandbox';
const DLL = SANDBOX + '\\varvel-agent.dll';
const HOST = 'C:\\Windows\\System32\\winver.exe';
const DLL_BYTES = Buffer.from('MZ-fake-varvel-agent-dll-bytes');
const HOST_BYTES = Buffer.from('MZ-fake-signed-host-bytes');
const TAG = 'VARVEL-test01';

// A Map-backed fake backend standing in for the filesystem + process creation —
// the technique machinery never touches the real ones from Node.
function mapBackend(seed = {}) {
  const files = new Map(Object.entries(seed));
  const dirs = new Set();
  const runs = [];
  return {
    files, dirs, runs,
    probe: (p) => (files.has(p) ? { present: true, sha256: sha256(files.get(p)) } : { present: false, sha256: null }),
    plant: (p, copyFrom) => { if (!files.has(copyFrom)) throw new Error('copy source missing: ' + copyFrom); files.set(p, Buffer.from(files.get(copyFrom))); },
    remove: (p) => { files.delete(p); },
    removeDir: (p) => { dirs.delete(p); },
    run: (argv) => { runs.push(argv.slice()); return { code: 0, output: 'host ran: ' + argv.join(' ') }; },
  };
}
const seededBackend = () => mapBackend({ [DLL]: DLL_BYTES, [HOST]: HOST_BYTES });

// The evidence JSON a REAL agent-side op returns (mirrors the PS host's shape),
// built by running the REAL state machine (ExecProxyStore) over the fake backend —
// the same contract the ==EXECPROXY-LIB== block fulfills against Windows.
function hostFromStore(backend) {
  const stores = new Map();
  const storeFor = (name) => {
    if (!stores.has(name)) stores.set(name, new ExecProxyStore({ backend, name, sandbox: SANDBOX }));
    return stores.get(name);
  };
  return async (jobJson) => {
    const job = JSON.parse(jobJson);
    if (job.op === 'run') {
      const ev = storeFor(job.name).run(job);
      return { stdout: JSON.stringify({ op: 'run', pid: 4321, state: ev.state, names: { [job.name]: ev }, at: new Date().toISOString() }), stderr: '' };
    }
    if (job.op === 'remove') {
      const names = job.all ? [...stores.keys()] : [job.name];
      const out = {};
      let worst = 'removed';
      for (const n of names) {
        const ev = storeFor(n).remove();
        out[n] = ev;
        if (ev.state === 'removal-failed' || ev.state === 'refused-foreign') worst = ev.state;
      }
      return { stdout: JSON.stringify({ op: 'remove', pid: 4321, state: worst, names: out, at: new Date().toISOString() }), stderr: '' };
    }
    // status: the sweep over every recorded name (or one)
    const names = job.name ? [job.name] : [...stores.keys()];
    const entries = [], open = [];
    for (const n of names) {
      const a = storeFor(n).audit();
      entries.push(...a.entries);
      open.push(...a.open);
    }
    const clean = open.length === 0;
    return { stdout: JSON.stringify({ op: 'status', pid: 4321, state: clean ? 'clean' : 'unclean', clean, entries, open, note: clean ? 'clean' : 'unclean', at: new Date().toISOString() }), stderr: '' };
  };
}

// ---------------- spec parse matrix ----------------
test('spec gate: parse matrix — kinds, techniques, exports, remove scope, caps', () => {
  assert.equal(EXECPROXY_KINDS.size, 3);
  assert.deepEqual(EXECPROXY_TECHNIQUES, ['rundll32', 'regsvr32', 'sideload']);
  // happy paths
  assert.deepEqual(parseExecProxySpec('execproxy-run', JSON.stringify({ technique: 'rundll32', dll: DLL, export: 'VarvelStatus', args: 'C:\\x\\out.json' })),
    { kind: 'execproxy-run', technique: 'rundll32', dll: DLL, name: null, args: 'C:\\x\\out.json', export: 'VarvelStatus' });
  const sl = parseExecProxySpec('execproxy-run', JSON.stringify({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll', name: 'My-Plant.1' }));
  assert.equal(sl.as, 'version.dll');
  assert.equal(sl.name, 'My-Plant.1');
  assert.equal(parseExecProxySpec('execproxy-remove', '{"all":true}').all, true);
  assert.equal(parseExecProxySpec('execproxy-remove', '{"name":"VARVEL-x"}').name, 'VARVEL-x');
  assert.deepEqual(parseExecProxySpec('execproxy-status', ''), { kind: 'execproxy-status', technique: null, name: null });
  // refusals, loud and early
  assert.throws(() => parseExecProxySpec('execproxy-run', '{}'), /unknown technique/);
  assert.throws(() => parseExecProxySpec('execproxy-run', JSON.stringify({ technique: 'rundll32', dll: DLL, export: 'AmsiScanBuffer' })), /export must be one of/);
  assert.throws(() => parseExecProxySpec('execproxy-run', JSON.stringify({ technique: 'rundll32', dll: 'agent.dll', export: 'VarvelStatus' })), /ABSOLUTE Windows path/);
  assert.throws(() => parseExecProxySpec('execproxy-run', JSON.stringify({ technique: 'sideload', dll: DLL, host: HOST, as: 'evil.dll' })), /as must be one of/);
  assert.throws(() => parseExecProxySpec('execproxy-run', JSON.stringify({ technique: 'sideload', dll: DLL, host: 'C:\\x\\host.com', as: 'version.dll' })), /must end in/);
  assert.throws(() => parseExecProxySpec('execproxy-remove', '{}'), /explicit scope/);
  assert.throws(() => parseExecProxySpec('execproxy-remove', '{"all":true,"name":"x"}'), /not both/);
  assert.throws(() => parseExecProxySpec('execproxy-status', '{"name":"bad name!"}'), /not a safe plant handle/);
  assert.throws(() => parseExecProxySpec('execproxy-nope', '{}'), /unknown kind/);
  for (const e of EXECPROXY_EXPORTS) assert.ok(e.startsWith('Varvel'), 'allow-listed export: ' + e);
  for (const n of EXECPROXY_HIJACK_NAMES) assert.match(n, /\.dll$/, 'hijack name: ' + n);
});

// ---------------- the engagement gate (both halves) ----------------
test('gate: default OFF — channel refuses to queue execproxy-*, loud + audited; ordinary kinds untouched', () => {
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: freshEng(), signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'gated' });
  const dataFor = (k) => k === 'execproxy-run' ? JSON.stringify({ technique: 'rundll32', dll: DLL, export: 'VarvelStatus' }) : k === 'execproxy-remove' ? '{"all":true}' : '';
  for (const kind of EXECPROXY_KINDS) {
    let err = null;
    try { ch.task(agentId, kind, dataFor(kind)); } catch (e) { err = e; }
    assert.ok(err && err.code === 'GOVERNANCE', kind + ' threw a governance refusal');
    assert.match(err.message, /exec\.proxy/);
    const refused = events.find((e) => e.type === 'task.refused' && e.kind === kind);
    assert.ok(refused, kind + ' audited its refusal');
    assert.match(refused.reason, /exec\.proxy/);
  }
  assert.throws(() => ch.taskWhere({ all: true }, 'execproxy-run', dataFor('execproxy-run')), (e) => e.code === 'GOVERNANCE', 'broadcast refuses identically');
  assert.ok(ch.task(agentId, 'shell', 'hostname'), 'the gate never touches ordinary kinds');
  const g = execProxyGate(freshEng());
  assert.equal(g.ok, false);
  assert.match(g.reason, /exec\.proxy/);
});

test('gate: ON — queue succeeds and the audit pins the normalized spec hash', () => {
  const eng = freshEng();
  Settings.for(eng).set('exec.proxy', true);
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'allowed' });
  const spec = { technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll', name: TAG };
  const taskId = ch.task(agentId, 'execproxy-run', JSON.stringify(spec));
  assert.ok(taskId, 'queued with the gate open');
  const evt = events.find((e) => e.type === 'execproxy.task' && e.taskId === taskId);
  assert.ok(evt, 'execproxy.task audited at queue time');
  assert.equal(evt.technique, 'sideload');
  assert.equal(evt.specSha256, execProxySpecSha256(parseExecProxySpec('execproxy-run', JSON.stringify(spec))), 'the audit hash == the normalized spec hash');
  assert.match(evt.specSha256, /^[0-9a-f]{64}$/);
  assert.throws(() => ch.task(agentId, 'execproxy-run', '{"technique":"dllmain"}'), (e) => e.code === 'GOVERNANCE' && /unknown technique/.test(e.message), 'spec gate still refuses pre-queue');
});

// ---------------- ExecProxyStore: the cleanup-proof state machine ----------------
test('store: rundll32 run — payload proof, separate-token argv doctrine, hash evidence; remove is trivially verified (no plants)', () => {
  const b = seededBackend();
  const s = new ExecProxyStore({ backend: b, name: TAG, sandbox: SANDBOX });
  const ev = s.run({ technique: 'rundll32', dll: DLL, export: 'VarvelStatus', args: 'C:\\sandbox\\out.json' });
  assert.equal(ev.state, 'ran');
  assert.equal(ev.dllSha256, sha256(DLL_BYTES), 'audit carries the executed DLL sha256');
  assert.equal(b.runs.length, 1);
  const argv = b.runs[0];
  assert.equal(argv[0], 'rundll32.exe');
  assert.equal(argv[1], DLL + ',VarvelStatus', 'the entry token is "<dll>,<Export>"');
  assert.equal(argv[2], 'C:\\sandbox\\out.json', 'the arg tail is its OWN argv token (the rundll32 quoting doctrine)');
  assert.equal(ev.files[0].role, 'payload');
  assert.equal(ev.files[0].planted, false, 'the payload is the input artifact — never a plant');
  // missing payload → loud, nothing runs
  const s2 = new ExecProxyStore({ backend: mapBackend(), name: TAG, sandbox: SANDBOX });
  const ev2 = s2.run({ technique: 'rundll32', dll: DLL, export: 'VarvelStatus' });
  assert.equal(ev2.state, 'failed');
  assert.match(ev2.error, /payload DLL not found/);
  // remove: nothing planted → verified clean, and the payload is NOT deleted
  const rem = s.remove();
  assert.equal(rem.state, 'removed');
  assert.equal(rem.removalVerified, true);
  assert.ok(b.files.has(DLL), 'remove never deletes the pre-staged payload');
  assert.equal(s.audit().clean, true);
});

test('store: sideload plant — snapshot-first, hash-verified copies, sandbox-confined; remove verifies ABSENCE', () => {
  const b = seededBackend();
  const s = new ExecProxyStore({ backend: b, name: TAG, sandbox: SANDBOX });
  const plantDir = execProxyPlantDir(SANDBOX, TAG);
  const ev = s.run({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll' });
  assert.equal(ev.state, 'ran');
  assert.equal(ev.installVerified, true);
  assert.equal(ev.dllSha256, sha256(DLL_BYTES));
  assert.equal(ev.hostSha256, sha256(HOST_BYTES));
  const hostCopy = plantDir + '\\winver.exe';
  const dllAs = plantDir + '\\version.dll';
  assert.ok(b.files.has(hostCopy) && b.files.has(dllAs), 'both copies planted');
  assert.equal(b.runs[0][0], hostCopy, 'the COPY is launched, never the original');
  assert.ok(!String(ev.command).includes(HOST), 'the original system path never executes');
  // status: live re-read, planted + intact
  const st = s.status();
  assert.equal(st.state, 'planted');
  // audit BEFORE remove: UNCLEAN (plants present)
  assert.equal(s.audit().clean, false, 'the engagement is not clean while plants exist');
  // remove: verified absent
  const rem = s.remove();
  assert.equal(rem.state, 'removed');
  assert.equal(rem.removalVerified, true);
  assert.ok(!b.files.has(hostCopy) && !b.files.has(dllAs), 'plants provably gone');
  assert.equal(s.audit().clean, true);
});

test('store: foreign-clobber refusal (no silent overwrite) + idempotent re-plant of our own bytes', () => {
  const plantDir = execProxyPlantDir(SANDBOX, TAG);
  const foreign = plantDir + '\\version.dll';
  const b = mapBackend({ [DLL]: DLL_BYTES, [HOST]: HOST_BYTES, [foreign]: Buffer.from('someone elses dll') });
  const s = new ExecProxyStore({ backend: b, name: TAG, sandbox: SANDBOX });
  const ev = s.run({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll' });
  assert.equal(ev.state, 'refused-clobber');
  assert.match(ev.error, /FOREIGN bytes/);
  assert.equal(b.files.get(foreign).toString(), 'someone elses dll', 'the foreign file was never touched');
  // idempotent: a second run over OUR OWN intact plants is a no-op re-verify
  const b2 = seededBackend();
  const s2 = new ExecProxyStore({ backend: b2, name: TAG, sandbox: SANDBOX });
  assert.equal(s2.run({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll' }).state, 'ran');
  const filesAfterFirst = b2.files.size;
  assert.equal(s2.run({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll' }).state, 'ran');
  assert.equal(b2.files.size, filesAfterFirst, 'idempotent re-run plants nothing twice');
});

test('store: cleanup-proof FAILURE paths are LOUD — tampered plant refuses removal; failed delete is removal-failed', () => {
  const b = seededBackend();
  const s = new ExecProxyStore({ backend: b, name: TAG, sandbox: SANDBOX });
  assert.equal(s.run({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll' }).state, 'ran');
  // TAMPER: the planted dll-as changes under us
  const dllAs = execProxyPlantDir(SANDBOX, TAG) + '\\version.dll';
  b.files.set(dllAs, Buffer.from('tampered'));
  assert.equal(s.status().state, 'tampered', 'status reports tampering honestly');
  const rem = s.remove();
  assert.equal(rem.state, 'refused-foreign', 'we never delete what we did not write');
  assert.match(rem.error, /FOREIGN bytes/);
  // FAILED DELETE: backend remove is a no-op (file stuck)
  const b2 = seededBackend();
  b2.remove = () => { /* the delete never takes */ };
  const s2 = new ExecProxyStore({ backend: b2, name: TAG, sandbox: SANDBOX });
  assert.equal(s2.run({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll' }).state, 'ran');
  const rem2 = s2.remove();
  assert.equal(rem2.state, 'removal-failed');
  assert.match(rem2.error, /STILL PRESENT/);
  assert.equal(s2.audit().clean, false, 'an unverified removal keeps the engagement UNCLEAN');
});

// ---------------- evidence intake + engagement-clean ----------------
test('evidence: parseExecProxyEvidence maps ops to audit events; remove-failed escalates; garbage yields no event', () => {
  const ran = JSON.stringify({ op: 'run', pid: 1, state: 'ran', names: { [TAG]: { state: 'ran', technique: 'rundll32', command: 'rundll32.exe ...', dllSha256: 'a'.repeat(64), hostSha256: 'b'.repeat(64), hostSigStatus: 'Valid', hostSigner: 'CN=Microsoft Windows', exitCode: 0, markerVerified: true, files: [{ role: 'payload', path: DLL, sha256: 'a'.repeat(64), present: true, planted: false }] } }, at: 't' });
  const ev1 = parseExecProxyEvidence(ran);
  assert.equal(ev1.event, 'execproxy.ran');
  assert.equal(ev1.fields.names[TAG].markerVerified, true);
  assert.equal(ev1.fields.names[TAG].hostSigStatus, 'Valid');
  assert.equal(ev1.fields.names[TAG].dllSha256, 'a'.repeat(64));
  const failed = JSON.stringify({ op: 'remove', pid: 1, state: 'removal-failed', names: { [TAG]: { state: 'removal-failed', technique: 'sideload', removalVerified: false } }, at: 't' });
  const ev2 = parseExecProxyEvidence(failed);
  assert.equal(ev2.event, 'execproxy.remove-failed', 'the event TYPE flips on an unverifiable removal');
  assert.equal(ev2.fields.escalated, true, 'the escalation is never buried');
  const sweep = parseExecProxyEvidence(JSON.stringify({ op: 'status', pid: 1, state: 'clean', clean: true, entries: [], open: [], at: 't' }));
  assert.equal(sweep.event, 'execproxy.status');
  assert.equal(sweep.fields.clean, true);
  assert.equal(parseExecProxyEvidence('execproxy-run REFUSED: agent-side proxy execution is OFF'), null, 'refusal text never fabricates an event');
  assert.equal(parseExecProxyEvidence('{"op":"run","names":{}}'), null, 'NO EVIDENCE, NO EVENT');
});

test('assessExecProxyClean: the engagement verdict over the audit stream', () => {
  const aid = 'agent-x';
  const plantRun = { type: 'execproxy.ran', agentId: aid, names: { [TAG]: { state: 'ran', technique: 'sideload', files: [{ role: 'dll-as', planted: true }] } } };
  const directRun = { type: 'execproxy.ran', agentId: aid, names: { 'VARVEL-direct': { state: 'ran', technique: 'rundll32', files: [{ role: 'payload', planted: false }] } } };
  // a rundll32-class run plants NOTHING — it never opens an entry
  assert.equal(assessExecProxyClean([directRun]).clean, true);
  // a sideload run opens one; unclosed → unclean
  assert.equal(assessExecProxyClean([plantRun]).clean, false);
  // a verified removal closes it
  const removed = { type: 'execproxy.removed', agentId: aid, names: { [TAG]: { state: 'removed', removalVerified: true } } };
  assert.equal(assessExecProxyClean([plantRun, removed]).clean, true);
  // a failed removal keeps it open AND escalated
  const failed = { type: 'execproxy.remove-failed', agentId: aid, names: { [TAG]: { state: 'removal-failed', removalVerified: false } } };
  const v = assessExecProxyClean([plantRun, failed]);
  assert.equal(v.clean, false);
  assert.equal(v.open[0].escalated, true);
  // a clean sweep closes whatever the agent had open
  const sweep = { type: 'execproxy.status', agentId: aid, clean: true, entries: [], open: [] };
  assert.equal(assessExecProxyClean([plantRun, sweep]).clean, true);
});

// ---------------- discovery ranker (fixture AuthenticodeSignature data) ----------------
test('discovery: rankHostCandidates over fixture signature data — Microsoft+Valid+names ranks top, honest verdicts', () => {
  const rows = [
    { path: 'C:\\Windows\\System32\\winver.exe', present: true, sigStatus: 'Valid', signer: 'CN=Microsoft Windows, O=Microsoft Corporation', hijackNames: ['version.dll'] },
    { path: 'C:\\Windows\\System32\\Sysprep\\sysprep.exe', present: true, sigStatus: 'Valid', signer: 'CN=Microsoft Windows, O=Microsoft Corporation', hijackNames: ['cryptsp.dll'] },
    { path: 'C:\\Windows\\System32\\rundll32.exe', present: true, sigStatus: 'Valid', signer: 'CN=Microsoft Windows', hijackNames: [] },
    { path: 'C:\\Tools\\unsigned.exe', present: true, sigStatus: 'NotSigned', signer: '', hijackNames: ['version.dll'] },
    { path: 'C:\\Windows\\System32\\gone.exe', present: false, sigStatus: null, signer: null, hijackNames: ['version.dll'] },
    { path: 'C:\\Vendor\\signed.exe', present: true, sigStatus: 'Valid', signer: 'CN=Some Vendor Inc', hijackNames: ['version.dll'] },
  ];
  const ranked = rankHostCandidates(rows);
  assert.equal(ranked[0].verdict, 'candidate');
  assert.ok(['winver.exe', 'sysprep.exe'].some((n) => ranked[0].path.endsWith(n)));
  assert.ok(ranked[0].score > ranked[2].score, 'hijack-name hosts outrank the bare system hosts');
  assert.equal(ranked.find((r) => r.path.includes('rundll32')).verdict, 'unsuitable', 'no hijack names → not a sideload candidate');
  assert.equal(ranked.find((r) => r.path.includes('unsigned')).verdict, 'unsuitable');
  assert.match(ranked.find((r) => r.path.includes('unsigned')).note, /signature not Valid/);
  assert.equal(ranked.find((r) => r.path.includes('gone')).verdict, 'unsuitable');
  assert.match(ranked.find((r) => r.path.includes('gone')).note, /not present/);
  assert.match(ranked.find((r) => r.path.includes('Vendor')).note, /NOT Microsoft/, 'non-Microsoft signers are called out honestly');
  assert.match(ranked[0].note, /never a claim/, 'the honesty contract rides on every row');
  // the discovery command/parser round-trip
  const cmd = buildDiscoveryCommand();
  assert.match(cmd, /Get-AuthenticodeSignature/);
  assert.match(cmd, /rundll32\.exe/);
  const fakeText = 'PROXYSIG|C:\\Windows\\System32\\winver.exe|1|Valid|CN=Microsoft Windows|version.dll\nPROXYSIG|C:\\Windows\\System32\\gone.exe|0|absent||version.dll\nnoise line';
  const parsed = parseDiscoveryExport(fakeText);
  assert.equal(parsed.length, 2, 'unparseable noise is skipped, never thrown on');
  assert.equal(parsed[0].present, true);
  assert.equal(parsed[0].hijackNames[0], 'version.dll');
  assert.equal(rankHostCandidates(parsed)[0].verdict, 'candidate');
});

// ---------------- runExecProxyTask (the Node agent seam) ----------------
test('runExecProxyTask: spec REJECTED pre-runner; no-runner REFUSED; job shape + error envelope', async () => {
  assert.match(await runExecProxyTask('execproxy-run', '{"technique":"nope"}', { runner: async () => ({ stdout: '' }) }), /REJECTED/);
  assert.match(await runExecProxyTask('execproxy-run', JSON.stringify({ technique: 'rundll32', dll: DLL, export: 'VarvelStatus' }), {}), /REFUSED: this agent has no execproxy host runner/);
  let seen = null;
  const runner = async (jobJson) => { seen = JSON.parse(jobJson); return { stdout: JSON.stringify({ op: seen.op, pid: 7, state: 'ran', names: { [seen.name]: { state: 'ran', technique: seen.technique } }, at: 't' }) }; };
  const out = JSON.parse(await runExecProxyTask('execproxy-run', JSON.stringify({ technique: 'rundll32', dll: DLL, export: 'VarvelStatus', args: 'C:\\o.json' }), { runner, sandboxDir: SANDBOX, manifestPath: SANDBOX + '\\m.json', defaultName: TAG }));
  assert.equal(out.op, 'run');
  assert.equal(seen.technique, 'rundll32');
  assert.equal(seen.export, 'VarvelStatus');
  assert.equal(seen.name, TAG, 'the deterministic default name applies');
  assert.equal(seen.sandbox, SANDBOX);
  assert.equal(seen.manifestPath, SANDBOX + '\\m.json');
  // status with no name carries NO name (the full sweep), even with a defaultName set
  await runExecProxyTask('execproxy-status', '', { runner, sandboxDir: SANDBOX, defaultName: TAG });
  assert.equal(seen.name, undefined, 'status sweeps are never pinned to the default handle');
  // a dead host → a failed envelope, never a throw
  const dead = powerShellExecProxyRunner({ spawnFn: () => { throw new Error('ENOENT'); } });
  const r = JSON.parse(await runExecProxyTask('execproxy-remove', '{"all":true}', { runner: dead }));
  assert.equal(r.state, 'failed');
  assert.match(r.error, /spawn failed/);
});

// ---------------- e2e over a REAL channel + REAL SimAgent (fake backend) ----------------
async function wiredAgent({ proxy, proxyRunner }) {
  const eng = freshEng();
  Settings.for(eng).set('exec.proxy', true); // channel half of the gate: OPEN
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['127.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  await ch.arm(0);
  const { agentId, token } = ch.registerAgent({ label: 'execproxy-e2e' });
  const dir = mkdtempSync(join(WORK, 'sbx-'));
  const agent = new SimAgent({ url: 'http://127.0.0.1:' + ch.port, agentId, token, dir, interval: 200, jitter: 0, proxy, proxyRunner });
  return { ch, agent, agentId, events, dir };
}

test('e2e: sideload run -> status -> remove routes channel -> agent -> audit; every planted/executed file hash lands; the sweep closes clean', async () => {
  const proxyRunner = hostFromStore(seededBackend());
  const { ch, agent, agentId, events } = await wiredAgent({ proxy: true, proxyRunner });
  try {
    const runSpec = { technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll', name: TAG };
    const t1 = ch.task(agentId, 'execproxy-run', JSON.stringify(runSpec));
    assert.equal(await agent.tick(), true);
    const r1 = ch.results(agentId, { taskId: t1 });
    assert.equal(JSON.parse(r1[0].data).state, 'ran');
    const ran = events.find((e) => e.type === 'execproxy.ran');
    assert.ok(ran, 'the intake audited the run');
    assert.equal(ran.taskId, t1);
    assert.equal(ran.names[TAG].dllSha256, sha256(DLL_BYTES), 'audit pins the payload sha256');
    assert.equal(ran.names[TAG].hostSha256, sha256(HOST_BYTES), 'audit pins the signed-host sha256');
    assert.equal(ran.names[TAG].installVerified, true);
    const plantedFiles = ran.names[TAG].files.filter((f) => f.planted);
    assert.equal(plantedFiles.length, 2, 'host-copy + dll-as audited');
    for (const f of plantedFiles) assert.match(f.sha256, /^[0-9a-f]{64}$/, 'sha256 audited for ' + f.role);
    const queued = events.find((e) => e.type === 'execproxy.task' && e.taskId === t1);
    assert.match(queued.specSha256, /^[0-9a-f]{64}$/, 'queue-time audit pins the spec hash');
    // an unclean verdict while planted
    assert.equal(assessExecProxyClean(events).clean, false);
    // STATUS sweep
    const t2 = ch.task(agentId, 'execproxy-status', '');
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t2 });
    assert.ok(events.some((e) => e.type === 'execproxy.status' && e.clean === false), 'the sweep reports unclean while planted');
    // REMOVE
    const t3 = ch.task(agentId, 'execproxy-remove', '{"all":true}');
    assert.equal(await agent.tick(), true);
    const r3 = ch.results(agentId, { taskId: t3 });
    assert.equal(JSON.parse(r3[0].data).state, 'removed');
    const rem = events.find((e) => e.type === 'execproxy.removed');
    assert.ok(rem, 'the intake audited the removal');
    assert.equal(rem.names[TAG].removalVerified, true, 'audit carries verified absence');
    assert.ok(!events.some((e) => e.type === 'execproxy.remove-failed'), 'no escalation on a verified cleanup');
    // final sweep + platform verdict
    const t4 = ch.task(agentId, 'execproxy-status', '');
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t4 });
    const verdict = assessExecProxyClean(events);
    assert.equal(verdict.clean, true, 'the engagement MAY be called clean — all plants verified removed');
    for (const t of ['task.queued', 'execproxy.task', 'task.delivered', 'result.received', 'execproxy.ran', 'execproxy.removed', 'execproxy.status']) {
      assert.ok(events.some((e) => e.type === t), 'audited: ' + t);
    }
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: agent launched WITHOUT --proxy refuses loudly even with the engagement gate open', async () => {
  const proxyRunner = hostFromStore(seededBackend());
  const { ch, agent, agentId, events } = await wiredAgent({ proxy: false, proxyRunner });
  try {
    const t1 = ch.task(agentId, 'execproxy-run', JSON.stringify({ technique: 'rundll32', dll: DLL, export: 'VarvelStatus' }));
    assert.equal(await agent.tick(), true);
    const r1 = ch.results(agentId, { taskId: t1 });
    assert.match(r1[0].data, /execproxy-run REFUSED: agent-side proxy execution is OFF/, 'the agent-side half of the gate refuses loudly');
    assert.ok(!events.some((e) => e.type === 'execproxy.ran'), 'a refusal never fabricates a ran event');
  } finally { agent.stop(); await ch.disarm(); }
});

test('e2e: an unverifiable removal escalates LOUDLY end-to-end and the engagement stays UNCLEAN', async () => {
  const stickyRunner = async (jobJson) => {
    const job = JSON.parse(jobJson);
    if (job.op === 'run') {
      return { stdout: JSON.stringify({ op: 'run', pid: 9, state: 'ran', names: { [job.name]: { state: 'ran', technique: 'sideload', dllSha256: 'a'.repeat(64), installVerified: true, files: [{ role: 'dll-as', path: 'C:\\sandbox\\execproxy-' + job.name + '\\version.dll', sha256: 'a'.repeat(64), present: true, planted: true }] } }, at: new Date().toISOString() }), stderr: '' };
    }
    if (job.op === 'remove') {
      return { stdout: JSON.stringify({ op: 'remove', pid: 9, state: 'removal-failed', names: { [job.name]: { state: 'removal-failed', technique: 'sideload', removalVerified: false, error: 'remove executed but the file is STILL PRESENT on re-read — CLEANUP-PROOF FAILED' } }, at: new Date().toISOString() }), stderr: '' };
    }
    return { stdout: JSON.stringify({ op: 'status', pid: 9, state: 'unclean', clean: false, entries: [{ name: job.name || TAG, technique: 'sideload', state: 'planted', removalVerified: false }], open: [{ name: TAG, technique: 'sideload', state: 'planted' }], at: new Date().toISOString() }), stderr: '' };
  };
  const { ch, agent, agentId, events } = await wiredAgent({ proxy: true, proxyRunner: stickyRunner });
  try {
    const t1 = ch.task(agentId, 'execproxy-run', JSON.stringify({ technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll', name: TAG }));
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t1 });
    const t2 = ch.task(agentId, 'execproxy-remove', '{"all":true}');
    assert.equal(await agent.tick(), true);
    ch.results(agentId, { taskId: t2 });
    const esc = events.find((e) => e.type === 'execproxy.remove-failed');
    assert.ok(esc, 'the unverifiable removal escalated as its own event type');
    assert.equal(esc.escalated, true);
    assert.equal(assessExecProxyClean(events).clean, false, 'the engagement CANNOT be called clean');
  } finally { agent.stop(); await ch.disarm(); }
});

// ---------------- tools: the EDR pairing loop ----------------
test('assessExecProxy: the full plant/run -> edrview -> remove -> sweep loop with a scripted channel', async () => {
  const b = seededBackend();
  const runner = hostFromStore(b);
  const calls = [];
  const taskAgent = async (agentId, kind, data) => {
    calls.push(kind);
    if (kind === 'execproxy-run' || kind === 'execproxy-remove' || kind === 'execproxy-status') {
      return runExecProxyTask(kind, data, { runner, sandboxDir: SANDBOX, manifestPath: SANDBOX + '\\m.json', defaultName: execProxyTag(agentId + '|' + DLL) });
    }
    if (kind === 'shell') {
      // the edrview telemetry query: three logs, all read, zero matching events
      return [
        'EDRVIEW|Microsoft-Windows-Windows Defender/Operational|[]',
        'EDRVIEW|Microsoft-Windows-Sysmon/Operational|[]',
        'EDRVIEW|Security|[]',
      ].join('\n');
    }
    return null;
  };
  const out = await assessExecProxy({ taskAgent, agentId: 'agent-live', technique: 'sideload', dll: DLL, host: HOST, as: 'version.dll', settleMs: 1 });
  assert.equal(out.refused, false);
  assert.equal(out.ran.state, 'ran');
  assert.equal(out.ran.dllSha256, sha256(DLL_BYTES));
  assert.equal(out.verdict, 'clean-in-telemetry', 'the edrview verdict on empty logs is honestly clean-in-telemetry');
  assert.equal(out.cleanupVerified, true, 'removal verified + sweep clean closes the loop');
  assert.deepEqual(calls.filter((k) => k.startsWith('execproxy')), ['execproxy-run', 'execproxy-remove', 'execproxy-status'], 'run -> remove -> status ordering');
  assert.ok(calls.includes('shell'), 'the edrview leg rode the channel');
  // refusal path: the channel-side refusal text surfaces as refused:true, verdict unknown
  const refusing = async () => 'execproxy-run REFUSED: agent-side proxy execution is OFF (this agent was launched without --proxy 1) — nothing planted, nothing executed';
  const out2 = await assessExecProxy({ taskAgent: refusing, agentId: 'agent-x', technique: 'rundll32', dll: DLL, export: 'VarvelStatus', settleMs: 1 });
  assert.equal(out2.refused, true);
  assert.equal(out2.verdict, 'unknown', 'a refused run makes no detectability claim');
  // spec refused pre-flight
  const out3 = await assessExecProxy({ taskAgent, agentId: 'agent-x', technique: 'bogus', dll: DLL, settleMs: 1 });
  assert.equal(out3.refused, true);
  assert.match(out3.reason, /unknown technique/);
  assert.equal(parseExecProxyResult('not json'), null);
});

// ---------------- GUARDED LIVE: build the real DLL, a real signed host runs it ----------------
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENCLAVE = join(REPO, '..');
const GO = join(ENCLAVE, 'tools', 'go', 'bin', 'go.exe');
const CC = 'C:\\msys64\\mingw64\\bin\\gcc.exe';
const LIVE = process.env.VARVEL_LIVE_PROXY === '1';

test('LIVE (VARVEL_LIVE_PROXY=1): the Go DLL builds; rundll32 (Microsoft-signed) really loads and runs VarvelStatus; cleanup verified absent', { skip: !LIVE, timeout: 420000 }, async () => {
  if (!existsSync(GO)) throw new Error('no portable Go toolchain at ' + GO + ' — see docs/NATIVE.md');
  if (!existsSync(CC)) throw new Error('buildmode=c-shared needs a C compiler (mingw gcc) at ' + CC);
  const live = mkdtempSync(join(WORK, 'live-'));
  const dll = join(live, 'varvel-agent.dll');
  const outJson = join(live, 'status.json');
  const manifest = join(live, 'varvel-execproxy-manifest.json');
  const runner = powerShellExecProxyRunner();
  try {
    // 1. BUILD the DLL form for real, contained caches only.
    const gocache = join(ENCLAVE, 'tools', 'gocache');
    const build = spawnSync(GO, ['build', '-tags', 'varveldll', '-buildmode=c-shared', '-ldflags=-s -w', '-o', dll, '.'], {
      cwd: join(REPO, 'agents', 'native'),
      env: {
        ...process.env,
        GOCACHE: join(gocache, 'cache'), GOPATH: join(gocache, 'path'),
        GOMODCACHE: join(gocache, 'modcache'), GOTMPDIR: join(gocache, 'tmp'), GOTOOLCHAIN: 'local',
        CGO_ENABLED: '1', CC,
      },
      encoding: 'utf8', timeout: 360000,
    });
    if (build.status !== 0) throw new Error('go build (c-shared) failed: ' + build.stderr);
    const dllSha = sha256(readFileSync(dll));
    console.log('  LIVE built', dll, readFileSync(dll).length, 'bytes, sha256', dllSha.slice(0, 16) + '…');

    // 2. RUN through the REAL execproxy host: rundll32-class, VarvelStatus (returns
    //    immediately — no C2 loop in a test).
    const runSpec = JSON.stringify({ technique: 'rundll32', dll, export: 'VarvelStatus', args: outJson, name: 'VARVEL-live01' });
    const runOut = JSON.parse(await runExecProxyTask('execproxy-run', runSpec, { runner, sandboxDir: live, manifestPath: manifest, defaultName: 'VARVEL-live01' }));
    assert.equal(runOut.op, 'run');
    const ev = runOut.names['VARVEL-live01'];
    assert.equal(ev.state, 'ran', 'the host ran: ' + JSON.stringify(ev));
    assert.equal(ev.dllSha256, dllSha, 'evidence pins the built DLL sha256');
    assert.equal(ev.hostSigStatus, 'Valid', 'the host binary signature is Valid');
    assert.match(ev.hostSigner || '', /Microsoft/i, 'the host binary is Microsoft-signed');
    assert.equal(ev.markerVerified, true, 'the host observed OUR marker — the signed binary really ran our code');
    console.log('  LIVE rundll32 evidence:', ev.command, '| sig:', ev.hostSigStatus, ev.hostSigner);

    // 3. The marker itself: written by OUR code inside the rundll32 process.
    const marker = JSON.parse(readFileSync(outJson, 'utf8'));
    assert.equal(marker.marker, 'varvel-agent-dll');
    assert.equal(marker.export, 'VarvelStatus');
    assert.equal(typeof marker.pid, 'number');
    console.log('  LIVE marker: pid', marker.pid, marker.go, '— written by our DLL inside rundll32.exe');

    // 4. REMOVE + SWEEP: cleanup-proof, verified absent.
    const remOut = JSON.parse(await runExecProxyTask('execproxy-remove', '{"name":"VARVEL-live01"}', { runner, sandboxDir: live, manifestPath: manifest }));
    assert.equal(remOut.names['VARVEL-live01'].removalVerified, true);
    const stOut = JSON.parse(await runExecProxyTask('execproxy-status', '{}', { runner, sandboxDir: live, manifestPath: manifest }));
    assert.equal(stOut.clean, true, 'the sweep is clean after the verified removal');
  } finally {
    try { runner.close(); } catch {}
    try { rmSync(live, { recursive: true, force: true }); } catch {}
  }
});

// libuv on win32 asserts (async.c UV_HANDLE_CLOSING) when the process exits while a
// handle is mid-close after the channel/agent teardown — the same guard the persist
// and native suites carry. Keep LAST.
test('teardown grace (win32)', async () => { await new Promise((r) => setTimeout(r, 600)); });
