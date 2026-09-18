// credaccess.test.mjs — the GOVERNED AD TIER, rung 3 (CREDENTIAL ACCESS — LSASS VIA
// COMSVCS). HERMETIC ONLY, by house rule: live LSASS dumping on the operator's own
// host is FORBIDDEN (this box IS the operator's machine) — the tier validates
// against the hardened RANGE. The minidump marker validator, the gate matrix, the
// cleanup-proof dump lifecycle, and the secret-negative contract pin here over an
// injected fake backend.
//
// HOUSE RULE: everything this suite writes lives under repo-local varvel/.tmp —
// never os.tmpdir(). VARVEL_SETTINGS_FILE points under .tmp; engagement names unique.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { CallbackChannel } from '../engine/callback.mjs';
import {
  CRED_KINDS, CRED_TECHNIQUE, credTag, validateMinidump,
  parseCredSpec, credAccessGate, credSpecSha256, CredAccessStore,
  parseCredEvidence, assessCredClean,
} from '../engine/credaccess.mjs';
import { Settings } from '../engine/settings.mjs';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(TMP_ROOT, { recursive: true });
const WORK = mkdtempSync(join(TMP_ROOT, 'credaccess-test-'));
process.env.VARVEL_SETTINGS_FILE = join(WORK, 'settings.json');

let engSeq = 0;
const freshEng = () => 'cred-' + (engSeq++) + '-' + Date.now();
const NAME = 'cred-test0001';
const SANDBOX = 'C:\\sandbox';

// A minimal well-formed MINIDUMP fixture: header + directory + in-bounds stream data.
function fixtureMdmp({ streams = [7, 9] } = {}) {
  const dirRva = 32;
  const dataStart = dirRva + streams.length * 12;
  const buf = Buffer.alloc(dataStart + streams.length * 16, 0xab);
  buf.writeUInt32LE(0x504d444d, 0); // 'MDMP'
  buf.writeUInt32LE(0xa793, 4);     // version
  buf.writeUInt32LE(streams.length, 8);
  buf.writeUInt32LE(dirRva, 12);
  streams.forEach((t, i) => {
    buf.writeUInt32LE(t, dirRva + i * 12);
    buf.writeUInt32LE(16, dirRva + i * 12 + 4);
    buf.writeUInt32LE(dataStart + i * 16, dirRva + i * 12 + 8);
  });
  return buf;
}

// ——— THE MARKER VALIDATOR (marker-level only — NEVER a content read) ———
test('a well-formed comsvcs-class full dump validates (SystemInfo + Memory64List present)', () => {
  const v = validateMinidump(fixtureMdmp({}));
  assert.equal(v.valid, true);
  assert.equal(v.streams, 2);
  assert.equal(v.full, true);
  assert.deepEqual(v.streamTypes, [7, 9]);
});

test('garbage, truncation, and structural lies are refused with the honest reason', () => {
  assert.match(validateMinidump(Buffer.alloc(0)).reason, /too small/);
  assert.match(validateMinidump(Buffer.from('NOTADUMP-payload-bytes-0123456789abcdef')).reason, /bad signature/);
  const truncated = fixtureMdmp({}).subarray(0, 40); // directory overruns the file
  assert.match(validateMinidump(truncated).reason, /overruns|too small/);
  const noSys = validateMinidump(fixtureMdmp({ streams: [3, 9] })); // ThreadList + Memory64, no SystemInfo
  assert.equal(noSys.valid, false);
  assert.match(noSys.reason, /SystemInfo/);
  const noMem = validateMinidump(fixtureMdmp({ streams: [7, 3] })); // no memory stream
  assert.equal(noMem.valid, false);
  assert.match(noMem.reason, /memory stream/);
  // a stream whose data overruns the file
  const liar = fixtureMdmp({});
  liar.writeUInt32LE(999999, 32 + 8); // stream 0 rva way past EOF
  assert.match(validateMinidump(liar).reason, /overruns/);
});

// ——— SPEC GATE ———
test('spec parse matrix: kinds, pid band, unambiguous remove scope', () => {
  assert.throws(() => parseCredSpec('cred-yolo', '{}'), /unknown kind/);
  assert.deepEqual(parseCredSpec('cred-dump', ''), { kind: 'cred-dump', name: null, pid: null });
  assert.deepEqual(parseCredSpec('cred-dump', '{"name":"cred-a","pid":740}'), { kind: 'cred-dump', name: 'cred-a', pid: 740 });
  assert.throws(() => parseCredSpec('cred-dump', '{"pid":2}'), /pid must be/);
  assert.throws(() => parseCredSpec('cred-dump', '{"name":"bad name!"}'), /safe dump handle/);
  assert.throws(() => parseCredSpec('cred-dump-remove', '{}'), /explicit scope/);
  assert.throws(() => parseCredSpec('cred-dump-remove', '{"name":"a","all":true}'), /not both/);
  assert.deepEqual(parseCredSpec('cred-dump-status', ''), { kind: 'cred-dump-status', name: null });
  assert.match(credTag('agent|url'), /^cred-[0-9a-f]{8}$/);
  assert.equal(credAccessGate('off-' + Date.now()).ok, false);
});

// ——— THE STORE over a fake backend (fixture dump bytes in a Map filesystem) ———
function fakeCredBackend({ dumpBytes = fixtureMdmp({}) } = {}) {
  const files = new Map();
  return {
    files, dumpBytes,
    run(job) { files.set(job.path, Buffer.from(this.dumpBytes)); return { code: 0, output: '' }; },
    probe(path) {
      if (!files.has(path)) return { present: false, sha256: null, bytes: null, mdmp: null };
      const b = files.get(path);
      return { present: true, sha256: sha256(b), bytes: b.length, mdmp: validateMinidump(b) };
    },
    remove(path) { files.delete(path); },
  };
}

test('dump(): marker-valid artifact lands audited (sha256 + bytes + streams), state dumped, manifest recorded', () => {
  const be = fakeCredBackend();
  const store = new CredAccessStore({ backend: be, name: NAME, sandbox: SANDBOX });
  const ev = store.dump({});
  assert.equal(ev.state, 'dumped');
  assert.equal(ev.sha256, sha256(fixtureMdmp({})));
  assert.equal(ev.mdmpValid, true);
  assert.equal(ev.streams, 2);
  assert.equal(ev.dumpPath, SANDBOX + '\\' + NAME + '.dmp');
  assert.equal(store.audit().clean, false, 'a live dump file keeps the engagement UNCLEAN until removed');
});

test('a marker-INVALID artifact is failed honestly and the stub is removed — garbage is never claimed', () => {
  const be = fakeCredBackend({ dumpBytes: Buffer.from('access-denied zero byte stub') });
  const store = new CredAccessStore({ backend: be, name: NAME, sandbox: SANDBOX });
  const ev = store.dump({});
  assert.equal(ev.state, 'failed');
  assert.match(ev.error, /marker check/);
  assert.equal(be.files.size, 0, 'the stub was removed');
});

test('clobber refusal: a foreign file at the dump path is never overwritten', () => {
  const be = fakeCredBackend();
  const path = SANDBOX + '\\' + NAME + '.dmp';
  be.files.set(path, Buffer.from('foreign bytes'));
  const store = new CredAccessStore({ backend: be, name: NAME, sandbox: SANDBOX });
  const ev = store.dump({});
  assert.equal(ev.state, 'refused-clobber');
  assert.equal(sha256(be.files.get(path)), sha256(Buffer.from('foreign bytes')), 'untouched');
});

test('remove(): verified absent; a hash-changed file is refused-foreign (we never delete what we did not write)', () => {
  const be = fakeCredBackend();
  const store = new CredAccessStore({ backend: be, name: NAME, sandbox: SANDBOX });
  store.dump({});
  const rm = store.remove();
  assert.equal(rm.state, 'removed');
  assert.equal(rm.removalVerified, true);
  assert.equal(store.audit().clean, true);
  // tamper case
  store.dump({});
  const path = SANDBOX + '\\' + NAME + '.dmp';
  be.files.set(path, Buffer.from('someone else rewrote the dump'));
  const rm2 = store.remove();
  assert.equal(rm2.state, 'refused-foreign');
  assert.ok(be.files.has(path), 'foreign bytes survive');
});

test('status() measures now: present / removed / tampered are live re-reads', () => {
  const be = fakeCredBackend();
  const store = new CredAccessStore({ backend: be, name: NAME, sandbox: SANDBOX });
  assert.equal(store.status().state, 'absent');
  store.dump({});
  assert.equal(store.status().state, 'present');
  store.remove();
  assert.equal(store.status().state, 'removed');
});

// ——— CHANNEL GATE MATRIX + INTAKE + SECRET-NEGATIVE ———
function gatedChannel(eng) {
  const events = [];
  const ch = new CallbackChannel({ scope: { engagement: eng, signedBy: 'test', cidrs: ['10.0.0.0/8'] }, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { agentId } = ch.registerAgent({ label: 'gated' });
  return { ch, events, agentId };
}

test('the gate is fail-closed for every cred kind (GOVERNANCE, audited task.refused)', () => {
  const { ch, events, agentId } = gatedChannel(freshEng());
  for (const kind of CRED_KINDS) {
    let err = null;
    try { ch.task(agentId, kind, kind === 'cred-dump' ? '{}' : '{"all":true}'); } catch (e) { err = e; }
    assert.ok(err && err.code === 'GOVERNANCE', kind + ' refused');
    assert.match(err.message, /cred\.access.*OFF/s);
  }
  assert.ok(events.filter((e) => e.type === 'task.refused').length >= 3);
});

test('gate on: cred.task audits the pin; cred.dumped carries sha256+marker ONLY (never a dump byte); the sweep governs clean', () => {
  const eng = freshEng();
  Settings.for(eng).set('cred.access', true);
  const { ch, events, agentId } = gatedChannel(eng);
  const t1 = ch.task(agentId, 'cred-dump', '{"name":"cred-live01"}');
  const dump = fixtureMdmp({});
  const body = JSON.stringify({
    op: 'dump', pid: 5150, state: 'dumped',
    names: { 'cred-live01': { state: 'dumped', technique: CRED_TECHNIQUE.id, pid: 740, dumpPath: 'C:\\agentbox\\cred-live01.dmp', sha256: sha256(dump), bytes: dump.length, mdmpValid: true, streams: 2, removalVerified: false } },
    at: new Date().toISOString(),
  });
  ch._intakeResult(ch.agents.get(agentId), t1, Buffer.from(body));
  const ev = events.find((e) => e.type === 'cred.dumped');
  assert.ok(ev);
  assert.equal(ev.names['cred-live01'].sha256, sha256(dump));
  assert.equal(ev.names['cred-live01'].mdmpValid, true);
  // SECRET-NEGATIVE: nothing resembling dump CONTENT rides the audit stream.
  assert.ok(!JSON.stringify(events).includes(dump.toString('base64').slice(0, 64)));
  assert.ok(!JSON.stringify(events).includes('abababab'), 'no content bytes, not even the fixture filler pattern');
  assert.equal(assessCredClean(events).clean, false, 'a live dump file keeps the engagement unclean');
  // verified removal closes it
  const t2 = ch.task(agentId, 'cred-dump-remove', '{"name":"cred-live01"}');
  ch._intakeResult(ch.agents.get(agentId), t2, Buffer.from(JSON.stringify({
    op: 'remove', pid: 5150, state: 'removed',
    names: { 'cred-live01': { state: 'removed', technique: CRED_TECHNIQUE.id, pid: 740, dumpPath: 'C:\\agentbox\\cred-live01.dmp', sha256: sha256(dump), bytes: dump.length, mdmpValid: true, streams: 2, removalVerified: true } },
    at: new Date().toISOString(),
  })));
  assert.equal(assessCredClean(events).clean, true);
  assert.ok(events.some((e) => e.type === 'cred.dump-removed'));
  // the escalated path flips the event type
  const t3 = ch.task(agentId, 'cred-dump-remove', '{"name":"cred-stuck1"}');
  ch._intakeResult(ch.agents.get(agentId), t3, Buffer.from(JSON.stringify({
    op: 'remove', pid: 1, state: 'removal-failed',
    names: { 'cred-stuck1': { state: 'removal-failed', technique: CRED_TECHNIQUE.id, dumpPath: 'C:\\agentbox\\cred-stuck1.dmp', removalVerified: false } },
    at: new Date().toISOString(),
  })));
  const failed = events.find((e) => e.type === 'cred.dump-remove-failed');
  assert.ok(failed && failed.escalated === true);
  assert.equal(parseCredEvidence('cred-dump REFUSED: ...'), null);
});

test('the engine module has NO exec/network imports — the live leg is the range agent\'s, never the operator host\'s', () => {
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'engine', 'credaccess.mjs'), 'utf8');
  assert.ok(!/node:(child_process|net|fs)/.test(src), 'credaccess engine is pure: no process, network, or filesystem access');
  assert.equal(credSpecSha256({ kind: 'cred-dump', name: 'a', pid: null }).length, 64);
});
