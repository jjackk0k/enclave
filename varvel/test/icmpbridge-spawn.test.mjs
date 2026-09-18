// icmpbridge-spawn.test.mjs — the bridge SPAWN wiring: python resolution order, store-stub
// detection, and the capability honesty window — plus the stdio/codec contract over REAL
// pipes against a node shim masquerading as the bridge (test/fixtures/fake-icmp-bridge.mjs).
// Hermetic: no admin, no raw sockets, loopback only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CallbackChannel, resolvePython } from '../engine/callback.mjs';
import { icmpPacket } from '../engine/icmpcodec.mjs';
import { encodeQuery } from '../engine/dnscodec.mjs';

const SHIM = fileURLToPath(new URL('./fixtures/fake-icmp-bridge.mjs', import.meta.url));
const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const tick = (ms = 15) => new Promise((r) => setTimeout(r, ms));

// A spawnFn that launches the shim as a real child process (real stdio pipes), ignoring
// the resolved python/script args — the shim IS the bridge for these tests.
const shimSpawn = (mode, capture = null) => (cmd, args) => {
  if (capture) { capture.cmd = cmd; capture.args = args; }
  return spawn(process.execPath, [SHIM], {
    env: { ...process.env, FAKE_BRIDGE_MODE: mode },
    windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
  });
};

async function statusWhenSettled(ch, ms = 4000) {
  const t0 = Date.now();
  while (ch.icmpStatus().supported === null && Date.now() - t0 < ms) await tick(20);
  return ch.icmpStatus();
}

test('resolvePython: explicit override wins verbatim', () => {
  const r = resolvePython('D:\\py\\python.exe', { LOCALAPPDATA: 'X:\\la' }, () => true);
  assert.equal(r.python, 'D:\\py\\python.exe');
  assert.equal(r.via, 'override');
});

test('resolvePython: %LOCALAPPDATA%\\Python\\bin\\python.exe preferred when the file exists', () => {
  const r = resolvePython(null, { LOCALAPPDATA: 'C:\\Users\\Jack\\AppData\\Local' }, () => true);
  assert.equal(r.python, 'C:\\Users\\Jack\\AppData\\Local\\Python\\bin\\python.exe');
  assert.equal(r.via, 'local');
});

test('resolvePython: falls back to bare python on PATH when no local install exists', () => {
  const r = resolvePython(null, { LOCALAPPDATA: 'C:\\Users\\Jack\\AppData\\Local' }, () => false);
  assert.equal(r.python, 'python');
  assert.equal(r.via, 'path');
});

test('resolvePython: LOCALAPPDATA unset → PATH fallback', () => {
  const r = resolvePython(null, {}, () => { throw new Error('must not stat without a path'); });
  assert.equal(r.python, 'python');
  assert.equal(r.via, 'path');
});

test('spawn wiring: the channel spawns exactly what resolvePython resolved', async () => {
  const capture = {};
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: () => {}, icmp: { spawnFn: shimSpawn('echo', capture) } });
  await ch.arm(0);
  assert.equal(capture.cmd, resolvePython(null).python); // box-independent: wiring, not resolution
  assert.match(capture.args[1], /icmp-bridge\.py$/);
  await ch.disarm();
});

test('shim over real pipes: capability → armed, governed pull intakes, liveVerified flips', async () => {
  const events = [];
  const capture = {};
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), icmp: { spawnFn: shimSpawn('echo', capture) } });
  await ch.arm(0);
  const st = await statusWhenSettled(ch);
  assert.equal(st.armed, true);
  assert.equal(st.supported, true);
  assert.ok(events.some((e) => e.type === 'channel.icmp-capability' && e.supported === true));

  // A governed agent pull, written to the shim's stdin as a send op: the shim 'sends' it
  // and loops it back as a recv from loopback — the channel's codec + governed intake
  // run against bytes that crossed REAL pipes both ways.
  const { agentId, token } = ch.registerAgent({ label: 'shim-agent' });
  const taskId = ch.task(agentId, 'shell', 'hostname');
  const q = encodeQuery({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pull') });
  const child = ch._icmpChild;
  child.stdin.write(JSON.stringify({ id: 99, op: 'send', dst: '127.0.0.1', packetB64: icmpPacket({ type: 8, seq: 7, kind: 'pull', data: Buffer.from(q) }).toString('base64') }) + '\n');
  await tick(60);

  assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'icmp' && e.agentId === agentId));
  assert.ok(events.some((e) => e.type === 'task.delivered' && e.transport === 'icmp' && e.taskId === taskId));
  assert.equal(ch.icmpStatus().liveVerified, true); // authenticated frame advanced the seq — observed, not asserted
  await ch.disarm();
});

test('store-stub detection: clean spawn + nag stderr + no capability → honestly unsupported, fast', async () => {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), icmp: { spawnFn: shimSpawn('stub') } });
  const t0 = Date.now();
  await ch.arm(0);
  const st = await statusWhenSettled(ch);
  assert.ok(Date.now() - t0 < 4000, 'the stub must be caught immediately, not after the capability window');
  assert.equal(st.supported, false);
  assert.equal(st.armed, false);
  assert.match(st.reason, /store stub|exited \(code 49\)/i); // stderr-race tolerant: either honest verdict
  assert.ok(events.some((e) => e.type === 'channel.icmp-capability' && e.supported === false));
  assert.ok(ch.port > 0); // the HTTP channel itself is unaffected
  await ch.disarm();
});

test('capability window: a clean-launching interpreter that never speaks is marked unavailable, not hung on', async () => {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), icmp: { spawnFn: shimSpawn('silent'), capWindowMs: 200 } });
  await ch.arm(0);
  const st = await statusWhenSettled(ch);
  assert.equal(st.supported, false);
  assert.equal(st.armed, false);
  assert.match(st.reason, /no capability line within 200ms/);
  assert.ok(events.some((e) => e.type === 'channel.icmp-capability' && e.supported === false));
  await ch.disarm();
});
