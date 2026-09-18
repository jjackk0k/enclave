// dnstransport.test.mjs — DNS C2 transport: wire codec, chunked push, UDP round-trip.
// Integration over a real armed channel; everything stays on loopback.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDnsQuery, craftDnsResponse, decodeTxtAnswer } from '../engine/dnswire.mjs';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { DnsTransport } from '../agents/dns-client.mjs';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };

test('dnswire: query parse + response craft/decode round-trip; malformed rejected', () => {
  // handcraft a query for a.b.c TXT
  const qname = 'abc123.def456.ax.sim';
  const labels = qname.split('.').map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p)]));
  const head = Buffer.alloc(12);
  head.writeUInt16BE(0x1234, 0);
  head.writeUInt16BE(0x0100, 2);
  head.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4); tail.writeUInt16BE(16, 0); tail.writeUInt16BE(1, 2);
  const packet = Buffer.concat([head, ...labels, Buffer.from([0]), tail]);
  const q = parseDnsQuery(packet);
  assert.equal(q.id, 0x1234);
  assert.equal(q.qname, qname);
  assert.equal(q.qtype, 16);
  assert.equal(q.rd, true);

  const resp = craftDnsResponse(q, 'hello-chunky-reply');
  assert.equal(resp.readUInt16BE(0), 0x1234);
  assert.equal(resp.readUInt16BE(6), 1); // ANCOUNT
  assert.equal(decodeTxtAnswer(resp), 'hello-chunky-reply');

  const empty = craftDnsResponse(q, '');
  assert.equal(empty.readUInt16BE(6), 0);
  assert.equal(decodeTxtAnswer(empty), '');

  assert.equal(parseDnsQuery(Buffer.from([1, 2, 3])), null);
  const bad = Buffer.from(packet); bad.writeUInt16BE(0x8000, 2); // QR=1 is not a query
  assert.equal(parseDnsQuery(bad), null);
  const bad2 = Buffer.from(packet); bad2[12] = 0xff; // label len > 63
  assert.equal(parseDnsQuery(bad2), null);
});

async function armedChannel(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, events };
}

test('DNS transport over the HTTP /d carrier: pull+exec+chunked push completes the ledger', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-dns-http-'));
  try { assert.equal(await dnsRoundTripHTTPHelper(dir), true); }
  finally { rmSync(dir, { recursive: true, force: true }); }
});

async function dnsRoundTripHTTPHelper(dir) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }) });
  await ch.arm(0);
  const { agentId, token } = ch.registerAgent({ label: 'dns-http-agent' });
  const taskId = ch.task(agentId, 'shell', 'hostname');
  const agent = new SimAgent({ url: `http://127.0.0.1:${ch.port}`, agentId, token, dir, transport: 'dns', interval: 200, jitter: 0 });
  assert.equal(await agent.tick(), true);
  const view = ch.tasksView(agentId).find((t) => t.taskId === taskId);
  assert.equal(view.status, 'resulted');
  assert.ok((view.resultPreview || '').length > 0);
  assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'dns-codec'));
  await ch.disarm();
  return true;
}

test('DNS transport over REAL UDP wire packets: pull+exec+chunked push completes the ledger', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-dns-udp-'));
  const events = [];
  const ch2 = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), dnsPort: 35353, bind: '127.0.0.1' });
  await ch2.arm(0);
  let agent = null;
  try {
    const { agentId, token } = ch2.registerAgent({ label: 'dns-udp-agent' });
    const taskId = ch2.task(agentId, 'shell', 'hostname');
    agent = new SimAgent({ url: 'dns-udp://127.0.0.1:35353', agentId, token, dir, transport: 'dns', interval: 200, jitter: 0 });
    assert.equal(await agent.tick(), true);
    const view = ch2.tasksView(agentId).find((t) => t.taskId === taskId);
    assert.equal(view.status, 'resulted');
    assert.ok((view.resultPreview || '').length > 0);
    assert.ok(events.some((e) => e.type === 'channel.dns-armed'));
    assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'dns-codec'));
  } finally {
    if (agent && agent._dns) agent._dns.close();
    await ch2.disarm();
    await new Promise((r) => setTimeout(r, 75)); // win32 libuv UV_HANDLE_CLOSING teardown grace
    rmSync(dir, { recursive: true, force: true });
  }
});

test('governance: tampered chunk HMAC never intakes a result; stale seq gets uniform empty', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'varvel-dns-gov-'));
  const { ch, events } = await armedChannel();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'gov' });
    const taskId = ch.task(agentId, 'shell', 'hostname');
    const good = new DnsTransport({ url: `http://127.0.0.1:${ch.port}`, agentId, token });
    const task = await good.pull();
    assert.equal(task.taskId, taskId);
    // tampered push: wrong hmac on chunk 0
    const s = good._nextSeq();
    const d = Buffer.from('forged').toString('base64');
    const reply = await good._roundTrip({ a: agentId, s, h: 'deadbeef'.repeat(8), t: taskId, k: 'push', i: 0, n: 1, d });
    assert.equal(reply, '');
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'dns-push-reject'));
    // stale seq (reuse an old one) → uniform empty
    const reply2 = await good._roundTrip({ a: agentId, s: 1, h: 'x'.repeat(64) });
    assert.equal(reply2, '');
    // the real result STILL lands afterwards (channel unharmed)
    await good.push(taskId, 'real-output');
    assert.equal(ch.tasksView(agentId).find((t) => t.taskId === taskId).status, 'resulted');
    good.close();
  } finally {
    await ch.disarm();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('governance: killed agent is indistinguishable from idle over DNS (uniform empty)', async () => {
  const { ch } = await armedChannel();
  const { agentId, token } = ch.registerAgent({});
  ch.kill(agentId);
  const t = new DnsTransport({ url: `http://127.0.0.1:${ch.port}`, agentId, token });
  assert.equal(await t.pull(), null);
  await ch.disarm();
});

// Teardown grace: on win32, --test-force-exit can fire while dgram/undici sockets are still
// closing after the last disarm/close (libuv UV_HANDLE_CLOSING assert). Same guard as
// callback-v2/chainrun — generous on purpose under suite CPU contention.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
