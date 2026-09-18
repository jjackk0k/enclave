// dns-dualbind.test.mjs — DNS C2 dual-bind: the udp6 half of the wire (the 2026-08-04
// follow-up, shipped). Hermetic: real UDP sockets on loopback only (127.0.0.1 / ::1),
// no external network, no raw sockets. v6-less hosts degrade to the named-gap assertions
// instead of failing — the contract is "one family unavailable = named gap, never a crash".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import os from 'node:os';
import crypto from 'node:crypto';
import { CallbackChannel, dnsV6Counterpart } from '../engine/callback.mjs';
import { encodeQuery } from '../engine/dnscodec.mjs';
import { decodeTxtAnswer } from '../engine/dnswire.mjs';
import { b32decode } from '../engine/dnscodec.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');

// A free UDP port for both families (bind a probe, learn, close).
function freePort() {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    s.once('error', reject);
    s.bind(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// Handcraft a minimal RFC 1035 TXT query for a qname (the dnstransport.test shape).
function craftQuery(qname, id = 0x1234) {
  const labels = qname.split('.').map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p)]));
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id, 0);
  head.writeUInt16BE(0x0100, 2); // RD
  head.writeUInt16BE(1, 4);      // QDCOUNT
  const tail = Buffer.alloc(4); tail.writeUInt16BE(16, 0); tail.writeUInt16BE(1, 2); // TXT IN
  return Buffer.concat([head, ...labels, Buffer.from([0]), tail]);
}

// One UDP round trip against the armed DNS wire, on the given family/address.
// SOURCE BINDING (2026-09-16): some Windows hosts (VPN/WFP filter layers) REFUSE a
// WILDCARD-source UDP send to a loopback destination with EADDRNOTAVAIL. Measured on
// this box: unbound -> 127.0.0.1 and bound-0.0.0.0 -> 127.0.0.1 both fail, while a
// specific-loopback source succeeds (both families; see .tmp/udp-source-bind-probe.mjs).
// The wire itself listens on the EXACT address, so binding the query socket to that same
// loopback keeps this test faithful (still real sockets, still loopback-only) and portable.
// Non-loopback addresses keep the unbound behaviour — no assumption is made about them.
const isLoopbackLiteral = (a) => a === '127.0.0.1' || a === '::1';
function udpQuery(family, packet, address, port, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket(family);
    const t = setTimeout(() => { try { s.close(); } catch {} reject(new Error('udp query timed out (' + family + ' -> ' + address + ':' + port + ')')); }, timeoutMs);
    s.once('error', (e) => { clearTimeout(t); try { s.close(); } catch {} reject(e); });
    s.once('message', (msg) => { clearTimeout(t); try { s.close(); } catch {} resolve(msg); });
    const send = () => s.send(packet, port, address, (e) => { if (e) { clearTimeout(t); try { s.close(); } catch {} reject(e); } });
    if (isLoopbackLiteral(address)) s.bind(0, address, send);
    else send();
  });
}

async function armed(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, events };
}

test('dnsV6Counterpart: loopback->::1, any->::, v6 passthrough; specific v4/hostnames have NO honest counterpart', () => {
  assert.equal(dnsV6Counterpart('127.0.0.1'), '::1');
  assert.equal(dnsV6Counterpart('127.0.0.99'), '::1');
  assert.equal(dnsV6Counterpart('0.0.0.0'), '::');
  assert.equal(dnsV6Counterpart('::1'), '::1');
  assert.equal(dnsV6Counterpart('fd00::5'), 'fd00::5');
  assert.equal(dnsV6Counterpart('::ffff:127.0.0.1'), '::1'); // v4-mapped IS the v4 loopback
  assert.equal(dnsV6Counterpart('10.10.0.5'), null);         // specific v4 NIC bind: never expands to ::
  assert.equal(dnsV6Counterpart('192.168.50.1'), null);
  assert.equal(dnsV6Counterpart('localhost'), null);         // hostname binds: no derivation
});

test('dual-bind on a v4 loopback bind: udp4 serves identically AND udp6 answers on ::1', async () => {
  const port = await freePort();
  const { ch, events } = await armed({ dnsPort: port, bind: '127.0.0.1' });
  try {
    assert.ok(events.some((e) => e.type === 'channel.dns-armed' && e.bind === '127.0.0.1' && e.port === port), 'udp4 arm event unchanged');
    const v6Armed = events.some((e) => e.type === 'channel.dns6-armed' && e.bind === '::1' && e.port === port);
    const v6Gap = events.find((e) => e.type === 'dns.bind-gap' && e.family === 'udp6');
    assert.ok(v6Armed || v6Gap, 'udp6 is either armed or a NAMED gap — never a crash, never silent');
    assert.ok(!(v6Armed && v6Gap), 'armed and gapped are mutually exclusive');

    // The udp4 wire: a governed pull delivers the queued task (today's path, unchanged).
    const { agentId, token } = ch.registerAgent({ label: 'dual-bind' });
    const taskId = ch.task(agentId, 'shell', 'hostname');
    const q4 = encodeQuery({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pull') }, { domain: ch.dnsDomain });
    const r4 = await udpQuery('udp4', craftQuery(q4), '127.0.0.1', port);
    const answer4 = decodeTxtAnswer(r4);
    assert.ok(answer4, 'udp4 still answers the governed wire');
    assert.equal(JSON.parse(b32decode(answer4).toString('utf8')).taskId, taskId);

    if (v6Armed) {
      // The udp6 wire: the SAME governed intake answers on ::1 (seq now at 2).
      const taskId2 = ch.task(agentId, 'shell', 'whoami');
      const q6 = encodeQuery({ a: agentId, s: 2, h: hmac(token, agentId + ':2:pull') }, { domain: ch.dnsDomain });
      const r6 = await udpQuery({ type: 'udp6', ipv6Only: true }, craftQuery(q6, 0x4242), '::1', port);
      assert.equal(r6.readUInt16BE(0), 0x4242, 'the v6 answer echoes the query id');
      const answer6 = decodeTxtAnswer(r6);
      assert.ok(answer6, 'udp6 answers the governed wire on ::1');
      assert.equal(JSON.parse(b32decode(answer6).toString('utf8')).taskId, taskId2);
      assert.ok(events.some((e) => e.type === 'agent.checkin' && e.remoteIp === '::1'), 'the v6 source address lands in the ledger');
    }
  } finally {
    await ch.disarm();
    await new Promise((r) => setTimeout(r, 75)); // win32 libuv teardown grace (dnstransport pattern)
  }
});

test('v6-only environment shape (bind ::1): udp4 is a NAMED gap, the arm survives on udp6', async () => {
  const port = await freePort();
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), dnsPort: port, bind: '::1' });
  try {
    await ch.arm(0); // must NOT die: one family unavailable = named gap, the other serves
    assert.ok(events.some((e) => e.type === 'dns.bind-gap' && e.family === 'udp4'), 'udp4 bind failure is a named gap');
    assert.ok(events.some((e) => e.type === 'channel.dns6-armed' && e.bind === '::1'), 'udp6 armed on the v6 bind');
    // The wire answers on ::1 — an unknown agent gets the uniform EMPTY answer (a valid
    // zero-answer packet, never an error): the governed shape, served over v6.
    const q = encodeQuery({ a: 'deadbeefdead', s: 1, h: 'x'.repeat(64) }, { domain: ch.dnsDomain });
    const r = await udpQuery({ type: 'udp6', ipv6Only: true }, craftQuery(q, 0x7777), '::1', port);
    assert.equal(r.readUInt16BE(0), 0x7777, 'a real response packet came back on the v6 wire');
    assert.equal(decodeTxtAnswer(r), '', 'uniform empty answer for a denied check-in — idle/deny parity on v6');
  } finally {
    if (ch.server) await ch.disarm();
    await new Promise((r) => setTimeout(r, 75));
  }
});

test('a specific v4 NIC bind never expands to ::: the no-honest-counterpart gap is NAMED, udp4 still serves', async () => {
  // A specific LOCAL non-loopback v4 address (skip honestly when the host has none).
  const nic = Object.values(os.networkInterfaces()).flat()
    .find((i) => i && i.family === 'IPv4' && !i.internal && i.address);
  if (!nic) { assert.ok(true, 'no non-loopback v4 NIC on this host — branch covered by the dnsV6Counterpart pure test'); return; }
  const port = await freePort();
  const events = [];
  const ch = new CallbackChannel({ scope: { ...SCOPE, cidrs: [...SCOPE.cidrs, nic.address + '/32'] }, onEvent: (t, o) => events.push({ type: t, ...o }), dnsPort: port, bind: nic.address });
  try {
    await ch.arm(0);
    assert.ok(events.some((e) => e.type === 'channel.dns-armed' && e.bind === nic.address), 'udp4 armed on the specific bind');
    assert.ok(!events.some((e) => e.type === 'channel.dns6-armed'), 'NO udp6 socket appeared');
    const gap = events.find((e) => e.type === 'dns.bind-gap' && e.family === 'udp6');
    assert.ok(gap && /no v6 counterpart/.test(gap.error), 'the gap is named — a specific v4 bind never silently exposes ::');
  } finally {
    if (ch.server) await ch.disarm();
    await new Promise((r) => setTimeout(r, 75));
  }
});

test('both families unavailable: the arm REFUSES (a DNS wire serving nothing is a lie) + both gaps named', async () => {
  const port = await freePort();
  // Occupy BOTH family binds so the channel's dual-bind has nowhere to land.
  const rogue4 = dgram.createSocket('udp4');
  await new Promise((res, rej) => { rogue4.once('error', rej); rogue4.bind(port, '127.0.0.1', res); });
  const rogue6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });
  const v6Held = await new Promise((res) => { rogue6.once('error', () => res(false)); rogue6.bind(port, '::1', () => res(true)); });
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), dnsPort: port, bind: '127.0.0.1' });
  try {
    await assert.rejects(() => ch.arm(0), /neither udp4 nor udp6 could bind/);
    assert.ok(events.some((e) => e.type === 'dns.bind-gap' && e.family === 'udp4'), 'udp4 gap named');
    assert.ok(events.some((e) => e.type === 'dns.bind-gap' && e.family === 'udp6'), 'udp6 gap named (held here, OS-unavailable on v6-less hosts)');
    assert.ok(!events.some((e) => e.type === 'channel.dns-armed') && !events.some((e) => e.type === 'channel.dns6-armed'), 'no armed event when nothing bound');
  } finally {
    if (ch.server) await ch.disarm(); // the http arm stays up on a refused DNS arm (today's shape) — clean it up
    try { rogue4.close(); } catch {}
    if (v6Held) { try { rogue6.close(); } catch {} }
    await new Promise((r) => setTimeout(r, 75));
  }
});

// Teardown grace: on win32, --test-force-exit can fire while dgram sockets are still
// closing after the last disarm (libuv UV_HANDLE_CLOSING assert). Same guard as
// dnstransport/callback-v2 — generous on purpose under suite CPU contention.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
