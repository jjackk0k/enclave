// doh.test.mjs - gap#2: DNS-over-HTTPS (RFC 8484) C2 transport. Hermetic: loopback only,
// ephemeral ports, the static lab cert (embedded PEM fixture, same pattern as ghost.test).
// The client is node:https with rejectUnauthorized:false; it still verifies the peer cert
// fingerprint against DOH_LAB_THUMBPRINT - the exact parity of the agent's TLS pin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import crypto from 'node:crypto';
import { CallbackChannel } from '../engine/callback.mjs';
import { encodeQuery, b32decode } from '../engine/dnscodec.mjs';
import { decodeTxtAnswer } from '../engine/dnswire.mjs';
import { DOH_LAB_THUMBPRINT } from '../engine/doh-labcert.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');

async function armedDoh(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), doh: { port: 0 }, ...extra });
  await ch.arm(0);
  return { ch, events, port: ch.dohStatus().port };
}

// The exact packet shape the agent's New-DnsQueryPacket builds: header + labels + TXT/IN.
function queryPacket(qname, id = 0x1234) {
  const labels = qname.split('.').filter(Boolean).map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'latin1')]));
  const head = Buffer.alloc(12);
  head.writeUInt16BE(id, 0);
  head.writeUInt16BE(0x0100, 2); // RD
  head.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(16, 0);     // TXT
  tail.writeUInt16BE(1, 2);      // IN
  return Buffer.concat([head, ...labels, Buffer.from([0]), tail]);
}
const pullPacket = (agentId, token, seq) => queryPacket(encodeQuery({ a: agentId, s: seq, h: hmac(token, agentId + ':' + seq + ':pull') }));

// Minimal DoH client: POST application/dns-message (primary) or GET ?dns=<base64url>.
function dohReq(port, { method = 'POST', packet, path = '/dns-query', contentType = 'application/dns-message' } = {}) {
  return new Promise((resolve, reject) => {
    const p = method === 'GET' ? path + '?dns=' + packet.toString('base64url') : path;
    const req = https.request({
      host: '127.0.0.1', port, path: p, method, rejectUnauthorized: false,
      headers: method === 'POST' ? { 'content-type': contentType, 'content-length': packet.length } : {},
    }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), cert: res.socket.getPeerCertificate() }));
    });
    req.on('error', reject);
    if (method === 'POST') req.write(packet);
    req.end();
  });
}

test('doh arm/status: lab cert source reported honestly; peer cert matches the agent pin', async () => {
  const { ch, port } = await armedDoh();
  try {
    const st = ch.dohStatus();
    assert.equal(st.configured, true);
    assert.equal(st.armed, true);
    assert.equal(st.port, port);
    assert.equal(st.certSource, 'lab');
    // an unconfigured channel says so plainly
    const plain = new CallbackChannel({ scope: SCOPE });
    assert.deepEqual(plain.dohStatus(), { configured: false });
    const { agentId, token } = ch.registerAgent({});
    const r = await dohReq(port, { packet: pullPacket(agentId, token, 1) });
    assert.equal((r.cert.fingerprint256 || '').replace(/:/g, ''), DOH_LAB_THUMBPRINT, 'the cert on the wire IS the pinned lab cert');
  } finally { await ch.disarm(); }
});

test('(a) idle pull: 200 application/dns-message, parses to zero answers', async () => {
  const { ch, events, port } = await armedDoh();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'doh-idle' });
    const r = await dohReq(port, { packet: pullPacket(agentId, token, 1) });
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'application/dns-message');
    assert.equal(r.body.readUInt16BE(6), 0, 'ANCOUNT 0 = the uniform idle shape');
    assert.equal(decodeTxtAnswer(r.body), '');
    // governed check-in observed + tagged on the doh bucket
    assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'doh' && e.agentId === agentId));
    const view = ch.agentsView()[0];
    assert.equal(view.transportCheckins.doh, 1);
    assert.equal(view.lastTransport, 'doh');
  } finally { await ch.disarm(); }
});

test('(b) task pull round-trip: the TXT answer decodes to the queued task', async () => {
  const { ch, events, port } = await armedDoh();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'doh-task' });
    const taskId = ch.task(agentId, 'note', 'hello-doh');
    const r = await dohReq(port, { packet: pullPacket(agentId, token, 1) });
    assert.equal(r.status, 200);
    assert.equal(r.body.readUInt16BE(6), 1, 'one TXT answer carries the task');
    // round-trip through the channel's own codec helpers (client side)
    const txt = decodeTxtAnswer(r.body);
    const task = JSON.parse(b32decode(txt).toString('utf8'));
    assert.equal(task.taskId, taskId);
    assert.equal(task.kind, 'note');
    assert.equal(task.data, 'hello-doh');
    assert.ok(events.some((e) => e.type === 'task.delivered' && e.transport === 'doh' && e.taskId === taskId));
    assert.equal(ch.tasksView(agentId).find((t) => t.taskId === taskId).status, 'delivered');
  } finally { await ch.disarm(); }
});

test('(c) push: a chunked result over doh lands in results()', async () => {
  const { ch, events, port } = await armedDoh();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'doh-push' });
    const taskId = ch.task(agentId, 'shell', 'hostname');
    const body = 'WIN-RANGE-11-doh';
    const d = Buffer.from(body, 'utf8').toString('base64');
    const s = 1;
    const payload = { a: agentId, s, h: hmac(token, [agentId, s, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d };
    const r = await dohReq(port, { packet: queryPacket(encodeQuery(payload)) });
    assert.equal(r.status, 200);
    assert.equal(r.body.readUInt16BE(6), 0, 'push gets the zero-answer shape (uniform with the UDP wire)');
    const res = ch.results(agentId);
    assert.equal(res.length, 1);
    assert.equal(res[0].taskId, taskId);
    assert.equal(res[0].data, body);
    assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'doh' && e.taskId === taskId));
  } finally { await ch.disarm(); }
});

test('(d) GET /dns-query?dns=<base64url> serves the same governed round trip', async () => {
  const { ch, port } = await armedDoh();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'doh-get' });
    const taskId = ch.task(agentId, 'note', 'get-shape');
    const r = await dohReq(port, { method: 'GET', packet: pullPacket(agentId, token, 1) });
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'application/dns-message');
    const task = JSON.parse(b32decode(decodeTxtAnswer(r.body)).toString('utf8'));
    assert.equal(task.taskId, taskId);
    assert.equal(task.data, 'get-shape');
  } finally { await ch.disarm(); }
});

test('(e) malformed packet: 400 JSON, no crash, the channel keeps serving', async () => {
  const { ch, port } = await armedDoh();
  try {
    const r = await dohReq(port, { packet: Buffer.from('not-a-dns-packet-at-all') });
    assert.equal(r.status, 400);
    assert.equal(r.headers['content-type'], 'application/json');
    assert.ok(JSON.parse(r.body.toString('utf8')).error);
    // wrong content-type is a 400 too, never a crash
    const { agentId, token } = ch.registerAgent({});
    const r2 = await dohReq(port, { packet: pullPacket(agentId, token, 1), contentType: 'text/plain' });
    assert.equal(r2.status, 400);
    // and a well-formed pull right after still answers 200
    const r3 = await dohReq(port, { packet: pullPacket(agentId, token, 1) });
    assert.equal(r3.status, 200);
    assert.equal(r3.body.readUInt16BE(6), 0);
  } finally { await ch.disarm(); }
});

test('(f) unknown/out-of-scope agent: 200 zero-answer (denial is indistinguishable from idle)', async () => {
  const { ch, port } = await armedDoh();
  try {
    const ghost = { agentId: 'deadbeefcafe', token: 'ab'.repeat(16) };
    const r = await dohReq(port, { packet: pullPacket(ghost.agentId, ghost.token, 1) });
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'application/dns-message');
    assert.equal(r.body.readUInt16BE(6), 0, 'denied == idle to an observer');
    assert.equal(decodeTxtAnswer(r.body), '');
    // and the fleet shows nothing for the ghost
    assert.equal(ch.agentsView().length, 0);
  } finally { await ch.disarm(); }
});

test('(g) any other route on the DoH server: 404', async () => {
  const { ch, port } = await armedDoh();
  try {
    for (const path of ['/', '/c', '/dns-query/extra', '/favicon.ico']) {
      const r = await dohReq(port, { method: 'GET', packet: queryPacket('x.ax.sim'), path });
      assert.equal(r.status, 404, path + ' -> 404');
      assert.ok(JSON.parse(r.body.toString('utf8')).error);
    }
  } finally { await ch.disarm(); }
});

test('channel-assigned switch accepts doh end to end (setTransport key on the task reply)', async () => {
  const { ch, port } = await armedDoh();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'doh-assign' });
    const asg = ch.setTransport(agentId, 'doh');
    assert.equal(asg.transport, 'doh');
    assert.equal(asg.state, 'assigned');
    ch.task(agentId, 'note', 'x');
    const r = await dohReq(port, { packet: pullPacket(agentId, token, 1) });
    const task = JSON.parse(b32decode(decodeTxtAnswer(r.body)).toString('utf8'));
    assert.equal(task.setTransport, 'doh', 'the switch request rides the non-empty task reply');
    // the observed doh check-in flips assigned -> active (the only way it can)
    assert.equal(ch.agentsView()[0].assignedTransport.state, 'active');
  } finally { await ch.disarm(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as dnstransport/transportfail.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
