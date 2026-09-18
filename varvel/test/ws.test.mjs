// ws.test.mjs - gap#4: WebSocket PUSH C2 transport (RFC 6455 upgrade on the channel's
// EXISTING http server). Hermetic: loopback only, ephemeral ports, the REAL upgrade
// path. The test client is a raw net.Socket speaking the channel's own wsframe codec
// (client frames masked, parsed with WsParser) - zero deps, same harness style as
// doh.test.mjs / transportfail.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import { CallbackChannel } from '../engine/callback.mjs';
import { WsParser, WsError, buildFrame, acceptKey, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, OP_CONT } from '../engine/wsframe.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');

async function armed(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, port: ch.port, events };
}

async function waitFor(fn, timeoutMs = 2000) {
  const start = Date.now();
  while (!fn()) {
    if (Date.now() - start > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 15));
  }
  return true;
}

// Minimal RFC 6455 client over a raw socket: manual upgrade request, then frames via
// the channel's OWN codec (masked client side - the channel's parser enforces masking).
// ready resolves to the HTTP status (101 or a denial 403; 0 on a 3s no-response).
function wsClient(port, query) {
  const messages = [];
  const parser = new WsParser(); // server->client frames are unmasked
  let closed = false;
  const sock = net.connect(port, '127.0.0.1');
  sock.on('error', () => {});
  sock.on('close', () => { closed = true; });
  let pre = Buffer.alloc(0);
  let handshook = false;
  const ready = new Promise((resolve) => {
    const timer = setTimeout(() => resolve(0), 3000);
    const feed = (buf) => {
      let frames;
      try { frames = parser.feed(buf); } catch { return; }
      for (const f of frames) messages.push(f);
    };
    sock.on('data', (d) => {
      if (!handshook) {
        pre = Buffer.concat([pre, d]);
        const idx = pre.indexOf('\r\n\r\n');
        if (idx < 0) return;
        const head = pre.slice(0, idx).toString('latin1');
        const status = Number((head.split('\r\n')[0] || '').split(/\s+/)[1]) || 0;
        handshook = true;
        const rest = pre.slice(idx + 4);
        clearTimeout(timer);
        resolve(status);
        if (rest.length) feed(rest); // flushed frames can ride the handshake's segment
        return;
      }
      feed(d);
    });
    sock.on('connect', () => {
      sock.write('GET /ws?' + query + ' HTTP/1.1\r\nhost: 127.0.0.1\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-key: ' + crypto.randomBytes(16).toString('base64') + '\r\nsec-websocket-version: 13\r\n\r\n');
    });
  });
  const send = (obj) => {
    const payload = Buffer.isBuffer(obj) ? obj : Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj), 'utf8');
    sock.write(buildFrame({ opcode: OP_TEXT, payload, mask: true }));
  };
  const sendRaw = (buf) => sock.write(buf);
  const next = async (timeoutMs = 2000) => {
    const start = Date.now();
    while (!messages.length) {
      if (Date.now() - start > timeoutMs) return null;
      await new Promise((r) => setTimeout(r, 10));
    }
    return messages.shift();
  };
  const close = () => { try { sock.destroy(); } catch {} };
  return { ready, send, sendRaw, next, close, isClosed: () => closed };
}

// ---------------- frame codec unit tests (engine/wsframe) ----------------
test('wsframe: accept-key matches the RFC 6455 worked example', () => {
  assert.equal(acceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
});

test('wsframe: build/parse round trip, unmasked server shape', () => {
  const f = buildFrame({ opcode: OP_TEXT, payload: Buffer.from('{"taskId":"x"}') });
  assert.equal(f[0], 0x80 | OP_TEXT);
  assert.equal(f[1] & 0x80, 0, 'server frames are never masked');
  const out = new WsParser().feed(f);
  assert.equal(out.length, 1);
  assert.equal(out[0].opcode, OP_TEXT);
  assert.equal(out[0].fin, true);
  assert.equal(out[0].payload.toString('utf8'), '{"taskId":"x"}');
});

test('wsframe: masked client frames unmask correctly; unmasked client frames are rejected (expectMask)', () => {
  const payload = Buffer.from('client says hi');
  const f = buildFrame({ opcode: OP_TEXT, payload, mask: true });
  assert.ok(f[1] & 0x80, 'mask bit on the wire');
  assert.notDeepEqual(f.subarray(6), payload, 'the wire bytes are the masked form, never plaintext');
  const out = new WsParser({ expectMask: true }).feed(f);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].payload, payload);
  // fail-closed half: an unmasked frame on a server-side parser is a typed violation
  assert.throws(() => new WsParser({ expectMask: true }).feed(buildFrame({ opcode: OP_TEXT, payload: Buffer.from('x') })), WsError);
});

test('wsframe: 126/127 extended lengths (and non-minimal encodings are rejected)', () => {
  const p126 = crypto.randomBytes(300);
  const f126 = buildFrame({ opcode: OP_BINARY, payload: p126 });
  assert.equal(f126[1] & 0x7f, 126);
  assert.equal(f126.readUInt16BE(2), 300);
  assert.deepEqual(new WsParser().feed(f126)[0].payload, p126);

  const p127 = crypto.randomBytes(70000);
  const f127 = buildFrame({ opcode: OP_BINARY, payload: p127 });
  assert.equal(f127[1] & 0x7f, 127);
  assert.equal(Number(f127.readBigUInt64BE(2)), 70000);
  assert.deepEqual(new WsParser().feed(f127)[0].payload, p127);

  // non-minimal: a 126 header carrying length 5 is a protocol violation, fail-closed
  assert.throws(() => new WsParser().feed(Buffer.from([0x82, 126, 0, 5, 1, 2, 3, 4, 5])), WsError);
});

test('wsframe: streaming - a frame split across arbitrary TCP chunks completes exactly once', () => {
  const parser = new WsParser({ expectMask: true });
  const f = buildFrame({ opcode: OP_TEXT, payload: Buffer.from('streamed across chunks'), mask: true });
  let yielded = [];
  for (let i = 0; i < f.length; i++) yielded = yielded.concat(parser.feed(f.subarray(i, i + 1)));
  assert.equal(yielded.length, 1, 'one frame, one message - no matter how TCP sliced it');
  assert.equal(yielded[0].payload.toString('utf8'), 'streamed across chunks');
  // and two frames in ONE chunk yield two messages, in order
  const two = Buffer.concat([buildFrame({ opcode: OP_TEXT, payload: Buffer.from('a'), mask: true }), buildFrame({ opcode: OP_TEXT, payload: Buffer.from('b'), mask: true })]);
  assert.deepEqual(new WsParser({ expectMask: true }).feed(two).map((m) => m.payload.toString('utf8')), ['a', 'b']);
});

test('wsframe: fragmentation reassembles by opcode; interleaved control frames surface in order', () => {
  const parser = new WsParser();
  const f1 = buildFrame({ opcode: OP_TEXT, payload: Buffer.from('Hello '), fin: false });
  const ping = buildFrame({ opcode: OP_PING, payload: Buffer.from('hb') });
  const f2 = buildFrame({ opcode: OP_CONT, payload: Buffer.from('wor'), fin: false });
  const f3 = buildFrame({ opcode: OP_CONT, payload: Buffer.from('ld') });
  const out = parser.feed(Buffer.concat([f1, ping, f2, f3]));
  assert.equal(out.length, 2);
  assert.equal(out[0].opcode, OP_PING, 'the interleaved control frame surfaces immediately, in arrival order');
  assert.equal(out[1].opcode, OP_TEXT, 'the reassembled message keeps the FIRST fragment opcode');
  assert.equal(out[1].payload.toString('utf8'), 'Hello world');
  // continuation without an open message: violation
  assert.throws(() => new WsParser().feed(buildFrame({ opcode: OP_CONT, payload: Buffer.from('x') })), WsError);
  // a new data frame while a fragmented message is still open: violation
  const p = new WsParser();
  p.feed(buildFrame({ opcode: OP_TEXT, payload: Buffer.from('open'), fin: false }));
  assert.throws(() => p.feed(buildFrame({ opcode: OP_TEXT, payload: Buffer.from('nested') })), WsError);
});

test('wsframe: ping->pong and close frame shapes', () => {
  const ping = new WsParser().feed(buildFrame({ opcode: OP_PING, payload: Buffer.from('x1') }))[0];
  assert.equal(ping.opcode, OP_PING);
  // the only legal answer to a ping: a pong carrying the identical payload
  const pong = new WsParser().feed(buildFrame({ opcode: OP_PONG, payload: ping.payload }))[0];
  assert.equal(pong.opcode, OP_PONG);
  assert.equal(pong.payload.toString('utf8'), 'x1');
  const status = Buffer.alloc(2);
  status.writeUInt16BE(1000, 0);
  const close = new WsParser().feed(buildFrame({ opcode: OP_CLOSE, payload: status }))[0];
  assert.equal(close.opcode, OP_CLOSE);
  assert.equal(close.payload.readUInt16BE(0), 1000);
});

test('wsframe: protocol violations are typed WsErrors (fail-closed)', () => {
  assert.throws(() => new WsParser().feed(Buffer.from([0xC1, 0x00])), WsError);   // RSV1 set
  assert.throws(() => new WsParser().feed(Buffer.from([0x83, 0x00])), WsError);   // reserved opcode 0x3
  assert.throws(() => new WsParser().feed(buildFrame({ opcode: OP_PING, payload: Buffer.alloc(0), fin: false })), WsError); // fragmented control
  assert.throws(() => new WsParser().feed(buildFrame({ opcode: OP_PING, payload: Buffer.alloc(126) })), WsError);           // control payload > 125
  try {
    new WsParser().feed(Buffer.from([0xC1, 0x00]));
    assert.unreachable('RSV violation must throw');
  } catch (e) {
    assert.ok(e instanceof WsError);
    assert.equal(e.code, 1002, 'protocol-error close status');
  }
  // over-cap frame carries the 1009 (message too big) close status
  assert.throws(() => new WsParser({ maxFrame: 32 }).feed(buildFrame({ opcode: OP_BINARY, payload: Buffer.alloc(64) })), (e) => e instanceof WsError && e.code === 1009);
});

// ---------------- channel e2e over the REAL upgrade path ----------------
test('ws e2e: valid handshake -> 101; the connection itself is a tagged ws check-in', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-hello' });
    const c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    const view = ch.agentsView()[0];
    assert.equal(view.transportCheckins.ws, 1, 'the handshake counts as a ws check-in');
    assert.equal(view.lastTransport, 'ws');
    assert.ok(view.transportLastSeen.ws > 0);
    assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'ws' && e.agentId === agentId));
    assert.ok(events.some((e) => e.type === 'agent.ws-open' && e.agentId === agentId));
    assert.equal(view.transportGrade.perTransport.ws.health, 'healthy', 'ws is a first-class graded transport');
    c.close();
  } finally { await ch.disarm(); }
});

test('ws e2e: a queued task arrives as a frame WITHOUT any pull (faster than any poll cadence)', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-push' });
    const c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    const t0 = Date.now();
    const taskId = ch.task(agentId, 'note', 'hello-ws');
    const f = await c.next(2000);
    const dt = Date.now() - t0;
    assert.ok(f, 'the task frame arrived with NO pull request at all');
    assert.ok(dt < 1500, 'delivered in ' + dt + 'ms - instant queue->frame, no poll cadence (the point of the transport)');
    assert.equal(f.opcode, OP_TEXT);
    assert.deepEqual(JSON.parse(f.payload.toString('utf8')), { taskId, kind: 'note', data: 'hello-ws' });
    assert.ok(events.some((e) => e.type === 'task.delivered' && e.transport === 'ws' && e.taskId === taskId));
    assert.equal(ch.tasksView(agentId).find((t) => t.taskId === taskId).status, 'delivered');
    c.close();
  } finally { await ch.disarm(); }
});

test('ws e2e: tasks queued while off-wire flush as frames on connect', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-flush' });
    const t1 = ch.task(agentId, 'note', 'one');
    const t2 = ch.task(agentId, 'note', 'two');
    const c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    const f1 = await c.next(1000);
    const f2 = await c.next(1000);
    assert.ok(f1 && f2, 'both queued tasks flushed immediately after the handshake');
    assert.deepEqual([JSON.parse(f1.payload.toString('utf8')).taskId, JSON.parse(f2.payload.toString('utf8')).taskId], [t1, t2], 'queue order preserved');
    assert.equal(ch.agentsView()[0].pendingTasks, 0);
    c.close();
  } finally { await ch.disarm(); }
});

test('ws e2e: agent-shaped push frames (single + 32KB-style chunked) land in results()', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-result' });
    const c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    const taskId1 = ch.task(agentId, 'note', 'one');
    const taskId2 = ch.task(agentId, 'note', 'two');
    assert.ok(await c.next(1000) && await c.next(1000), 'both task frames delivered (push, no pull)');
    // single-frame push (small body) - the SAME object shape as a dns-codec push query
    const body1 = 'WIN-RANGE-11-ws';
    const d1 = Buffer.from(body1, 'utf8').toString('base64');
    c.send({ a: agentId, s: 2, h: hmac(token, [agentId, 2, taskId1, 0, 1, d1].join(':')), t: taskId1, k: 'push', i: 0, n: 1, d: d1 });
    // chunked push: a >32KB body rides the governed {k:'push',t,i,n,d} chunk shape.
    // Chunk split at 30000: a multiple of 3 - per-chunk base64 bodies are joined and
    // decoded as one string by the intake, so non-final chunks must be 3-byte aligned
    // (the agent chunks at 32766 for the same reason; dns-push uses 96).
    const body2 = 'B'.repeat(40000);
    const b2 = Buffer.from(body2, 'utf8');
    const c0 = b2.subarray(0, 30000).toString('base64');
    const c1 = b2.subarray(30000).toString('base64');
    c.send({ a: agentId, s: 3, h: hmac(token, [agentId, 3, taskId2, 0, 2, c0].join(':')), t: taskId2, k: 'push', i: 0, n: 2, d: c0 });
    c.send({ a: agentId, s: 4, h: hmac(token, [agentId, 4, taskId2, 1, 2, c1].join(':')), t: taskId2, k: 'push', i: 1, n: 2, d: c1 });
    assert.ok(await waitFor(() => ch.agents.get(agentId).results.length === 2), 'both results landed via the shared intake');
    const res1 = ch.results(agentId, { taskId: taskId1 });
    const res2 = ch.results(agentId, { taskId: taskId2 });
    assert.equal(res1[0].data, body1);
    assert.equal(res2[0].data, body2, 'chunked body reassembled byte-exact');
    assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'ws' && e.taskId === taskId1));
    assert.ok(ch.agentsView()[0].transportCheckins.ws >= 4, 'handshake + every accepted push frame tagged the ws bucket');
    c.close();
  } finally { await ch.disarm(); }
});

test('ws e2e: setTransport rides a task frame; active flips ONLY on the next inbound ws frame', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-assign' });
    const c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    const asg = ch.setTransport(agentId, 'ws');
    assert.equal(asg.state, 'assigned');
    const tid = ch.task(agentId, 'note', 'ride');
    const f = await c.next(1000);
    assert.equal(JSON.parse(f.payload.toString('utf8')).setTransport, 'ws', 'the switch request rides the task frame (same shape as pull replies)');
    assert.equal(ch.agentsView()[0].assignedTransport.state, 'assigned', 'delivery never flips the lifecycle');
    // an observed inbound ws frame is the ONLY thing that flips assigned -> active
    const d = Buffer.from('ack', 'utf8').toString('base64');
    c.send({ a: agentId, s: 2, h: hmac(token, [agentId, 2, tid, 0, 1, d].join(':')), t: tid, k: 'push', i: 0, n: 1, d });
    assert.ok(await waitFor(() => ch.agentsView()[0].assignedTransport.state === 'active'));
    assert.ok(events.some((e) => e.type === 'agent.transport-active' && e.transport === 'ws'));
    c.close();
  } finally { await ch.disarm(); }
});

test('ws e2e: bad HMAC / unknown agent / stale seq / killed -> observable 403 + socket end', async () => {
  // Documented denial shape: ws denial is the http-family observable 403, NOT the dns
  // wire's zero-answer camouflage. (Out-of-scope silent-destroy cannot be exercised on
  // loopback - ipAllowed() always admits loopback, same constraint as the doh tests.)
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-deny' });
    let c = wsClient(port, 'a=' + agentId + '&s=1&h=' + '0'.repeat(64));
    assert.equal(await c.ready, 403, 'bad HMAC -> 403');
    c = wsClient(port, 'a=deadbeefcafe&s=1&h=' + '0'.repeat(64));
    assert.equal(await c.ready, 403, 'unknown agent -> 403');
    // a GOOD handshake consumes seq 1; replaying it is a stale-seq 403 (replay protection)
    c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    c.close();
    c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 403, 'replayed handshake seq -> 403');
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'stale-seq'));
    ch.kill(agentId);
    c = wsClient(port, 'a=' + agentId + '&s=2&h=' + hmac(token, agentId + ':2:ws'));
    assert.equal(await c.ready, 403, 'killed agent -> 403');
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'killed-agent'));
  } finally { await ch.disarm(); }
});

test('ws e2e: ping gets a verbatim pong; an unmasked client frame is fail-closed', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-ctrl' });
    const c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    c.sendRaw(buildFrame({ opcode: OP_PING, payload: Buffer.from('alive?'), mask: true }));
    const f = await c.next(1000);
    assert.equal(f.opcode, OP_PONG, 'the wire answers a ping with a pong - the only control exchange it speaks (no heartbeat exists)');
    assert.equal(f.payload.toString('utf8'), 'alive?');
    // RFC violation: client frames MUST mask - the channel drops the session, fail-closed
    c.sendRaw(buildFrame({ opcode: OP_TEXT, payload: Buffer.from('{}'), mask: false }));
    assert.ok(await waitFor(() => c.isClosed()), 'protocol violation closed the session');
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'ws-protocol'));
    assert.ok(events.some((e) => e.type === 'agent.ws-close' && e.reason === 'protocol-violation'));
  } finally { await ch.disarm(); }
});

test('ws e2e: socket death clears da._ws - new tasks stay QUEUED, then flush on reconnect', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-drop' });
    const c = wsClient(port, 'a=' + agentId + '&s=1&h=' + hmac(token, agentId + ':1:ws'));
    assert.equal(await c.ready, 101);
    c.close();
    assert.ok(await waitFor(() => events.some((e) => e.type === 'agent.ws-close')), 'the channel observed the socket death');
    const taskId = ch.task(agentId, 'note', 'queued-while-dead');
    assert.equal(ch.tasksView(agentId).find((t) => t.taskId === taskId).status, 'queued', 'dead socket: queued, never silently consumed');
    const c2 = wsClient(port, 'a=' + agentId + '&s=2&h=' + hmac(token, agentId + ':2:ws'));
    assert.equal(await c2.ready, 101);
    const f = await c2.next(1000);
    assert.equal(JSON.parse(f.payload.toString('utf8')).taskId, taskId, 'the reconnect flushed the backlog');
    c2.close();
  } finally { await ch.disarm(); }
});

test('ws e2e: plain /c traffic is untouched by the upgrade listener; non-/ws upgrades are destroyed', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ws-coexist' });
    const r = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull') } });
    assert.equal(r.status, 204, 'plain http check-in unaffected on the same server');
    const got = await new Promise((resolve) => {
      const sock = net.connect(port, '127.0.0.1', () => {
        sock.write('GET /c HTTP/1.1\r\nhost: x\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-key: ' + crypto.randomBytes(16).toString('base64') + '\r\nsec-websocket-version: 13\r\n\r\n');
      });
      let data = Buffer.alloc(0);
      sock.on('data', (d) => { data = Buffer.concat([data, d]); });
      sock.on('error', () => {});
      sock.on('close', () => resolve(data.length));
      setTimeout(() => { try { sock.destroy(); } catch {} }, 1500);
    });
    assert.equal(got, 0, 'non-/ws upgrade: destroyed with nothing parseable (nothing else consumes upgrades here)');
  } finally { await ch.disarm(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as dnstransport/transportfail/doh.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
