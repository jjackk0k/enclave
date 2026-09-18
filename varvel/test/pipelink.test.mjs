// pipelink.test.mjs — the pivot-mesh SMB LINK transport (gap #4b). Hermetic: real Windows
// named pipes on loopback (\\.\pipe\...), a REAL CallbackChannel on 127.0.0.1, and REAL
// SimAgents for the parent + child roles. No raw sockets, no privileges, no services
// touched. House pattern follows ws.test.mjs / icmpbridge.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  LINK_VERSION, MAX_FRAME, PipeLinkError, canonical, validLinkId, pipeNameFor,
  deriveVerifyKey, encodeFrame, FrameParser, LinkSession, ChildLink, ParentLinkHub,
} from '../engine/pipelink.mjs';
import { PipeServer, PipeClient, PipeTransport } from '../agents/pipeendpoint.mjs';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const tick = (ms = 15) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, timeoutMs = 3000) {
  const start = Date.now();
  while (!fn()) {
    if (Date.now() - start > timeoutMs) return false;
    await new Promise((r) => setTimeout(r, 15));
  }
  return true;
}

// A fresh pipe name per test — the OS pipe namespace is global, so tests never collide.
let pipeSeq = 0;
const freshLink = () => 't' + (pipeSeq++).toString(16).padStart(3, '0') + crypto.randomBytes(3).toString('hex');

// ---------------- pure codec: framing ----------------
test('pipelink frame: length-prefixed round trip, stream-splitting, multi-frame chunks', () => {
  const f1 = encodeFrame({ t: 'up', s: 1, m: 'a'.repeat(64), p: { a: 'x' } });
  assert.equal(f1.readUInt32LE(0), f1.length - 4);
  const f2 = encodeFrame({ t: 'down', s: 1, m: 'b'.repeat(64), p: '' });
  // split at every possible byte boundary — a frame completes exactly once
  const wire = Buffer.concat([f1, f2]);
  for (const cut of [1, 3, 4, 5, f1.length - 1, f1.length, f1.length + 2, wire.length - 1]) {
    const p = new FrameParser();
    const out = [...p.feed(wire.subarray(0, cut)), ...p.feed(wire.subarray(cut))];
    assert.equal(out.length, 2, 'cut at ' + cut);
    assert.equal(out[0].t, 'up');
    assert.equal(out[1].t, 'down');
  }
});

test('pipelink frame: fail-closed on impossible length, non-JSON, untyped body', () => {
  const bad = Buffer.alloc(4); bad.writeUInt32LE(MAX_FRAME + 1, 0);
  assert.throws(() => new FrameParser().feed(bad), PipeLinkError);
  const zero = Buffer.alloc(4);
  assert.throws(() => new FrameParser().feed(zero), PipeLinkError);
  const notJson = Buffer.alloc(4); notJson.writeUInt32LE(3, 0);
  assert.throws(() => new FrameParser().feed(Buffer.concat([notJson, Buffer.from('xyz')])), PipeLinkError);
  const noType = encodeFrame({ no: 'type' });
  assert.throws(() => new FrameParser().feed(noType), /type/);
  assert.throws(() => encodeFrame({ big: 'x'.repeat(MAX_FRAME) }), PipeLinkError);
});

// ---------------- pure codec: identity + handshake + chain ----------------
test('pipelink ids: governed pipe namespace + link-scoped verify key derivation', () => {
  assert.ok(validLinkId('ab12cd34'));
  assert.ok(!validLinkId('') && !validLinkId('x') && !validLinkId('HAS-UPPER') && !validLinkId('a'.repeat(25)));
  assert.equal(pipeNameFor('ab12cd34'), 'varvel_link_ab12cd34');
  assert.throws(() => pipeNameFor('nope!'), PipeLinkError);
  const k1 = deriveVerifyKey('tokenA', 'link0001');
  const k2 = deriveVerifyKey('tokenA', 'link0002');
  const k3 = deriveVerifyKey('tokenB', 'link0001');
  assert.match(k1, /^[0-9a-f]{64}$/);
  assert.notEqual(k1, k2, 'the key is link-scoped');
  assert.notEqual(k1, k3, 'the key is token-bound');
});

test('pipelink handshake: hello/welcome authenticates BOTH ends from a derived key', () => {
  const token = crypto.randomBytes(16).toString('hex');
  const linkId = freshLink();
  const hub = new ParentLinkHub({ linkId, children: { child01: deriveVerifyKey(token, linkId) } });
  const child = new ChildLink({ linkId, agentId: 'child01', token });
  const hello = child.makeHello();
  assert.equal(hello.t, 'hello');
  assert.equal(hello.v, LINK_VERSION);
  const { session, welcome } = hub.acceptHello(hello);
  assert.ok(session && welcome.t === 'welcome');
  assert.equal(child.acceptWelcome(welcome), true, 'the child verified the parent knows the key');
  // a wrong-token child (bad verify key) is refused; an unenrolled id is refused
  const evil = new ChildLink({ linkId, agentId: 'child01', token: crypto.randomBytes(16).toString('hex') });
  assert.throws(() => hub.acceptHello(evil.makeHello()), /mac mismatch/);
  const stranger = new ChildLink({ linkId, agentId: 'strange', token });
  assert.throws(() => hub.acceptHello(stranger.makeHello()), /not enrolled/);
  // a welcome from a key-holder-less "parent" fails the child
  const { welcome: goodWelcome } = hub.acceptHello(child.makeHello());
  const forged = { ...goodWelcome, h: '0'.repeat(64) };
  assert.throws(() => child.acceptWelcome(forged), /welcome mac mismatch/);
  // the hub NEVER saw the child token: it holds only the derivative
  assert.notEqual(hub._children.get('child01'), token);
});

test('pipelink chain: sequenced HMAC-chained data frames both directions; replay/forgery fail closed', () => {
  const token = crypto.randomBytes(16).toString('hex');
  const linkId = freshLink();
  const hub = new ParentLinkHub({ linkId, children: { c1: deriveVerifyKey(token, linkId) } });
  const child = new ChildLink({ linkId, agentId: 'c1', token, nonce: 'a'.repeat(16) });
  const { session } = hub.acceptHello(child.makeHello());

  const payload = { a: 'c1', s: 1, h: 'deadbeef' };
  const up1 = child.sealUp(payload);
  const up2 = child.sealUp({ a: 'c1', s: 2, h: 'cafe' });
  assert.equal(up1.s, 1);
  assert.equal(up2.s, 2);
  assert.notEqual(up1.m, up2.m, 'the chain advances');
  assert.deepEqual(session.openUp(up1), payload);
  session.openUp(up2);
  // REPLAY: frame 1 again -> seq violation
  assert.throws(() => session.openUp(up1), /seq 1 is not the expected 3/);
  // FORGERY: a tampered payload breaks the chain mac
  const forged = { ...up2, s: 3, p: { a: 'c1', s: 2, h: 'owned' } };
  assert.throws(() => session.openUp(forged), /chain mac mismatch/);
  // down direction is an independent chain
  const d1 = session.sealDown('reply-one');
  assert.equal(child.openDown(d1), 'reply-one');
  const d2 = session.sealDown('');
  assert.equal(child.openDown(d2), '', 'the idle/deny empty reply is a legal down payload');
  // wrong direction / wrong type refused
  assert.throws(() => child.openDown(up1), PipeLinkError);
  // canonical(): key order does not matter to the chain
  const a1 = child.sealUp({ x: 1, y: 2 });
  const reordered = { t: 'up', v: LINK_VERSION, s: a1.s, m: a1.m, p: JSON.parse('{"y":2,"x":1}') };
  assert.deepEqual(session.openUp(reordered), { x: 1, y: 2 }, 'reordered keys verify identically');
});

test('pipelink death: isDead inactivity predicate + hub reap; reconnect replaces the stale session', () => {
  const token = crypto.randomBytes(16).toString('hex');
  const linkId = freshLink();
  const events = [];
  const hub = new ParentLinkHub({ linkId, children: { c1: deriveVerifyKey(token, linkId) }, onEvent: (t, o) => events.push({ type: t, ...o }), linkTimeoutMs: 1000 });
  const child = new ChildLink({ linkId, agentId: 'c1', token, nonce: 'b'.repeat(16) });
  const { session } = hub.acceptHello(child.makeHello(), { now: 1000 });
  assert.equal(session.isDead(1500, 1000), false);
  assert.equal(session.isDead(2500, 1000), true, 'silent past the timeout = dead');
  assert.deepEqual(hub.reapDead({ now: 2500 }), ['c1']);
  assert.ok(events.some((e) => e.type === 'link.dead' && e.child === 'c1'));
  // reconnect: a fresh hello REPLACES the stale session (audited)
  const child2 = new ChildLink({ linkId, agentId: 'c1', token, nonce: 'c'.repeat(16) });
  const { session: s2 } = hub.acceptHello(child2.makeHello(), { now: 3000 });
  assert.notEqual(s2.nonce, session.nonce);
  assert.ok(events.some((e) => e.type === 'link.up'));
});

// ---------------- stage 2: real named pipes on loopback ----------------
test('pipe endpoints: hello + relayed round trips over a REAL \\\\.\\pipe, byte-exact chain', async () => {
  const token = crypto.randomBytes(16).toString('hex');
  const linkId = freshLink();
  const seen = [];
  const server = new PipeServer({
    linkId,
    children: { childX: deriveVerifyKey(token, linkId) },
    relayUp: async (payload) => { seen.push(payload); return 'reply:' + JSON.stringify(payload); },
  });
  await server.listen();
  try {
    const client = new PipeClient({ linkId, agentId: 'childX', token });
    await client.connect();
    const r1 = await client.roundTrip({ a: 'childX', s: 1, h: 'h1' });
    assert.match(r1, /^reply:/);
    const r2 = await client.roundTrip({ a: 'childX', s: 2, h: 'h2' });
    assert.ok(r2.length > r1.length - 2);
    assert.equal(seen.length, 2, 'the parent relayed both payloads');
    assert.deepEqual(seen[0], { a: 'childX', s: 1, h: 'h1' });
    const st = server.status();
    assert.equal(st.connections, 1);
    assert.equal(st.relayed, 2);
    assert.equal(st.sessions[0].up, 2);
    assert.equal(st.sessions[0].down, 2);
    await client.close();
    assert.ok(await waitFor(() => server.status().connections === 0), 'bye torn the session down');
  } finally { await server.close(); }
});

test('pipe endpoints: bad hello is refused and killed; a forged chain frame kills the connection', async () => {
  const token = crypto.randomBytes(16).toString('hex');
  const linkId = freshLink();
  const events = [];
  const server = new PipeServer({
    linkId,
    children: { good: deriveVerifyKey(token, linkId) },
    relayUp: async () => 'ok',
    onEvent: (t, o) => events.push({ type: t, ...o }),
  });
  await server.listen();
  try {
    // wrong token -> hello mac mismatch -> connection destroyed, audited
    const bad = new PipeClient({ linkId, agentId: 'good', token: crypto.randomBytes(16).toString('hex'), timeout: 1200 });
    await assert.rejects(() => bad.connect(), /timeout|closed|mac/);
    assert.ok(await waitFor(() => events.some((e) => e.type === 'link.hello-denied')), 'hello denial audited');
    // a valid handshake, then a forged frame -> fail-closed kill
    const good = new PipeClient({ linkId, agentId: 'good', token });
    await good.connect();
    good._sock.write(encodeFrame({ t: 'up', v: LINK_VERSION, s: 1, m: '0'.repeat(64), p: { forged: true } }));
    assert.ok(await waitFor(() => events.some((e) => e.type === 'link.error' && e.code === 'chain')), 'chain violation audited');
    assert.ok(await waitFor(() => good.dead), 'the forged connection is dead');
  } finally { await server.close(); }
});

test('PipeTransport: pull/push round-trip through a relay stub with the governed payload shapes', async () => {
  const token = crypto.randomBytes(16).toString('hex');
  const linkId = freshLink();
  const agentId = 'childT';
  const intake = [];
  // a relay stub that mimics the listener: pull seq1 -> a task reply (b32), pushes -> ''
  const { b32encode } = await import('../engine/dnscodec.mjs');
  const server = new PipeServer({
    linkId,
    children: { [agentId]: deriveVerifyKey(token, linkId) },
    relayUp: async (p) => {
      intake.push(p);
      if (!p.k) {
        assert.equal(p.h, hmac(token, agentId + ':' + p.s + ':pull'), 'the INNER payload HMAC is end-to-end child->listener');
        return b32encode(Buffer.from(JSON.stringify({ taskId: 'task-1', kind: 'note', data: 'via-pipe' })));
      }
      return '';
    },
  });
  await server.listen();
  try {
    const t = new PipeTransport({ linkId, agentId, token });
    await t.connect();
    const task = await t.pull();
    assert.deepEqual(task, { taskId: 'task-1', kind: 'note', data: 'via-pipe' });
    await t.push('task-1', 'x'.repeat(9000)); // > PIPE_PUSH_CHUNK: chunked push frames
    const pushes = intake.filter((p) => p.k === 'push');
    assert.equal(pushes.length, 3, '9000 bytes = 4092+4092+816 over three chained frames');
    for (const p of pushes) {
      assert.equal(p.h, hmac(token, [agentId, p.s, 'task-1', p.i, p.n, p.d].join(':')), 'per-chunk HMAC intact through the link');
    }
    await t.close();
  } finally { await server.close(); }
});

// ---------------- stage 4: the channel relay, hermetic end-to-end ----------------
async function armedChannel(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, port: ch.port, events };
}

test('enrollment: registerLinkedAgent issues governed creds + tasks the parent (merge on same link)', async () => {
  const { ch, events } = await armedChannel();
  try {
    const parent = ch.registerAgent({ label: 'parent' });
    const e1 = ch.registerLinkedAgent({ parentId: parent.agentId, label: 'child-1' });
    assert.ok(e1.agentId && e1.token, 'the child gets the SAME class of credential as a direct agent');
    assert.ok(validLinkId(e1.link.linkId));
    assert.equal(e1.link.pipe, 'varvel_link_' + e1.link.linkId);
    assert.ok(events.some((e) => e.type === 'agent.link-enrolled' && e.agentId === e1.agentId && e.parentId === parent.agentId));
    // the parent holds ONLY verify keys in its link-listen task — never child tokens
    const lt = ch.agents.get(parent.agentId).tasks.find((t) => t.kind === 'link-listen');
    assert.ok(lt, 'link-listen task queued for the parent');
    const spec = JSON.parse(lt.data);
    assert.equal(spec.pipe, e1.link.pipe);
    assert.equal(spec.children.length, 1);
    assert.equal(spec.children[0].k, deriveVerifyKey(e1.token, e1.link.linkId));
    assert.ok(!JSON.stringify(lt.data).includes(e1.token), 'the child token never leaves the channel');
    // second child on the SAME link merges into the pending task (no duplicate listener)
    const e2 = ch.registerLinkedAgent({ parentId: parent.agentId, linkId: e1.link.linkId, label: 'child-2' });
    const tasks = ch.agents.get(parent.agentId).tasks.filter((t) => t.kind === 'link-listen');
    assert.equal(tasks.length, 1);
    assert.equal(JSON.parse(tasks[0].data).children.length, 2);
    assert.equal(e2.link.pipe, e1.link.pipe);
    // unknown/killed parent -> refused
    assert.equal(ch.registerLinkedAgent({ parentId: 'nope' }), null);
    ch.kill(parent.agentId);
    assert.equal(ch.registerLinkedAgent({ parentId: parent.agentId }), null, 'a killed parent hosts no new links');
    // views: via on the child, pivotsView groups under the parent
    const view = ch.agentsView().find((a) => a.agentId === e1.agentId);
    assert.deepEqual(view.via, { parent: parent.agentId, link: e1.link.linkId, pipe: e1.link.pipe });
    const pv = ch.pivotsView();
    assert.equal(pv.length, 1);
    assert.equal(pv[0].children.length, 2);
    assert.equal(pv[0].parentId, parent.agentId);
  } finally { await ch.disarm(); }
});

test('relay route /l: governed batch relay, per-link seq, foreign-child refusal, 204-uniform denial', async () => {
  const { ch, port, events } = await armedChannel();
  try {
    const parent = ch.registerAgent({ label: 'parent' });
    const child = ch.registerLinkedAgent({ parentId: parent.agentId, label: 'child' });
    const other = ch.registerAgent({ label: 'not-linked' });
    const taskId = ch.task(child.agentId, 'shell', 'whoami');

    const relayPost = (body, seq, tok = parent.token, agent = parent.agentId) =>
      fetch(`http://127.0.0.1:${port}/l`, {
        method: 'POST', body,
        headers: { 'x-agent': agent, 'x-seq': String(seq), 'x-auth': hmac(tok, agent + ':' + seq + ':link:' + crypto.createHash('sha256').update(body).digest('hex')) },
      });

    // a child PULL relayed: the shared intake delivers the task (transport tagged smb)
    const pullPayload = { a: child.agentId, s: 1, h: hmac(child.token, child.agentId + ':1:pull') };
    const body1 = Buffer.from(JSON.stringify({ link: child.link.linkId, up: [pullPayload] }));
    const r1 = await relayPost(body1, 1);
    assert.equal(r1.status, 200);
    const j1 = await r1.json();
    assert.equal(j1.down.length, 1);
    assert.equal(j1.down[0].a, child.agentId);
    const { b32decode } = await import('../engine/dnscodec.mjs');
    const task = JSON.parse(b32decode(j1.down[0].p).toString('utf8'));
    assert.equal(task.taskId, taskId, 'the task reached the child through the relay');
    assert.ok(events.some((e) => e.type === 'link.relay' && e.agentId === parent.agentId));
    assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'smb' && e.agentId === child.agentId));
    assert.equal(ch.agentsView().find((a) => a.agentId === child.agentId).transportCheckins.smb, 1);

    // a child PUSH relayed: result intake works through the link
    const d = Buffer.from('CHILD-RESULT').toString('base64');
    const pushPayload = { a: child.agentId, s: 2, h: hmac(child.token, [child.agentId, 2, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d };
    const body2 = Buffer.from(JSON.stringify({ link: child.link.linkId, up: [pushPayload] }));
    const r2 = await relayPost(body2, 2);
    assert.equal(r2.status, 200);
    const rs = ch.results(child.agentId, { taskId });
    assert.equal(rs.length, 1);
    assert.equal(rs[0].data, 'CHILD-RESULT');
    assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'smb'));

    // replayed link seq -> 204-uniform (the relay is replay-strict per link)
    const r3 = await relayPost(body2, 2);
    assert.equal(r3.status, 204);
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'stale-seq'));

    // a FOREIGN agent id in the batch (not this parent's child on this link) -> fail closed
    const foreign = { a: other.agentId, s: 1, h: hmac(other.token, other.agentId + ':1:pull') };
    const body3 = Buffer.from(JSON.stringify({ link: child.link.linkId, up: [foreign] }));
    const r4 = await relayPost(body3, 3);
    assert.equal(r4.status, 204);
    assert.ok(events.some((e) => e.type === 'link.rejected' && e.reason === 'link-foreign-child'));

    // bad HMAC -> 204; unknown parent -> 204; malformed body -> 204 (all uniform)
    const r5 = await fetch(`http://127.0.0.1:${port}/l`, { method: 'POST', body: body1, headers: { 'x-agent': parent.agentId, 'x-seq': '9', 'x-auth': 'deadbeef' } });
    assert.equal(r5.status, 204);
    const r6 = await relayPost(Buffer.from('not-json'), 9);
    assert.equal(r6.status, 204);
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'bad-auth'));
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'link-malformed'));
  } finally { await ch.disarm(); }
});

test('FULL MESH e2e: real parent sim-agent hosts the pipe; real linked child checks in THROUGH it', async (t) => {
  if (process.platform !== 'win32') return t.skip('named pipes are the Windows build target');
  const { ch, port, events } = await armedChannel();
  // enroll parent + linked child (link id random); the parent gets its link-listen task
  const pcred = ch.registerAgent({ label: 'parent' });
  const ccred = ch.registerLinkedAgent({ parentId: pcred.agentId, label: 'linked-child' });
  const parent = new SimAgent({ url: 'http://127.0.0.1:' + port, agentId: pcred.agentId, token: pcred.token, interval: 300, jitter: 0, label: 'parent' });
  let child = null;
  try {
    // parent runs over plain http; its FIRST check-in should deliver link-listen
    const parentRun = parent.run({ onTick: () => {} });
    assert.ok(await waitFor(() => parent.log.some((l) => /link-listen/.test(l.msg))), 'parent received the link-listen task');
    assert.ok(await waitFor(() => parent._link && parent._link._server), 'the pipe server is up inside the parent');
    // child: smb transport, no url, via the parent's pipe on THIS host
    child = new SimAgent({ transport: 'smb', link: ccred.link.linkId, agentId: ccred.agentId, token: ccred.token, interval: 300, jitter: 0, label: 'linked-child' });
    // task the child BEFORE it ever checks in — the task must ride DOWN the link
    const taskId = ch.task(ccred.agentId, 'note', 'hello-through-the-pipe');
    const childRun = child.run({ onTick: () => {} });
    let got = null;
    assert.ok(await waitFor(() => { const r = ch.results(ccred.agentId, { taskId }); if (r.length) { got = r[0]; return true; } return false; }, 6000), 'the child task result came back THROUGH the parent pipe relay');
    assert.equal(got.data, 'noted: hello-through-the-pipe');
    // governance evidence: enrollment, link up, smb-tagged checkins on the CHILD
    assert.ok(events.some((e) => e.type === 'agent.link-enrolled' && e.agentId === ccred.agentId));
    assert.ok(events.some((e) => e.type === 'link.relay' && e.agentId === pcred.agentId));
    const cv = ch.agentsView().find((a) => a.agentId === ccred.agentId);
    assert.ok(cv.transportCheckins.smb >= 2, 'child checkins tagged smb (pull + push)');
    assert.ok(cv.via && cv.via.parent === pcred.agentId);
    // the parent's own check-ins stayed on http, unraced by the relay traffic
    const pv = ch.agentsView().find((a) => a.agentId === pcred.agentId);
    assert.ok(pv.transportCheckins.http >= 1);
    parent.stop(); child.stop();
    await Promise.allSettled([parentRun, childRun]);
  } finally {
    try { if (child) await child._pipe?.close(); } catch {}
    try { if (parent._link) await parent._link.close(); } catch {}
    await ch.disarm();
  }
});

test('mesh e2e: killed child is denied THROUGH the link (uniform idle), link death is observed', async (t) => {
  if (process.platform !== 'win32') return t.skip('named pipes are the Windows build target');
  const { ch, port } = await armedChannel();
  const pcred = ch.registerAgent({ label: 'parent2' });
  const ccred = ch.registerLinkedAgent({ parentId: pcred.agentId, label: 'child2' });
  const parent = new SimAgent({ url: 'http://127.0.0.1:' + port, agentId: pcred.agentId, token: pcred.token, interval: 300, jitter: 0 });
  let child = null;
  try {
    const parentRun = parent.run();
    assert.ok(await waitFor(() => parent._link && parent._link._server), 'pipe server up');
    child = new SimAgent({ transport: 'smb', link: ccred.link.linkId, agentId: ccred.agentId, token: ccred.token, interval: 300, jitter: 0 });
    const childRun = child.run();
    assert.ok(await waitFor(() => ch.agents.get(ccred.agentId).checkins >= 1, 5000), 'child alive through the link');
    // kill the CHILD listener-side: its next pull returns '' (uniform idle) — the mesh
    // carries the kill-list semantics exactly like a direct wire
    ch.kill(ccred.agentId);
    await tick(1200);
    const before = ch.agents.get(ccred.agentId).checkins;
    await tick(900);
    assert.equal(ch.agents.get(ccred.agentId).checkins, before, 'a killed child gets no further governed intake');
    // link death: child stops; the parent observes the pipe close
    child.stop();
    await childRun.catch(() => {});
    try { await child._pipe?.close(); } catch {}
    assert.ok(await waitFor(() => !parent._link.status().sessions.length || parent._link.status().connections === 0, 4000), 'parent observed the link death');
    parent.stop();
    await parentRun.catch(() => {});
  } finally {
    try { if (parent._link) await parent._link.close(); } catch {}
    await ch.disarm();
  }
});

// ---------------- cli surface: `pivots` off the live /api/channel payload ----------------
test('cli pivots: linked agents grouped by parent+link; unarmed channel is an honest empty', async () => {
  const { spawn, spawnSync } = await import('node:child_process');
  const { writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join, dirname } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'cli.mjs');
  // The mock API must be a SEPARATE process: spawnSync blocks this loop (cli.test.mjs pattern).
  const file = join(tmpdir(), 'varvel-pivots-mock-' + process.pid + '.mjs');
  writeFileSync(file, `import http from 'node:http';
http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ armed: true, agents: [
    { agentId: 'p1', label: 'landed-parent', health: 'active', checkins: 9, lastSeen: 1, via: null },
    { agentId: 'c1', label: 'child-one', health: 'active', checkins: 4, lastSeen: 2, via: { parent: 'p1', link: 'ab12cd34', pipe: 'varvel_link_ab12cd34' } },
    { agentId: 'c2', label: 'child-two', health: 'quiet', checkins: 1, lastSeen: 3, via: { parent: 'p1', link: 'ab12cd34', pipe: 'varvel_link_ab12cd34' } },
    { agentId: 'd1', label: 'direct-agent', health: 'active', checkins: 7, lastSeen: 4, via: null },
  ] }));
}).listen(0, '127.0.0.1', function () { console.log(this.address().port); });`);
  const proc = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise((resolve) => {
    let buf = '';
    proc.stdout.on('data', (d) => { buf += d; const p = parseInt(buf, 10); if (p > 0) resolve(p); });
  });
  try {
    const r = spawnSync(process.execPath, [CLI, 'pivots', 'http://127.0.0.1:' + port], { encoding: 'utf8', timeout: 15000 });
    assert.equal(r.status, 0, r.stderr.slice(0, 300));
    const out = JSON.parse(r.stdout);
    assert.equal(out.armed, true);
    assert.equal(out.agents, 4);
    assert.equal(out.pivots.length, 1, 'one link');
    assert.equal(out.pivots[0].parentId, 'p1');
    assert.equal(out.pivots[0].pipe, 'varvel_link_ab12cd34');
    assert.equal(out.pivots[0].children.length, 2, 'both linked children under the parent');
    assert.deepEqual(out.pivots[0].children.map((c) => c.agentId), ['c1', 'c2']);
    // unarmed channel -> honest empty
    writeFileSync(file, `import http from 'node:http';
http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ armed: false })); }).listen(0, '127.0.0.1', function () { console.log(this.address().port); });`);
    const proc2 = spawn(process.execPath, [file], { stdio: ['ignore', 'pipe', 'ignore'] });
    const port2 = await new Promise((resolve) => { let b = ''; proc2.stdout.on('data', (d) => { b += d; const p = parseInt(b, 10); if (p > 0) resolve(p); }); });
    const r2 = spawnSync(process.execPath, [CLI, 'pivots', 'http://127.0.0.1:' + port2], { encoding: 'utf8', timeout: 15000 });
    assert.equal(r2.status, 0);
    assert.deepEqual(JSON.parse(r2.stdout), { armed: false, pivots: [] });
    proc2.kill();
  } finally {
    proc.kill();
    try { rmSync(file); } catch {}
  }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets/pipes are still
// closing (libuv UV_HANDLE_CLOSING assert). Same guard as ws/doh/transportfail.
test('teardown grace for pipe/socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
