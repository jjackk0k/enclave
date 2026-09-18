// icmpbridge.test.mjs — channel-side ICMP transport over a MOCK stdio bridge (hermetic:
// no raw sockets, no privileges). The bridge is a dumb byte pump by design; these tests
// pin everything that lives above it: capability honesty, the scope ring, codec parse,
// frame reassembly, and the shared governed intake (HMAC/seq/reassembly) via _dnsPayload.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { CallbackChannel } from '../engine/callback.mjs';
import { icmpPacket, parseIcmpPacket, inetChecksum } from '../engine/icmpcodec.mjs';
import { encodeQuery, b32decode } from '../engine/dnscodec.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const tick = (ms = 15) => new Promise((r) => setTimeout(r, ms));

// A fake child_process: stdio streams + kill(), no process. stdin writes are captured
// as parsed JSON lines (what the channel ASKED the bridge to put on the wire).
function fakeChild() {
  const c = new EventEmitter();
  c.stdin = new PassThrough();
  c.stdout = new PassThrough();
  c.stderr = new PassThrough();
  c.killed = false;
  c.kill = () => { c.killed = true; return true; };
  c.sent = [];
  let buf = '';
  c.stdin.on('data', (d) => {
    buf += d.toString('utf8');
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) { c.sent.push(JSON.parse(buf.slice(0, nl))); buf = buf.slice(nl + 1); }
  });
  return c;
}
const feed = (child, obj) => child.stdout.write(JSON.stringify(obj) + '\n');
const capOk = (child) => feed(child, { op: 'capability', supported: true, reason: 'raw ICMP socket open (elevated)' });

function armed(extra = {}) {
  const events = [];
  const child = fakeChild();
  const ch = new CallbackChannel({
    scope: SCOPE,
    onEvent: (t, o) => events.push({ type: t, ...o }),
    icmp: { spawnFn: () => child, ...extra },
  });
  return { ch, events, child };
}

// Craft an inbound agent frame the way a real agent-side bridge would emit it.
function agentFrame(child, { src = '127.0.0.9', packet }) {
  feed(child, { op: 'recv', src, packetB64: packet.toString('base64') });
}

test('capability unsupported: honest status, bridge killed, channel itself unaffected', async () => {
  const { ch, events, child } = armed();
  await ch.arm(0);
  feed(child, { op: 'capability', supported: false, reason: 'raw ICMP socket refused: 10013 (elevated Administrator/root required)' });
  await tick();
  const st = ch.icmpStatus();
  assert.equal(st.configured, true);
  assert.equal(st.armed, false);
  assert.equal(st.supported, false);
  assert.match(st.reason, /refused/);
  assert.equal(st.liveVerified, false);
  assert.equal(child.killed, true); // unsupported bridge must not linger
  assert.ok(events.some((e) => e.type === 'channel.icmp-capability' && e.supported === false));
  assert.ok(ch.port > 0); // HTTP channel armed regardless
  await ch.disarm();
});

test('pull over ICMP: governed intake, task delivered on echo-reply frames, liveVerified flips', async () => {
  const { ch, events, child } = armed();
  await ch.arm(0);
  capOk(child);
  await tick();
  assert.equal(ch.icmpStatus().armed, true);

  const { agentId, token } = ch.registerAgent({ label: 'icmp-agent' });
  const taskId = ch.task(agentId, 'shell', 'hostname');
  const h = hmac(token, agentId + ':1:pull');
  const q = encodeQuery({ a: agentId, s: 1, h }, { domain: 'ax.sim' });
  // type 0 (echo reply): agents may frame either way — unsolicited replies pass firewalls
  // that drop inbound echo requests (the default Windows public-profile rule)
  agentFrame(child, { packet: icmpPacket({ type: 0, seq: 7, kind: 'pull', data: Buffer.from(q) }) });
  await tick();

  assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'icmp'));
  assert.ok(events.some((e) => e.type === 'task.delivered' && e.transport === 'icmp' && e.taskId === taskId));
  assert.equal(ch.icmpStatus().liveVerified, true); // authenticated frame advanced the seq — real round trip

  assert.equal(child.sent.length, 1);
  assert.equal(child.sent[0].op, 'send');
  assert.equal(child.sent[0].dst, '127.0.0.9');
  const reply = parseIcmpPacket(Buffer.from(child.sent[0].packetB64, 'base64'));
  assert.ok(reply);
  assert.equal(reply.type, 8);         // echo REQUEST: python raw type-0 sends are
                                       // silently dropped off-loopback (range matrix7)
  assert.equal(reply.id, 0x5602);      // distinct from the agent-facing 0x5601
  assert.equal(reply.kind, 'reply');
  assert.equal(reply.seq, 7);          // echo semantics: same seq as the request
  const task = JSON.parse(b32decode(reply.data.toString('utf8')).toString('utf8'));
  assert.equal(task.taskId, taskId);
  assert.equal(task.kind, 'shell');
  assert.equal(task.data, 'hostname');
  await ch.disarm();
});

test('push over ICMP: per-chunk HMAC result intake, transport labelled icmp', async () => {
  const { ch, events, child } = armed();
  await ch.arm(0);
  capOk(child);
  await tick();
  const { agentId, token } = ch.registerAgent({ label: 'icmp-push' });
  const taskId = ch.task(agentId, 'shell', 'hostname');
  // pull first (delivers the task), then push the result
  const h1 = hmac(token, agentId + ':1:pull');
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 1, kind: 'pull', data: Buffer.from(encodeQuery({ a: agentId, s: 1, h: h1 })) }) });
  await tick();

  const d = Buffer.from('PING-RESULT-BODY').toString('base64');
  const h2 = hmac(token, [agentId, 2, taskId, 0, 1, d].join(':'));
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 2, kind: 'push', data: Buffer.from(encodeQuery({ a: agentId, s: 2, h: h2, t: taskId, k: 'push', i: 0, n: 1, d })) }) });
  await tick();

  assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'icmp' && e.taskId === taskId));
  const rs = ch.results(agentId, { taskId });
  assert.equal(rs.length, 1);
  assert.equal(rs[0].data, 'PING-RESULT-BODY');
  // a push frame carries no application reply — nothing further should have been sent
  assert.equal(child.sent.length, 1); // exactly one: the earlier pull's task reply
  await ch.disarm();
});

test('push regression: a 15-chunk result (two-digit i/n/s, enc > 480) completes — the decode cap must not eat tail chunks', async () => {
  // Range-found bug: decodeQuery capped the b32 payload at 480 chars; the tail chunks
  // of any push past ~9 chunks cross it (two-digit metadata) and were silently
  // rejected — a 1400B result NEVER resulted over ICMP while a 300B one did.
  const { ch, events, child } = armed();
  await ch.arm(0);
  capOk(child);
  await tick();
  const { agentId, token } = ch.registerAgent({ label: 'icmp-push-big' });
  const taskId = ch.task(agentId, 'shell', 'hostname');
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 1, kind: 'pull', data: Buffer.from(encodeQuery({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pull') })) }) });
  await tick();

  const body = Buffer.from('q'.repeat(1400));
  const chunks = [];
  for (let i = 0; i < body.length; i += 96) chunks.push(body.subarray(i, i + 96).toString('base64'));
  assert.equal(chunks.length, 15);
  for (let i = 0; i < chunks.length; i++) {
    const s = 2 + i;
    const h = hmac(token, [agentId, s, taskId, i, chunks.length, chunks[i]].join(':'));
    agentFrame(child, { packet: icmpPacket({ type: 8, seq: s, kind: 'push', data: Buffer.from(encodeQuery({ a: agentId, s, h, t: taskId, k: 'push', i, n: chunks.length, d: chunks[i] })) }) });
  }
  await tick(40);

  assert.ok(events.some((e) => e.type === 'task.resulted' && e.transport === 'icmp' && e.taskId === taskId && e.bytes === 1400));
  const rs = ch.results(agentId, { taskId });
  assert.equal(rs.length, 1);
  assert.equal(rs[0].data.length, 1400);
  assert.equal(rs[0].data, 'q'.repeat(1400));
  await ch.disarm();
});

test('governance on the wire: out-of-scope silent drop, denial byte-identical to idle, non-VARVEL noise ignored', async () => {
  const { ch, events, child } = armed();
  await ch.arm(0);
  capOk(child);
  await tick();
  const { agentId, token } = ch.registerAgent({ label: 'icmp-gov' });
  ch.task(agentId, 'shell', 'hostname');

  // 1) out-of-scope source: SILENT — no intake event, no reply, no ledger noise
  const h = hmac(token, agentId + ':1:pull');
  const q = encodeQuery({ a: agentId, s: 1, h });
  const baseline = events.length; // armed + capability + registered + queued
  agentFrame(child, { src: '10.9.9.9', packet: icmpPacket({ type: 8, seq: 3, kind: 'pull', data: Buffer.from(q) }) });
  await tick();
  assert.equal(events.length, baseline); // the silent drop adds NOTHING — not even a rejection
  assert.equal(child.sent.length, 0);

  // 2) bad HMAC from an in-scope source: rejected (audited) — but the WIRE answer is an
  //    EMPTY echo reply, exactly the DNS path's zero-answer: denial ≡ idle to an observer.
  const badQ = encodeQuery({ a: agentId, s: 1, h: 'deadbeef' });
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 4, kind: 'pull', data: Buffer.from(badQ) }) });
  await tick();
  assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'bad-auth'));
  assert.equal(child.sent.length, 1);
  const denyReply = parseIcmpPacket(Buffer.from(child.sent[0].packetB64, 'base64'));
  assert.equal(denyReply.kind, 'reply');
  assert.equal(denyReply.data.length, 0);
  assert.equal(ch.icmpStatus().liveVerified, false); // seq frozen: no round trip credited

  // 3) a VALID agent with an EMPTY queue gets the byte-identical shape (the uniformity proof)
  const idle = ch.registerAgent({ label: 'icmp-idle' });
  const idleQ = encodeQuery({ a: idle.agentId, s: 1, h: hmac(idle.token, idle.agentId + ':1:pull') });
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 5, kind: 'pull', data: Buffer.from(idleQ) }) });
  await tick();
  assert.equal(child.sent.length, 2);
  const idleReply = parseIcmpPacket(Buffer.from(child.sent[1].packetB64, 'base64'));
  assert.equal(idleReply.kind, 'reply');
  assert.equal(idleReply.data.length, 0); // denied and idle are indistinguishable on the wire

  // 4) kernel ICMP noise: valid checksum, no VC magic — ignored silently (no reply at all)
  const noise = icmpPacket({ type: 8, seq: 6, kind: 'pull', data: Buffer.from('x') });
  noise[9] ^= 0xff;                   // smash the magic
  noise.writeUInt16BE(0, 2);
  noise.writeUInt16BE(inetChecksum(noise), 2); // checksum stays VALID — only the magic is wrong
  agentFrame(child, { packet: noise });
  const rawNoise = Buffer.from('this-is-not-an-icmp-frame-at-all');
  agentFrame(child, { packet: rawNoise });
  await tick();
  assert.equal(child.sent.length, 2);

  // 4b) the guest KERNEL's auto-reply copies (kind 'reply', type 0 — echoes of OUR
  // type-8 replies) must never intake: kind filter drops them, no reply generated
  const kernelEcho = icmpPacket({ type: 0, seq: 6, kind: 'reply', data: Buffer.from('x') });
  agentFrame(child, { packet: kernelEcho });
  await tick();
  assert.equal(child.sent.length, 2);
  assert.ok(!events.some((e) => e.type === 'agent.checkin' && e.transport === 'icmp' && e.agentId === undefined));

  // 5) and the SAME agent still works afterwards with the right auth (no state poisoning)
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 7, kind: 'pull', data: Buffer.from(q) }) });
  await tick();
  assert.equal(child.sent.length, 3);
  const taskReply = parseIcmpPacket(Buffer.from(child.sent[2].packetB64, 'base64'));
  assert.ok(taskReply.data.length > 0); // a real task this time
  assert.ok(events.some((e) => e.type === 'agent.checkin' && e.transport === 'icmp'));
  await ch.disarm();
});

test('frame-level chunking: multi-frame pull reassembles in any order; oversized task chunks the reply; cnt conflict rejected', async () => {
  const { ch, events, child } = armed();
  await ch.arm(0);
  capOk(child);
  await tick();
  const { agentId, token } = ch.registerAgent({ label: 'icmp-chunk' });
  const bigCmd = 'run ' + 'A'.repeat(1200); // forces the task reply across several frames
  const taskId = ch.task(agentId, 'shell', bigCmd);

  // multi-frame PULL, delivered idx 1 before idx 0
  const h = hmac(token, agentId + ':1:pull');
  const q = Buffer.from(encodeQuery({ a: agentId, s: 1, h }));
  const half = Math.ceil(q.length / 2);
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 11, kind: 'pull', idx: 1, cnt: 2, data: q.subarray(half) }) });
  await tick();
  assert.equal(child.sent.length, 0); // incomplete — nothing intaked, nothing replied
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 11, kind: 'pull', idx: 0, cnt: 2, data: q.subarray(0, half) }) });
  await tick();

  // the reply: 1200-char task data → encode → >512 → several echo-reply frames
  assert.ok(child.sent.length >= 2);
  const replies = child.sent.map((m) => parseIcmpPacket(Buffer.from(m.packetB64, 'base64')));
  assert.ok(replies.every((r) => r && r.type === 8 && r.kind === 'reply' && r.seq === 11));
  const cnt = replies[0].cnt;
  assert.ok(cnt > 1);
  assert.equal(replies.length, cnt);
  const ordered = [];
  for (let i = 0; i < cnt; i++) ordered.push(replies.find((r) => r.idx === i).data);
  const task = JSON.parse(b32decode(Buffer.concat(ordered).toString('utf8')).toString('utf8'));
  assert.equal(task.taskId, taskId);
  assert.equal(task.data, bigCmd);

  // cnt changing mid-stream on a NEW session is a shape violation → rejected + dropped
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 12, kind: 'pull', idx: 0, cnt: 2, data: Buffer.from('ab') }) });
  agentFrame(child, { packet: icmpPacket({ type: 8, seq: 12, kind: 'pull', idx: 1, cnt: 3, data: Buffer.from('cd') }) });
  await tick();
  assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'icmp-reassemble'));
  await ch.disarm();
});
