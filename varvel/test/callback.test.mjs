// VARVEL callback-channel tests — hermetic (loopback HTTP, in-process channel).
// The "agent" here is a plain HTTP client speaking the protocol — no implant logic.
//   node --test varvel/test/callback.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { CallbackChannel, ipAllowed } from '../engine/callback.mjs';

const SCOPE = { cidrs: ['127.0.0.0/8', '10.10.0.0/16'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// A simulated agent: speaks the protocol over loopback, nothing more.
async function checkin(port, agentId, token, seq, { authOverride } = {}) {
  const r = await fetch(`http://127.0.0.1:${port}/c`, {
    headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-auth': authOverride ?? hmac(token, agentId + ':' + seq + ':pull') },
  });
  const buf = Buffer.from(await r.arrayBuffer());
  return { status: r.status, task: buf.length ? JSON.parse(buf.toString()) : null };
}
async function postResult(port, agentId, token, seq, taskId, data, { authOverride } = {}) {
  const body = Buffer.from(data);
  const r = await fetch(`http://127.0.0.1:${port}/r`, {
    method: 'POST', body,
    headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-task': taskId, 'x-auth': authOverride ?? hmac(token, agentId + ':' + seq + ':' + taskId + ':' + sha256(body)) },
  });
  return { status: r.status };
}

async function armed() {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { port } = await ch.arm(0);
  return { ch, port, events };
}

test('governance: arming REFUSES without a signed scope', () => {
  assert.throws(() => new CallbackChannel({}), /signed scope/);
  assert.throws(() => new CallbackChannel({ scope: {} }), /signed scope/);
});

test('full round-trip: register → empty check-in → task → delivery → result → correlation', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'range-sim-1' });
    // 1. check-in with nothing queued → 204 (empty semantics)
    const idle = await checkin(port, agentId, token, 1);
    assert.equal(idle.status, 204);
    assert.equal(idle.task, null);
    // 2. queue a task → next check-in delivers it with its taskId
    const taskId = ch.task(agentId, 'shell', 'whoami');
    assert.ok(taskId, 'taskId issued');
    const pull = await checkin(port, agentId, token, 2);
    assert.equal(pull.status, 200);
    assert.equal(pull.task.taskId, taskId);
    assert.equal(pull.task.data, 'whoami');
    // 3. post the result → correlated by taskId, drainable
    const posted = await postResult(port, agentId, token, 3, taskId, 'nt authority\\system');
    assert.equal(posted.status, 200);
    const rs = ch.results(agentId, { taskId });
    assert.equal(rs.length, 1);
    assert.equal(rs[0].data, 'nt authority\\system');
    assert.equal(ch.results(agentId, { taskId }).length, 0, 'drained, not duplicated');
    // 4. audit captured the whole lifecycle
    for (const t of ['agent.registered', 'agent.checkin', 'task.queued', 'task.delivered', 'result.received']) {
      assert.ok(events.some((e) => e.type === t), 'audited: ' + t);
    }
    const view = ch.agentsView();
    assert.equal(view[0].checkins, 3);
    assert.equal(view[0].label, 'range-sim-1');
  } finally { await ch.disarm(); }
});

test('authentication: a bare agent ID (Fang-style) is worthless — bad HMAC → uniform 204', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId } = ch.registerAgent({});
    const r1 = await checkin(port, agentId, 'wrong-token', 1);
    assert.equal(r1.status, 204, 'rejected — and indistinguishable from idle');
    const r2 = await checkin(port, 'nonexistent-agent', 'x', 1);
    assert.equal(r2.status, 204, 'unknown agent also gets the uniform 204');
    assert.ok(events.filter((e) => e.type === 'checkin.rejected').length >= 2, 'rejections audited with reasons');
  } finally { await ch.disarm(); }
});

test('replay protection: a stale/replayed sequence is rejected + audited', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    assert.equal((await checkin(port, agentId, token, 5)).status, 204);
    const replay = await checkin(port, agentId, token, 5); // same seq again
    assert.equal(replay.status, 204);
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'stale-seq'), 'replay audited');
    assert.equal((await checkin(port, agentId, token, 6)).status, 204, 'next seq fine');
  } finally { await ch.disarm(); }
});

test('kill-list: a killed agent is 204-indistinguishable from idle (Fang trick kept)', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    assert.equal((await checkin(port, agentId, token, 1)).status, 204);
    ch.kill(agentId);
    const r = await checkin(port, agentId, token, 2);
    assert.equal(r.status, 204, 'killed looks exactly like idle');
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'killed-agent'));
    assert.ok(events.some((e) => e.type === 'agent.killed'));
    assert.equal(ch.task(agentId, 'shell', 'id'), null, 'no tasks for dead agents');
  } finally { await ch.disarm(); }
});

test('task correlation: out-of-order results are tagged by taskId (Fang mis-tags these)', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    const t1 = ch.task(agentId, 'shell', 'ipconfig');
    const t2 = ch.task(agentId, 'shell', 'hostname');
    const p1 = await checkin(port, agentId, token, 1);
    const p2 = await checkin(port, agentId, token, 2);
    assert.equal(p1.task.taskId, t1);
    assert.equal(p2.task.taskId, t2);
    // answer the SECOND task first — correlation survives because taskId is echoed
    await postResult(port, agentId, token, 3, t2, 'rangebox');
    await postResult(port, agentId, token, 4, t1, '10.10.0.5');
    assert.equal(ch.results(agentId, { taskId: t1 })[0].data, '10.10.0.5');
    assert.equal(ch.results(agentId, { taskId: t2 })[0].data, 'rangebox');
  } finally { await ch.disarm(); }
});

test('forged result auth (right agent, wrong content binding) is rejected', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    const taskId = ch.task(agentId, 'shell', 'id');
    await checkin(port, agentId, token, 1);
    // attacker flips the body but keeps a stale auth → rejected
    const forged = await postResult(port, agentId, token, 2, taskId, 'TAMPERED', { authOverride: hmac(token, agentId + ':2:' + taskId + ':' + sha256(Buffer.from('original'))) });
    assert.equal(forged.status, 204);
    assert.equal(ch.results(agentId).length, 0);
  } finally { await ch.disarm(); }
});

test('ipAllowed: loopback always, CIDR ring enforced, garbage refused', () => {
  assert.equal(ipAllowed('127.0.0.1', []), true);
  assert.equal(ipAllowed('::1', []), true);
  assert.equal(ipAllowed('10.10.0.5', ['10.10.0.0/16']), true);
  assert.equal(ipAllowed('10.11.0.5', ['10.10.0.0/16']), false);
  assert.equal(ipAllowed('192.168.1.9', ['10.10.0.0/16']), false);
  assert.equal(ipAllowed('10.10.0.5', ['10.10.0.0/24']), true);
  assert.equal(ipAllowed('10.10.1.5', ['10.10.0.0/24']), false);
  // dual-stack: v6 rings enforce identically; mapped v4 collapses; ALL of 127/8 is loopback
  assert.equal(ipAllowed('127.0.0.2', []), true);
  assert.equal(ipAllowed('fd00::5', ['fd00::/8']), true);
  assert.equal(ipAllowed('fd00:0:0:1::5', ['fd00::/64']), false);
  assert.equal(ipAllowed('::ffff:10.10.0.5', ['10.10.0.0/16']), true);
  assert.equal(ipAllowed('2001:db8::1', ['10.10.0.0/16']), false); // family-strict
  assert.equal(ipAllowed('garbage', ['10.0.0.0/8']), false);
  assert.equal(ipAllowed('', ['10.0.0.0/8']), false);
});

test('bounded queues: result buffer drops oldest beyond the cap', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    const taskId = ch.task(agentId, 'shell', 'spam');
    await checkin(port, agentId, token, 1);
    for (let i = 0; i < 1005; i++) {
      // results don't need fresh tasks; seq just must increase
      await postResult(port, agentId, token, i + 2, taskId, 'r' + i);
    }
    const view = ch.agentsView()[0];
    assert.ok(view.bufferedResults <= 1000, 'capped at 1000, got ' + view.bufferedResults);
  } finally { await ch.disarm(); }
});
