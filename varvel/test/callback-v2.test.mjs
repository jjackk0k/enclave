// VARVEL callback-channel v2 tests — task ledger, tags, broadcast, artifacts, health.
//   node --test varvel/test/callback-v2.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { CallbackChannel } from '../engine/callback.mjs';

const SCOPE = { cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function checkin(port, agentId, token, seq) {
  const r = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-auth': hmac(token, agentId + ':' + seq + ':pull') } });
  const buf = Buffer.from(await r.arrayBuffer());
  return { status: r.status, task: buf.length ? JSON.parse(buf.toString()) : null };
}
async function postResult(port, agentId, token, seq, taskId, data) {
  const body = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const r = await fetch(`http://127.0.0.1:${port}/r`, { method: 'POST', body, headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-task': taskId, 'x-auth': hmac(token, agentId + ':' + seq + ':' + taskId + ':' + sha256(body)) } });
  return { status: r.status };
}
async function armed() {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { port } = await ch.arm(0);
  return { ch, port, events };
}

test('task ledger: queued → delivered → resulted with previews', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({ label: 'ledger-1' });
    const taskId = ch.task(agentId, 'shell', 'whoami');
    assert.equal(ch.tasksView(agentId)[0].status, 'queued');
    const pull = await checkin(port, agentId, token, 1);
    assert.equal(ch.tasksView(agentId)[0].status, 'delivered');
    await postResult(port, agentId, token, 2, taskId, 'nt authority\\system');
    const t = ch.tasksView(agentId)[0];
    assert.equal(t.status, 'resulted');
    assert.ok(t.resultPreview.includes('system'));
    assert.ok(t.queuedAt && t.deliveredAt && t.resultAt);
  } finally { await ch.disarm(); }
});

test('tags + broadcast: taskWhere hits only the tagged subset; all hits every live agent', async () => {
  const { ch, port } = await armed();
  try {
    const a1 = ch.registerAgent({ label: 'web-1' });
    const a2 = ch.registerAgent({ label: 'db-1' });
    const a3 = ch.registerAgent({ label: 'web-2' });
    ch.tagAgent(a1.agentId, 'web');
    ch.tagAgent(a3.agentId, 'web');
    ch.tagAgent(a2.agentId, 'db');
    const out = ch.taskWhere({ tag: 'web' }, 'shell', 'id');
    assert.equal(out.length, 2, 'only the two web agents tasked');
    assert.ok(!out.some((o) => o.agentId === a2.agentId), 'db agent untouched');
    const all = ch.taskWhere({ all: true }, 'shell', 'hostname');
    assert.equal(all.length, 3, 'broadcast to all live agents');
    assert.equal(ch.taskWhere({}, 'shell', 'x').length, 0, 'empty broadcast refused (no accidental fleet-wide fire)');
    ch.kill(a1.agentId);
    assert.equal(ch.taskWhere({ all: true }, 'shell', 'y').length, 2, 'killed agents excluded');
    assert.equal(ch.tagAgent(a1.agentId, 'web', false).length, 0, 'tag removal works');
  } finally { await ch.disarm(); }
});

test('health: registered → active → stale → quiet → killed', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    assert.equal(ch.agentsView()[0].health, 'registered');
    await checkin(port, agentId, token, 1);
    assert.equal(ch.agentsView()[0].health, 'active');
    const future = Date.now() + 120_000;
    assert.equal(ch.agentsView({ now: future })[0].health, 'stale');
    const far = Date.now() + 600_000;
    assert.equal(ch.agentsView({ now: far })[0].health, 'quiet');
    ch.kill(agentId);
    assert.equal(ch.agentsView()[0].health, 'killed');
  } finally { await ch.disarm(); }
});

test('artifact staging: push delivers name+bytes+sha256 the agent can verify', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    const payload = Buffer.from('MZ fake artifact bytes for staging');
    const st = ch.stageArtifact(agentId, 'tool.exe', payload);
    assert.ok(st && st.taskId && st.artifactId);
    const pull = await checkin(port, agentId, token, 1);
    assert.equal(pull.task.kind, 'stage');
    const staged = JSON.parse(pull.task.data);
    assert.equal(staged.name, 'tool.exe');
    assert.equal(Buffer.from(staged.b64, 'base64').toString(), payload.toString());
    assert.equal(staged.sha256, sha256(payload), 'the agent can verify integrity on receipt');
    assert.ok(events.some((e) => e.type === 'artifact.staged'));
    // operator-side: the artifact is listed (metadata) and retrievable (bytes)
    const listed = ch.artifacts().find((a) => a.id === st.artifactId);
    assert.equal(listed.direction, 'push');
    assert.equal(listed.data, undefined, 'listing carries metadata only');
    assert.equal(ch.artifact(st.artifactId).toString(), payload.toString());
  } finally { await ch.disarm(); }
});

test('artifact pull: a fetch task registers the result as a hashed artifact', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    const taskId = ch.fetchArtifact(agentId, '/etc/flag.txt');
    await checkin(port, agentId, token, 1);
    const content = Buffer.from('flag{callback-channel-works}');
    await postResult(port, agentId, token, 2, taskId, content);
    const arts = ch.artifacts().filter((a) => a.direction === 'pull');
    assert.equal(arts.length, 1);
    assert.equal(arts[0].name, 'flag.txt');
    assert.equal(arts[0].sha256, sha256(content));
    assert.equal(ch.artifact(arts[0].id).toString(), content.toString());
    assert.ok(events.some((e) => e.type === 'artifact.received'));
    assert.equal(ch.tasksView(agentId)[0].status, 'resulted');
  } finally { await ch.disarm(); }
});

test('staging discipline: caps enforced, rename works, killed agents stage nothing', async () => {
  const { ch } = await armed();
  try {
    const { agentId } = ch.registerAgent({ label: 'x' });
    assert.throws(() => ch.stageArtifact(agentId, 'big.bin', Buffer.alloc(2 * 1024 * 1024 + 1)), TypeError);
    assert.throws(() => ch.stageArtifact(agentId, 'empty', Buffer.alloc(0)), TypeError);
    assert.equal(ch.renameAgent(agentId, 'rangebox-01'), 'rangebox-01');
    ch.kill(agentId);
    assert.equal(ch.stageArtifact(agentId, 'x', Buffer.from('y')), null, 'no staging for dead agents');
  } finally { await ch.disarm(); }
});

// Teardown grace: on win32, --test-force-exit can fire while undici's pooled client sockets
// are still closing after the last disarm (libuv UV_HANDLE_CLOSING assert). Let them finish —
// generous on purpose: under full-suite CPU contention 250ms proved marginal.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
