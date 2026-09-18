// repro-push-intake.mjs — one-shot deterministic replay: register + queue a task on a
// hermetic channel, spawn the PS query generator with the live token, then feed the
// exact agent-produced push queries back through the REAL intake and report events.
import { readFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { execFile } from 'node:child_process';
import { CallbackChannel } from '../varvel/engine/callback.mjs';
import { icmpPacket } from '../varvel/engine/icmpcodec.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8', '192.168.50.0/24'] };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function fakeChild() {
  const c = new EventEmitter();
  c.stdin = new PassThrough(); c.stdout = new PassThrough(); c.stderr = new PassThrough();
  c.killed = false; c.kill = () => { c.killed = true; return true; };
  return c;
}
const feed = (child, obj) => child.stdout.write(JSON.stringify(obj) + '\n');

const events = [];
const child = fakeChild();
const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), icmp: { spawnFn: () => child } });
await ch.arm(0);
feed(child, { op: 'capability', supported: true, reason: 'mock' });
await sleep(20);

const { agentId, token } = ch.registerAgent({ label: 'repro' });
const taskId = ch.task(agentId, 'shell', 'echo repro');
console.log('agent', agentId, 'task', taskId);

await new Promise((resolve, reject) => {
  execFile('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\\Users\\Jack\\Downloads\\enclave\\scripts\\make-push-queries.ps1', '-Token', token, '-AgentId', agentId, '-TaskId', taskId], (e, stdout) => {
    if (e) return reject(e);
    console.log('generator:', String(stdout).trim());
    resolve();
  });
});

const queries = readFileSync(process.env.TEMP + '\\push-queries.txt', 'utf8').trim().split(/\r?\n/);
console.log('replaying', queries.length, 'agent-produced push queries');
for (const q of queries) {
  feed(child, { op: 'recv', src: '192.168.50.130', packetB64: icmpPacket({ type: 0, seq: 1, kind: 'push', data: Buffer.from(q) }).toString('base64') });
  await sleep(25);
}
await sleep(300);
console.log('push chunks intaked:', events.filter((e) => e.type === 'agent.push').length, 'of', queries.length);
console.log('rejects:', JSON.stringify(events.filter((e) => e.type === 'checkin.rejected')));
console.log('resulted:', JSON.stringify(events.filter((e) => e.type === 'task.resulted')));
await ch.disarm();
