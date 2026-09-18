// VARVEL sim-agent integration tests — a real agent against a real channel, full protocol.
//   node --test varvel/test/sim-agent.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';

const SCOPE = { cidrs: ['127.0.0.0/8'] };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function rig() {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }) });
  const { port } = await ch.arm(0);
  return { ch, port, events, url: `http://127.0.0.1:${port}` };
}

test('sim agent: registers work end-to-end — health active, shell round-trip, ledger resulted', async () => {
  const { ch, url } = await rig();
  const dir = mkdtempSync(join(tmpdir(), 'sim-'));
  try {
    const { agentId, token } = ch.registerAgent({ label: 'sim-01' });
    const agent = new SimAgent({ url, agentId, token, dir, interval: 300, jitter: 100 });
    const run = agent.run();
    try {
      await sleep(700); // a few jittered check-ins
      const v = ch.agentsView()[0];
      assert.equal(v.health, 'active', 'heartbeat visible to the fleet view');
      assert.ok(v.checkins >= 1);
      // task it: shell in the sandbox
      const taskId = ch.task(agentId, 'shell', 'echo channel-works');
      await sleep(900);
      const t = ch.tasksView(agentId)[0];
      assert.equal(t.status, 'resulted', 'full queued→delivered→resulted lifecycle with a live agent');
      assert.ok(/channel-works/.test(t.resultPreview), 'result content flows back');
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

test('sim agent: stage delivers a sha256-VERIFIED artifact into the sandbox; fetch pulls a file back', async () => {
  const { ch, url } = await rig();
  const dir = mkdtempSync(join(tmpdir(), 'sim-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    const agent = new SimAgent({ url, agentId, token, dir, interval: 300, jitter: 50 });
    const run = agent.run();
    try {
      await sleep(600);
      // PUSH: stage an artifact; the agent verifies the hash and writes it into its sandbox
      const payload = Buffer.from('agent-side artifact contents');
      ch.stageArtifact(agentId, 'drop.bin', payload);
      await sleep(900);
      const stagedPath = join(dir, 'drop.bin');
      assert.ok(existsSync(stagedPath), 'artifact landed in the sandbox');
      assert.equal(readFileSync(stagedPath).toString(), payload.toString(), 'bytes are verbatim after hash verification');
      // PULL: fetch it back through the protocol
      writeFileSync(join(dir, 'flag.txt'), 'flag{sim-agent-protocol-complete}');
      ch.fetchArtifact(agentId, 'flag.txt');
      await sleep(900);
      const arts = ch.artifacts().filter((a) => a.direction === 'pull');
      assert.equal(arts.length, 1);
      assert.equal(arts[0].name, 'flag.txt');
      assert.equal(ch.artifact(arts[0].id).toString(), 'flag{sim-agent-protocol-complete}');
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

test('sim agent: killed agents get the uniform 204 and stop receiving tasks', async () => {
  const { ch, url, events } = await rig();
  const dir = mkdtempSync(join(tmpdir(), 'sim-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    const agent = new SimAgent({ url, agentId, token, dir, interval: 300, jitter: 50 });
    const run = agent.run();
    try {
      await sleep(600);
      ch.kill(agentId);
      const taskId = ch.task(agentId, 'shell', 'echo never');
      assert.equal(taskId, null, 'killed agents cannot be tasked');
      await sleep(600);
      assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'killed-agent'), 'rejected check-ins audited');
      assert.equal(ch.agentsView()[0].health, 'killed');
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

// Sandbox lifecycle pins (the .sim-* platform-root leak fix): a DEFAULT sandbox (no dir)
// is module-owned mkdtemp scratch under the OS temp root — never the launch cwd — removed
// on stop(), on a failed run's teardown, and by the process exit hooks; a caller-supplied
// dir is NEVER removed. Loopback only (127.0.0.1:9 is refused instantly, nothing external).
test('sim agent sandbox: default dir is minted under the OS temp root and removed on stop()', () => {
  const agent = new SimAgent({ url: 'http://127.0.0.1:9', agentId: 'sbx-own', token: 't' });
  const dir = agent.dir;
  assert.ok(existsSync(dir), 'the default sandbox exists from construction');
  assert.ok(dir.startsWith(join(tmpdir(), 'varvel-sim-')), 'default sandbox is OS-temp scratch, not the cwd/platform root: ' + dir);
  agent.stop();
  assert.ok(!existsSync(dir), 'module-owned sandbox removed on stop()');
});

test('sim agent sandbox: teardown removes the default dir after a FAILED run (dead channel)', async () => {
  const agent = new SimAgent({ url: 'http://127.0.0.1:9', agentId: 'sbx-fail', token: 't', interval: 200, jitter: 0 });
  const dir = agent.dir;
  await agent.run({ once: true }); // every tick errors (connection refused) — noted, not thrown
  assert.ok(agent.log.some((l) => /tick error/.test(l.msg)), 'the failure path really ran');
  agent.stop();
  assert.ok(!existsSync(dir), 'module-owned sandbox removed on the error teardown path');
});

test('sim agent sandbox: a caller-supplied dir is NEVER removed (cleanup stays bounded)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sim-caller-'));
  const agent = new SimAgent({ url: 'http://127.0.0.1:9', agentId: 'sbx-caller', token: 't', dir });
  assert.equal(agent.dir, dir);
  agent.stop();
  assert.ok(existsSync(dir), 'caller-owned dirs survive stop() — the module removes only what it minted');
});

test('sim agent sandbox: process exit sweeps the default sandbox (the CLI never calls stop)', () => {
  const script = join(dirname(fileURLToPath(import.meta.url)), '..', 'agents', 'sim-agent.mjs');
  const r = spawnSync(process.execPath, [script, '--url', 'http://127.0.0.1:9', '--id', 'sbx-exit', '--token', 't', '--once', '1'], { encoding: 'utf8', timeout: 30000 });
  assert.equal(r.status, 0, 'one-shot run exits cleanly: ' + (r.stderr || '').slice(0, 200));
  const m = /sandbox (.+?) · cadence/.exec(r.stdout || '');
  assert.ok(m, 'the CLI prints its sandbox path: ' + (r.stdout || '').slice(0, 200));
  assert.ok(m[1].startsWith(join(tmpdir(), 'varvel-sim-')), 'default sandbox under the OS temp root: ' + m[1]);
  assert.ok(!existsSync(m[1]), 'the exit hook swept the module-owned sandbox (nothing for the platform root to leak)');
});

// Teardown grace for win32 libuv socket-close race (see callback-v2 tests).
test('teardown grace (win32)', async () => { await sleep(400); });
