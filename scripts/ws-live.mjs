// ws-live.mjs — independent live verification of the WebSocket push channel (one-shot).
// (1) agent on -Transport ws -> note task delivered INSTANTLY (no poll wait), tc.ws>0.
// (2) channel-assigned switch to http rides a task frame -> agent honors -> assignment
//     flips to 'active' only after an observed http checkin.
import { spawn } from 'node:child_process';

const API_V = 'http://127.0.0.1:8971';
const API_E = 'http://127.0.0.1:8977';
const AGENT_PS1 = 'C:/Users/Jack/Downloads/enclave/varvel/agents/varvel-agent.ps1';
const BASE = 'http://192.168.50.1:49561';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (p) => { try { const r = await p; return await r.json(); } catch { return {}; } };
const post = (u, b) => j(fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) }));

console.log('[1] varvel restart + arm...');
await post(API_E + '/api/varvel/stop'); await sleep(2000);
await post(API_E + '/api/varvel/open');
let up = false;
for (let i = 0; i < 30 && !up; i++) { await sleep(1000); const c = await j(fetch(API_V + '/api/channel')); up = c && !c._err; }
console.log('    arm:', JSON.stringify(await post(API_V + '/api/channel/arm')));

const reg = await post(API_V + '/api/channel/agent', { action: 'register', label: 'ws-live' });
console.log('[2] registered: ' + reg.agentId + ' — agent on -Transport ws');
const child = spawn('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', AGENT_PS1,
  '-Url', BASE, '-Transports', 'ws,http', '-AgentId', reg.agentId, '-Token', reg.token,
  '-MaxLoops', '60', '-Interval', '700', '-Jitter', '150',
  '-Sandbox', 'C:/Windows/Temp/ws-live-box'], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
let agentOut = '';
child.stdout.on('data', (d) => { agentOut += d; });
child.stderr.on('data', (d) => { agentOut += d; });

await sleep(6000); // let the ws handshake land
const queuedAt = Date.now();
await post(API_V + '/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'ws instant push proof' });
let sawTask = null;
for (let i = 1; i <= 10; i++) {
  await sleep(1000);
  if (/task\(ws\) note/.test(agentOut)) { sawTask = Date.now() - queuedAt; break; }
}
console.log('[3] instant delivery: task executed ' + (sawTask === null ? 'NEVER (fail)' : sawTask + 'ms after queue (poll cadence would be up to ~850ms + task pickup)') );

console.log('[4] assigning http — setTransport must ride a task frame, flip active on observed http checkin');
await post(API_V + '/api/channel/agent', { action: 'transport', agentId: reg.agentId, transport: 'http' });
await post(API_V + '/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'ws assignment test' });
let flipped = null;
for (let i = 1; i <= 15; i++) {
  await sleep(4000);
  const c = await j(fetch(API_V + '/api/channel'));
  const a = (c.agents || []).find((x) => x.agentId === reg.agentId) || {};
  console.log('    poll ' + i + ': lastTransport=' + a.lastTransport + ' assigned=' + JSON.stringify(a.assignedTransport) + ' tc=' + JSON.stringify(a.transportCheckins));
  if (a.assignedTransport && a.assignedTransport.state === 'active' && a.lastTransport === 'http') { flipped = a; break; }
}
try { child.kill(); } catch {}
console.log('AGENT TAIL: ' + agentOut.trim().split('\n').slice(-8).join(' | '));
console.log(sawTask !== null && flipped ? 'WS-LIVE-OK' : 'WS-LIVE-PARTIAL (see above)');
