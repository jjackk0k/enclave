// fp-live-host.mjs — host-side live proof for fporacle: run the REAL varvel-agent.ps1
// (HTTP transport, .NET WebClient wire) against the armed channel on loopback and
// capture its observed JA4H + findings via /api/fp. Bounded: MaxLoops 4, note task only.
import { spawn } from 'node:child_process';

const API_V = 'http://127.0.0.1:8971';
const CHANNEL = 'http://192.168.50.1:49561'; // channel binds the lab NIC only (netstat-verified), not loopback
const AGENT_PS1 = 'C:/Users/Jack/Downloads/enclave/varvel/agents/varvel-agent.ps1';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (p) => { try { const r = await p; return await r.json(); } catch { return {}; } };
const post = (u, b) => j(fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) }));

const reg = await post(API_V + '/api/channel/agent', { action: 'register', label: 'fp-live-host' });
if (!reg.ok) { console.log('FATAL register: ' + JSON.stringify(reg)); process.exit(1); }
console.log('[1] registered: ' + reg.agentId);

const t = await post(API_V + '/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'fp live host proof' });
console.log('[2] note task queued: ' + JSON.stringify(t));

const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', AGENT_PS1,
  '-Url', CHANNEL, '-AgentId', reg.agentId, '-Token', reg.token,
  '-MaxLoops', '4', '-Interval', '700', '-Jitter', '150',
  '-Sandbox', 'C:/Windows/Temp/fp-live-host-box'];
console.log('[3] launching real agent (4 loops, http transport)...');
const child = spawn('powershell', args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
let out = '';
child.stdout.on('data', (d) => { out += d; });
child.stderr.on('data', (d) => { out += d; });
const rc = await new Promise((res) => child.on('exit', res));
console.log('[4] agent exited rc=' + rc + ' tail: ' + out.trim().split('\n').slice(-4).join(' | '));

await sleep(1500);
const fp = await j(fetch(API_V + '/api/fp'));
const obs = (fp.observations || []);
console.log('[5] observations=' + obs.length + ' distinctJa4h=' + fp.distinctJa4h);
for (const o of obs.slice(-6)) console.log('    ' + JSON.stringify(o));
if (obs.length > 0) console.log('FP-HOST-OK'); else console.log('FP-HOST-EMPTY');
