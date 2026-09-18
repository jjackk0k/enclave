// tradecraft-live.mjs — independent live verification of the agent-tradecraft tier.
// Two real agents: A tasked with a deliberately agent-shaped shell stream, B with a
// human-ish stream. GET /api/channel/tradecraft must score A strictly higher, with
// per-signature evidence from the REAL task ledger.
import { spawn } from 'node:child_process';

const API_V = 'http://127.0.0.1:8971';
const API_E = 'http://127.0.0.1:8977';
const AGENT_PS1 = 'C:/Users/Jack/Downloads/enclave/varvel/agents/varvel-agent.ps1';
const BASE = 'http://192.168.50.1:49561';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (p) => { try { const r = await p; return await r.json(); } catch { return {}; } };
const post = (u, b) => j(fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) }));

const STREAM_A = ["echo '---'; whoami", "ipconfig /all 2>/dev/null | head -20", "net user 2>/dev/null", "dir C:\\Users 2>&1 | head -5", "echo '---'; hostname", "systeminfo 2>/dev/null | head -3"];
const STREAM_B = ['whoami', 'hostname', 'net user', 'dir C:\\Users', 'ipconfig'];

console.log('[1] varvel restart + arm...');
await post(API_E + '/api/varvel/stop'); await sleep(2000);
await post(API_E + '/api/varvel/open');
let up = false;
for (let i = 0; i < 30 && !up; i++) { await sleep(1000); const c = await j(fetch(API_V + '/api/channel')); up = c && !c._err; }
console.log('    arm:', JSON.stringify(await post(API_V + '/api/channel/arm')));

const regA = await post(API_V + '/api/channel/agent', { action: 'register', label: 'tc-agent-shaped' });
const regB = await post(API_V + '/api/channel/agent', { action: 'register', label: 'tc-human-ish' });
console.log('[2] A=' + regA.agentId + ' B=' + regB.agentId);
const mk = (reg, box) => spawn('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', AGENT_PS1,
  '-Url', BASE, '-AgentId', reg.agentId, '-Token', reg.token, '-MaxLoops', '60', '-Interval', '600', '-Jitter', '100', '-Sandbox', box],
  { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
const aA = mk(regA, 'C:/Windows/Temp/tc-a-box');
const aB = mk(regB, 'C:/Windows/Temp/tc-b-box');
await sleep(3000);
for (const c of STREAM_A) await post(API_V + '/api/channel/task', { agentId: regA.agentId, kind: 'shell', data: c });
for (const c of STREAM_B) await post(API_V + '/api/channel/task', { agentId: regB.agentId, kind: 'shell', data: c });
console.log('[3] streams tasked; waiting for execution...');
await sleep(20000);
try { aA.kill(); } catch {}
try { aB.kill(); } catch {}

const ta = await j(fetch(API_V + '/api/channel/tradecraft?agent=' + regA.agentId));
const tb = await j(fetch(API_V + '/api/channel/tradecraft?agent=' + regB.agentId));
const slim = (t) => ({ score: t.score, band: t.band, fired: (t.signatures || []).filter((s) => s.fired).map((s) => s.id) });
console.log('[4] A(agent-shaped): ' + JSON.stringify(slim(ta)));
console.log('    B(human-ish):    ' + JSON.stringify(slim(tb)));
const ok = ta.score != null && tb.score != null && ta.score > tb.score;
console.log(ok ? 'TRADECRAFT-LIVE-OK: agent-shaped stream scored strictly higher on the real ledger' : 'TRADECRAFT-LIVE-CHECK: scores did not separate');
