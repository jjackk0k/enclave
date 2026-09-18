// flow-live.mjs — independent live verification of the flow-beacon tier (one-shot).
// Two real agents in parallel: A metronomic (700ms, jitter 0), B heavy jitter (5s +/-2.5s).
// The tier must score A strictly more machine-like than B, with honest feature flags.
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

const regA = await post(API_V + '/api/channel/agent', { action: 'register', label: 'flow-metro' });
const regB = await post(API_V + '/api/channel/agent', { action: 'register', label: 'flow-jitter' });
console.log('[2] agents: A(metro)=' + regA.agentId + ' B(jitter)=' + regB.agentId);

const mk = (reg, ms, jit, box) => spawn('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', AGENT_PS1,
  '-Url', BASE, '-AgentId', reg.agentId, '-Token', reg.token,
  '-MaxLoops', '80', '-Interval', String(ms), '-Jitter', String(jit), '-Sandbox', box],
  { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
const aA = mk(regA, 700, 0, 'C:/Windows/Temp/flow-a-box');
const aB = mk(regB, 5000, 2500, 'C:/Windows/Temp/flow-b-box');
console.log('[3] both agents running ~75s...');
await sleep(75000);
try { aA.kill(); } catch {}
try { aB.kill(); } catch {}

const fa = await j(fetch(API_V + '/api/channel/flow?agent=' + regA.agentId));
const fb = await j(fetch(API_V + '/api/channel/flow?agent=' + regB.agentId));
console.log('[4] A(metro): ' + JSON.stringify({ score: fa.score, band: fa.band, gapCV: fa.features && fa.features.gapCV, points: fa.features && fa.features.points, flagged: fa.flagged }));
console.log('    B(jitter): ' + JSON.stringify({ score: fb.score, band: fb.band, gapCV: fb.features && fb.features.gapCV, points: fb.features && fb.features.points, flagged: fb.flagged }));
const ok = fa.score != null && fb.score != null && fa.score > fb.score;
console.log(ok ? 'FLOW-LIVE-OK: metronome scored strictly more machine-like than jittered' : 'FLOW-LIVE-CHECK: scores did not separate as expected');
