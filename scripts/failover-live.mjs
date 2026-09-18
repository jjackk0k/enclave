// failover-live.mjs — live proof of oracle-graded transport failover (one-shot).
// Agent starts on a DEAD http port with dns in its list: it must cycle autonomously
// and appear on the channel via dns. Then a channel assignment back to the dead http
// must stay honestly 'assigned' (never 'active') while the agent recovers to dns.
import { spawn } from 'node:child_process';

const API_V = 'http://127.0.0.1:8971';
const API_E = 'http://127.0.0.1:8977';
const AGENT_PS1 = 'C:/Users/Jack/Downloads/enclave/varvel/agents/varvel-agent.ps1';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (p) => { try { const r = await p; return await r.json(); } catch { return {}; } };
const post = (u, b) => j(fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) }));

console.log('[1] varvel restart + arm...');
await post(API_E + '/api/varvel/stop'); await sleep(2000);
await post(API_E + '/api/varvel/open');
let up = false;
for (let i = 0; i < 30 && !up; i++) { await sleep(1000); const c = await j(fetch(API_V + '/api/channel')); up = c && !c._err; }
console.log('    arm:', JSON.stringify(await post(API_V + '/api/channel/arm')));

const reg = await post(API_V + '/api/channel/agent', { action: 'register', label: 'failover-live' });
console.log('[2] registered: ' + reg.agentId);

console.log('[3] agent up: http DEAD (49999) + dns fallback (5335), FailAfter 4');
const child = spawn('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', AGENT_PS1,
  '-Url', 'http://192.168.50.1:49999', '-DnsPort', '5335', '-Transports', 'http,dns', '-FailAfter', '4',
  '-AgentId', reg.agentId, '-Token', reg.token, '-MaxLoops', '60', '-Interval', '700', '-Jitter', '150',
  '-Sandbox', 'C:/Windows/Temp/failover-live-box'], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
let agentOut = '';
child.stdout.on('data', (d) => { agentOut += d; });
child.stderr.on('data', (d) => { agentOut += d; });

const fleet = async () => { const c = await j(fetch(API_V + '/api/channel')); return (c.agents || []).find((a) => a.agentId === reg.agentId) || {}; };
let landed = null;
for (let i = 1; i <= 18; i++) {
  await sleep(5000);
  const a = await fleet();
  console.log('    poll ' + i + ': checkins=' + a.checkins + ' lastTransport=' + a.lastTransport + ' tc=' + JSON.stringify(a.transportCheckins));
  if (a.transportCheckins && a.transportCheckins.dns >= 2) { landed = a; break; }
}
if (!landed) { console.log('FAILOVER-LIVE-FAIL: no dns checkins in 90s'); console.log(agentOut.slice(-600)); try { child.kill(); } catch {} process.exit(1); }
console.log('[4] AUTONOMOUS FAILOVER PROVEN: agent cycles http(dead) -> dns and checks in. grade=' + JSON.stringify(landed.transportGrade && landed.transportGrade.recommendation));

console.log('[5] assigning http (dead) + note task — assignment must stay honestly assigned, agent must recover to dns');
await post(API_V + '/api/channel/agent', { action: 'transport', agentId: reg.agentId, transport: 'http' });
await post(API_V + '/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'failover assignment test' });
let recovered = null;
for (let i = 1; i <= 15; i++) {
  await sleep(5000);
  const a = await fleet();
  console.log('    poll ' + i + ': lastTransport=' + a.lastTransport + ' assigned=' + JSON.stringify(a.assignedTransport) + ' tc=' + JSON.stringify(a.transportCheckins));
  if (a.lastTransport === 'dns' && a.assignedTransport && a.assignedTransport.transport === 'http') { recovered = a; if ((a.transportCheckins.dns || 0) >= ((landed.transportCheckins.dns || 0) + 2)) break; }
}
console.log('[6] assignment outcome: state=' + JSON.stringify(recovered && recovered.assignedTransport));
console.log('AGENT LOG TAIL: ' + agentOut.trim().split('\n').slice(-8).join(' | '));
try { child.kill(); } catch {}
console.log('FAILOVER-LIVE-DONE');
