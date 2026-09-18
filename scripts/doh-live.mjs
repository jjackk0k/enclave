// doh-live.mjs — independent live verification of the DoH channel (one-shot).
// (1) varvel restart (enclave spawn now bakes VARVEL_DOH=1) + arm -> doh status honest.
// (2) agent on dead http + doh fallback -> autonomous failover -> doh checkins observed.
// (3) fporacle probeJa4s on the DoH port — the honest TLS shape of the new transport.
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
const arm = await post(API_V + '/api/channel/arm');
console.log('    arm:', JSON.stringify(arm));
const ch = await j(fetch(API_V + '/api/channel'));
console.log('[2] doh status: ' + JSON.stringify(ch.doh));
if (!ch.doh || !ch.doh.armed) { console.log('DOH-LIVE-FAIL: doh not armed'); process.exit(1); }

const reg = await post(API_V + '/api/channel/agent', { action: 'register', label: 'doh-live' });
console.log('[3] registered: ' + reg.agentId + ' — agent: http DEAD (49999) + doh fallback, FailAfter 4');
const child = spawn('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', AGENT_PS1,
  '-Url', 'http://192.168.50.1:49999', '-Transports', 'http,doh', '-FailAfter', '4',
  '-AgentId', reg.agentId, '-Token', reg.token, '-MaxLoops', '40', '-Interval', '700', '-Jitter', '150',
  '-Sandbox', 'C:/Windows/Temp/doh-live-box'], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
let agentOut = '';
child.stdout.on('data', (d) => { agentOut += d; });
child.stderr.on('data', (d) => { agentOut += d; });

await post(API_V + '/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'doh live proof' });
let landed = null;
for (let i = 1; i <= 18; i++) {
  await sleep(5000);
  const c = await j(fetch(API_V + '/api/channel'));
  const a = (c.agents || []).find((x) => x.agentId === reg.agentId) || {};
  console.log('    poll ' + i + ': checkins=' + a.checkins + ' lastTransport=' + a.lastTransport + ' tc=' + JSON.stringify(a.transportCheckins));
  if (a.transportCheckins && (a.transportCheckins.doh || 0) >= 3) { landed = a; break; }
}
try { child.kill(); } catch {}
if (!landed) { console.log('DOH-LIVE-FAIL: no doh checkins'); console.log(agentOut.slice(-800)); process.exit(1); }
console.log('[4] FAILOVER-TO-DOH PROVEN. agent tail: ' + agentOut.trim().split('\n').slice(-5).join(' | '));

const { probeJa4s } = await import('C:/Users/Jack/Downloads/enclave/varvel/tools/fporacle.mjs');
const fp = await probeJa4s('192.168.50.1', 4453, { servername: 'varvel-doh-lab.local' });
console.log('[5] fporacle JA4S of the DoH endpoint: ' + JSON.stringify(fp));
console.log('DOH-LIVE-DONE');
