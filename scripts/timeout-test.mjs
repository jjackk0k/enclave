// timeout-test.mjs <icmpAgentId> — the wedge-class killer test: task the live agent
// with a command that runs ~119s (ping -n 120). The 45s timeout+kill must return a
// loud TASK TIMEOUT result instead of freezing the loop; a follow-up hostname task
// proves the loop survived.
const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
if (!AGENT) { console.error('usage: node timeout-test.mjs <icmpAgentId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function waitResult(agentId, taskId, s) {
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + agentId);
    const x = (tasks || []).find((y) => y.taskId === taskId);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return null;
}

const t1 = await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data: 'ping -n 120 127.0.0.1' });
console.log('blocking task queued:', t1.taskId);
const r1 = await waitResult(AGENT, t1.taskId, 70);
console.log('BLOCKING RESULT:', JSON.stringify(r1));

const t2 = await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data: 'hostname' });
const r2 = await waitResult(AGENT, t2.taskId, 30);
console.log('SURVIVAL CHECK:', JSON.stringify(r2));
