// run-agenttest.mjs <footholdId> — register a probe identity, queue a note task
// (non-empty reply), stage + run guest-icmp-agenttest.ps1 as a direct foothold task.
const API = 'http://127.0.0.1:8971';
const FOOTHOLD = process.argv[2];
if (!FOOTHOLD) { console.error('usage: node run-agenttest.mjs <footholdId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { readFileSync } = await import('node:fs');

async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function waitTask(agentId, taskId, s = 60) {
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + agentId);
    const x = (tasks || []).find((y) => y.taskId === taskId);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return null;
}

const reg = await j('/api/channel/agent', { action: 'register', label: 'agenttest-probe' });
console.log('identity:', reg.agentId);
await j('/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'agenttest-nonempty' });
const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-agenttest.ps1', b64: readFileSync(new URL('./guest-icmp-agenttest.ps1', import.meta.url)).toString('base64') });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));
const t = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\agentbox\\guest-icmp-agenttest.ps1 -AgentId ' + reg.agentId + ' -Token ' + reg.token });
console.log('AGENT-TEST:', JSON.stringify(await waitTask(FOOTHOLD, t.taskId, 60)));
