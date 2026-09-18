// run-matrix7.mjs <footholdId> — bridge-send A/B: send a VC type-0 frame (seq 7001)
// and a VC type-8 frame (seq 7002) from a scratch host bridge to the guest while the
// matrix6 listener watches. Which crosses the NIC decides the reply wire shape.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { icmpPacket } from '../varvel/engine/icmpcodec.mjs';

const API = 'http://127.0.0.1:8971';
const GUEST = '192.168.50.130';
const BRIDGE = fileURLToPath(new URL('../varvel/agents/icmp-bridge.py', import.meta.url));
const FOOTHOLD = process.argv[2];
if (!FOOTHOLD) { console.error('usage: node run-matrix7.mjs <footholdId>'); process.exit(2); }
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

const st = await j('/api/channel/stage', { agentId: FOOTHOLD, name: 'guest-icmp-matrix6.ps1', b64: readFileSync(new URL('./guest-icmp-matrix6.ps1', import.meta.url)).toString('base64') });
console.log('staged:', await waitTask(FOOTHOLD, st.taskId, 30));

// start the listener task WITHOUT awaiting it (blocks the foothold ~20s by design)
const lt = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\System32\\agentbox\\guest-icmp-matrix6.ps1' });
console.log('listener task:', lt.taskId);

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

await sleep(5000); // listener up
send(icmpPacket({ type: 0, id: 0x5602, seq: 7001, kind: 'reply', idx: 0, cnt: 1, data: Buffer.from('m7-type0-crosses?') }));
await sleep(800);
send(icmpPacket({ type: 8, id: 0x5602, seq: 7002, kind: 'reply', idx: 0, cnt: 1, data: Buffer.from('m7-type8-crosses?') }));
console.log('sent: type0/seq7001 and type8/seq7002 to ' + GUEST);

await sleep(18000);
child.kill();
console.log('MATRIX7:', JSON.stringify(await waitTask(FOOTHOLD, lt.taskId, 60)));
