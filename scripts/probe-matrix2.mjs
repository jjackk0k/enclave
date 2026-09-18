// probe-matrix2.mjs <footholdId> — does the HOST raw bridge receive the guest's
// UNSOLICITED type-8 echo requests? (The last unmeasured link. Guest re-runs the
// already-staged guest-icmp-matrix.ps1 which sends one type-8 VC probe seq 4242;
// a scratch python bridge on the host logs every VARVEL frame it sees.)
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseIcmpPacket } from '../varvel/engine/icmpcodec.mjs';

const API = 'http://127.0.0.1:8971';
const BRIDGE = fileURLToPath(new URL('../varvel/agents/icmp-bridge.py', import.meta.url));
const FOOTHOLD = process.argv[2];
if (!FOOTHOLD) { console.error('usage: node probe-matrix2.mjs <footholdId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}

// host sniffer first — it must already be listening when the guest probe fires
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
console.log('sniffer up:', cap.reason);

// guest re-fires its type-8 probe (script already staged on the same disk)
const wmi = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Windows\\System32\\agentbox\\guest-icmp-matrix.ps1 -ListenMs 12000'}; $r.ReturnValue";
await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: wmi });
console.log('guest probe launched');

await sleep(20000); // guest sends ~2-4s in; sniff plenty past it
child.kill();
const frames = [];
for (const m of lines) {
  if (m.op !== 'recv') continue;
  const f = parseIcmpPacket(Buffer.from(String(m.packetB64 || ''), 'base64'));
  if (f) frames.push('type=' + f.type + ' kind=' + f.kind + ' seq=' + f.seq + ' dlen=' + f.data.length + ' src=' + m.src);
}
console.log('HOST-SAW:', frames.length ? frames.join(' | ') : '(nothing)');
