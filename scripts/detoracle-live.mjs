// detoracle-live.mjs <agentId> — the oracle's own proof on the range: a known-safe
// command (hostname) must come back 'clean'; the EICAR standard AV test string
// (harmless by design — every AV detects it) must come back 'detected' or 'blocked'.
// Anything else means the oracle is lying, and we say so.
import { assess, buildSnapshotCommand } from '../varvel/tools/detoracle.mjs';

const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
if (!AGENT) { console.error('usage: node detoracle-live.mjs <agentId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function taskAgent(agentId, data) {
  const t = await j('/api/channel/task', { agentId, kind: 'shell', data });
  for (let i = 0; i < 30; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + agentId);
    const x = (tasks || []).find((y) => y.taskId === t.taskId);
    if (x && x.status === 'resulted') return x.resultPreview || '';
  }
  return null;
}

const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const eicarCmd = 'powershell -NoProfile -Command "Set-Content -Path \'C:\\Windows\\Temp\\eicar.tmp\' -Value \'' + EICAR + '\'"';

console.log('=== benign probe (expect clean) ===');
const v1 = await assess({ taskAgent, agentId: AGENT, command: 'hostname', settleMs: 4000 });
console.log(JSON.stringify({ verdict: v1.verdict, newDetections: v1.newDetections, note: v1.note }));

console.log('=== EICAR probe (expect detected/blocked) ===');
const v2 = await assess({ taskAgent, agentId: AGENT, command: eicarCmd, settleMs: 8000 });
console.log(JSON.stringify({ verdict: v2.verdict, newDetections: v2.newDetections, newActions: v2.newActions, note: v2.note, probeResult: v2.evidence.probeResult }));

await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data: 'del %TEMP%\\eicar.tmp' });
const honest = (v1.verdict === 'clean') && (v2.verdict === 'detected' || v2.verdict === 'blocked');
console.log('ORACLE-VERDICT:', honest ? 'TRUSTWORTHY (clean=safe, loud=flagged)' : 'MISCALIBRATED: benign=' + v1.verdict + ' eicar=' + v2.verdict);
