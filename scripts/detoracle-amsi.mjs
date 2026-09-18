// detoracle-amsi.mjs <agentId> — oracle proof via the AMSI test sample (the EICAR
// of script scanning): Invoke-Expression of the official AMSI test string must light
// up Defender (1116) while a benign probe stays clean.
import { assess } from '../varvel/tools/detoracle.mjs';

const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
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

const AMSI = 'powershell -NoProfile -Command "Invoke-Expression \'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386\'"';

console.log('=== benign (expect clean) ===');
const v1 = await assess({ taskAgent, agentId: AGENT, command: 'hostname', settleMs: 4000 });
console.log(JSON.stringify({ verdict: v1.verdict, newDetections: v1.newDetections }));

console.log('=== AMSI sample (expect detected/blocked) ===');
const v2 = await assess({ taskAgent, agentId: AGENT, command: AMSI, settleMs: 8000 });
console.log(JSON.stringify({ verdict: v2.verdict, newDetections: v2.newDetections, newActions: v2.newActions, note: v2.note, probeResult: v2.evidence.probeResult, before: v2.evidence.before, after: v2.evidence.after }));
const honest = v1.verdict === 'clean' && (v2.verdict === 'detected' || v2.verdict === 'blocked');
console.log('ORACLE-VERDICT:', honest ? 'TRUSTWORTHY' : 'MISCALIBRATED: benign=' + v1.verdict + ' amsi=' + v2.verdict);
