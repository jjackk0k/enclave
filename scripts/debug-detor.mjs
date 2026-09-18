// debug-detor.mjs <agentId> — raw state after the EICAR probe: snapshot output,
// eicar file presence, and a raw threat-detection count.
import { buildSnapshotCommand } from '../varvel/tools/detoracle.mjs';
const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function task(data, s = 40) {
  const t = await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data });
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + AGENT);
    const x = (tasks || []).find((y) => y.taskId === t.taskId);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return '(no result)';
}
console.log('SNAPSHOT RAW:', JSON.stringify(await task(buildSnapshotCommand())));
console.log('EICAR FILE:', JSON.stringify(await task('type C:\\Windows\\Temp\\eicar.tmp 2>&1')));
console.log('THREATS RAW:', JSON.stringify(await task('powershell -NoProfile -Command "(Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count"')));
