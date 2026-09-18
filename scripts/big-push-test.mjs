const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
const t = await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data: 'powershell -NoProfile -Command "Write-Output (\'q\' * 1400)"' });
console.log('1400B task:', t.taskId);
for (let i = 0; i < 25; i++) {
  await sleep(2000);
  const { tasks } = await j('/api/channel/tasks?agent=' + AGENT);
  const x = (tasks || []).find((y) => y.taskId === t.taskId);
  if (x && x.status === 'resulted') { console.log('BIG RESULT: landed, preview len', (x.resultPreview || '').length); process.exit(0); }
}
console.log('BIG RESULT: NO-RESULT (burst-loss confirmed)');
