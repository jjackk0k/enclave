const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
const t = await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data: 'rem produces-no-output' });
console.log('rem task:', t.taskId);
for (let i = 0; i < 20; i++) {
  await sleep(2000);
  const { tasks } = await j('/api/channel/tasks?agent=' + AGENT);
  const x = (tasks || []).find((y) => y.taskId === t.taskId);
  if (x && x.status === 'resulted') { console.log('REM RESULT:', JSON.stringify(x.resultPreview)); process.exit(0); }
}
console.log('REM RESULT: NO-RESULT (zero-byte push bug CONFIRMED)');
