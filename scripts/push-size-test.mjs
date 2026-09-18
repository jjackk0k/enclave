// push-size-test.mjs <icmpAgentId> — which result sizes make it back over ICMP?
// Queues tasks with ~11B, ~100B, ~300B outputs. 96B is the agent's ICMP chunk
// boundary: if only sub-96B results land, multi-frame push is the bug.
const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
if (!AGENT) { console.error('usage: node push-size-test.mjs <icmpAgentId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function waitResult(agentId, taskId, s) {
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + agentId);
    const x = (tasks || []).find((y) => y.taskId === taskId);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return null;
}

const cases = [
  ['hostname', 'small(~11B)'],
  ['powershell -NoProfile -Command "Write-Output (\'y\' * 90)"', 'edge(~90B)'],
  ['powershell -NoProfile -Command "Write-Output (\'z\' * 300)"', 'multi(~300B)'],
];
for (const [cmd, label] of cases) {
  const t = await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data: cmd });
  const r = await waitResult(AGENT, t.taskId, 40);
  console.log(label, '=>', r === null ? 'NO-RESULT' : JSON.stringify((r || '').slice(0, 60)) + ' len~' + (r || '').length);
}
