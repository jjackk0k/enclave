// post-reset-read.mjs — after a guest reset: wait for the fresh foothold, then
// (1) dump the persisted listen log, (2) run BSOD forensics (Event 41 times +
// bugcheck 1001 + unexpected-shutdown 6008). Serial on the foothold task loop.
const API = 'http://127.0.0.1:8971';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function findFoothold() {
  try {
    const j = await (await fetch(API + '/api/channel')).json();
    const live = (j.agents || []).filter((a) => a.health === 'active' && a.label === 'win11-range-foothold' && a.checkins > 2);
    return live.length ? live[0].agentId : null;
  } catch { return null; }
}

async function task(agentId, data, waitS = 60) {
  const t = await (await fetch(API + '/api/channel/task', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ agentId, kind: 'shell', data }),
  })).json();
  if (!t.taskId) return '(rejected: ' + JSON.stringify(t) + ')';
  for (let i = 0; i < waitS / 2; i++) {
    await sleep(2000);
    const { tasks } = await (await fetch(API + '/api/channel/tasks?agent=' + agentId)).json();
    const x = (tasks || []).find((y) => y.taskId === t.taskId);
    if (x && x.status === 'resulted') return x.resultPreview || '(empty result)';
  }
  return '(no result in ' + waitS + 's)';
}

let agent = null;
for (let i = 0; i < 60 && !agent; i++) { agent = await findFoothold(); if (!agent) await sleep(6000); }
if (!agent) { console.log('VERDICT: no foothold in 6 min'); process.exit(1); }
console.log('FOOTHOLD:', agent);

console.log('LISTEN-LOG:', JSON.stringify(await task(agent, 'type C:\\Windows\\Temp\\icmp-listen.log')));

const bsod = [
  'powershell -NoProfile -Command "',
  "$a=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41} -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated.ToString('HH:mm') }) -join ',';",
  "$b=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$c=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "Write-Output ('41@[' + $a + '] BC1001=' + $b + ' 6008=' + $c)",
  '"',
].join('');
console.log('BSOD-FORENSICS:', JSON.stringify(await task(agent, bsod)));
