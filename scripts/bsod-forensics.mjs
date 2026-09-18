// bsod-forensics.mjs <agentId> — distinguish real BSODs from our own hard resets.
// Event 41 = any improper shutdown (BSOD *or* vmrun reset). Event 1001 (bugcheck)
// = BSOD only. Timestamps let us cross out the resets we caused ourselves.
const API = 'http://127.0.0.1:8971';
const agentId = process.argv[2];
if (!agentId) { console.error('usage: node bsod-forensics.mjs <agentId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ps = [
  'powershell -NoProfile -Command "',
  "$a=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41} -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated.ToString('HH:mm') }) -join ',';",
  "$b=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$c=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=6008} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "Write-Output ('41@[' + $a + '] BC1001=' + $b + ' 6008=' + $c)",
  '"',
].join('');

const t = await (await fetch(API + '/api/channel/task', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ agentId, kind: 'shell', data: ps }),
})).json();
console.log('task queued:', t.taskId);
for (let i = 0; i < 30; i++) {
  await sleep(2000);
  const { tasks } = await (await fetch(API + '/api/channel/tasks?agent=' + agentId)).json();
  const x = (tasks || []).find((y) => y.taskId === t.taskId);
  if (x && x.status === 'resulted') { console.log('BSOD-FORENSICS:', x.resultPreview); process.exit(0); }
}
console.log('TIMEOUT: no result in 60s');
process.exit(1);
