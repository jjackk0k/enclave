// forensics-guest.mjs <agentId> — settle Defender-vs-BSOD on the range guest.
// Fires a governed shell task: Defender threat-detection count, Defender
// Operational 1116/1117 counts, kernel-power 41 count. Prints FORENSICS: line.
const API = 'http://127.0.0.1:8971';
const agentId = process.argv[2];
if (!agentId) { console.error('usage: node forensics-guest.mjs <agentId>'); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ps = [
  'powershell -NoProfile -Command "',
  "$DEF=(Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$D1116=(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$D1117=(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1117} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$KP41=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "Write-Output ('DEF=' + $DEF + ' D1116=' + $D1116 + ' D1117=' + $D1117 + ' KP41=' + $KP41)",
  '"',
].join('');

const t = await (await fetch(API + '/api/channel/task', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ agentId, kind: 'shell', data: ps }),
})).json();
console.log('task queued:', t.taskId);
for (let i = 0; i < 40; i++) {
  await sleep(2000);
  const { tasks } = await (await fetch(API + '/api/channel/tasks?agent=' + agentId)).json();
  const x = (tasks || []).find((y) => y.taskId === t.taskId);
  if (x && x.status === 'resulted') { console.log('FORENSICS:', x.resultPreview); process.exit(0); }
  if (x && x.status === 'delivered' && i % 5 === 4) console.log('...delivered, awaiting result');
}
console.log('TIMEOUT: no result in 80s');
process.exit(1);
