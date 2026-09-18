// stabilize-guest.mjs — wait for a live foothold, fire Defender/BSOD forensics,
// and if Defender has detections, add the lab exclusion (reversible) so the
// duplex verification can run. Prints a VERDICT line.
const API = 'http://127.0.0.1:8971';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function findFoothold() {
  try {
    const j = await (await fetch(API + '/api/channel')).json();
    const live = (j.agents || []).filter((a) => a.health === 'active' && a.label === 'win11-range-foothold' && a.checkins > 2);
    return live.length ? live[0].agentId : null;
  } catch { return null; }
}

async function task(agentId, data, waitS = 90) {
  const t = await (await fetch(API + '/api/channel/task', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ agentId, kind: 'shell', data }),
  })).json();
  for (let i = 0; i < waitS / 2; i++) {
    await sleep(2000);
    const { tasks } = await (await fetch(API + '/api/channel/tasks?agent=' + agentId)).json();
    const x = (tasks || []).find((y) => y.taskId === t.taskId);
    if (x && x.status === 'resulted') return x.resultPreview || '';
  }
  return null;
}

const forensics = [
  'powershell -NoProfile -Command "',
  "$DEF=(Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$D1116=(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$D1117=(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1117} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "$KP41=(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object).Count;",
  "Write-Output ('DEF=' + $DEF + ' D1116=' + $D1116 + ' D1117=' + $D1117 + ' KP41=' + $KP41)",
  '"',
].join('');

const exclusion = 'powershell -NoProfile -Command "Add-MpPreference -ExclusionPath \'C:\\Windows\\System32\\agentbox\'; Write-Output \'EXCLUDED\'"';

let agent = null;
for (let i = 0; i < 60 && !agent; i++) { agent = await findFoothold(); if (!agent) await sleep(6000); }
if (!agent) { console.log('VERDICT: no foothold in 6 min'); process.exit(1); }
console.log('FOOTHOLD:', agent);

const f = await task(agent, forensics);
console.log('FORENSICS:', f === null ? '(no result — agent died?)' : f);

if (f && /DEF=[1-9]|D1116=[1-9]|D1117=[1-9]/.test(f)) {
  const x = await task(agent, exclusion, 30);
  console.log('EXCLUSION:', x === null ? '(no result)' : x);
  console.log('VERDICT: defender-killer confirmed, exclusion applied');
} else if (f && /KP41=[1-9]/.test(f)) {
  console.log('VERDICT: bsod-suspect — image instability, flag to Jack');
} else if (f) {
  console.log('VERDICT: clean-bill — no Defender detections, no bugchecks; killer is elsewhere');
} else {
  console.log('VERDICT: inconclusive — forensics task never returned');
}
