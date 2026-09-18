// debug-exclusions.mjs <agentId> — dump Defender exclusions, then write EICAR to a
// path outside any exclusion and snapshot the detection counters.
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
const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
console.log('EXCLUSIONS:', JSON.stringify(await task('powershell -NoProfile -Command "$p=Get-MpPreference; Write-Output (\'PATH=[\' + ($p.ExclusionPath -join \';\') + \'] EXT=[\' + ($p.ExclusionExtension -join \';\') + \'] PROC=[\' + ($p.ExclusionProcess -join \';\') + \'])"')));
console.log('WRITE PUBLIC:', JSON.stringify(await task('powershell -NoProfile -Command "Set-Content -Path \'C:\\Users\\Public\\eicar.txt\' -Value \'' + EICAR + '\'; Write-Output \'written\'"')));
await sleep(6000);
console.log('THREATS:', JSON.stringify(await task('powershell -NoProfile -Command "(Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count"')));
console.log('FILE:', JSON.stringify(await task('if exist C:\\Users\\Public\\eicar.txt (echo STILL-THERE) else (echo GONE)')));
