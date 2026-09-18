// debug-defender.mjs <agentId> — which Defender knobs are actually on, and does an
// on-demand scan flag the EICAR file that real-time ignored?
const API = 'http://127.0.0.1:8971';
const AGENT = process.argv[2];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function j(path, body) {
  const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
  return r.json();
}
async function task(data, s = 60) {
  const t = await j('/api/channel/task', { agentId: AGENT, kind: 'shell', data });
  for (let i = 0; i < s / 2; i++) {
    await sleep(2000);
    const { tasks } = await j('/api/channel/tasks?agent=' + AGENT);
    const x = (tasks || []).find((y) => y.taskId === t.taskId);
    if (x && x.status === 'resulted') return x.resultPreview;
  }
  return '(no result)';
}
console.log('STATUS:', JSON.stringify(await task('powershell -NoProfile -Command "$cs=Get-MpComputerStatus; Write-Output (\'AV=\' + $cs.AntivirusEnabled + \' SVC=\' + $cs.AMServiceEnabled + \' RTP=\' + $cs.RealTimeProtectionEnabled + \' OAP=\' + $cs.OnAccessProtectionEnabled + \' SIG=\' + $cs.AntivirusSignatureVersion)"')));
console.log('ON-DEMAND SCAN:', JSON.stringify(await task('powershell -NoProfile -Command "Start-MpScan -ScanPath C:\\Windows\\Temp\\eicar.tmp -ScanType CustomScan; Write-Output \'scan-done\'"', 120)));
console.log('THREATS AFTER SCAN:', JSON.stringify(await task('powershell -NoProfile -Command "(Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count"')));
console.log('FILE AFTER:', JSON.stringify(await task('if exist C:\\Windows\\Temp\\eicar.tmp (echo STILL-THERE) else (echo GONE)')));
