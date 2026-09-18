const API = 'http://127.0.0.1:8971';
const agentId = process.argv[2];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function task(data, waitS = 40) {
  const t = await (await fetch(API + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId, kind: 'shell', data }) })).json();
  for (let i = 0; i < waitS / 2; i++) {
    await sleep(2000);
    const { tasks } = await (await fetch(API + '/api/channel/tasks?agent=' + agentId)).json();
    const x = (tasks || []).find((y) => y.taskId === t.taskId);
    if (x && x.status === 'resulted') return x.resultPreview || '(empty)';
  }
  return '(no result)';
}
console.log('RULE:', JSON.stringify(await task('netsh advfirewall firewall show rule name=VARVEL-lab-ICMP-in')));
console.log('PROFILE:', JSON.stringify(await task('powershell -NoProfile -Command "(Get-NetConnectionProfile | Select-Object -First 1).Name + \'/\' + (Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory"')));
console.log('MATRIX2-LOG:', JSON.stringify(await task('type C:\Windows\Temp\icmp-matrix.log')));
