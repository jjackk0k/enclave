// debug-bytes.mjs <agentId> — first bytes of the eicar file: a BOM breaks the
// signature at byte 0 and explains RTP silence.
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
console.log('BYTES:', JSON.stringify(await task('powershell -NoProfile -Command "$l=(Get-Content -Path \'C:\\Users\\Public\\eicar.txt\' -Encoding Byte -TotalCount 8) -join \' \'; $n=(Get-Item \'C:\\Users\\Public\\eicar.txt\').Length; Write-Output (\'\' + $n + \'b: \' + $l)"')));
