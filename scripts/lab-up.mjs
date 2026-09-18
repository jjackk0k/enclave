// lab-up.mjs — cold-start helper: hold the lab, then labUp (revert+boot) and report.
// Used at breach-test kickoff; holds protect the window from the Enclave watchdog.
const API_E = 'http://127.0.0.1:8977';
const j = async (p) => { try { const r = await p; return await r.json(); } catch { return {}; } };
const post = (u, b) => j(fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) }));

console.log('[1] hold (breach-test, 60min):', JSON.stringify(await post(API_E + '/api/vm-lab/hold', { owner: 'breach-test', minutes: 60 })));
const st0 = await j(fetch(API_E + '/api/vm-lab'));
console.log('[2] before: targetRunning=' + st0.targetRunning);
if (!st0.targetRunning) {
  console.log('[3] labUp (revert+boot) — takes minutes...');
  const m = await import('../vm-lab.mjs');
  const st = await m.labUp();
  console.log('[4] after: ' + JSON.stringify(st));
} else {
  console.log('[3] already running — no revert (kept as-is)');
}
