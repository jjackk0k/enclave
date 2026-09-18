// fp-live.mjs — live verification for the fporacle build (one-shot, re-runnable).
// Restarts VARVEL on the new build, arms the channel, holds the lab, then polls
// /api/fp until a real agent check-in has been fingerprinted. Prints the evidence.
const API_E = 'http://127.0.0.1:8977';
const API_V = 'http://127.0.0.1:8971';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (p) => { try { const r = await p; return await r.json(); } catch (e) { return { _err: String((e && e.cause && e.cause.code) || e) }; } };
const post = (u, b) => j(fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) }));

console.log('[1] hold lab (fp-live, 30min):', JSON.stringify(await post(API_E + '/api/vm-lab/hold', { owner: 'fp-live', minutes: 30 })));
console.log('[2] varvel stop:', JSON.stringify(await post(API_E + '/api/varvel/stop')));
await sleep(2000);
console.log('[3] varvel open (new build):', JSON.stringify(await post(API_E + '/api/varvel/open')));
let up = false;
for (let i = 0; i < 30 && !up; i++) { await sleep(1000); const c = await j(fetch(API_V + '/api/channel')); up = c && !c._err; }
console.log('[4] varvel reachable:', up);
if (!up) { console.log('FATAL: varvel did not come up'); process.exit(1); }
console.log('[5] arm:', JSON.stringify(await post(API_V + '/api/channel/arm')));

let seen = null;
for (let i = 1; i <= 24; i++) {
  await sleep(10000);
  const fp = await j(fetch(API_V + '/api/fp'));
  const n = (fp && fp.observations && fp.observations.length) || 0;
  console.log('[poll ' + i + '] distinctJa4h=' + (fp && fp.distinctJa4h) + ' observations=' + n);
  if (n > 0) { seen = fp; break; }
}
if (seen) {
  console.log('FP-LIVE-OK ' + JSON.stringify(seen.observations[seen.observations.length - 1]));
  const distinct = [...new Set(seen.observations.map((o) => o.ja4h))];
  console.log('distinct ja4h: ' + JSON.stringify(distinct));
} else {
  console.log('FP-LIVE-EMPTY: no HTTP observations in 4 min (agent may be wedged or ICMP-only)');
}
