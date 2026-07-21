// smoke.mjs — prove the DEPLOYED Cedar PDP answers authorization over the network,
// the same decisions the in-process demo makes. Run after `docker compose up -d`.
const BASE = process.env.PDP_URL || 'http://127.0.0.1:8990';
const get = p => fetch(BASE + p).then(r => r.json());
const post = (p, b) => fetch(BASE + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }).then(r => r.json());

(async () => {
  const health = await get('/health');
  const deny = await post('/authorize', { principalId: 'sam', action: 'deleteFiles', resource: { type: 'Workspace', id: 'triage-queue' }, context: {} });
  const allow = await post('/authorize', { principalId: 'dana', action: 'deleteFiles', resource: { type: 'Workspace', id: 'incident-2231' }, context: {} });
  const offscope = await post('/authorize', { principalId: 'marcus', action: 'networkScan', resource: { type: 'Target', id: '9.9.9.9' }, context: { inScope: false } });

  console.log('deployed PDP:', JSON.stringify(health));
  console.log(`  sam · deleteFiles (under-cleared)  → ${deny.decision}   (expect deny)`);
  console.log(`  dana · deleteFiles (own workspace) → ${allow.decision}  (expect allow)`);
  console.log(`  marcus · networkScan (off-scope)   → ${offscope.decision}   (expect deny)`);

  const ok = health.ok && deny.decision === 'deny' && allow.decision === 'allow' && offscope.decision === 'deny';
  console.log(ok ? '\nDEPLOY-SMOKE: PASS ✓' : '\nDEPLOY-SMOKE: FAIL ✗');
  process.exit(ok ? 0 : 1);
})().catch(e => { console.error('smoke error (is the PDP up? `docker compose up -d --build`):', e.message); process.exit(1); });
