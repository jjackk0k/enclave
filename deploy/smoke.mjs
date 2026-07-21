// smoke.mjs — prove the DEPLOYED control plane works over the network, the same
// decisions the in-process demos make. Run after `docker compose up -d --build`.
const PDP = process.env.PDP_URL || 'http://127.0.0.1:8990';
const BROKER = process.env.BROKER_URL || 'http://127.0.0.1:8080';
const get = u => fetch(u).then(r => r.json());
const post = (u, b, h = {}) => fetch(u, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: JSON.stringify(b) }).then(async r => ({ status: r.status, json: await r.json() }));

let ok = true;
const line = (label, got, pass) => { if (!pass) ok = false; console.log(`  ${pass ? '✓' : '✗'} ${label} → ${got}`); };

(async () => {
  // ── PDP ──
  console.log('\n  Cedar PDP (authorization):');
  const health = await get(PDP + '/health');
  line('health', JSON.stringify(health), health.ok);
  const deny = (await post(PDP + '/authorize', { principalId: 'sam', action: 'deleteFiles', resource: { type: 'Workspace', id: 'triage-queue' }, context: {} })).json;
  line('sam · deleteFiles (under-cleared)  = deny', deny.decision, deny.decision === 'deny');
  const allow = (await post(PDP + '/authorize', { principalId: 'dana', action: 'deleteFiles', resource: { type: 'Workspace', id: 'incident-2231' }, context: {} })).json;
  line('dana · deleteFiles (own workspace) = allow', allow.decision, allow.decision === 'allow');
  const off = (await post(PDP + '/authorize', { principalId: 'marcus', action: 'networkScan', resource: { type: 'Target', id: '9.9.9.9' }, context: { inScope: false } })).json;
  line('marcus · networkScan (off-scope)   = deny', off.decision, off.decision === 'deny');

  // ── broker ──
  console.log('\n  Egress broker (deny-all + key injection):');
  const allowed = await post(BROKER + '/v1/messages', { prompt: 'hi' }, { 'x-egress-host': 'api.anthropic.com' });
  const upstreamSaw = allowed.json?.upstream?.upstreamSawApiKey;
  line('api.anthropic.com: broker injects key, upstream receives it', `${allowed.status} · upstreamSawKey=${upstreamSaw}`, allowed.status === 200 && upstreamSaw === true);
  const exfil = await post(BROKER + '/x', { data: 'secret' }, { 'x-egress-host': 'pastebin.com' });
  line('pastebin.com: exfil denied', `${exfil.status}`, exfil.status === 403);

  console.log('\n' + (ok ? 'DEPLOY-SMOKE: PASS ✓' : 'DEPLOY-SMOKE: FAIL ✗') + '\n');
  process.exit(ok ? 0 : 1);
})().catch(e => { console.error('smoke error (is the stack up? `docker compose up -d --build`):', e.message); process.exit(1); });
