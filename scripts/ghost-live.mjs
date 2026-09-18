// ghost-live.mjs — live verification of the Tor free-identity path (one-shot).
// Restarts VARVEL, then: (a) GET /api/ghost (expect tor detected:false on this box),
// (b) arm 'on' with EMPTY chain (expect the honest free-path error — the old silent bug),
// (c) with a local SOCKS5 stub on 9050, arm again (expect auto-chain + honest verify
// failure, since the stub greets but cannot proxy), (d) reset to off.
import net from 'node:net';

const API_E = 'http://127.0.0.1:8977';
const API_V = 'http://127.0.0.1:8971';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const j = async (p) => { try { const r = await p; const body = await r.json(); return { status: r.status, body }; } catch (e) { return { status: 0, body: { err: String(e) } }; } };
const post = (u, b) => j(fetch(u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b || {}) }));

console.log('[1] varvel restart on new build...');
console.log('    stop:', JSON.stringify((await post(API_E + '/api/varvel/stop')).body));
await sleep(2000);
console.log('    open:', JSON.stringify((await post(API_E + '/api/varvel/open')).body));
let up = false;
for (let i = 0; i < 30 && !up; i++) { await sleep(1000); const c = await j(fetch(API_V + '/api/ghost')); up = c.status === 200; }
console.log('    reachable:', up);
if (!up) { console.log('FATAL'); process.exit(1); }

const g0 = await j(fetch(API_V + '/api/ghost'));
console.log('[2] GET /api/ghost: mode=' + g0.body.mode + ' tor=' + JSON.stringify(g0.body.tor));

const noTor = await post(API_V + '/api/ghost', { mode: 'on', chain: '' });
console.log('[3] arm on/empty, NO Tor: http ' + noTor.status + ' -> ' + JSON.stringify(noTor.body).slice(0, 260));

const stub = net.createServer((s) => { s.on('data', () => s.write(Buffer.from([0x05, 0x00]))); s.on('error', () => {}); });
await new Promise((res) => stub.listen(9050, '127.0.0.1', res));
console.log('[4] SOCKS5-greeting stub up on 127.0.0.1:9050 (greets, cannot proxy)');

const withTor = await post(API_V + '/api/ghost', { mode: 'on', chain: '' });
const b = withTor.body || {};
console.log('[5] arm on/empty, Tor present: http ' + withTor.status);
console.log('    mode=' + b.mode + ' chain=' + JSON.stringify(b.chain) + ' tor=' + JSON.stringify(b.tor));
console.log('    verified=' + JSON.stringify(b.verified));

const reset = await post(API_V + '/api/ghost', { mode: 'off', chain: '' });
console.log('[6] reset: mode=' + (reset.body && reset.body.mode));
stub.close();
console.log('GHOST-LIVE-DONE');
