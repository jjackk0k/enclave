// broker-server.mjs — runs INSIDE the broker container. Dual-homed: it receives
// from the sandbox (on the internal, no-internet network) and forwards to the
// upstream (on a separate network the sandbox can't reach). It (1) denies anything
// off the allowlist and (2) injects the broker-held key on the outbound hop, after
// STRIPPING any credential the sandbox tried to send.
import http from 'node:http';

const ALLOW = ['api.anthropic.com', 'case-ledger.internal'];
const KEY = process.env.ENCLAVE_KEY || 'sk-ant-BROKER-HELD';
const UPSTREAM = process.env.UPSTREAM_URL || 'http://enclave-fs-upstream:9090';
const redact = k => (k ? k.slice(0, 10) + '…redacted' : k);

http.createServer((req, res) => {
  const host = req.headers['x-egress-host'];
  const sandboxSentKey = !!(req.headers['x-api-key'] || req.headers['authorization']);
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    if (!host || !ALLOW.includes(host)) {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ allowed: false, reason: `deny-all: ${host || 'none'} not in allowlist`, allowlist: ALLOW }));
      return;
    }
    const u = new URL(UPSTREAM);
    const body = Buffer.concat(chunks);
    const up = http.request({ hostname: u.hostname, port: u.port, path: '/', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': body.length, 'x-api-key': KEY, 'x-egress-host': host } },
      ur => { let b = ''; ur.on('data', c => (b += c)); ur.on('end', () => {
        let uj; try { uj = JSON.parse(b); } catch { uj = {}; }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ allowed: true, host, sandboxSentKey, keyInjectedByBroker: true, keyPrefix: redact(KEY), upstream: uj }));
      }); });
    up.on('error', e => { res.writeHead(502, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'upstream', detail: e.code })); });
    up.end(body);
  });
}).listen(8080, () => console.log('broker up on 8080'));
