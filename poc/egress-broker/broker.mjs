// broker.mjs — the egress broker / proxy. It is the ONLY component the sandbox can
// reach the network through, and it does two jobs:
//   1. DENY-ALL egress with a per-workspace allowlist — anything off the list is 403.
//   2. Inject the broker-held credential on the outbound hop, so the key never has
//      to exist inside the sandbox. A request arriving WITH a sandbox-supplied auth
//      header has it stripped (a compromised sandbox can't smuggle or override creds).
// Every request is audited (allow/deny) — never the key value.

import http from 'node:http';
import { URL } from 'node:url';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { appendAudit } from '../enforcement-seam/util.mjs';
import { getKey } from './vault.mjs';

const LEDGER = join(dirname(fileURLToPath(import.meta.url)), 'egress-ledger.jsonl');
export { LEDGER };

// Only these request headers are forwarded from the sandbox; auth headers are NOT
// (the broker owns credentials, not the sandbox).
function safeHeaders(h) {
  const out = {};
  for (const k of ['content-type', 'content-length', 'accept']) if (h[k]) out[k] = h[k];
  return out;
}

/**
 * @param {{allowlist:string[], upstreamBase?:Record<string,string>}} cfg
 *   upstreamBase maps an allowlisted host to a base URL to forward to (for the demo,
 *   local mock servers). In production this is just `https://<host>`.
 */
export function createBroker({ allowlist, upstreamBase = {} }) {
  return http.createServer((req, res) => {
    const host = req.headers['x-enclave-egress-host'];
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const sandboxTriedToSendKey = !!(req.headers['x-api-key'] || req.headers['authorization']);

      // 1) deny-all + allowlist
      if (!host || !allowlist.includes(host)) {
        appendAudit(LEDGER, { ts: new Date().toISOString(), event: 'egress.block', host: host || '(none)', reason: 'deny-all: host not in allowlist' });
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'egress denied by policy (deny-all)', host: host || null, allowlist }));
        return;
      }

      // 2) inject the broker-held credential (outside the sandbox) and forward
      const key = getKey(host);
      const base = upstreamBase[host] || `https://${host}`;
      const target = new URL(base + (req.url || '/'));
      const opts = { method: req.method, headers: { ...safeHeaders(req.headers), 'x-api-key': key || '' } };

      const up = http.request(target, opts, upRes => {
        const ub = [];
        upRes.on('data', c => ub.push(c));
        upRes.on('end', () => {
          appendAudit(LEDGER, { ts: new Date().toISOString(), event: 'egress.allow', host,
            sandboxTriedToSendKey, keyInjectedByBroker: !!key /* value never logged */ });
          res.writeHead(upRes.statusCode || 200, { 'content-type': upRes.headers['content-type'] || 'application/json' });
          res.end(Buffer.concat(ub));
        });
      });
      up.on('error', e => { res.writeHead(502, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: 'upstream error', detail: e.message })); });
      up.end(body);
    });
  });
}
