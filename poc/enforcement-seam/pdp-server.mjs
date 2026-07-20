#!/usr/bin/env node
// pdp-server.mjs — the Cedar Policy Decision Point as a NETWORK SERVICE.
//
// The PoC evaluates Cedar in-process for a self-contained demo. Production doesn't:
// the PEP (the PreToolUse hook) calls a PDP *service* over mTLS so the decision lives
// entirely outside the sandbox host. This is that service (plain HTTP here). It loads
// the same policies + entities and answers /authorize. Point the hook at it and the
// enforcement demo is byte-for-byte unchanged — same 20/20.
//
//   node pdp-server.mjs
//   ENCLAVE_PDP_URL=http://127.0.0.1:8990  node demo.mjs

import http from 'node:http';
import { authorize, cedarVersion } from './policy-engine.mjs';

const PORT = Number(process.env.PDP_PORT) || 8990;

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, cedar: cedarVersion }));
  }
  if (req.url === '/authorize' && req.method === 'POST') {
    let b = '';
    req.on('data', c => (b += c));
    req.on('end', () => {
      let q;
      try { q = JSON.parse(b || '{}'); }
      catch { res.writeHead(400, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ decision: 'deny', errors: ['bad request'] })); }
      const verdict = authorize(q); // real Cedar, decided out-of-process from the sandbox
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(verdict));
    });
    return;
  }
  res.writeHead(404); res.end('not found');
});

server.listen(PORT, '127.0.0.1', () => console.log(`Cedar PDP (v${cedarVersion}) on http://127.0.0.1:${PORT}  ·  POST /authorize`));
