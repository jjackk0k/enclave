// range-iso loopback-only HTTP transport for the mcp-poison lab.
// The MCP/JSON-RPC message layer is engine/mcprpc.mjs (unchanged); this file is ONLY
// a socket. Hard rule: fixtures bind 127.0.0.1 / ::1 / localhost and NOTHING else —
// assertLoopback is the choke-point, and serveLoopback calls it before listen().

import http from 'node:http';

export const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

export function assertLoopback(host) {
  const h = String(host || '').trim().toLowerCase();
  if (!LOOPBACK_HOSTS.has(h)) {
    throw new Error(`range-iso lab fixtures bind loopback only — refused bind host ${JSON.stringify(host)}`);
  }
  return h;
}

// Mount one fixture server ({ name, handleMessage }) on 127.0.0.1:<ephemeral>.
// POST / accepts ONE JSON-RPC message (JSON body) and answers with the response
// (204 for notifications). GET /health is the boot probe the tests use.
export async function serveLoopback({ name = 'fixture', handleMessage, host = '127.0.0.1', port = 0 } = {}) {
  const bindHost = assertLoopback(host);
  if (typeof handleMessage !== 'function') throw new TypeError('serveLoopback needs handleMessage');
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, name, transport: 'loopback-http' }));
      return;
    }
    if (req.method !== 'POST' || req.url !== '/') {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (c) => { body += c; if (body.length > (1 << 20)) req.destroy(); });
    req.on('end', async () => {
      let msg;
      try { msg = JSON.parse(body); } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
        return;
      }
      try {
        const out = await handleMessage(msg);
        if (out === null || out === undefined) { res.writeHead(204); res.end(); return; }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(out));
      } catch (e) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: String((e && e.message) || e) } }));
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, bindHost, () => {
      const addr = server.address();
      resolve({
        name,
        server,
        host: addr.address,
        port: addr.port,
        url: `http://${addr.address === '::1' ? '[::1]' : addr.address}:${addr.port}`,
        address: () => server.address(),
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

// Minimal JSON-RPC client for the harness/tests (loopback URLs only — same rule).
export function makeClient(url) {
  const u = new URL(url);
  assertLoopback(u.hostname.replace(/^\[|\]$/g, ''));
  let nextId = 1;
  async function rpc(method, params = {}) {
    const id = nextId++;
    const res = await fetch(u, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    });
    if (res.status === 204) return null;
    const msg = await res.json();
    if (msg.error) { const e = new Error(`RPC ${msg.error.code}: ${msg.error.message}`); e.rpc = msg.error; throw e; }
    return msg.result;
  }
  return {
    url,
    initialize: () => rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'mcp-poison-lab', version: '0.1.0' } }),
    listTools: async () => (await rpc('tools/list', {})).tools,
    callTool: async (name, args = {}) => rpc('tools/call', { name, arguments: args }),
  };
}
