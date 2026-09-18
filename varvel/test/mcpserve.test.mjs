// mcpserve.test.mjs — Direction A: VARVEL as an MCP server (tools/mcpserve.mjs).
// In-process handleMessage tests (spy runners prove the bridge gates BEFORE the tool
// runs) + one REAL stdio round-trip against a hermetic loopback HTTP fixture, with
// the audit ledger asserted from disk. All artifacts under varvel/.tmp (house rule).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { createVarvelMcpServer, varvelTools } from '../tools/mcpserve.mjs';

const TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'mcpserve-test');
mkdirSync(TMP, { recursive: true });

const SCOPE = { engagement: 'mcp-test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };

const mkServer = (over = {}) => {
  const audit = [];
  const calls = [];
  const spy = (name) => async (...args) => { calls.push([name, ...args]); return { ran: name }; };
  const tools = varvelTools({ engagement: 'mcp-test', readImpl: { crawl: spy('crawl'), webScan: spy('webscan'), apiSurface: spy('apisurface'), scanHost: spy('recon'), analyzeTls: spy('tlsscan') } });
  const srv = createVarvelMcpServer({ scope: SCOPE, ghost: { mode: 'off', verifiedOk: false }, engagement: 'mcp-test', auditSink: (e) => audit.push(e), tools, ...over });
  return { srv, audit, calls };
};
const call = (srv, name, args, id = 7) => srv.handleMessage({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

test('initialize: handshake negotiates protocolVersion and names the server; tools/list shows the curated surface', async () => {
  const { srv } = mkServer();
  const init = await srv.handleMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } });
  assert.equal(init.result.protocolVersion, '2025-06-18');
  assert.equal(init.result.serverInfo.name, 'varvel-mcp');
  const list = await srv.handleMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  const names = list.result.tools.map((t) => t.name);
  assert.deepEqual(names, ['varvel_ghost_status', 'varvel_state_query', 'varvel_recon', 'varvel_webscan', 'varvel_apisurface', 'varvel_crawl', 'varvel_tlsscan']);
  for (const t of list.result.tools) assert.deepEqual(Object.keys(t).sort(), ['description', 'inputSchema', 'name']); // policy never leaks
});

test('server disabled: initialize is refused with an error, and the refusal is audited', async () => {
  const { srv, audit } = mkServer({ serverEnabled: false });
  const r = await srv.handleMessage({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
  assert.equal(r.error.code, -32603);
  assert.match(r.error.message, /disabled/);
  assert.equal(audit[0].verdict, 'deny');
});

test('in-scope target-touching call: bridge allows, the tool runs, result is MCP-shaped', async () => {
  const { srv, calls, audit } = mkServer();
  const r = await call(srv, 'varvel_crawl', { url: 'http://127.0.0.1:8000/', maxPages: 5 });
  assert.equal(r.result.isError, undefined);
  assert.deepEqual(r.result.structuredContent, { ran: 'crawl' });
  assert.deepEqual(calls, [['crawl', 'http://127.0.0.1:8000/', { maxPages: 5 }]]); // runner receives (url, opts) like cli.mjs calls it
  assert.equal(audit.at(-1).verdict, 'allow');
  assert.match(audit.at(-1).argsDigest, /^sha256:/);
});

test('out-of-scope call: DENIED before the tool runs (spy never fires), isError result, audited', async () => {
  const { srv, calls, audit } = mkServer();
  const r = await call(srv, 'varvel_webscan', { url: 'http://10.9.9.9/' });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /DENIED.*outside the signed scope/);
  assert.equal(calls.length, 0);
  assert.equal(audit.at(-1).verdict, 'deny');
});

test('hold path: unsurfaced hostname HELDS, tool never runs, operator-resolution hint given', async () => {
  const { srv, calls, audit } = mkServer();
  const r = await call(srv, 'varvel_tlsscan', { host: 'mail.lab.example' });
  assert.equal(r.result.isError, true);
  assert.match(r.result.content[0].text, /HELD/);
  assert.match(r.result.content[0].text, /operator/);
  assert.equal(calls.length, 0);
  assert.equal(audit.at(-1).verdict, 'hold');
});

test('ghost-required-down: target-touching refused while read-only tools still answer', async () => {
  const { srv, calls } = mkServer({ ghost: { mode: 'required', verifiedOk: false } });
  const denied = await call(srv, 'varvel_recon', { host: '127.0.0.1' });
  assert.equal(denied.result.isError, true);
  assert.match(denied.result.content[0].text, /identity chain is unverified/);
  assert.equal(calls.length, 0);
  const ro = await call(srv, 'varvel_ghost_status', {});
  assert.equal(ro.result.isError, undefined);
  assert.equal(ro.result.structuredContent.mode, 'off'); // posture answer, not a target
});

test('read-only state query: counts + REDACTED listing (a stored cred secret never leaves)', async () => {
  const dataDir = join(TMP, 'data-' + process.pid);
  mkdirSync(dataDir, { recursive: true });
  process.env.VARVEL_DATA_DIR = dataDir;
  try {
    const { upsert } = await import('../engine/statestore.mjs');
    const eng = 'mcp-redact-' + process.pid;
    upsert(eng, 'creds', { kind: 'password', principal: 'admin', secret: 'TOPSECRET-VALUE' });
    const { srv } = mkServer({ engagement: eng, tools: varvelTools({ engagement: eng }) });
    const r = await call(srv, 'varvel_state_query', { kind: 'creds' });
    assert.equal(r.result.structuredContent.counts.creds, 1);
    assert.equal(r.result.structuredContent.creds[0].secret, '[REDACTED]');
    assert.ok(!JSON.stringify(r.result).includes('TOPSECRET-VALUE'));
  } finally { delete process.env.VARVEL_DATA_DIR; }
});

test('unknown tool: INVALID_PARAMS error, nothing audited as a call, nothing runs', async () => {
  const { srv, calls, audit } = mkServer();
  const r = await call(srv, 'varvel_nope', {});
  assert.equal(r.error.code, -32602);
  assert.equal(calls.length, 0);
  assert.equal(audit.length, 0);
});

// ── the real stdio round-trip (spawned server, newline-delimited JSON-RPC) ────

test('stdio: spawn tools/mcpserve.mjs, handshake, list, governed calls, audit ledger on disk', async (t) => {
  // hermetic loopback target
  const fixture = http.createServer((req, res) => {
    if (req.url === '/') { res.setHeader('content-type', 'text/html'); res.end('<html><body><a href="/about">a</a></body></html>'); }
    else if (req.url === '/about') res.end('<html><body>about</body></html>');
    else { res.statusCode = 404; res.end('nf'); }
  });
  await new Promise((r) => fixture.listen(0, '127.0.0.1', r));
  const port = fixture.address().port;

  const auditFile = join(TMP, 'serve-audit-' + process.pid + '.jsonl');
  const dataDir = join(TMP, 'serve-data-' + process.pid);
  const child = spawn(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'mcpserve.mjs')], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
      VARVEL_MCP_SERVER: '1',                       // explicit operator enable
      VARVEL_MCP_SCOPE: '127.0.0.0/8',              // the signed-ring stand-in
      VARVEL_ENGAGEMENT: 'mcp-stdio-' + process.pid,
      VARVEL_DATA_DIR: dataDir,
      VARVEL_SETTINGS_FILE: join(dataDir, 'settings.json'), // absent -> schema defaults (ghost off)
      VARVEL_MCP_AUDIT_FILE: auditFile,
    },
  });
  t.after(() => { try { child.kill(); } catch { /* */ } fixture.close(); });

  let buf = '';
  const pending = new Map();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (c) => {
    buf += c; let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (!line) continue;
      let m; try { m = JSON.parse(line); } catch { continue; }
      if (m.id != null && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    }
  });
  const send = (msg) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('stdio response timeout for id ' + msg.id)), 20000);
    pending.set(msg.id, (m) => { clearTimeout(timer); resolve(m); });
    child.stdin.write(JSON.stringify(msg) + '\n');
  });

  const init = await send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '0' } } });
  assert.equal(init.result.protocolVersion, '2025-03-26'); // older client version echoes
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

  const list = await send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.equal(list.result.tools.length, 7);

  // real governed tool run against the hermetic fixture (in-scope: 127.0.0.0/8)
  const crawlRes = await send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'varvel_crawl', arguments: { url: `http://127.0.0.1:${port}/`, maxPages: 3 } } });
  assert.equal(crawlRes.result.isError, undefined);
  const eps = (crawlRes.result.structuredContent.endpoints || []).map((e) => e.url || e.path || '');
  assert.ok(eps.some((u) => String(u).includes('/about')), 'crawl should surface /about, got: ' + JSON.stringify(eps));

  // out-of-scope: DENIED over the wire, and no request ever leaves (bridge pre-dispatch)
  const deny = await send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'varvel_webscan', arguments: { url: 'http://192.0.2.9/' } } });
  assert.equal(deny.result.isError, true);
  assert.match(deny.result.content[0].text, /DENIED/);

  // malformed frame: parse error, server stays alive
  child.stdin.write('{garbage line\n');
  const still = await send({ jsonrpc: '2.0', id: 5, method: 'ping' });
  assert.deepEqual(still.result, {});

  // the audit ledger on disk: every call above, digests only, no secrets
  assert.ok(existsSync(auditFile), 'audit ledger missing at ' + auditFile);
  const entries = readFileSync(auditFile, 'utf8').trim().split('\n').map(JSON.parse);
  const calls = entries.filter((e) => e.kind === 'mcp.call' && e.tool.startsWith('varvel_'));
  assert.deepEqual(calls.map((e) => e.verdict), ['allow', 'deny']);
  assert.equal(calls[0].tool, 'varvel_crawl');
  assert.equal(calls[1].tool, 'varvel_webscan');
  assert.ok(calls.every((e) => /^sha256:[0-9a-f]{64}$/.test(e.argsDigest)));
  assert.ok(entries.some((e) => e.tool === 'mcp.initialize'));
}, { timeout: 60000 });
