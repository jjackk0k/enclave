// mcpclient.test.mjs — Direction B: VARVEL as an MCP client (engine/mcpclient.mjs).
// The crux assertions: external servers are never auto-discovered, mcp.allowExternal
// gates the SPAWN itself, and an out-of-scope call is DENIED before the child exists
// (spy assertion). Fixture servers are payload-class test artifacts: they live under
// varvel/.tmp per the house rule — NEVER os.tmpdir().
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpClient, loadExternalServers } from '../engine/mcpclient.mjs';

const TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'mcpclient-test');
mkdirSync(TMP, { recursive: true });

// ── fixture external MCP servers (test artifacts under varvel/.tmp) ──────────
// A well-behaved one: initialize/tools/list/tools/call ('echo' answers, 'hang' never
// replies — the timeout path). A garbage one: emits non-JSON then exits.
const FIXTURE = join(TMP, 'fixture-ext-server.mjs');
writeFileSync(FIXTURE, `// fixture external MCP server (test artifact — newline-delimited JSON-RPC)
let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  buf += c; let i;
  while ((i = buf.indexOf('\\n')) >= 0) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.id == null) continue; // notifications
    const reply = (result) => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result }) + '\\n');
    if (m.method === 'initialize') reply({ protocolVersion: (m.params || {}).protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'fixture-ext', version: '0.0.1' } });
    else if (m.method === 'tools/list') reply({ tools: [
      { name: 'echo', description: 'echoes its arguments', inputSchema: { type: 'object' } },
      { name: 'hang', description: 'never replies (timeout fixture)', inputSchema: { type: 'object' } },
    ] });
    else if (m.method === 'tools/call') {
      if ((m.params || {}).name === 'hang') continue; // silence -> the client must time out + reap
      reply({ content: [{ type: 'text', text: JSON.stringify((m.params || {}).arguments || {}) }] });
    }
    else process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'no such method' } }) + '\\n');
  }
});
`);
const GARBAGE = join(TMP, 'garbage-ext-server.mjs');
writeFileSync(GARBAGE, `process.stdout.write('this is not JSON-RPC at all\\n');\nsetTimeout(() => process.exit(1), 60);\n`);

const SCOPE = { engagement: 'mcp-ext-test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const EXT_SERVER = { name: 'fixture', command: process.execPath, args: [FIXTURE], env: {}, timeoutMs: 5000 };
const mkClient = (over = {}) => {
  const audit = [];
  const client = new McpClient({ server: EXT_SERVER, scope: SCOPE, externalAllowed: true, auditSink: (e) => audit.push(e), ...over });
  return { client, audit };
};

// ── config loading: explicit, absolute-path, never auto-discovered ───────────

test('loadExternalServers: missing file / relative command / valid registry', () => {
  const missing = loadExternalServers(join(TMP, 'no-such-file.json'));
  assert.equal(missing.ok, false);
  assert.match(missing.errors[0], /never auto-discovered/);

  const relFile = join(TMP, 'rel-servers.json');
  writeFileSync(relFile, JSON.stringify({ servers: [{ name: 'bad', command: 'node tools/x.mjs' }] }));
  const rel = loadExternalServers(relFile);
  assert.equal(rel.servers.length, 0);
  assert.match(rel.errors[0], /ABSOLUTE path/);

  const okFile = join(TMP, 'ok-servers.json');
  writeFileSync(okFile, JSON.stringify({ servers: [{ name: 'fixture', command: process.execPath, args: [FIXTURE], env: { FOO: 'bar' }, timeoutMs: 4000 }] }));
  const ok = loadExternalServers(okFile);
  assert.equal(ok.ok, true);
  assert.equal(ok.servers[0].name, 'fixture');
  assert.equal(ok.servers[0].timeoutMs, 4000);
  assert.deepEqual(ok.servers[0].env, { FOO: 'bar' });
});

test('loadExternalServers: corrupt JSON fails closed with an honest error, never throws', () => {
  const bad = join(TMP, 'corrupt-servers.json');
  writeFileSync(bad, '{not json');
  const r = loadExternalServers(bad);
  assert.equal(r.servers.length, 0);
  assert.ok(r.errors.length >= 1);
});

// ── the governance bridge BEFORE the child ────────────────────────────────────

test('DENIAL BEFORE SPAWN: an out-of-scope call never reaches spawnImpl (spy assertion)', async () => {
  const spawns = [];
  const { client } = mkClient({ spawnImpl: (...a) => { spawns.push(a); throw new Error('spawn must never be reached for a denied call'); } });
  const r = await client.callTool('echo', { url: 'http://10.9.9.9/' });
  assert.equal(r.ok, false);
  assert.equal(r.denied, true);
  assert.match(r.error, /outside the signed scope/);
  assert.equal(spawns.length, 0);
  await client.close();
});

test('mcp.allowExternal=false: calls AND listTools are refused without spawning', async () => {
  const spawns = [];
  const { client, audit } = mkClient({ externalAllowed: false, spawnImpl: (...a) => { spawns.push(a); throw new Error('must not spawn'); } });
  const c = await client.callTool('echo', { url: 'http://127.0.0.1/' });
  assert.equal(c.denied, true);
  assert.match(c.error, /mcp\.allowExternal=false/);
  const l = await client.listTools();
  assert.equal(l.ok, false);
  assert.equal(spawns.length, 0);
  // both the refused call and the refused spawn are audited
  assert.ok(audit.some((e) => e.tool === 'mcp.external.spawn' && e.verdict === 'deny'));
  await client.close();
});

test('unclassifiable call (no target args) -> HELD before spawn, operator-resolvable', async () => {
  const spawns = [];
  const { client } = mkClient({ spawnImpl: (...a) => { spawns.push(a); throw new Error('must not spawn'); } });
  const r = await client.callTool('echo', { path: '/etc/hostname' });
  assert.equal(r.held, true);
  assert.match(r.error, /held for the operator/i);
  assert.equal(spawns.length, 0);
  await client.close();
});

// ── live round-trip against the fixture child ────────────────────────────────

test('round-trip: lazy spawn on first allowed call, handshake, list, echo result', async (t) => {
  const { client, audit } = mkClient();
  t.after(() => client.close());
  const l = await client.listTools();
  assert.equal(l.ok, true);
  assert.deepEqual(l.tools.map((x) => x.name), ['echo', 'hang']);
  const r = await client.callTool('echo', { url: 'http://127.0.0.1:8971/api', note: 'hello', token: 'TOPSECRET-VALUE' });
  assert.equal(r.ok, true);
  const echoed = JSON.parse(r.result.content[0].text);
  assert.equal(echoed.note, 'hello');
  assert.equal(client.status().running, true);
  // audit: spawn allow + call allow; the token VALUE never lands in the ledger
  assert.ok(audit.some((e) => e.tool === 'mcp.external.spawn' && e.verdict === 'allow'));
  assert.ok(audit.some((e) => e.tool === 'echo' && e.verdict === 'allow'));
  const raw = JSON.stringify(audit);
  assert.ok(!raw.includes('TOPSECRET-VALUE'), 'secret leaked into the audit trail');
  assert.match(raw, /REDACTED/);
});

test('egress discipline: allowlisted research host dispatches; non-allowlisted public host denies pre-spawn', async (t) => {
  const { client } = mkClient();
  t.after(() => client.close());
  const ok = await client.callTool('echo', { url: 'https://github.com/some/poc' });
  assert.equal(ok.ok, true);
  const no = await client.callTool('echo', { url: 'https://dead-drop.example.net/x' });
  assert.equal(no.denied, true);
  assert.match(no.error, /allowlist/);
});

test('timeout: a hung server call times out and the child is reaped (next call respawns)', async (t) => {
  const { client } = mkClient({ server: { ...EXT_SERVER, timeoutMs: 1000 } });
  t.after(() => client.close());
  const l = await client.listTools();
  assert.equal(l.ok, true);
  const r = await client.callTool('hang', { url: 'http://127.0.0.1/' }); // fixture never replies
  assert.equal(r.ok, false);
  assert.equal(r.timeout, true);
  assert.match(r.error, /timed out/);
  assert.equal(client.status().running, false); // reaped
  const again = await client.callTool('echo', { url: 'http://127.0.0.1/' }); // fresh child answers
  assert.equal(again.ok, true);
}, { timeout: 30000 });

test('never-throw: a garbage child (non-JSON, then exit) yields { ok:false }, not an exception', async (t) => {
  const { client } = mkClient({ server: { name: 'garbage', command: process.execPath, args: [GARBAGE], env: {}, timeoutMs: 5000 } });
  t.after(() => client.close());
  const l = await client.listTools();
  assert.equal(l.ok, false);
  assert.match(l.error, /handshake|exited|timed out/i);
  const c = await client.callTool('echo', { url: 'http://127.0.0.1/' });
  assert.equal(c.ok, false); // verdict allow path, but the child is dead — reported, never thrown
}, { timeout: 30000 });
