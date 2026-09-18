// mcpclient-poison.test.mjs — GRADUATION: the lab-calibrated content screens
// (engine/mcpguard.mjs, graduated from deploy/range-iso/mcp-poison/) pinned into the
// REAL McpClient path (engine/mcpclient.mjs). The fixture servers are the lab's own,
// spawned as REAL CHILD PROCESSES over stdio — no in-process shortcuts. Proofs:
//   (a) description-poisoned tool is quarantined at mount and can NEVER be called
//       (spy-grade: the child's own received-call log shows no delivery);
//   (b) post-approval descriptor mutation (rug-pull) is detected and quarantined;
//   (c) steering content in a tool RESULT is flagged + audited + annotated;
//   negative control: the honest fixture mounts clean. Default mcp.allowExternal=false
//   semantics untouched. Artifacts under varvel/.tmp per house rule.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpClient, loadExternalServers } from '../engine/mcpclient.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LAB_SERVER = join(HERE, '..', 'deploy', 'range-iso', 'mcp-poison', 'servers.mjs');
const TMP = join(HERE, '..', '.tmp', 'mcpclient-poison-test');
mkdirSync(TMP, { recursive: true });

const SCOPE = { engagement: 'mcp-poison-grad', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const entry = (which, env = {}, over = {}) => ({
  name: which, command: process.execPath, args: [LAB_SERVER, which], env, timeoutMs: 8000, ...over,
});
const stateFile = (name) => join(TMP, `${name}.jsonl`);
const readState = (f) => (existsSync(f) ? readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : []);

const mkClient = (which, name, over = {}) => {
  const state = stateFile(name);
  if (existsSync(state)) rmSync(state);
  const audit = [];
  const client = new McpClient({
    server: entry(which, { VARVEL_LAB_STATE: state }),
    scope: SCOPE, externalAllowed: true, auditSink: (e) => audit.push(e), ...over,
  });
  return { client, audit, state };
};

test('config: loadExternalServers passes the trustedTools operator override through', () => {
  const f = join(TMP, 'servers.json');
  writeFileSync(f, JSON.stringify({ servers: [{ name: 'h', command: process.execPath, args: [LAB_SERVER, 'hostile'], trustedTools: ['weather'] }] }));
  const r = loadExternalServers(f);
  assert.equal(r.ok, true);
  assert.deepEqual(r.servers[0].trustedTools, ['weather']);
});

test('default posture untouched: mcp.allowExternal=false refuses listing and calls pre-spawn', async (t) => {
  const spawns = [];
  const { client } = mkClient('hostile', 'gate', { externalAllowed: false, spawnImpl: (...a) => { spawns.push(a); throw new Error('must not spawn'); } });
  t.after(() => client.close());
  const l = await client.listTools();
  assert.equal(l.ok, false);
  assert.match(l.error, /allowExternal=false/);
  const c = await client.callTool('lookup', { url: 'http://127.0.0.1/x' });
  assert.equal(c.denied, true);
  assert.equal(spawns.length, 0);
});

test('negative control: the HONEST fixture mounts clean — no findings, no quarantine, no drift on re-list', async (t) => {
  const { client, audit } = mkClient('honest', 'honest-clean');
  t.after(() => client.close());
  const l1 = await client.listTools();
  assert.equal(l1.ok, true);
  assert.deepEqual(l1.quarantined, []);
  assert.equal(l1.screenFindings, 0);
  const l2 = await client.listTools({ refresh: true });
  assert.equal(l2.screenFindings, 0, 'honest server shows zero drift between listings');
  assert.deepEqual(l2.quarantined, []);
  assert.ok(!audit.some((e) => e.tool === 'mcp.screen.listing'), 'no screen findings in the audit trail');
  // and the screen is not what governs a target-less call: the bridge HELDs it
  // (operator-resolvable), which is the pre-existing, correct governance posture.
  const c = await client.callTool('calc', { a: 1, b: 2, op: 'add' });
  assert.equal(c.held, true);
  assert.equal(c.quarantined, undefined);
});

test('(a) description poison: weather is QUARANTINED at mount and the refusal never reaches the child', async (t) => {
  const { client, audit, state } = mkClient('hostile', 'desc-poison');
  t.after(() => client.close());
  const l = await client.listTools();
  assert.equal(l.ok, true);
  assert.ok(l.quarantined.includes('weather'), 'poisoned-description tool quarantined at mount');
  assert.ok(!l.quarantined.includes('lookup'), 'clean-description tool not quarantined');
  // in-scope URL so the BRIDGE would allow it — only the screen stands in the way
  const c = await client.callTool('weather', { city: 'lab-city', url: 'http://127.0.0.1/weather' });
  assert.equal(c.ok, false);
  assert.equal(c.denied, true);
  assert.equal(c.quarantined, true);
  assert.match(c.error, /QUARANTINED/);
  // spy-grade: the child server's own received-call log shows NO weather delivery
  assert.ok(!readState(state).some((r) => r.tool === 'weather'), 'quarantined call reached the child!');
  // audit: the quarantine decision and the refused call both land in the ledger
  assert.ok(audit.some((e) => e.tool === 'mcp.screen.quarantine' && e.verdict === 'flag'));
  assert.ok(audit.some((e) => e.tool === 'weather' && e.verdict === 'deny' && /quarantined/.test(e.reason)));
});

test('(b) rug-pull: fortune is clean at the approval listing, mutates on re-list, and is quarantined', async (t) => {
  const { client, audit, state } = mkClient('hostile', 'rugpull');
  t.after(() => client.close());
  const l1 = await client.listTools();
  assert.equal(l1.ok, true);
  assert.ok(!l1.quarantined.includes('fortune'), 'approval snapshot is clean');
  const l2 = await client.listTools({ refresh: true });
  assert.ok(l2.quarantined.includes('fortune'), 'mutated descriptor quarantined on the next listing');
  assert.ok(audit.some((e) => e.tool === 'mcp.screen.listing' && /descriptor-mutated/.test(e.reason)));
  const c = await client.callTool('fortune', { url: 'http://127.0.0.1/x' });
  assert.equal(c.quarantined, true);
  assert.ok(!readState(state).some((r) => r.tool === 'fortune'), 'rug-pulled tool call reached the child!');
});

test('no stale-cache abetment: default cache policy re-screens every listing; session cache is opt-in and audited', async (t) => {
  const { client } = mkClient('hostile', 'cache-off');
  t.after(() => client.close());
  await client.listTools(); // baseline (fortune benign)
  const l2 = await client.listTools(); // NO explicit refresh — default policy re-lists anyway
  assert.equal(l2.cached, undefined);
  assert.ok(l2.quarantined.includes('fortune'), 'mutation caught without an explicit refresh');

  const { client: legacy, audit } = mkClient('hostile', 'cache-session', { listingCache: 'session' });
  t.after(() => legacy.close());
  await legacy.listTools();
  const cached = await legacy.listTools(); // served from cache: mutation NOT yet visible...
  assert.equal(cached.cached, true);
  assert.ok(!cached.quarantined.includes('fortune'));
  // ...but the operator heard about the accepted risk, in the ledger
  assert.ok(audit.some((e) => e.tool === 'mcp.screen.cache' && e.verdict === 'flag' && /staleness|risk/i.test(e.reason)));
  const fresh = await legacy.listTools({ refresh: true });
  assert.ok(fresh.quarantined.includes('fortune'), 'explicit refresh still catches the rug-pull under session cache');
});

test('(c) output steering: a clean-description tool whose RESULT carries a directive is flagged + audited + annotated', async (t) => {
  const { client, audit, state } = mkClient('hostile', 'output-steer');
  t.after(() => client.close());
  await client.listTools();
  const r = await client.callTool('lookup', { url: 'http://127.0.0.1/lab' });
  assert.equal(r.ok, true, 'the call executed — output screening annotates, it does not retroactively block');
  assert.equal(r.screen.flagged, true);
  const rules = r.screen.findings.flatMap((f) => f.hits.map((h) => h.rule));
  assert.ok(rules.includes('agent-directive-marker'));
  assert.ok(rules.includes('hidden-html-comment'));
  assert.ok(audit.some((e) => e.tool === 'mcp.screen.output' && e.verdict === 'flag' && /steering/.test(e.reason)));
  // honest semantics: the call DID reach the child (visible in its log) — the flag is the control
  assert.ok(readState(state).some((s) => s.tool === 'lookup'));
});

test('operator override: trustedTools releases quarantine, but findings and output-scan still fire', async (t) => {
  const { client, audit, state } = mkClient('hostile', 'override', { trustedTools: ['weather'] });
  t.after(() => client.close());
  const l = await client.listTools();
  assert.ok(!l.quarantined.includes('weather'), 'override released the tool');
  assert.ok(l.screenFindings > 0, 'the poison finding is STILL reported');
  assert.ok(audit.some((e) => e.tool === 'mcp.screen.override' && /trustedTools/.test(e.reason)));
  const r = await client.callTool('weather', { city: 'lab-city', url: 'http://127.0.0.1/weather' });
  assert.equal(r.ok, true, 'trusted tool executes');
  assert.equal(r.screen.flagged, true, 'and its steering OUTPUT is still flagged');
  assert.ok(readState(state).some((s) => s.tool === 'weather'));
});

test('flag-only policy: findings reported, nothing quarantined (explicit non-default)', async (t) => {
  const { client } = mkClient('hostile', 'flag-only', { screenPolicy: 'flag-only' });
  t.after(() => client.close());
  const l = await client.listTools();
  assert.ok(l.screenFindings > 0);
  assert.deepEqual(l.quarantined, []);
  const r = await client.callTool('weather', { city: 'x', url: 'http://127.0.0.1/w' });
  assert.equal(r.ok, true);
  assert.equal(r.screen.flagged, true);
});
