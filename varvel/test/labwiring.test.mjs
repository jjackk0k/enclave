// VARVEL lab-wiring tests — the 2026-09-01 LAB + AGENT-TOOLMAKING build
// (docs/builds/2026-09-01-lab-wiring.md):
//   1. AUTO-SHELVE: scratch tools the agent declares in its output JSON are persisted
//      to the tool shelf as QUARANTINED data (bytes read back from the campaign
//      workspace, or inline content) before the disposable workspace is reaped —
//      best-effort, never thrown into the campaign.
//   2. THE BRIEF: operatingBrief() tells agents about the auto-shelve, the shelf API,
//      and the attackbench invention ledger (live campaigns AND chat both ride
//      operatingBrief — server.mjs builds both briefs from it).
//   3. THE ROUTE: GET /api/attackbench serves the honest coverage report over the
//      real server (house boot pattern: h1watch-api/agentsig/flowscore spawn
//      server.mjs on a dedicated loopback port).
// Hermetic: the shelf + attackbench data are isolated temp dirs; no network beyond
// loopback.
//   node --test test/labwiring.test.mjs

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

// Isolate the shelf BEFORE importing the module under test — tests never touch the real
// shelf (the posture.test.mjs pattern; the shelf dir resolves lazily per call anyway).
process.env.VARVEL_SHELF_DIR = mkdtempSync(join(tmpdir(), 'varvel-labwiring-shelf-'));

import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { shelfList, shelfRead } from '../engine/toolshelf.mjs';
import { operatingBrief } from '../engine/live.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const scope = (e, extra = {}) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'], ...extra });
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const mkWs = () => mkdtempSync(join(tmpdir(), 'varvel-labwiring-ws-'));

// ——— auto-shelve (fix B: scratch tools no longer die with the workspace) ———

test('auto-shelve: a declared scratch tool\'s bytes leave the disposable workspace and land QUARANTINED on the shelf', () => {
  const ws = mkWs();
  const bytes = '#!/usr/bin/env python3\nprint("forge")\n';
  writeFileSync(join(ws, 'token-forge.py'), bytes);
  const c = new Campaign({ engine: { model: 'test-model' }, scope: scope('LAB-S1'), runAgent: mockAgent, wsDir: ws, stallCheckMs: 0 });
  c._ingest('validate', { scratchTools: [{ name: 'token-forge.py', kind: 'exploit-aid', description: 'forges demo tokens' }] });
  const e = shelfList().find((x) => x.name === 'token-forge.py');
  assert.ok(e, 'the declared tool was shelved, not just logged');
  assert.equal(e.status, 'quarantined', 'shelf entries are quarantined DATA — promotion stays human');
  assert.equal(e.kind, 'exploit-aid');
  assert.equal(e.description, 'forges demo tokens');
  assert.equal(e.files.length, 1);
  assert.equal(e.files[0].name, 'token-forge.py');
  assert.equal(e.files[0].sha256, sha256(bytes), 'the reviewed bytes are provably the bytes the agent wrote');
  assert.equal(shelfRead(e.id, 'token-forge.py'), bytes);
  assert.equal(e.origin.agent, 'test-model', 'attributed to the writing agent');
  assert.equal(e.origin.session, 'LAB-S1', 'attributed to the engagement');
  assert.ok(c.activity.some((ev) => ev.kind === 'scratch-tools.shelved' && ev.data.id === e.id), 'the shelve is on the activity record');
  assert.ok(c.activity.some((ev) => ev.kind === 'scratch-tools'), 'the pre-existing name log still fires');
});

test('auto-shelve: inline content shelves without a workspace; a bare name with no bytes logs but shelves nothing', () => {
  const c = new Campaign({ engine: {}, scope: scope('LAB-S2'), runAgent: mockAgent, stallCheckMs: 0 }); // no wsDir at all
  c._ingest('recon', { scratchTools: [{ name: 'inline-probe', content: 'console.log(1)\n', file: 'probe.mjs' }, 'name-only-tool'] });
  const e = shelfList().find((x) => x.name === 'inline-probe');
  assert.ok(e, 'inline bytes shelved');
  assert.equal(e.kind, 'utility', 'the default kind');
  assert.equal(e.files[0].name, 'probe.mjs');
  assert.equal(shelfRead(e.id, 'probe.mjs'), 'console.log(1)\n');
  assert.equal(shelfList().some((x) => x.name === 'name-only-tool'), false, 'no bytes, no shelf entry — declared names alone carry nothing to keep');
  assert.ok(c.activity.some((ev) => ev.kind === 'scratch-tools' && ev.data.tools.includes('name-only-tool')), 'the name is still on the audit log');
});

test('auto-shelve: traversal out of the workspace is refused, and a shelve failure never reaches the campaign', () => {
  const ws = mkWs();
  const c = new Campaign({ engine: {}, scope: scope('LAB-S3'), runAgent: mockAgent, wsDir: ws, stallCheckMs: 0 });
  c._ingest('validate', { scratchTools: [{ name: '../escape.py' }, { name: '!!!bad', content: 'x' }] });
  assert.equal(shelfList().some((x) => /escape/.test(x.name)), false, 'no read outside the workspace');
  assert.equal(shelfList().some((x) => x.name === '!!!bad'), false, 'an unsafe shelf name is rejected by the shelf itself');
  assert.ok(c.activity.some((ev) => ev.kind === 'scratch-tools.shelve-error'), 'the failure is logged, never swallowed');
  assert.ok(c.surface.phaseLog.some((n) => /scratch tool/.test(n.summary)), 'the ingest still completed normally');
});

test('auto-shelve: a tool is shelved once per campaign even when re-declared across phases', () => {
  const ws = mkWs();
  writeFileSync(join(ws, 'probe.mjs'), '// v1\n');
  const c = new Campaign({ engine: {}, scope: scope('LAB-S4'), runAgent: mockAgent, wsDir: ws, stallCheckMs: 0 });
  c._ingest('recon', { scratchTools: ['probe.mjs'] });
  c._ingest('validate', { scratchTools: ['probe.mjs'] });
  assert.equal(shelfList().filter((x) => x.name === 'probe.mjs').length, 1, 'one shelf entry per tool per campaign');
});

// ——— the brief (fix A: agents are told about the lab) ———

test('operatingBrief: the LAB & TOOLMAKING block names the auto-shelve, the shelf API, and the attackbench ledger', () => {
  const b = operatingBrief();
  assert.match(b, /LAB & TOOLMAKING/, 'the block exists');
  assert.match(b, /auto-?shelv/i, 'agents learn scratch tools are auto-shelved');
  assert.match(b, /POST \/api\/toolshelf/, 'the shelf API is advertised');
  assert.match(b, /data\/attackbench\/techniques\.json/, 'the invention ledger is named');
  assert.match(b, /never\s+edit the catalog/i, 'agents never self-modify the catalog — the operator adds new techniques');
});

// ——— the route (fix C: attackbench coverage on the wire) ———

const AB = mkdtempSync(join(tmpdir(), 'varvel-labwiring-ab-'));
writeFileSync(join(AB, 'techniques.json'), JSON.stringify({
  techniques: [
    { id: 'T1078', name: 'Valid Accounts', tactics: ['initial-access'], why: 'fixture priority' },
    { id: 'T1098', name: 'Account Manipulation', tactics: ['persistence'], why: 'fixture priority' },
    { id: 'T1003', name: 'OS Credential Dumping', tactics: ['credential-access'], why: 'fixture priority' },
  ],
}));
writeFileSync(join(AB, 'map.json'), JSON.stringify({
  capabilities: [
    { id: 'fixture-exists', title: 'exists fixture', status: 'exists', modules: ['engine/attackbench.mjs'], techniques: ['T1078'], note: 'fixture — module exists in the real repo' },
    { id: 'fixture-planned', title: 'planned fixture', status: 'planned', techniques: ['T1098'], note: 'fixture — claims no code', basis: 'docs/builds/2026-09-01-lab-wiring.md' },
  ],
}));

let proc = null, port = 39461, base = null;
async function boot() {
  const serverFile = join(__dir, '..', 'server.mjs');
  proc = spawn(process.execPath, [serverFile], {
    env: {
      ...process.env,
      VARVEL_PORT: String(port), VARVEL_DEMO_PORT: '39462', VARVEL_HARD_PORT: '39463',
      VARVEL_ATTACKBENCH_DIR: AB,
    },
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('server.mjs did not report listening within 25s')), 25000);
    let buf = '';
    proc.stdout.on('data', (d) => { buf += d; if (buf.includes('VARVEL service on')) { clearTimeout(to); resolve(); } });
    proc.on('exit', () => reject(new Error('server.mjs exited before listening: ' + buf.slice(0, 200))));
  });
  base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 20; i++) { // the log line precedes the demo-target boot — give routes a moment
    try { const r = await fetch(base + '/api/attackbench'); if (r.ok) return; } catch { await new Promise((x) => setTimeout(x, 250)); }
  }
  throw new Error('route never answered');
}
after(() => {
  try { if (proc) proc.kill(); } catch {}
  try { rmSync(AB, { recursive: true, force: true }); } catch {}
});

test('GET /api/attackbench serves the honest coverage report (mapped / planned-only / gap) over the wire', async () => {
  await boot();
  const r = await fetch(base + '/api/attackbench');
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.ok, true);
  assert.equal(j.coverage.total, 3);
  assert.equal(j.coverage.mapped, 1, 'the exists fixture maps T1078');
  assert.equal(j.coverage.plannedOnly, 1, 'the planned fixture claims nothing today');
  assert.equal(j.coverage.gaps, 1, 'T1003 is honestly a gap');
  assert.deepEqual(j.coverage.gapIds, ['T1003']);
  assert.ok(Array.isArray(j.coverage.byTactic) && j.coverage.byTactic.length, 'the per-tactic rollup rides');
  assert.match(j.nonClaim, /NOT affiliated/, 'the non-claim is carried on the wire — capability, never detection');
});
// The loud-refusal path (unreadable/invalid catalog or map → NAMED error, never
// guessed data) is pinned against tools/attackbench directly by test/attackbench.test.mjs.

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as transportfail/dnstransport/flowscore/h1watch-api.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
