// recon-watchdog.test.mjs — the 2026-08-29 trip_com stall: one wedged host await froze
// the whole sweep for ~50 min with zero sockets. These tests pin the fix: per-host budget
// in recon(), per-tool budget in the campaign merge loop — both skip + REPORT, never freeze.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import http from 'node:http';

process.env.VARVEL_DATA_DIR = mkdtempSync(join(tmpdir(), 'varvel-watchdog-'));

const { recon } = await import('../tools/recon.mjs');
const { Campaign } = await import('../engine/campaign.mjs');
const { mockAgent } = await import('../mock-agent.mjs');
const { saveSurface } = await import('../engine/store.mjs');

// Track accepted sockets so t.after can hard-destroy them — orphaned tool promises
// (watchdog-tripped but still burning against the fixture) must not hang server.close().
const track = (srv) => { const socks = new Set(); srv.on('connection', (s) => { socks.add(s); s.on('close', () => socks.delete(s)); }); return () => { srv.close(); for (const s of socks) s.destroy(); }; };

test('recon(): a wedged host is skipped + reported, live hosts still scanned', async () => {
  const scanHostImpl = (ip) => ip === '10.9.9.9'
    ? new Promise(() => {}) // never settles — the wedge class
    : Promise.resolve({ services: [{ port: 443, proto: 'https', name: 'https' }], tech: ['x'] });
  const t0 = Date.now();
  const r = await recon(['10.9.9.9', '10.1.1.1'], { hostBudgetMs: 150, scanHostImpl });
  assert.ok(Date.now() - t0 < 5000, 'sweep completes despite the wedge');
  assert.deepEqual(r.stalled, ['10.9.9.9'], 'the wedged host is REPORTED as stalled');
  assert.equal(r.hosts.length, 1, 'the live host still lands');
  assert.equal(r.hosts[0].ip, '10.1.1.1');
});

test('campaign._withBudget: a never-settling tool await trips, logs, resolves null', async () => {
  const c = new Campaign({ engine: {}, scope: { engagement: 'T-watchdog', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: mockAgent, targets: ['127.0.0.1'] });
  const out = await c._withBudget(new Promise(() => {}), 80, 'fake-tool:127.0.0.1');
  assert.equal(out, null, 'trips to null so callers fall back safely');
  const evt = c.getState().activity.find((a) => (a.kind || a.type) === 'recon.watchdog');
  assert.ok(evt, 'the trip is logged to the activity feed (honest, visible)');
});

test('campaign._withBudget: a fast tool passes through untouched', async () => {
  const c = new Campaign({ engine: {}, scope: { engagement: 'T-watchdog', signedBy: 'x', cidrs: ['127.0.0.0/8'] }, runAgent: mockAgent, targets: ['127.0.0.1'] });
  const out = await c._withBudget(Promise.resolve({ endpoints: ['/'] }), 2000, 'fast-tool');
  assert.deepEqual(out, { endpoints: ['/'] });
});

// ---- 2026-08-30 recon dead-time elimination ----
// Wire profile is unchanged: the preflight probe is the SAME tcpProbe socket the sweep
// already used, and skipping means FEWER packets, never different ones.

test('preflight: port filtered at tool time → 4 web tools skipped with ONE probe', async () => {
  let probes = 0;
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-preflight-skip', signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: mockAgent, targets: ['10.255.255.1'], tooledRecon: true,
    reconOpts: {
      toolWatchdogMs: 500,
      scanHostImpl: async () => ({ services: [{ port: 8080, proto: 'tcp', name: 'http' }], tech: [] }),
      probeImpl: async () => { probes++; return { open: false }; }, // answered at sweep, filtered now
    },
  });
  const t0 = Date.now();
  await c.tooledRecon();
  const elapsed = Date.now() - t0;
  assert.equal(probes, 1, 'one cheap probe, not four tool batteries');
  assert.ok(elapsed < 2000, `zero watchdog budget burned (elapsed ${elapsed}ms; pre-fix shape = 4 x 500ms)`);
  const act = c.getState().activity;
  const skips = act.filter((a) => a.kind === 'recon.skip');
  assert.equal(skips.length, 1, 'the skip is logged, never hidden');
  assert.deepEqual(skips[0].data.tools, ['webscan', 'apisurface', 'crawl', 'vulncheck']);
  assert.ok(skips[0].data.reason, 'skip carries an honest reason');
  assert.ok(!act.some((a) => a.kind === 'recon.watchdog'), 'no tool even ran long enough to trip');
  assert.equal([...c.surface.nodes.values()].filter((n) => n.type === 'endpoint').length, 0, 'no phantom endpoints from a dead host');
});

test('preflight: open port passes through — endpoints land, nothing skipped', async (t) => {
  const srv = http.createServer((req, res) => {
    if (req.url === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html><title>t</title></html>'); }
    else { res.writeHead(404); res.end('nope'); } // real 404s — keeps the soft-host detector honest
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(track(srv));
  const port = srv.address().port;
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-preflight-pass', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
    reconOpts: {
      toolWatchdogMs: 8000,
      scanHostImpl: async () => ({ services: [{ port, proto: 'tcp', name: 'http' }], tech: [] }),
      probeImpl: async () => ({ open: true }),
    },
  });
  await c.tooledRecon();
  assert.ok(!c.getState().activity.some((a) => a.kind === 'recon.skip'), 'a live host is never preflight-skipped');
  const eps = [...c.surface.nodes.values()].filter((n) => n.type === 'endpoint');
  assert.ok(eps.some((n) => n.label === '/'), 'endpoints still land through the full tool chain');
});

test('degraded host: 2 wedge trips halve later budgets + skip non-essential extras', async (t) => {
  const srv = http.createServer((req, res) => setTimeout(() => { res.writeHead(200); res.end('slow'); }, 400));
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(track(srv));
  const webPort = srv.address().port;
  let osfpCalls = 0;
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-degraded', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
    reconOpts: {
      toolWatchdogMs: 200,
      smbPorts: [4445], // stand-in port, no listener needed — osfpImpl must never fire
      osfpImpl: async () => { osfpCalls++; return { family: 'windows' }; },
      scanHostImpl: async () => ({ services: [
        { port: webPort, proto: 'tcp', name: 'http' },
        { port: 4445, proto: 'tcp', name: 'smb' },
      ], tech: [] }),
      probeImpl: async () => ({ open: true }),
    },
  });
  await c.tooledRecon();
  const act = c.getState().activity;
  const trips = act.filter((a) => a.kind === 'recon.watchdog');
  assert.ok(trips.some((a) => a.data.tool === 'webscan:127.0.0.1' && a.data.budgetMs === 200), 'webscan trips at full budget (trip 1)');
  assert.ok(trips.some((a) => a.data.tool === 'apisurface:127.0.0.1' && a.data.budgetMs === 200), 'apisurface trips at full budget (trip 2 → degrade)');
  assert.ok(trips.some((a) => a.data.tool === 'crawl:127.0.0.1' && a.data.budgetMs === 100), 'crawl budget halved once degraded');
  assert.ok(trips.some((a) => a.data.tool === 'vulncheck:127.0.0.1' && a.data.budgetMs === 100), 'vulncheck budget halved once degraded');
  assert.ok(act.some((a) => a.kind === 'recon.degraded' && a.data.host === '127.0.0.1'), 'degradation is logged, never hidden');
  assert.equal(osfpCalls, 0, 'osfp never runs on a degraded host');
  assert.ok(act.some((a) => a.kind === 'recon.skip' && a.data.tools.includes('osfp')), 'the osfp skip is logged with a reason');
});

// The bykea pattern at test scale: port answers the probe, then every tool await wedges
// (blackhole server accepts and never replies). Pre-fix shape = 4 full budgets; post-fix =
// 2 full (trip counter) + 2 halved. Measured in-test, scaled in the report.
test('dead-time: wedged-tool host burns 2 full budgets then degrades (not 4)', async (t) => {
  const srv = http.createServer(() => { /* blackhole: accept, never respond */ });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(track(srv));
  const B = 400;
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-deadtime', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: mockAgent, targets: ['127.0.0.1'], tooledRecon: true,
    reconOpts: {
      toolWatchdogMs: B,
      scanHostImpl: async () => ({ services: [{ port: srv.address().port, proto: 'tcp', name: 'http' }], tech: [] }),
      probeImpl: async () => ({ open: true }), // probe succeeds — the wedge is per-request, post-connect
    },
  });
  const t0 = Date.now();
  await c.tooledRecon();
  const elapsed = Date.now() - t0;
  const preFix = 4 * B;
  assert.ok(elapsed < preFix - B + 250, `degradation cuts dead time: ${elapsed}ms vs pre-fix shape ${preFix}ms`);
  const trips = c.getState().activity.filter((a) => a.kind === 'recon.watchdog');
  assert.deepEqual(trips.map((a) => a.data.budgetMs), [B, B, B / 2, B / 2], 'two full budgets to learn, then halved');
});

test('freshness gate: fresh prior surface skips the resweep, detail carried forward', async () => {
  const eng = 'T-fresh';
  saveSurface(eng, {
    nodes: [
      { id: 'host-1', type: 'host', ip: '10.1.2.3', label: 'cached-host', sweptAt: new Date().toISOString() },
      { id: 'svc-1', type: 'service', host: 'host-1', port: 443, proto: 'tcp', name: 'https', label: 'https:443' },
      { id: 'ep-1', type: 'endpoint', label: '/admin', method: 'GET' },
    ],
    edges: [
      { from: 'host-1', to: 'svc-1', kind: 'svc' },
      { from: 'host-1', to: 'ep-1', kind: 'exposes' },
    ],
  });
  let scans = 0;
  const c = new Campaign({
    engine: {}, scope: { engagement: eng, signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: mockAgent, targets: ['10.1.2.3'], tooledRecon: true, carryForward: true,
    reconOpts: { scanHostImpl: async () => { scans++; return { services: [], tech: [] }; } },
  });
  await c.tooledRecon();
  assert.equal(scans, 0, 'a fresh host is NOT reswept');
  const inh = c.getState().activity.filter((a) => a.kind === 'recon.inherited');
  assert.equal(inh.length, 1, 'the carry-forward is logged with provenance');
  assert.equal(inh[0].data.services, 1);
  assert.equal(inh[0].data.endpoints, 1);
  const nodes = [...c.surface.nodes.values()];
  assert.ok(nodes.some((n) => n.type === 'service' && n.port === 443 && n.inherited), 'prior service lands in the live surface, marked inherited');
  assert.ok(nodes.some((n) => n.type === 'endpoint' && n.label === '/admin' && n.inherited), 'prior endpoint lands, marked inherited');
});

test('freshness gate: resweepAfterMs 0 forces a resweep (old behaviour preserved)', async () => {
  let scans = 0;
  const c = new Campaign({
    engine: {}, scope: { engagement: 'T-fresh', signedBy: 'x', cidrs: ['10.0.0.0/8'] }, // same saved surface as above
    runAgent: mockAgent, targets: ['10.1.2.3'], tooledRecon: true, carryForward: true,
    reconOpts: { resweepAfterMs: 0, scanHostImpl: async () => { scans++; return { services: [], tech: [] }; } },
  });
  await c.tooledRecon();
  assert.equal(scans, 1, 'explicit 0 means always resweep');
  assert.ok(!c.getState().activity.some((a) => a.kind === 'recon.inherited'));
});

test('freshness gate: stale sweptAt (25h) resweeps', async () => {
  const eng = 'T-stale';
  saveSurface(eng, {
    nodes: [
      { id: 'host-1', type: 'host', ip: '10.1.2.4', label: 'stale-host', sweptAt: new Date(Date.now() - 25 * 3600 * 1000).toISOString() },
      { id: 'svc-1', type: 'service', host: 'host-1', port: 443, proto: 'tcp', name: 'https', label: 'https:443' },
      { id: 'ep-1', type: 'endpoint', label: '/admin', method: 'GET' },
    ],
    edges: [
      { from: 'host-1', to: 'svc-1', kind: 'svc' },
      { from: 'host-1', to: 'ep-1', kind: 'exposes' },
    ],
  });
  let scans = 0;
  const c = new Campaign({
    engine: {}, scope: { engagement: eng, signedBy: 'x', cidrs: ['10.0.0.0/8'] },
    runAgent: mockAgent, targets: ['10.1.2.4'], tooledRecon: true, carryForward: true,
    reconOpts: { scanHostImpl: async () => { scans++; return { services: [], tech: [] }; } },
  });
  await c.tooledRecon();
  assert.equal(scans, 1, 'a stale record is reswept, not trusted');
});
