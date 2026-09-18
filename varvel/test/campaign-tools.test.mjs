// VARVEL campaign-tools wiring tests — the hunting-tool lanes as campaign
// primitives (Build 2, 2026-08-30): jsminer in recon, OOB + DOM-XSS canary in the
// gated exploit phase, the SEPARATE budget.tools bucket, and the kill-fast
// hypothesis budgets. Local 127.0.0.1 labs + fake drivers only.
//   node --test varvel/test/campaign-tools.test.mjs
//
// Pinned: tool requests charge budget.tools and NEVER the step counter; a tripped
// cap logs killfast.stop + budget.exhausted {bucket:'tools'} and marks the partial
// result; endpoints harvested by jsminer land as endpoint nodes (the authz oracle's
// harvest feed); secrets file ONLY when the opt-in verifier graduates them; OOB and
// DOM-XSS file CONFIRMED findings on proven callbacks/executions ONLY, and a lane
// with no launch option logs *.skip — a dormant lane is never silent.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { renderReport } from '../engine/report.mjs';

const scope = (e, extra = {}) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'], ...extra });

async function withServer(srv, fn) {
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally { await new Promise((r) => srv.close(r)); }
}

// a JS-serving lab: HTML pulls three scripts; app.js carries an id-bearing endpoint
// path and an AWS-shaped key
function createJsLab() {
  return http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html' });
      return res.end('<!doctype html><script src="/app.js"></script><script src="/vendor.js"></script><script src="/extra.js"></script>');
    }
    if (u.pathname === '/app.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      return res.end('fetch("/api/orders/1042"); const key = "AKIAIOSFODNN7EXAMPLE";');
    }
    if (u.pathname === '/vendor.js' || u.pathname === '/extra.js') {
      res.writeHead(200, { 'content-type': 'application/javascript' });
      return res.end('console.log("vendor");');
    }
    res.writeHead(404); res.end('{}');
  });
}

// the AWS STS differential mock: a REAL key id earns SignatureDoesNotMatch
function createStsMock() {
  return http.createServer((req, res) => {
    res.writeHead(400, { 'content-type': 'text/xml' });
    res.end('<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>');
  });
}

// a blind-SSRF lab: /fetch?url= dials the URL out-of-band; /nofetch ignores it
function createOobApp() {
  return http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/fetch') {
      const target = u.searchParams.get('url');
      try {
        const t = new URL(target);
        http.get({ hostname: t.hostname, port: t.port, path: t.pathname + t.search, timeout: 2000 }, (r) => r.resume()).on('error', () => {});
      } catch { /* unparseable — quiet like a real app */ }
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"ok":true}');
    }
    if (u.pathname === '/nofetch') { res.writeHead(200); return res.end('ok'); }
    res.writeHead(404); res.end('{}');
  });
}

// a fake browser driver: 'execute' simulates the page running the canary payload
function makeFakeDriver({ execute = true } = {}) {
  const drv = {
    lastId: null,
    async goto(url) {
      const m = /__varvelCanary(?:%3D|=)(?:%22|")?(vx[0-9a-f]{12})/.exec(url);
      drv.lastId = execute && m ? m[1] : null;
      return { ok: true, url, links: [], forms: [], xhrs: [] };
    },
    async evalJs(expr) { return expr === 'window.__varvelCanary' ? drv.lastId : null; },
    consoleLogs() { return ['[log] fake page console']; },
    async screenshot() { return null; },
    async close() {},
  };
  return drv;
}

const seedHost = (c, label = 'lab') => c.surface.host('127.0.0.1', { label });

// ——— jsminer lane ———

test('runJsMiner: harvested endpoints land as endpoint nodes; unverified secrets are NOTES, never findings', () => withServer(createJsLab(), async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('TOOLS-J1'), runAgent: mockAgent, jsminer: true, stallCheckMs: 0 });
  const hid = seedHost(c);
  c._reconWebBases.push(base);
  const res = await c.runJsMiner();
  assert.equal(res.ok, true);
  assert.ok(res.endpoints >= 1, 'endpoints surfaced');
  const eps = [...c.surface.nodes.values()].filter((n) => n.type === 'endpoint').map((n) => n.label);
  assert.ok(eps.includes('/api/orders/1042'), 'the JS-mined endpoint landed as an endpoint node — the authz harvest pass sees it');
  assert.equal(res.secrets, 1, 'the AWS-shaped key extracted as a candidate');
  assert.equal(res.verified, 0, 'no verification without jsminerVerify');
  const findings = [...c.surface.nodes.values()].filter((n) => n.type === 'finding');
  assert.equal(findings.length, 0, 'unverified secret candidates file NOTHING');
  assert.ok(c.surface.phaseLog.some((n) => /UNVERIFIED secret candidate/.test(n.summary)), 'the candidate is a surface note');
  assert.ok(c.activity.some((e) => e.kind === 'jsminer.done'), 'the pass is on the record');
  assert.ok(hid);
}));

test('runJsMiner: jsminerVerify graduates the secret via the live-use differential → CONFIRMED finding', async () => {
  await withServer(createJsLab(), async (base) => {
    await withServer(createStsMock(), async (stsBase) => {
      const c = new Campaign({
        engine: {}, scope: scope('TOOLS-J2'), runAgent: mockAgent,
        jsminer: true, jsminerVerify: true, jsminerVerifyEndpoints: { aws: stsBase }, stallCheckMs: 0,
      });
      seedHost(c);
      c._reconWebBases.push(base);
      const res = await c.runJsMiner();
      assert.equal(res.ok, true);
      assert.equal(res.verified, 1, 'the verifier graduated the key (SignatureDoesNotMatch = known to AWS)');
      const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && String(n.ref || '').startsWith('jsminer:'));
      assert.ok(f, 'verified secret filed');
      assert.equal(f.confidence, 'confirmed');
      assert.equal(f.sev, 'high');
      assert.match(f.evidence, /live-use oracle \(jsminer verifySecret\)/, 'evidence cites the objective oracle');
    });
  });
});

// ——— budget.tools + killfast ———

test('budget.tools: a SEPARATE bucket — tool requests never touch the step counter; exhaustion is honest', () => withServer(createJsLab(), async (base) => {
  const c = new Campaign({
    engine: {}, scope: scope('TOOLS-B1'), runAgent: mockAgent,
    jsminer: true, budget: { maxSteps: 50, tools: { maxRequests: 2, maxMs: 600000 } }, stallCheckMs: 0,
  });
  seedHost(c);
  c._reconWebBases.push(base); // HTML + 3 scripts wants 4 requests; the cap is 2
  const res = await c.runJsMiner();
  assert.equal(res.ok, true);
  assert.equal(res.stopped, 'killfast', 'the killfast cap tripped and marked the partial result');
  assert.ok(c.activity.some((e) => e.kind === 'killfast.stop' && e.data.name === 'jsminer'), 'killfast.stop logged with reason');
  const be = c.activity.find((e) => e.kind === 'budget.exhausted' && e.data.bucket === 'tools');
  assert.ok(be, 'budget.exhausted {bucket:tools} on the record');
  assert.equal(c.budget.usedSteps, 0, 'the agent STEP counter was never charged');
  const st = c.getState();
  assert.equal(st.budget.maxSteps, 50);
  assert.equal(st.budget.tools.used >= 2, true);
  assert.equal(st.budget.tools.exhausted, true, 'the bucket state is exposed');
}));

test('killfast: _killfast wraps any lane honestly — cap trip stops, partial marked', async () => {
  const c = new Campaign({ engine: {}, scope: scope('TOOLS-B2'), runAgent: mockAgent, budget: { tools: { maxRequests: 100, maxMs: 600000 } }, stallCheckMs: 0 });
  const out = await c._killfast('probe-lane', async ({ budget, onLog }) => {
    // simulate a tool that honors the budget contract the real tools implement
    let used = 0;
    const spend = (what) => {
      if (used >= budget.maxRequests) { onLog({ type: 'budget.exhausted', tool: 'probe-lane', what, used, maxRequests: budget.maxRequests }); return false; }
      used++; return true;
    };
    const items = [];
    for (let i = 0; i < 10; i++) { if (!spend('unit:' + i)) break; items.push(i); }
    return { ok: true, items, budget: { used } };
  }, { maxCalls: 3, maxMs: 60000 });
  assert.deepEqual(out.items, [0, 1, 2], 'the lane stopped at the cap with partial results');
  assert.equal(out.stopped, 'killfast');
  assert.ok(c.activity.some((e) => e.kind === 'killfast.stop' && e.data.name === 'probe-lane'));
  assert.equal(c.toolBudget.used, 3, 'actual usage settled into the tools bucket');
  assert.equal(c.budget.usedSteps, 0);
});

// ——— OOB lane ———

test('runOobPass: canary-correlated callback files a CONFIRMED ssrf finding (high); journal attached', () => withServer(createOobApp(), async (base) => {
  const port = Number(new URL(base).port);
  const c = new Campaign({
    engine: {}, scope: scope('TOOLS-O1'), runAgent: mockAgent,
    oob: { publicBaseUrl: 'auto', adminToken: 'tok-123', kinds: ['ssrf'], deadlineMs: 3000 }, stallCheckMs: 0,
  });
  const hid = seedHost(c);
  c.surface.service(hid, port, 'tcp', 'http');
  c.surface.endpoint(hid, '/fetch?url=x', 'GET');
  const res = await c.runOobPass();
  assert.equal(res.ok, true);
  assert.equal(res.proven, 1, 'the SSRF callback correlated');
  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && String(n.ref || '').startsWith('oob:ssrf:'));
  assert.ok(f, 'the finding filed');
  assert.equal(f.confidence, 'confirmed');
  assert.equal(f.sev, 'high', 'ssrf files at high');
  assert.match(f.evidence, /out-of-band oracle \(oob\)/, 'evidence cites the objective oracle');
  assert.ok(f.oob && f.oob.canary && f.oob.callback, 'the canary journal (payload/request/response/callback) is attached');
  assert.ok(c.budget.usedSteps === 0 && c.toolBudget.used >= 1, 'charged to the tools bucket, not steps');
}));

test('runOobPass: NO callback = ZERO findings, and the surface note says the pass proved nothing', () => withServer(createOobApp(), async (base) => {
  const port = Number(new URL(base).port);
  const c = new Campaign({
    engine: {}, scope: scope('TOOLS-O2'), runAgent: mockAgent,
    oob: { publicBaseUrl: 'auto', kinds: ['ssrf'], deadlineMs: 1200 }, stallCheckMs: 0,
  });
  const hid = seedHost(c);
  c.surface.service(hid, port, 'tcp', 'http');
  c.surface.endpoint(hid, '/nofetch?url=x', 'GET');
  const res = await c.runOobPass();
  assert.equal(res.ok, true);
  assert.equal(res.proven, 0);
  assert.equal(![...c.surface.nodes.values()].some((n) => n.type === 'finding' && String(n.ref || '').startsWith('oob:')), true, 'no callback, no finding');
  assert.ok(c.surface.phaseLog.some((n) => /OOB pass ran and PROVED NOTHING/.test(n.summary)), 'the honest nothing-found note');
}));

test('runOobPass: publicBaseUrl unset skips LOUDLY (a canary nobody can dial proves nothing)', () => withServer(createOobApp(), async (base) => {
  const c = new Campaign({ engine: {}, scope: scope('TOOLS-O3'), runAgent: mockAgent, oob: { adminToken: 'tok' }, stallCheckMs: 0 });
  const hid = seedHost(c);
  c.surface.endpoint(hid, '/fetch?url=x', 'GET');
  const res = await c.runOobPass();
  assert.equal(res.skipped, 'publicBaseUrl-unset');
  assert.ok(c.activity.some((e) => e.kind === 'oob.skip' && e.data.reason === 'publicBaseUrl-unset'));
  assert.ok(c.surface.phaseLog.some((n) => /OOB pass SKIPPED/.test(n.summary)));
  void base;
}));

test('exploit phase wires the OOB lane inside the countersigned window', () => withServer(createOobApp(), async (base) => {
  const port = Number(new URL(base).port);
  const c = new Campaign({
    engine: {}, scope: scope('TOOLS-O4'), runAgent: async () => ({ text: '{"exploits":[]}', steps: 1 }),
    oob: { publicBaseUrl: 'auto', kinds: ['ssrf'], deadlineMs: 3000 },
    hooks: { approve: async () => true }, stallCheckMs: 0,
  });
  const hid = seedHost(c);
  c.surface.service(hid, port, 'tcp', 'http');
  c.surface.endpoint(hid, '/fetch?url=x', 'GET');
  c.surface.finding(hid, { title: 'seed', sev: 'low', ref: 'F-0', confidence: 'confirmed', evidence: 'x' }); // progression gate
  const { PHASES } = await import('../engine/phases.mjs');
  const r = await c.runPhase(PHASES.find((p) => p.id === 'exploit'), '');
  assert.ok(!r.held && !r.skipped, 'the exploit phase ran under the approved gate');
  assert.ok(c.oobResult && c.oobResult.proven === 1, 'the OOB pass fired from the phase hook and proved the SSRF');
  assert.ok(c.activity.some((e) => e.kind === 'browseragent.skip' && e.data.reason === 'not-enabled'), 'the dormant browser lane logged its skip');
}));

// ——— DOM-XSS canary lane ———

test('runBrowserPass: canary EXECUTION files a CONFIRMED medium finding; reflection-only files nothing', async () => {
  const c = new Campaign({
    engine: {}, scope: scope('TOOLS-X1'), runAgent: mockAgent,
    browseragent: true, browserDriverFactory: async () => makeFakeDriver({ execute: true }), stallCheckMs: 0,
  });
  seedHost(c);
  c._reflectedParams.push({ base: 'http://127.0.0.1:9/search', param: 'q' });
  const res = await c.runBrowserPass();
  assert.equal(res.ok, true);
  assert.equal(res.proven, 1, 'the canary executed in page context');
  const f = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && String(n.ref || '').startsWith('domxss:q:'));
  assert.ok(f);
  assert.equal(f.confidence, 'confirmed');
  assert.equal(f.sev, 'med');
  assert.match(f.evidence, /browser oracle \(browseragent\)/);
  assert.ok(f.domxss && f.domxss.executedBy === 'window.__varvelCanary', 'the execution signal is named');

  const c2 = new Campaign({
    engine: {}, scope: scope('TOOLS-X2'), runAgent: mockAgent,
    browseragent: true, browserDriverFactory: async () => makeFakeDriver({ execute: false }), stallCheckMs: 0,
  });
  seedHost(c2);
  c2._reflectedParams.push({ base: 'http://127.0.0.1:9/search', param: 'q' });
  const res2 = await c2.runBrowserPass();
  assert.equal(res2.proven, 0, 'reflection without execution is unproven');
  assert.equal([...c2.surface.nodes.values()].filter((n) => n.type === 'finding').length, 0, 'ZERO findings');
  assert.ok(c2.surface.phaseLog.some((n) => /DOM-XSS canary pass ran and PROVED NOTHING/.test(n.summary)));
});

// ——— dormant lanes are never silent ———

test('dormant lanes log *.skip with the reason (jsminer / oob / browseragent)', async () => {
  const c = new Campaign({ engine: {}, scope: scope('TOOLS-S1'), runAgent: mockAgent, stallCheckMs: 0 });
  const r1 = await c.runJsMiner();
  const r2 = await c.runOobPass();
  const r3 = await c.runBrowserPass();
  assert.equal(r1.skipped, 'not-enabled');
  assert.equal(r2.skipped, 'not-enabled');
  assert.equal(r3.skipped, 'not-enabled');
  for (const k of ['jsminer.skip', 'oob.skip', 'browseragent.skip']) {
    assert.ok(c.activity.some((e) => e.kind === k && e.data.reason === 'not-enabled'), `${k} logged`);
  }
});

// ——— report governance ———

test('report governance section records the tools bucket', async () => {
  const c = new Campaign({ engine: {}, scope: scope('TOOLS-R1'), runAgent: mockAgent, budget: { tools: { maxRequests: 7, maxMs: 60000 } }, stallCheckMs: 0 });
  c._toolCharge('jsminer', 3);
  const md = renderReport(c.surface.toJSON(), { toolsBudget: c.toolBudget });
  assert.match(md, /Tool-lane budget/);
  assert.match(md, /3\/7\*\* governed requests/);
  assert.match(md, /SEPARATE from the agent step/);
});
