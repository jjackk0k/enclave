// VARVEL targetscore tests — the target scoring / ROI layer (Build 3, 2026-08-31).
// Local crafted signal sets + a live Surface only; the module is pure (no I/O).
//   node --test varvel/test/targetscore.test.mjs
//
// Pinned: a soft API-heavy host OUTRANKS a Cloudflare static edge; every reason
// names its signal and cites observed evidence (absent signals emit NO reasons);
// scoring is deterministic (same surface, same scores); the campaign attaches
// scores to host nodes, orders the sweep + the OOB probe budget score-descending
// (REORDER ONLY — nothing skipped/hidden), and the report renders the "Target
// scoring" section; targetScore:false skips LOUDLY.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { scoreHost, scoreSurface, preScoreTargets } from '../tools/targetscore.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { mockAgent } from '../mock-agent.mjs';
import { renderReport } from '../engine/report.mjs';

const scope = (e, extra = {}) => ({ engagement: e, signedBy: 'x', cidrs: ['127.0.0.0/8'], ...extra });

async function withServer(srv, fn) {
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '0.0.0.0', r));
  const port = srv.address().port;
  try { return await fn(port); }
  finally { await new Promise((r) => srv.close(r)); }
}

// a blind-SSRF lab: /fetch?url= dials the URL out-of-band (the campaign-tools shape)
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
    res.writeHead(404); res.end('{}');
  });
}

// ——— the module: crafted signal sets ———

test('scoreHost: a soft API-heavy host OUTRANKS a Cloudflare static edge', () => {
  const soft = scoreHost({
    host: 'staging-api.lab.example',
    services: ['https:443'],
    endpoints: ['/login', '/api/users', '/api/orders?id=', '/api/items/{id}', '/api/chat', '/graphql',
      '/api/a', '/api/b', '/api/c', '/api/d', '/api/e', '/api/f'],
    tech: ['Laravel', 'PHP 8.1'],
  });
  const edge = scoreHost({
    host: 'www.lab.example', services: ['https:443'], endpoints: ['/'], tech: ['Cloudflare'],
  });
  assert.ok(soft.score > edge.score, `soft ${soft.score} must outrank edge ${edge.score}`);
  assert.ok(soft.score >= 80, 'the soft host scores high');
  assert.ok(edge.score <= 10, 'the edge-walled static host scores DOWN, not out');
  assert.ok(soft.classes.includes('api-heavy') && soft.classes.includes('idor-candidate') && soft.classes.includes('ai-surface'), 'soft host class hints');
  assert.ok(edge.classes.includes('edge-walled'), 'edge host class hint');
});

test('scoreHost: reasons are HONEST — each names its signal + observed evidence; absent signals emit nothing', () => {
  const bare = scoreHost({ host: 'plain.example' });
  assert.equal(bare.score, 30, 'a bare live host scores the base');
  assert.deepEqual(bare.reasons, [], 'no observed signals, NO reasons');
  assert.deepEqual(bare.classes, []);
  const edge = scoreHost({ host: 'www.example', services: ['https:443'], endpoints: ['/'], tech: ['Akamai'] });
  assert.ok(!edge.reasons.some((r) => /non-cdn-origin/.test(r)), 'an edge-fingerprinted host must NOT claim origin reachability');
  assert.ok(edge.reasons.some((r) => /edge-walled -20 — .*Akamai/.test(r)), 'the edge reason names the fingerprinted vendor');
  const dense = scoreHost({ host: 'api.example', endpoints: ['/a', '/b', '/c', '/d', '/e', '/f'] });
  assert.ok(dense.reasons.some((r) => /api-density \+12 — 6 endpoints harvested/.test(r)), 'the density reason cites the REAL count');
  assert.ok(!dense.reasons.some((r) => /auth-surface/.test(r)), 'no login endpoint observed, no auth-surface reason');
  assert.ok(!dense.reasons.some((r) => /ai-surface/.test(r)), 'no AI hint observed, no ai-surface reason');
  const ai = scoreHost({ host: 'app.example', endpoints: ['/v1/chat/completions'] });
  assert.ok(ai.reasons.some((r) => /ai-surface \+12 — .*\/v1\/chat\/completions/.test(r)), 'the AI reason names the observed endpoint');
});

test('scoreHost: deterministic — same ctx, byte-identical output', () => {
  const ctx = { host: 'dev.lab', endpoints: ['/login', '/api/x?id='], tech: ['Drupal'], services: ['http:80'] };
  assert.equal(JSON.stringify(scoreHost(ctx)), JSON.stringify(scoreHost(ctx)));
});

// ——— scoreSurface over the live graph ———

test('scoreSurface: groups graph nodes per host, orders score-descending, exposes the scores map', () => {
  const c = new Campaign({ engine: {}, scope: scope('TS-M1'), runAgent: mockAgent, stallCheckMs: 0 });
  const soft = c.surface.host('10.0.0.1', { label: 'staging.lab.example' });
  c.surface.service(soft, 443, 'tcp', 'https');
  for (const p of ['/login', '/api/a', '/api/b?id=', '/api/items/{id}']) c.surface.endpoint(soft, p, 'GET');
  c.surface.tech(soft, 'WordPress');
  const edge = c.surface.host('10.0.0.2', { label: 'www.lab.example' });
  c.surface.service(edge, 443, 'tcp', 'https');
  c.surface.tech(edge, 'Cloudflare');
  const scored = scoreSurface(c.surface);
  assert.equal(scored.ordered[0], 'staging.lab.example', 'the soft host leads');
  assert.equal(scored.scores['staging.lab.example'], scored.hosts[0].score);
  assert.equal(scored.scores['10.0.0.2'], scored.hosts[1].score, 'the map keys by ip too');
  // and it reads the serialized form identically (determinism across toJSON)
  const fromJson = scoreSurface(c.surface.toJSON());
  assert.equal(JSON.stringify(fromJson.hosts), JSON.stringify(scored.hosts));
});

test('preScoreTargets: sweep pre-pass orders by hostname keywords (+ inherited surface detail)', () => {
  const rows = preScoreTargets(['www.example', 'staging.example', 'api.example']);
  assert.deepEqual(rows.map((r) => r.target), ['staging.example', 'api.example', 'www.example']);
  assert.ok(rows[0].score > rows[2].score);
});

// ——— campaign wiring ———

test('runTargetScoring: scores land ON host nodes; getState + the report section render them', () => {
  const c = new Campaign({ engine: {}, scope: scope('TS-C1'), runAgent: mockAgent, tooledRecon: true, stallCheckMs: 0 });
  assert.equal(c.targetScoreEnabled, true, 'default ON under tooledRecon');
  const soft = c.surface.host('10.0.0.1', { label: 'staging-api.lab.example' });
  c.surface.service(soft, 443, 'tcp', 'https');
  for (const p of ['/login', '/api/orders?id=', '/api/items/{id}', '/api/chat']) c.surface.endpoint(soft, p, 'GET');
  c.surface.tech(soft, 'Laravel');
  const edge = c.surface.host('10.0.0.2', { label: 'www.lab.example' });
  c.surface.service(edge, 443, 'tcp', 'https');
  c.surface.tech(edge, 'Cloudflare');
  const res = c.runTargetScoring();
  assert.equal(res.ok, true);
  assert.equal(res.ordered[0], 'staging-api.lab.example');
  const softNode = c.surface.nodes.get(soft);
  assert.ok(softNode.targetScore && softNode.targetScore.score > 80, 'the score rides the host node (persists with the surface)');
  assert.ok(softNode.targetScore.reasons.length >= 4, 'the reasons ride along');
  assert.ok(c.activity.some((e) => e.kind === 'targetscore.scored' && e.data.hosts === 2), 'scored event on the record');
  assert.ok(c.getState().targetScore.ordered[0] === 'staging-api.lab.example', 'the rollup is exposed in state');
  const md = renderReport(c.surface.toJSON());
  assert.match(md, /## Target scoring/);
  assert.match(md, /staging-api\.lab\.example/);
  assert.match(md, /reordered per-host tool budgets ONLY/, 'the report states the reorder-only doctrine');
  assert.match(md, /hostname:soft-env/, 'a scored reason renders verbatim');
});

test('runTargetScoring: targetScore:false skips LOUDLY; default OFF without tooledRecon', () => {
  const off = new Campaign({ engine: {}, scope: scope('TS-C2'), runAgent: mockAgent, tooledRecon: true, targetScore: false, stallCheckMs: 0 });
  off.surface.host('10.0.0.1', { label: 'a.lab' });
  const r = off.runTargetScoring();
  assert.equal(r.skipped, 'not-enabled');
  assert.ok(off.activity.some((e) => e.kind === 'targetscore.skip' && e.data.reason === 'not-enabled'), 'a dormant layer is never silent');
  const plain = new Campaign({ engine: {}, scope: scope('TS-C3'), runAgent: mockAgent, stallCheckMs: 0 });
  assert.equal(plain.targetScoreEnabled, false, 'no tooledRecon, no default scoring');
});

test('tooledRecon pre-pass: the sweep order is score-descending and on the record', () => {
  const c = new Campaign({
    engine: {}, scope: scope('TS-C4'), runAgent: mockAgent, tooledRecon: true, stallCheckMs: 0,
    targets: ['www.lab.example', 'staging.lab.example'], reconOpts: { passive: false },
  });
  // drive just the pre-pass shape: preScoreTargets is what tooledRecon logs
  const pre = preScoreTargets(c.targets.filter((t) => true), null);
  assert.equal(pre[0].target, 'staging.lab.example', 'the non-prod host sweeps first');
  assert.ok(pre[0].reasons.some((r) => /hostname:soft-env/.test(r)));
});

test('runOobPass: the probe budget orders score-descending when the ROI layer ran', async () => {
  await withServer(createOobApp(), async (portSoft) => {
    await withServer(createOobApp(), async (portEdge) => {
      const c = new Campaign({
        engine: {}, scope: scope('TS-O1'), runAgent: mockAgent,
        targetScore: true, oob: { publicBaseUrl: 'auto', kinds: ['ssrf'], deadlineMs: 2500 }, stallCheckMs: 0,
      });
      const soft = c.surface.host('127.0.0.1', { label: 'staging.lab.example' });
      c.surface.service(soft, portSoft, 'tcp', 'http');
      for (const p of ['/login', '/api/a', '/api/b?id=']) c.surface.endpoint(soft, p, 'GET');
      c.surface.endpoint(soft, '/fetch?url=x', 'GET');
      c.surface.tech(soft, 'WordPress');
      const edge = c.surface.host('127.0.0.2', { label: 'www.lab.example' });
      c.surface.service(edge, portEdge, 'tcp', 'http');
      c.surface.endpoint(edge, '/fetch?url=x', 'GET');
      c.surface.tech(edge, 'Cloudflare');
      const sres = c.runTargetScoring();
      assert.equal(sres.ordered[0], 'staging.lab.example');
      const res = await c.runOobPass();
      assert.equal(res.ok, true);
      assert.equal(res.proven, 2, 'both endpoints still proved — the reorder hides NOTHING');
      // the FIRST filed oob finding must be the soft host's probe
      const findingEvents = c.activity.filter((e) => e.kind === 'finding' && String(e.data.ref || '').startsWith('oob:ssrf:'));
      assert.equal(findingEvents.length, 2);
      const first = [...c.surface.nodes.values()].find((n) => n.type === 'finding' && n.ref === findingEvents[0].data.ref);
      assert.match(first.oob.request.url, new RegExp(`127\\.0\\.0\\.1:${portSoft}`), 'the soft host was probed FIRST');
    });
  });
});
