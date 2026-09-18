// VARVEL guided web search (LATS applied to content discovery) against the live demo.
// Non-destructive: only GET + OPTIONS are sent — the write surface is found, never used.
//   node --test varvel/test/webpaths.test.mjs

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createDemoTarget } from '../targets/demo-corp.mjs';
import { guidedWebSearch } from '../engine/webpaths.mjs';
import { Campaign } from '../engine/campaign.mjs';

let server, base, PORT;
before(async () => {
  server = createDemoTarget();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  PORT = server.address().port;
  base = `http://127.0.0.1:${PORT}`;
});
after(() => server && server.close());

const get = (path) => new Promise((resolve) => {
  const u = new URL(path, base);
  http.get({ hostname: u.hostname, port: u.port, path: u.pathname }, (res) => { let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve(b)); }).on('error', () => resolve(''));
});

test('the search activates and surfaces the demo’s high-value paths', async () => {
  const r = await guidedWebSearch(base, { maxProbes: 60, timeout: 2000 });
  assert.equal(r.activated, true, 'multiple credible paths -> tree search runs');
  assert.ok(r.probes <= 60, 'respects the probe budget');

  const banner = r.trace.find((t) => /\/admin\/api\/banner$/.test(t.descriptor.path));
  assert.ok(banner, 'reached /admin/api/banner');
  assert.equal(banner.cls, 'write-candidate', 'flagged as a write surface (non-destructively, via OPTIONS)');

  assert.ok(r.trace.some((t) => /\.env$/.test(t.descriptor.path) && t.cls === 'sensitive-hit'), '/.env is a sensitive hit');
  assert.ok(!r.trace.some((t) => t.cls === 'not-found' && !t.pruned), '404s are pruned');
});

test('the top-ranked path leads to the write surface or a sensitive exposure', async () => {
  const r = await guidedWebSearch(base, { maxProbes: 60, timeout: 2000 });
  const best = r.best[0];
  assert.ok(best, 'a best path exists');
  const cls = new Set(best.path.map((s) => s.cls));
  assert.ok(cls.has('write-candidate') || cls.has('sensitive-hit') || best.terminal === 'listing',
    'the highest-value path is a real exposure');
});

test('the prober is non-destructive: the banner is unchanged after a full search', async () => {
  const before = await get('/admin/api/banner');
  await guidedWebSearch(base, { maxProbes: 40, timeout: 2000 });
  const afterSearch = await get('/admin/api/banner');
  assert.equal(before, afterSearch, 'the search changed nothing (GET/OPTIONS only)');
  assert.match(afterSearch, /Industrial automation/, 'banner still holds the original value');
});

test('campaign: guided search runs before the exploit phase and focuses the agent', async () => {
  let exploitPrompt = '';
  const agent = async (opts) => {
    const c = opts.messages[0].content;
    if (c.startsWith('Under a countersigned')) { exploitPrompt = c; return { text: 'proved the write path', steps: 1 }; }
    return { text: 'ok', steps: 1 };
  };
  const c = new Campaign({
    engine: {}, scope: { engagement: 'GUIDED-EXP', signedBy: 'x', cidrs: ['127.0.0.0/8'] },
    runAgent: agent, tooledRecon: true, guidedSearch: true, maxReplan: 0,
    targets: ['127.0.0.1'], reconOpts: { ports: [PORT], webPorts: new Set([PORT]), timeout: 2000 },
    hooks: { approve: async () => true },
  });
  const st = await c.run();
  assert.ok(c.exploitFocus && c.exploitFocus.length, 'guided search produced a focus list');
  assert.ok(c.exploitFocus.some((f) => /banner/.test(f.path)), 'focus includes the write-candidate endpoint');
  assert.match(exploitPrompt, /guided search/, 'the exploit prompt carries the focus list');
  assert.ok(st.activity.some((a) => a.kind === 'guided.search' && a.data.activated), 'guided.search activation logged');
  // the banner must still be untouched — detonation is the agent's job, not the search's
  assert.match(await get('/admin/api/banner'), /Industrial automation/, 'search left the target clean');
});
