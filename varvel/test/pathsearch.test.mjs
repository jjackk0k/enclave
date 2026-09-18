// VARVEL value-guided path search (LATS) tests — hermetic, mock target, no network.
//   node --test varvel/test/pathsearch.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pathSearch, classifyResponse, rank, OUTCOME_VALUE } from '../engine/pathsearch.mjs';

test('classifyResponse maps responses to outcome classes', () => {
  assert.equal(classifyResponse({ status: 404 }).cls, 'not-found');
  assert.equal(classifyResponse({ status: 403 }).cls, 'auth-wall');
  assert.equal(classifyResponse({ status: 405 }).cls, 'method-block');
  assert.equal(classifyResponse({ status: 301 }).cls, 'redirect');
  assert.equal(classifyResponse({ status: 200, body: 'DB_PASSWORD=hunter2' }).cls, 'sensitive-hit');
  assert.equal(classifyResponse({ status: 200, body: '<h1>Index of /x</h1>' }).cls, 'listing');
  assert.equal(classifyResponse({ status: 200, body: 'Traceback (most recent call last)' }).cls, 'error-leak');
  assert.equal(classifyResponse({ status: 200, body: 'hello' }).cls, 'reachable');
  assert.equal(classifyResponse({ status: 200, wrote: true }).cls, 'writable');
  assert.ok(OUTCOME_VALUE.writable > OUTCOME_VALUE['sensitive-hit'] && OUTCOME_VALUE['sensitive-hit'] > OUTCOME_VALUE['auth-wall']);
});

// A synthetic target: path -> response. Everything else is a 404.
const TARGET = {
  '/admin': { status: 200, body: 'portal' },
  '/.env': { status: 200, body: 'DB_PASSWORD=secret\nAPI_KEY=x' },       // sensitive
  '/images': { status: 200, body: '<img>' },                             // reachable
  '/backup': { status: 200, body: '<h1>Index of /backup</h1>' },         // listing
  '/admin/api': { status: 200, body: '{}' },
  '/admin/api/banner': { status: 200, body: '{"ok":true}', wrote: true },// writable
  '/admin/login': { status: 403, body: 'forbidden' },                    // auth-wall
  '/backup/db.sql': { status: 200, body: 'user password hash dump' },    // sensitive
  '/backup/': { status: 200, body: '<h1>Index of /backup</h1>' },        // listing
};
const CHILDREN = {
  __root__: ['/admin', '/.env', '/images', '/nope1', '/nope2', '/backup'],
  '/admin': ['/admin/api', '/admin/login', '/admin/dead'],
  '/admin/api': ['/admin/api/banner', '/admin/api/dead'],
  '/backup': ['/backup/db.sql', '/backup/', '/backup/dead'],
};
const expand = (d) => (CHILDREN[d.path || '__root__'] || []).map((p) => ({ path: p, method: p.endsWith('banner') ? 'POST' : 'GET' }));
const probe = async (d) => TARGET[d.path] || { status: 404 };
const root = { path: '__root__' };

test('auto-activation: fires with ≥2 credible paths, declines with <2', async () => {
  const on = await pathSearch(root, { expand, probe, maxProbes: 40 });
  assert.equal(on.activated, true, 'multiple credible paths -> tree search activates');

  const sparseChildren = { __root__: ['/.env', '/nope1', '/nope2', '/nope3'] };
  const off = await pathSearch(root, { expand: (d) => (sparseChildren[d.path || '__root__'] || []).map((p) => ({ path: p })), probe, maxProbes: 40 });
  assert.equal(off.activated, false, 'one credible path -> linear loop suffices');
  assert.match(off.reason, /credible/);
});

test('the search concentrates on high-value branches and prunes dead ones', async () => {
  const r = await pathSearch(root, { expand, probe, maxProbes: 50, pruneFloor: 0.15 });
  assert.ok(r.probes <= 50, 'respects the probe budget');

  // Dead (404) probes are pruned, never expanded further.
  const deadExpanded = r.trace.filter((t) => /dead|nope/.test(t.descriptor.path) && !t.pruned);
  assert.equal(deadExpanded.length, 0, '404 branches are pruned');

  // The top-ranked path reaches a genuinely valuable terminal.
  const best = r.best[0];
  assert.ok(best, 'surfaced at least one path');
  assert.ok(['sensitive-hit', 'writable', 'listing'].includes(best.terminal) || best.path.some((s) => ['sensitive-hit', 'writable'].includes(s.cls)),
    'top path leads to a real exposure');

  // The writable banner endpoint (depth 3) is discovered by following the promising branch.
  const foundWritable = r.trace.some((t) => t.descriptor.path === '/admin/api/banner' && t.cls === 'writable');
  assert.ok(foundWritable, 'the search drilled to the writable endpoint');
});

test('opsecCost lowers a noisy path’s value (quieter paths win ties)', async () => {
  const noisy = (d) => (d.path === '/.env' ? 1 : 0);
  const r = await pathSearch(root, { expand, probe, maxProbes: 30, opsecCost: noisy });
  const envHit = r.trace.find((t) => t.descriptor.path === '/.env');
  assert.ok(envHit, 'probed /.env');
  assert.ok(envHit.score < 0.95, `noisy /.env scored ${envHit.score} < its base 0.95`);
});

test('prior boosts a known-good descriptor', async () => {
  const prior = (d) => (d.path === '/images' ? 1 : 0); // pretend a prior session found /images useful
  const r = await pathSearch(root, { expand, probe, maxProbes: 30, prior });
  const img = r.trace.find((t) => t.descriptor.path === '/images');
  assert.ok(img.score > 0.35, `prior lifted /images above its base 0.35 (got ${img.score})`);
});

test('rank() returns paths ordered by cumulative value', async () => {
  const r = await pathSearch(root, { expand, probe, maxProbes: 50 });
  const paths = rank(r.tree);
  for (let i = 1; i < paths.length; i++) assert.ok(paths[i - 1].score >= paths[i].score, 'sorted desc');
});
