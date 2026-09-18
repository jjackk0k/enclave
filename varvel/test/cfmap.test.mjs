// cfmap.test.mjs — hermetic pins for the challenge-surface mapper.
// Fake fetchers with canned responses only — NO live network, ever.

import test from 'node:test';
import assert from 'node:assert/strict';
import { checkUrl, mapSurface, DEFAULT_PATHS } from '../tools/cfmap.mjs';

const CF_HEADERS = { server: 'cloudflare', 'cf-ray': '97abc123-LHR', 'cf-mitigated': 'challenge' };
const CHALLENGE_BODY = '<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>';
const LABYRINTH_BODY = '<html><body><a href="/cdn-cgi/labyrinth/abc123">more</a></body></html>';

// A fetcher over a { path: {status, headers, body} } route map; unknown paths 404.
// Records every invocation ({ url, at }) when a `calls` array is handed in.
const fakeFetcher = (routes, calls) => async (url) => {
  if (calls) calls.push({ url, at: Date.now() });
  const r = routes[new URL(url).pathname];
  if (!r) return { status: 404, headers: { server: 'cloudflare' }, body: 'not found' };
  if (r.throw) throw new Error(r.throw);
  return { status: r.status, headers: r.headers || {}, body: r.body || '' };
};

test('DEFAULT_PATHS export is the documented probe set', () => {
  assert.deepEqual(DEFAULT_PATHS, ['/', '/api', '/api/health', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/feed', '/wp-json/', '/graphql']);
});

test('checkUrl: fetcher result becomes { url, status, detection, fetchedAt } with engine detection', async () => {
  const r = await checkUrl('https://target.example/', {
    fetcher: async () => ({ status: 403, headers: CF_HEADERS, body: CHALLENGE_BODY }),
  });
  assert.equal(r.url, 'https://target.example/');
  assert.equal(r.status, 403);
  assert.equal(r.detection.kind, 'managed-js');
  assert.equal(r.detection.cf.mitigated, 'challenge');
  assert.ok(!('error' in r), 'no error key on a clean probe');
  assert.ok(Number.isFinite(Date.parse(r.fetchedAt)), 'fetchedAt is an ISO timestamp');
});

test('map: challenged paths counted, the one open 200 lands in summary.open with the honesty note', async () => {
  const routes = {
    '/': { status: 403, headers: CF_HEADERS, body: CHALLENGE_BODY },
    '/api': { status: 403, headers: CF_HEADERS, body: CHALLENGE_BODY },
    '/api/health': { status: 200, headers: { server: 'cloudflare', 'cf-ray': '1-LHR' }, body: '{"ok":true}' },
  };
  const res = await mapSurface('https://target.example', { paths: ['/', '/api', '/api/health'], paceMs: 0, fetcher: fakeFetcher(routes) });
  assert.equal(res.baseUrl, 'https://target.example');
  assert.equal(res.summary.total, 3);
  assert.equal(res.summary.challenged, 2);
  assert.deepEqual(res.summary.open, [{ path: '/api/health', status: 200 }]);
  assert.equal(res.summary.stopped, undefined, 'no stop on a clean map');
  assert.match(res.summary.note, /not a bypass/i);
  assert.match(res.note, /surface, not a bypass/i);
  assert.equal(res.pace.paceMs, 0);
  const open = res.probes.find((p) => p.path === '/api/health');
  assert.equal(open.status, 200);
  assert.equal(open.detection.kind, 'none');
  const blocked = res.probes.find((p) => p.path === '/');
  assert.equal(blocked.detection.kind, 'managed-js');
});

test('labyrinth-suspect STOPS the map: zero further requests, stop recorded, links-not-followed stated', async () => {
  const calls = [];
  const routes = {
    '/': { status: 403, headers: CF_HEADERS, body: CHALLENGE_BODY },
    '/a': { status: 200, headers: { server: 'cloudflare' }, body: LABYRINTH_BODY },
    '/b': { status: 200, headers: {}, body: 'ok' },
    '/c': { status: 200, headers: {}, body: 'ok' },
  };
  const res = await mapSurface('https://target.example', { paths: ['/', '/a', '/b', '/c'], paceMs: 0, fetcher: fakeFetcher(routes, calls) });
  assert.equal(calls.length, 2, 'fetcher saw / and /a only — nothing requested after the labyrinth hit');
  assert.deepEqual(calls.map((c) => new URL(c.url).pathname), ['/', '/a']);
  assert.equal(res.probes.length, 2);
  assert.equal(res.summary.stopped, 'labyrinth-suspect');
  assert.deepEqual(res.summary.labyrinth, ['/a']);
  assert.match(res.summary.note, /NOT followed/);
  assert.match(res.note, /NOT followed/);
  assert.match(res.note, /Labyrinth/);
});

test('throwing fetcher: honest error entries, never a crash', async () => {
  const r = await checkUrl('https://target.example/', { fetcher: async () => { throw new Error('socket boom'); } });
  assert.equal(r.status, 0);
  assert.match(r.error, /socket boom/);
  assert.equal(r.detection.kind, 'none');

  const res = await mapSurface('https://target.example', {
    paths: ['/', '/api'], paceMs: 0,
    fetcher: async () => { throw new Error('connection refused'); },
  });
  assert.equal(res.summary.errors.length, 2);
  assert.deepEqual(res.summary.errors.map((e) => e.path), ['/', '/api']);
  assert.ok(res.probes.every((p) => p.status === 0 && /connection refused/.test(p.error)));
  assert.equal(res.summary.challenged, 0);
});

test('pacing: gaps between request starts honor paceMs', async () => {
  const at = [];
  const fetcher = async () => { at.push(Date.now()); return { status: 200, headers: {}, body: 'ok' }; };
  const paceMs = 150;
  const res = await mapSurface('https://target.example', { paths: ['/', '/a', '/b'], paceMs, fetcher });
  assert.equal(at.length, 3);
  assert.equal(res.pace.paceMs, paceMs);
  const EPS = 25; // Windows timer slop
  for (let i = 1; i < at.length; i++) {
    const gap = at[i] - at[i - 1];
    assert.ok(gap >= paceMs - EPS, `gap ${i} paced: ${gap}ms >= ${paceMs - EPS}ms`);
  }
});

test('usage error: a non-http(s) baseUrl is a TypeError, not a probe', async () => {
  await assert.rejects(() => mapSurface('ftp://target.example', { fetcher: async () => ({}) }), /http\(s\) URL/);
});
