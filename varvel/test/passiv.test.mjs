// VARVEL passiv tests — fully hermetic (fetchImpl injected, no network at all).
//   node --test varvel/test/passiv.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { passiveRecon, parseCrtSh, parseWaybackCdx } from '../tools/passiv.mjs';

const CRTSH_FIXTURE = JSON.stringify([
  { name_value: 'www.acme.test' },
  { name_value: 'api.acme.test\nmail.acme.test' },
  { name_value: '*.dev.acme.test' },
  { name_value: 'www.acme.test' },                    // dup
  { name_value: 'evil.other-domain.test' },           // off-zone — must be dropped
  { name_value: 'ACME.test' },                        // apex, odd case
  { name_value: 'bad name.acme.test' },               // malformed — dropped
]);

const WAYBACK_FIXTURE = JSON.stringify([
  ['original'],
  ['http://www.acme.test/index.html'],
  ['https://api.acme.test/v1/users?id=42&role=admin'],
  ['https://api.acme.test/v1/users?id=42&role=admin'], // dup
  ['http://www.acme.test/old-admin/login?next=/dashboard'],
  ['http://www.acme.test/static/site.css'],            // asset — skipped
  ['https://other-domain.test/x?y=1'],                 // off-zone — dropped
  ['ftp://www.acme.test/file'],                        // non-http — dropped
]);

// A fetchImpl router: url → fixture response (or failure).
function fakeFetch(map) {
  const seen = [];
  const fn = async (url) => {
    seen.push(url);
    const hit = Object.entries(map).find(([k]) => url.includes(k));
    if (!hit) return { ok: false, status: 404, text: async () => '' };
    if (hit[1] === 'THROW') throw new Error('provider down');
    return { ok: true, status: 200, text: async () => hit[1] };
  };
  fn.seen = seen;
  return fn;
}

test('crt.sh parsing: dedupe, wildcard-strip, apex allowed, off-zone + malformed dropped', () => {
  const names = parseCrtSh(CRTSH_FIXTURE, 'acme.test');
  assert.deepEqual(names, ['acme.test', 'api.acme.test', 'dev.acme.test', 'mail.acme.test', 'www.acme.test']);
});

test('wayback parsing: endpoints + params mined per host, dups/assets/off-zone dropped', () => {
  const { endpoints, params } = parseWaybackCdx(WAYBACK_FIXTURE, 'acme.test');
  assert.deepEqual(endpoints.map((e) => e.host + e.path).sort(), [
    'api.acme.test/v1/users',
    'www.acme.test/index.html',
    'www.acme.test/old-admin/login',
  ]);
  assert.deepEqual(params.map((p) => p.host + ':' + p.name).sort(), [
    'api.acme.test:id', 'api.acme.test:role', 'www.acme.test:next',
  ]);
  assert.ok(endpoints.every((e) => e.source === 'wayback'));
});

test('aggregator: both sources merge; wayback-only hosts become subdomains; targetContact is 0', async () => {
  const fetchImpl = fakeFetch({ 'crt.sh': CRTSH_FIXTURE, 'web.archive.org': WAYBACK_FIXTURE });
  const res = await passiveRecon('acme.test', { fetchImpl });
  assert.equal(res.targetContact, 0);
  assert.equal(res.sources.crtsh, 'ok');
  assert.equal(res.sources.wayback, 'ok');
  assert.equal(res.requests, 2, 'requests went to providers only');
  assert.ok(fetchImpl.seen.every((u) => /crt\.sh|web\.archive\.org/.test(u)), 'no URL outside the providers was ever fetched');
  assert.ok(res.subdomains.some((s) => s.name === 'api.acme.test' && s.source === 'crt.sh'));
  assert.ok(res.endpoints.some((e) => e.path === '/old-admin/login'), 'forgotten endpoint surfaced');
  assert.ok(res.params.some((p) => p.name === 'role'), 'historic param surfaced');
});

test('resilience: one provider down never sinks the run', async () => {
  const fetchImpl = fakeFetch({ 'crt.sh': 'THROW', 'web.archive.org': WAYBACK_FIXTURE });
  const res = await passiveRecon('acme.test', { fetchImpl });
  assert.ok(/error/.test(res.sources.crtsh), 'crt.sh failure recorded honestly');
  assert.equal(res.sources.wayback, 'ok');
  assert.ok(res.endpoints.length > 0, 'surviving source still produced');
});

test('source selection: wayback-only run touches no other provider', async () => {
  const fetchImpl = fakeFetch({ 'web.archive.org': WAYBACK_FIXTURE });
  const res = await passiveRecon('acme.test', { sources: ['wayback'], fetchImpl });
  assert.equal(res.requests, 1);
  assert.ok(fetchImpl.seen.every((u) => u.includes('web.archive.org')));
  assert.deepEqual(res.subdomains.every((s) => s.source === 'wayback'), true);
});

test('robustness: garbage domain throws TypeError; provider garbage parses empty', async () => {
  await assert.rejects(() => passiveRecon('not a domain', { fetchImpl: fakeFetch({}) }), TypeError);
  const res = await passiveRecon('acme.test', { fetchImpl: fakeFetch({ 'crt.sh': '{{{', 'web.archive.org': 'not json' }) });
  assert.equal(res.subdomains.length, 0);
  assert.equal(res.endpoints.length, 0);
});
