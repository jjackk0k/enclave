// challenge.test.mjs — hermetic pins for the challenge-taxonomy engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { detectChallenge, summarizeSurface } from '../engine/challenge.mjs';

const CF_403 = {
  status: 403,
  headers: { server: 'cloudflare', 'cf-mitigated': 'challenge', 'cf-ray': '97abc123-LHR' },
  body: '<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></html>',
};

test('managed challenge: cf-mitigated + interstitial + platform markers classify managed-js', () => {
  const d = detectChallenge(CF_403);
  assert.equal(d.present, true);
  assert.equal(d.kind, 'managed-js');
  assert.ok(d.cf.server && d.cf.ray === '97abc123-LHR' && d.cf.mitigated === 'challenge');
  assert.ok(d.signals.some((s) => /cf-mitigated/.test(s)) && d.signals.some((s) => /challenge-platform/.test(s)));
});

test('1020 block page is its own kind (rule fired, no challenge offered)', () => {
  const d = detectChallenge({ status: 403, headers: { server: 'cloudflare' }, body: '<h1>Access denied</h1><p>Error code: 1020</p>' });
  assert.equal(d.kind, 'block-1020');
});

test('429 with retry-after is rate-limit, not a challenge', () => {
  const d = detectChallenge({ status: 429, headers: { server: 'cloudflare', 'retry-after': '30' }, body: '' });
  assert.equal(d.kind, 'rate-limit');
  assert.equal(d.present, true);
});

test('turnstile iframe markers classify turnstile', () => {
  const d = detectChallenge({ status: 403, headers: { server: 'cloudflare' }, body: '<iframe src="https://challenges.cloudflare.com/turnstile/v0/abc"></iframe>' });
  assert.equal(d.kind, 'turnstile');
});

test('labyrinth markers classify labyrinth-suspect (never follow)', () => {
  const d = detectChallenge({ status: 200, headers: { server: 'cloudflare' }, body: '<a href="/cdn-cgi/labyrinth/abc123">more</a>' });
  assert.equal(d.kind, 'labyrinth-suspect');
  assert.ok(d.signals.some((s) => /do NOT follow/i.test(s)));
});

test('a clean 200 through CF is honestly none-with-caveat, not "unprotected"', () => {
  const d = detectChallenge({ status: 200, headers: { server: 'cloudflare', 'cf-ray': '1-LHR' }, body: '<html>real page</html>' });
  assert.equal(d.present, false);
  assert.equal(d.kind, 'none');
  assert.ok(d.signals.some((s) => /not proof/i.test(s)));
});

test('non-CF 200 is none', () => {
  const d = detectChallenge({ status: 200, headers: { server: 'nginx' }, body: 'ok' });
  assert.equal(d.kind, 'none');
});

test('fetch-style Headers objects work', () => {
  const h = new Headers({ server: 'cloudflare', 'cf-mitigated': 'challenge' });
  const d = detectChallenge({ status: 403, headers: h, body: 'Just a moment...' });
  assert.equal(d.kind, 'managed-js');
});

test('summarizeSurface separates open paths from challenged/blocked and keeps the honesty note', () => {
  const mk = (path, status, body) => ({ path, status, detection: detectChallenge({ status, headers: { server: 'cloudflare', 'cf-mitigated': status === 403 ? 'challenge' : '' }, body }) });
  const s = summarizeSurface([
    mk('/', 403, 'Just a moment... <script src="/cdn-cgi/challenge-platform/x">'),
    mk('/api/health', 200, '{"ok":true}'),
    mk('/feed', 200, '<rss/>'),
  ]);
  assert.equal(s.challenged, 1);
  assert.deepEqual(s.open.map((o) => o.path).sort(), ['/api/health', '/feed']);
  assert.ok(/NOT a bypass|not a bypass|surface/i.test(s.note));
});
