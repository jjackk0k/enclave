// VARVEL target-defense fingerprinting + per-target stealth calibration tests.
//   node --test varvel/test/target-profile.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fingerprintDefenses, calibrateStealth, mergeFingerprints, detectStack } from '../engine/target-profile.mjs';

test('fingerprintDefenses: Cloudflare by cf-ray + server header', () => {
  const fp = fingerprintDefenses({ status: 200, headers: { server: 'cloudflare', 'cf-ray': '82a1b2c3', 'cf-cache-status': 'DYNAMIC' }, body: '' });
  const cf = fp.defenses.find((d) => d.id === 'cloudflare');
  assert.ok(cf, 'cloudflare detected');
  assert.equal(cf.monitoring, 'high');
  assert.ok(cf.signals.length >= 2);
});

test('fingerprintDefenses: WAF block page only on the miss response (Imperva cookie)', () => {
  const fp = fingerprintDefenses({ status: 403, headers: { 'set-cookie': ['visid_incap_123=abc; Path=/', 'incap_ses_1=xyz'] }, body: 'Incapsula incident ID: 999' });
  assert.ok(fp.defenses.find((d) => d.id === 'imperva'), 'imperva via cookie + block page');
});

test('fingerprintDefenses: rate-limit headers + 429 throttle detected', () => {
  const fp = fingerprintDefenses({ status: 429, headers: { 'x-ratelimit-limit': '100', 'x-ratelimit-remaining': '0', 'retry-after': '30' } });  assert.ok(fp.rateLimit, 'rate limit parsed');
  assert.equal(fp.rateLimit.limit, 100);
  assert.equal(fp.rateLimit.throttled, true);
});

test('fingerprintDefenses: security-header maturity + no false WAF on a bare app', () => {
  const fp = fingerprintDefenses({ status: 200, headers: { server: 'Werkzeug/2.0 Python/3.11', 'strict-transport-security': 'max-age=1', 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY' }, body: '<h1>dev</h1>' });
  assert.equal(fp.defenses.length, 0, 'no WAF falsely matched on a dev server');
  assert.equal(fp.securityHeaders.length, 3);
});

test('fingerprintDefenses: Axiom Shield (our practice WAF) detected from its header', () => {
  const fp = fingerprintDefenses({ status: 200, headers: { server: 'Axiom', 'x-axiom-shield': 'active', 'content-security-policy': "default-src 'self'" }, body: '<h1>ok</h1>' });
  const sh = fp.defenses.find((d) => d.id === 'axiom-shield');
  assert.ok(sh, 'axiom-shield detected');
  assert.equal(sh.kind, 'waf');
  assert.equal(sh.monitoring, 'high', 'a shielded target calibrates quiet');
  assert.ok(fp.securityHeaders.includes('csp'));
});

test('calibrateStealth: hardened WAF → quiet; throttled/challenge → paranoid; bare → normal', () => {
  const waf = calibrateStealth({ defenses: [{ id: 'cloudflare', vendor: 'Cloudflare', kind: 'waf-cdn', monitoring: 'high', signals: ['header:cf-ray'] }], rateLimit: null, challenge: null, securityHeaders: [] });
  assert.equal(waf.recommended, 'quiet');
  assert.match(waf.reasons.join(' '), /Cloudflare/);

  const throttled = calibrateStealth({ defenses: [], rateLimit: { limit: 60, throttled: true }, challenge: null, securityHeaders: [] });
  assert.equal(throttled.recommended, 'paranoid');

  const challenge = calibrateStealth({ defenses: [], rateLimit: null, challenge: { markers: ['bot-challenge'] }, securityHeaders: [] });
  assert.equal(challenge.recommended, 'paranoid');

  const bare = calibrateStealth({ defenses: [], rateLimit: null, challenge: null, securityHeaders: [] });
  assert.equal(bare.recommended, 'normal');
  assert.match(bare.reasons.join(' '), /faster sweep is acceptable/);
});

test('calibrateStealth: advertised rate limit yields a rateHint at ~half the limit', () => {
  const c = calibrateStealth({ defenses: [], rateLimit: { limit: 120, throttled: false }, challenge: null, securityHeaders: [] });
  assert.equal(c.recommended, 'quiet');
  assert.equal(c.rateHint, 60);
  assert.ok(c.budget.maxNoise <= 40, 'quiet budget attached');
});

test('mergeFingerprints unions defenses (max signals) + keeps the throttle', () => {
  const a = fingerprintDefenses({ status: 200, headers: { 'cf-ray': '1' } });                     // weak cloudflare
  const b = fingerprintDefenses({ status: 429, headers: { server: 'cloudflare', 'cf-ray': '1', 'retry-after': '5' } }); // stronger + throttled
  const m = mergeFingerprints(a, b);
  const cf = m.defenses.find((d) => d.id === 'cloudflare');
  assert.ok(cf.signals.length >= 2, 'kept the stronger cloudflare match');
  assert.equal(m.rateLimit.throttled, true, 'kept the throttle signal');
});

test('detectStack: hermetic — a WAF-like localhost server is fingerprinted + calibrated to quiet', async () => {
  const srv = http.createServer((req, res) => {
    const h = { server: 'cloudflare', 'cf-ray': '82abc', 'cf-cache-status': 'DYNAMIC' };
    if (req.url === '/') { res.writeHead(200, h); return res.end('<title>ok</title>'); }
    res.writeHead(403, { ...h, 'cf-mitigated': 'challenge' }); res.end('Attention Required! Cloudflare __cf_chl');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const r = await detectStack(`http://127.0.0.1:${srv.address().port}`, { timeout: 800 });
    assert.ok(r && r.defenses.find((d) => d.id === 'cloudflare'), 'cloudflare fingerprinted across the 2 probes');
    assert.ok(r.challenge, 'bot-challenge on the miss detected');
    assert.equal(r.calibration.recommended, 'paranoid', 'challenge → paranoid');
    assert.equal(r.probes, 2, 'passive-first: only 2 GETs');
  } finally { srv.close(); }
});
