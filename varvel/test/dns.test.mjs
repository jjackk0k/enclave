// VARVEL DNS recon tests — hermetic (injected mock resolver, no network).
//   node --test varvel/test/dns.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dnsRecon, subdomainScan, DEFAULT_SUBDOMAINS } from '../tools/dns.mjs';

const nx = () => { const e = new Error('NXDOMAIN'); e.code = 'ENOTFOUND'; throw e; };
const err = (code) => () => { const e = new Error(code); e.code = code; throw e; };

test('subdomainScan: reports only resolving subdomains', async () => {
  const live = new Set(['www.example.com', 'api.example.com']);
  const resolver = { resolve4: async (h) => (live.has(h) ? ['1.2.3.4'] : nx()) };
  const res = await subdomainScan('example.com', { words: ['www', 'api', 'nope', 'also-nope'], resolver });
  assert.deepEqual(res.subdomains.map((s) => s.name), ['api.example.com', 'www.example.com']); // sorted
  assert.equal(res.tried, 4);
  assert.equal(res.wildcard, false);
});

test('subdomainScan: WILDCARD dns is detected and filtered (P1)', async () => {
  // every host resolves (wildcard) to 9.9.9.9 except a real one with a distinct IP
  const resolver = { resolve4: async (h) => (h === 'real.victim.com' ? ['1.2.3.4'] : ['9.9.9.9']) };
  const res = await subdomainScan('victim.com', { words: ['www', 'api', 'real', 'junk'], resolver });
  assert.equal(res.wildcard, true, 'wildcard zone detected');
  assert.deepEqual(res.subdomains.map((s) => s.name), ['real.victim.com'], 'only the distinct-IP host survives');
  assert.ok(res.wildcardIps.includes('9.9.9.9'));
});

test('subdomainScan: concurrency<=0 is clamped, not zeroed (P3)', async () => {
  const resolver = { resolve4: async (h) => (h.startsWith('www.') ? ['1.2.3.4'] : nx()) };
  const res = await subdomainScan('x.com', { words: ['www', 'nope'], resolver, concurrency: 0 });
  assert.equal(res.subdomains.length, 1, 'still scanned with a clamped pool');
});

test('subdomainScan: transient errors are surfaced, not swallowed as absent (P2)', async () => {
  const resolver = { resolve4: async (h) => (h.startsWith('real.') ? ['1.2.3.4'] : (h.startsWith('flaky.') ? err('SERVFAIL')() : nx())) };
  const res = await subdomainScan('x.com', { words: ['real', 'flaky', 'gone'], resolver });
  assert.deepEqual(res.subdomains.map((s) => s.name), ['real.x.com']);
  assert.ok(res.errors && res.errors.some((e) => /flaky/.test(e.host) && e.code === 'SERVFAIL'), 'SERVFAIL surfaced');
});

test('subdomainScan: IPv6-only subdomain (ENODATA on A) found via AAAA (P2)', async () => {
  const resolver = {
    resolve4: async (h) => (h.startsWith('v6.') ? err('ENODATA')() : nx()),
    resolve6: async (h) => (h.startsWith('v6.') ? ['::1'] : nx()),
  };
  const res = await subdomainScan('x.com', { words: ['v6', 'nope'], resolver });
  assert.ok(res.subdomains.some((s) => s.name === 'v6.x.com' && s.v6), 'IPv6-only host discovered');
});

test('subdomainScan: v6-only WILDCARD zone is baselined and filtered (no A records at all)', async () => {
  // every random label answers AAAA fd00::99 (a v6 wildcard); only a real host differs
  const resolver = {
    resolve4: async () => err('ENODATA')(),
    resolve6: async (h) => (h === 'real.victim6.com' ? ['fd00::1'] : ['fd00::99']),
  };
  const res = await subdomainScan('victim6.com', { words: ['www', 'real', 'junk'], resolver });
  assert.equal(res.wildcard, true, 'an AAAA-only wildcard is still a wildcard');
  assert.deepEqual(res.subdomains.map((s) => s.name), ['real.victim6.com'], 'wildcard answers filtered on the v6 path too');
  assert.ok(res.wildcardIps.includes('fd00::99'), 'the v6 wildcard answer is reported in the baseline');
  assert.ok(res.subdomains[0].v6, 'the survivor is marked v6');
});

test('subdomainScan: v6 wildcard with NO distinct host yields nothing (fail-closed, no false assets)', async () => {
  const resolver = {
    resolve4: async () => err('ENODATA')(),
    resolve6: async () => ['2001:db8::53'], // everything answers the same v6 — pure wildcard
  };
  const res = await subdomainScan('allwild.com', { words: ['www', 'api'], resolver });
  assert.equal(res.wildcard, true);
  assert.equal(res.subdomains.length, 0, 'no phantom v6 subdomains from a wildcard zone');
});

test('subdomainScan: v4-only resolver behavior unchanged (no resolve6 -> no AAAA probing)', async () => {
  // pins the zero-v4-change contract: a resolver without resolve6 never sees a fallback
  const live = new Set(['www.example.com']);
  const resolver = { resolve4: async (h) => (live.has(h) ? ['1.2.3.4'] : nx()) };
  const res = await subdomainScan('example.com', { words: ['www', 'gone'], resolver });
  assert.deepEqual(res.subdomains.map((s) => s.name), ['www.example.com']);
  assert.equal(res.wildcard, false);
});

test('subdomainScan: throws clearly when resolver lacks resolve4 (P4)', async () => {
  await assert.rejects(() => subdomainScan('x.com', { resolver: { resolve6: async () => [] } }), /resolve4 is required/);
});

test('subdomainScan: IDN domain is punycoded before lookup (P5)', async () => {
  const seen = [];
  const resolver = { resolve4: async (h) => { seen.push(h); return nx(); } };
  await subdomainScan('münchen.de', { words: ['www'], resolver });
  assert.ok(seen.some((h) => h.includes('xn--mnchen-3ya.de')), 'queried the A-label, not raw unicode');
});

test('dnsRecon: aggregates record types incl. SOA/TXT shapes, tolerates missing', async () => {
  const resolver = {
    resolve4: async () => ['1.2.3.4'],
    resolve6: async () => nx(),
    resolveMx: async () => [{ exchange: 'mail.example.com', priority: 10 }],
    resolveTxt: async () => [['v=spf1 -all']],
    resolveNs: async () => ['ns1.example.com'],
    resolveCname: async () => nx(),
    resolveSoa: async () => ({ nsname: 'ns1.example.com', serial: 42 }),
  };
  const res = await dnsRecon('example.com', { resolver });
  assert.deepEqual(res.records.A, ['1.2.3.4']);
  assert.equal(res.records.AAAA, undefined, 'missing AAAA tolerated');
  assert.equal(res.records.MX[0].exchange, 'mail.example.com');
  assert.equal(res.records.SOA.nsname, 'ns1.example.com', 'SOA object shape kept');
  assert.deepEqual(res.records.TXT, [['v=spf1 -all']], 'TXT chunked string[][] shape kept');
});

test('dnsRecon: transient lookup failures surface in errors, not as absent', async () => {
  const resolver = { resolve4: async () => ['1.2.3.4'], resolveMx: async () => err('SERVFAIL')() };
  const res = await dnsRecon('example.com', { resolver });
  assert.deepEqual(res.records.A, ['1.2.3.4']);
  assert.equal(res.records.MX, undefined);
  assert.equal(res.errors.MX, 'SERVFAIL');
});

test('DEFAULT_SUBDOMAINS: substantial wordlist', () => {
  assert.ok(DEFAULT_SUBDOMAINS.length >= 40);
  assert.ok(DEFAULT_SUBDOMAINS.includes('vpn') && DEFAULT_SUBDOMAINS.includes('api'));
});
