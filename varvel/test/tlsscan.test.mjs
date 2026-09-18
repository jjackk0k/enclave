// VARVEL TLS analyzer tests — pure classifier (deterministic) + analyzeTls robustness.
//   node --test varvel/test/tlsscan.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tlsFindings, analyzeTls } from '../tools/tlsscan.mjs';

const NOW = Date.parse('2026-01-01T00:00:00Z');
const DAY = 86400000;
const inDays = (d) => new Date(NOW + d * DAY).toUTCString();
const has = (f, ref) => f.some((x) => x.ref === ref);
const sev = (f, ref) => (f.find((x) => x.ref === ref) || {}).sev;

test('tlsFindings: OpenSSL valid_to format parses (expired + future, double-space day)', () => {
  assert.ok(has(tlsFindings({ cert: { validTo: 'Dec 31 23:59:59 2025 GMT' }, now: NOW }), 'TLS-EXPIRED'));
  assert.ok(!has(tlsFindings({ cert: { validTo: 'Apr  1 00:00:00 2027 GMT' }, now: NOW }), 'TLS-EXPIRED'));
});

test('tlsFindings: expiry buckets (expired / imminent<=7 / soon<=30 / ok)', () => {
  assert.equal(sev(tlsFindings({ cert: { validTo: inDays(-40) }, now: NOW }), 'TLS-EXPIRED'), 'high');
  assert.equal(sev(tlsFindings({ cert: { validTo: inDays(3) }, now: NOW }), 'TLS-EXPIRING'), 'med');
  assert.equal(sev(tlsFindings({ cert: { validTo: inDays(20) }, now: NOW }), 'TLS-EXPIRING'), 'low');
  assert.ok(!has(tlsFindings({ cert: { validTo: inDays(200) }, now: NOW }), 'TLS-EXPIRING'));
});

test('tlsFindings: unparseable expiry -> BADDATE; future validFrom -> NOTYETVALID', () => {
  assert.ok(has(tlsFindings({ cert: { validTo: 'not-a-date' }, now: NOW }), 'TLS-BADDATE'));
  assert.ok(has(tlsFindings({ cert: { validFrom: inDays(10), validTo: inDays(300) }, now: NOW }), 'TLS-NOTYETVALID'));
});

test('tlsFindings: uses Node trust verdict (untrusted / expired / self-signed)', () => {
  assert.ok(has(tlsFindings({ authorized: false, authorizationError: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', cert: {} }), 'TLS-UNTRUSTED'));
  assert.ok(has(tlsFindings({ authorized: false, authorizationError: 'CERT_HAS_EXPIRED', cert: {} }), 'TLS-EXPIRED'));
  assert.ok(has(tlsFindings({ authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT', cert: {} }), 'TLS-SELFSIGNED'));
});

test('tlsFindings: weak ciphers flagged, modern not', () => {
  assert.ok(has(tlsFindings({ cipher: 'ECDHE-RSA-RC4-SHA', cert: null }), 'TLS-CIPHER'));
  assert.ok(has(tlsFindings({ cipher: 'DES-CBC3-SHA', cert: null }), 'TLS-CIPHER'));
  assert.ok(!has(tlsFindings({ cipher: 'TLS_AES_256_GCM_SHA384', cert: null }), 'TLS-CIPHER'));
});

test('tlsFindings: SAN coverage — wildcard apex/multi-label negatives, no-SAN, trailing dot, IP-SAN', () => {
  assert.ok(has(tlsFindings({ cert: { san: 'DNS:*.example.com' }, hostname: 'example.com', now: NOW }), 'TLS-HOSTNAME'), 'wildcard does NOT cover apex');
  assert.ok(has(tlsFindings({ cert: { san: 'DNS:*.example.com' }, hostname: 'a.b.example.com', now: NOW }), 'TLS-HOSTNAME'), 'wildcard is single-label only');
  assert.ok(!has(tlsFindings({ cert: { san: 'DNS:*.example.com' }, hostname: 'api.example.com', now: NOW }), 'TLS-HOSTNAME'));
  assert.ok(has(tlsFindings({ cert: { subject: 'example.com' }, hostname: 'example.com', now: NOW }), 'TLS-NOSAN'), 'no-SAN cert flagged');
  assert.ok(!has(tlsFindings({ cert: { san: 'DNS:example.com' }, hostname: 'example.com.', now: NOW }), 'TLS-HOSTNAME'), 'trailing dot tolerated');
  assert.ok(!has(tlsFindings({ cert: { san: 'IP Address:10.0.0.1' }, hostname: '10.0.0.1', now: NOW }), 'TLS-HOSTNAME'), 'IP SAN matches IP host');
});

test('tlsFindings: v6 literal hosts — bracketed/expanded forms classify as IP, IP SANs compare canonically', () => {
  // a bracketed or compressed v6 host is an IP literal: no no-SAN flag, and a v6 IP SAN
  // in the cert's expanded form covers it (a false TLS-HOSTNAME here misclassifies the endpoint)
  assert.ok(!has(tlsFindings({ cert: { san: 'IP Address:0:0:0:0:0:0:0:1' }, hostname: '::1', now: NOW }), 'TLS-HOSTNAME'), 'expanded v6 SAN covers ::1');
  assert.ok(!has(tlsFindings({ cert: { san: 'IP Address:2001:0db8:0000:0000:0000:0000:0000:0025' }, hostname: '[2001:db8::25]', now: NOW }), 'TLS-HOSTNAME'), 'bracketed host + expanded SAN cover');
  assert.ok(has(tlsFindings({ cert: { san: 'IP Address:2001:0db8:0000:0000:0000:0000:0000:0026' }, hostname: '2001:db8::25', now: NOW }), 'TLS-HOSTNAME'), 'a DIFFERENT v6 SAN still mismatches');
  assert.ok(!has(tlsFindings({ cert: {}, hostname: '[fd00::1]', now: NOW }), 'TLS-NOSAN'), 'bracketed v6 host is an IP literal — no-SAN is not flagged for literals');
  // v4 regression: dotted-quad behavior is byte-for-byte what it was
  assert.ok(has(tlsFindings({ cert: { san: 'IP Address:10.0.0.2' }, hostname: '10.0.0.1', now: NOW }), 'TLS-HOSTNAME'), 'different v4 SAN still mismatches');
});

test('tlsFindings: overly-broad wildcard flagged', () => {
  assert.ok(has(tlsFindings({ cert: { san: 'DNS:*.com' }, hostname: 'x.com', now: NOW }), 'TLS-WILDCARD-BROAD'));
});

test('tlsFindings: severity-ordered and deduped', () => {
  const f = tlsFindings({ weakProtocols: ['TLS 1.0'], cert: { selfSigned: true, validTo: inDays(-5), san: null }, hostname: 'h.com', authorized: false, authorizationError: 'CERT_HAS_EXPIRED', now: NOW });
  const ranks = f.map((x) => ({ high: 1, med: 2, low: 3, info: 4 }[x.sev]));
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b), 'severity ordered');
  assert.equal(new Set(f.map((x) => x.ref)).size, f.length, 'no duplicate refs');
});

test('tlsFindings: clean modern cert -> no findings', () => {
  const f = tlsFindings({ protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', cert: { san: 'DNS:target.com', validTo: inDays(300), validFrom: inDays(-30), selfSigned: false }, hostname: 'target.com', weakProtocols: [], authorized: true, now: NOW });
  assert.deepEqual(f, []);
});

test('analyzeTls: bad port resolves {ok:false} instead of throwing', async () => {
  const r = await analyzeTls('127.0.0.1', 99999, { timeout: 300 });
  assert.equal(r.ok, false);
});
