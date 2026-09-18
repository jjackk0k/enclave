// canary.test.mjs — hermetic tests for tools/canary.mjs (all data injected, zero network).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canaryScan, labelIsTokenShape, WEIGHTS } from '../tools/canary.mjs';

test('token shape: 16-hex and UUID labels, not ordinary words', () => {
  assert.equal(labelIsTokenShape('a1b2c3d4e5f60718'), true);
  assert.equal(labelIsTokenShape('550e8400-e29b-41d4-a716-446655440000'), true);
  assert.equal(labelIsTokenShape('mail'), false);
  assert.equal(labelIsTokenShape('static'), false);
});

test('known canary domain in a CNAME is near-certain', async () => {
  const r = await canaryScan({
    target: 'acme.test',
    dnsData: { cname: ['www.acme.test.a1b2.canarytokens.com'], a: [], txt: [], mx: [] },
  });
  assert.equal(r.suspicion, WEIGHTS['known-canary-domain']); // 'a1b2' is not token-shaped → domain weight only
  assert.ok(r.artifacts.some((a) => a.kind === 'known-canary-domain'));
  assert.equal(r.verdict, 'deception likely');
  assert.ok(r.caveats.some((c) => /treat reachable data as bait/.test(c)));
});

test('token-shaped label alone scores the token weight', async () => {
  const r = await canaryScan({
    target: 'acme.test',
    dnsData: { cname: ['cdn.550e8400-e29b-41d4-a716-446655440000.example.test'], a: [], txt: [], mx: [] },
  });
  assert.equal(r.suspicion, WEIGHTS['canary-token-shape']);
  assert.equal(r.verdict, 'deception possible');
});

test('honey paths and shares score from data without any request', async () => {
  const r = await canaryScan({
    target: 'acme.test',
    dnsData: { a: [], cname: [], txt: [], mx: [] },
    paths: ['/index.html', '/passwords.xlsx', '/hr/salaries.csv'],
    shares: ['IPC$', 'backup$'],
  });
  const kinds = r.artifacts.map((a) => a.kind).sort();
  assert.deepEqual(kinds, ['honey-path', 'honey-path', 'honey-share'].sort());
  assert.equal(r.suspicion, 25 + 25 + 20);
});

test('single bait subdomain does NOT fire (real-estate honesty); clusters do', async () => {
  const one = await canaryScan({ target: 'acme.test', dnsData: { a: [], cname: [], txt: [], mx: [], subs: [{ name: 'admin.acme.test', ips: ['10.0.0.1'] }] } });
  assert.equal(one.artifacts.filter((a) => a.kind === 'bait-subdomain').length, 0);
  const many = await canaryScan({ target: 'acme.test', dnsData: { a: [], cname: [], txt: [], mx: [], subs: [{ name: 'admin.acme.test', ips: [] }, { name: 'backup.acme.test', ips: [] }, { name: 'jenkins.acme.test', ips: [] }] } });
  assert.equal(many.artifacts.filter((a) => a.kind === 'bait-subdomain').length, 1);
  assert.ok(many.caveats.some((c) => /real estates/.test(c)));
});

test('clean estate scores zero with the clean-shape verdict', async () => {
  const r = await canaryScan({
    target: 'acme.test',
    dnsData: { a: ['93.184.216.34'], cname: [], txt: ['v=spf1 -all'], mx: ['mail.acme.test'], subs: [{ name: 'www.acme.test', ips: ['93.184.216.34'] }] },
    paths: ['/index.html', '/about', '/contact'],
    shares: ['IPC$'],
  });
  assert.equal(r.suspicion, 0);
  assert.equal(r.verdict, 'clean shape');
});

test('custom patterns catch self-hosted canary consoles', async () => {
  const r = await canaryScan({
    target: 'acme.test',
    customPatterns: ['honeypot.internal.example'],
    dnsData: { cname: ['timecard.honeypot.internal.example'], a: [], txt: [], mx: [] },
  });
  assert.ok(r.artifacts.some((a) => a.kind === 'known-canary-domain' && /honeypot\.internal/.test(a.evidence)));
});

test('live resolver path uses injected resolveImpl and tolerates NXDOMAIN', async () => {
  const calls = [];
  const r = await canaryScan({
    target: 'acme.test',
    resolveImpl: async (host, rr) => { calls.push(rr); if (rr === 'TXT') throw Object.assign(new Error('NXDOMAIN'), { code: 'ENOTFOUND' }); return []; },
  });
  assert.deepEqual(calls, ['A', 'CNAME', 'TXT', 'MX']);
  assert.ok(r.caveats.some((c) => /TXT lookup/.test(c)));
  assert.equal(r.suspicion, 0);
});

test('target is required', async () => {
  await assert.rejects(() => canaryScan({}), /target is required/);
});
