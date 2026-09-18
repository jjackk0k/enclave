// VARVEL engine test suite — run with:  node --test varvel/test/
// Covers the surface model, classifier, OPSEC ledger, campaign FSM (incl. HITL
// gate, budget, Fireteam), cross-session memory, and report — with edge cases,
// not just the happy path.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { Surface, NODE_TYPES, EDGE_KINDS } from '../engine/surface.mjs';
import { classify, remediation } from '../engine/classify.mjs';
import { Opsec } from '../engine/opsec.mjs';
import { Campaign } from '../engine/campaign.mjs';
import { renderReport } from '../engine/report.mjs';
import { PHASES } from '../engine/phases.mjs';
import { mockAgent } from '../mock-agent.mjs';

const DATA = join(dirname(fileURLToPath(import.meta.url)), '..', '.data');
const clean = () => { try { rmSync(DATA, { recursive: true, force: true }); } catch {} };
clean();

const scope = (eng) => ({ engagement: eng, signedBy: 'M.Vale L4', cidrs: ['10.0.0.0/8'] });

test('surface: rich graph, host dedupe by IP', () => {
  const s = new Surface(scope('T'));
  const h1 = s.host('10.0.0.1', { label: 'a' });
  const h2 = s.host('10.0.0.1', { label: 'a' });
  assert.equal(h1, h2, 'same IP dedupes to one host');
  s.service(h1, 443, 'tcp', 'https');
  s.subdomain(h1, 'x.example');
  s.tech(h1, 'nginx', '1.24');
  s.finding(h1, { title: 't', sev: 'crit', ref: 'F1' });
  const c = s.counts();
  assert.equal(c.hosts, 1);
  assert.equal(c.svcs, 1);
  assert.equal(c.subdomains, 1);
  assert.equal(c.tech, 1);
  assert.equal(c.crit, 1);
});

test('surface: model meets RedAmon parity (16+ node types, 20+ edge kinds)', () => {
  assert.ok(Object.keys(NODE_TYPES).length >= 16, 'node types');
  assert.ok(EDGE_KINDS.length >= 20, 'edge kinds');
});

test('surface: toJSON/fromJSON roundtrip preserves graph', () => {
  const s = new Surface(scope('T2'));
  const h = s.host('10.0.0.2', {});
  s.service(h, 22, 'tcp', 'ssh');
  const back = Surface.fromJSON(s.toJSON());
  assert.equal(back.nodes.size, s.nodes.size);
  assert.equal(back.edges.length, s.edges.length);
  assert.equal(back.scope.engagement, 'T2');
});

test('surface: invalid severity is coerced to med', () => {
  const s = new Surface(scope('T3'));
  const h = s.host('10.0.0.3', {});
  const fid = s.finding(h, { title: 't', sev: 'NONSENSE' });
  assert.equal(s.nodes.get(fid).sev, 'med');
  assert.equal(s.nodes.get(fid).risk, 'medium');
});

test('surface: severity dialects normalize — a long-form critical is NOT downgraded', () => {
  // regression: cvepacks speaks 'critical'; the old unknown→'med' coercion silently
  // reported KEV-criticals as MEDIUM on the surface and in reports.
  const s = new Surface(scope('T3b'));
  const h = s.host('10.0.0.9', {});
  const crit = s.finding(h, { title: 'KEV RCE', sev: 'critical' });
  assert.equal(s.nodes.get(crit).sev, 'crit');
  assert.equal(s.nodes.get(crit).risk, 'high');
  const med = s.finding(h, { title: 'disclosure', sev: 'medium' });
  assert.equal(s.nodes.get(med).sev, 'med');
  assert.equal(s.nodes.get(med).risk, 'medium');
  const c = s.counts();
  assert.equal(c.crit, 1);
  assert.equal(c.risk.high, 1);
  assert.equal(c.risk.medium, 1);
});

test('surface: fromJSON backfills risk levels on legacy saves', () => {
  const s = new Surface(scope('T3c'));
  const h = s.host('10.0.0.10', {});
  s.finding(h, { title: 'legacy', sev: 'high', ref: 'L1' });
  const j = s.toJSON();
  for (const n of j.nodes) delete n.risk; // simulate a pre-riskLevel save
  const back = Surface.fromJSON(j);
  const f = [...back.nodes.values()].find((n) => n.type === 'finding');
  assert.equal(f.risk, 'high');
});

test('surface: link is idempotent (no duplicate edges)', () => {
  const s = new Surface(scope('T4'));
  const h = s.host('10.0.0.4', {});
  const before = s.edges.length;
  s.link(s.root, h, 'recon');
  s.link(s.root, h, 'recon');
  assert.equal(s.edges.length, before, 'duplicate edge not added');
});

test('classify: known categories + safe default', () => {
  assert.match(classify('unauthenticated admin panel').owasp, /A01/);
  assert.match(classify('weak postgres credentials').owasp, /A07/);
  assert.match(classify('SQL injection in search').owasp, /A03/);
  assert.match(classify('SSRF via webhook').owasp, /A10/);
  assert.match(classify('totally novel thing').owasp, /A04/);
  assert.ok(classify('anything').fix.length > 0, 'always yields a fix');
});

test('remediation: sorted by severity, one per finding', () => {
  const s = new Surface(scope('T5'));
  const h = s.host('10.0.0.5', {});
  s.finding(h, { title: 'low thing', sev: 'low' });
  s.finding(h, { title: 'crit thing', sev: 'crit' });
  const r = remediation(s.toJSON());
  assert.equal(r.length, 2);
  assert.equal(r[0].sev, 'crit', 'critical first');
});

test('opsec: record, cleanup, posture, out-of-range', () => {
  const o = new Opsec();
  o.record({ host: 'h', kind: 'file', path: '/tmp/x', cleanup: 'rm' });
  assert.equal(o.posture().cleanState, false);
  assert.equal(o.posture().pending, 1);
  assert.equal(o.markClean(0), true);
  assert.equal(o.posture().cleanState, true);
  assert.equal(o.markClean(99), false, 'out-of-range cleanup is safe');
});

test('campaign: full governed run builds surface; NO audit key (that is the enclave)', async () => {
  const c = new Campaign({ engine: {}, scope: scope('T-run'), runAgent: mockAgent, hooks: { approve: async () => true } });
  const st = await c.run();
  assert.equal(st.status, 'done');
  assert.ok(st.surface.counts.findings >= 1);
  assert.ok(st.surface.counts.exploits >= 1);
  assert.equal('audit' in st, false, 'VARVEL keeps no audit of record');
  assert.ok(Array.isArray(st.activity) && st.activity.length > 0);
});

test('campaign: HITL gate blocks exploit when approval denied', async () => {
  const c = new Campaign({ engine: {}, scope: scope('T-deny'), runAgent: mockAgent, hooks: { approve: async () => false } });
  const st = await c.run();
  assert.equal(st.surface.counts.exploits, 0, 'no exploit without countersignature');
  assert.ok(st.surface.holds.some((h) => h.rule === 'HITL-required'));
});

test('campaign: budget exhaustion skips later phases', async () => {
  const c = new Campaign({ engine: {}, scope: scope('T-bud'), runAgent: mockAgent, budget: { maxSteps: 1 }, hooks: { approve: async () => true } });
  const st = await c.run();
  assert.equal(st.surface.counts.findings, 0, 'validate skipped once budget spent by recon');
});

test('campaign: Fireteam recon merges parallel specialist output', async () => {
  const c = new Campaign({ engine: {}, scope: scope('T-ft'), runAgent: mockAgent, fireteam: true, hooks: { approve: async () => true } });
  const st = await c.run();
  assert.ok(st.surface.counts.hosts >= 2);
  assert.ok(st.surface.counts.subdomains >= 1, 'surface-mapper contributed');
  assert.ok(st.surface.counts.endpoints >= 1, 'web-prober contributed');
  assert.ok(st.activity.some((a) => a.kind === 'fireteam'));
});

test('campaign: cross-session memory inherits prior findings', async () => {
  await new Campaign({ engine: {}, scope: scope('T-mem'), runAgent: mockAgent, hooks: { approve: async () => true } }).run();
  const c2 = new Campaign({ engine: {}, scope: scope('T-mem'), runAgent: mockAgent, hooks: { approve: async () => true } });
  assert.ok(c2.prior.length >= 1, 'second session inherits prior findings');
});

test('report: renders every section incl. OWASP mapping', () => {
  const s = new Surface(scope('T-rep'));
  const h = s.host('10.0.0.9', { label: 'web' });
  s.finding(h, { title: 'unauthenticated admin panel', sev: 'crit', ref: 'F1' });
  const md = renderReport(s.toJSON());
  for (const sec of ['## Executive summary', '## Findings', '## Governance & scope', '## OPSEC', '## Remediation']) {
    assert.ok(md.includes(sec), 'missing ' + sec);
  }
  assert.match(md, /A01/, 'OWASP mapping present');
});

test('phases: five phases; exploit + post-ex are HITL-gated', () => {
  assert.equal(PHASES.length, 5);
  assert.equal(PHASES.find((p) => p.id === 'exploit').gate, 'sigil');
  assert.equal(PHASES.find((p) => p.id === 'postex').gate, 'sigil');
  assert.equal(PHASES.find((p) => p.id === 'recon').gate, 'none');
});

test('surface: route() creates a pivot node with two directed edges', () => {
  const s = new Surface(scope('T-route'));
  const a = s.host('10.0.0.1', {}); const b = s.host('10.0.0.2', {});
  const before = s.edges.length;
  s.route(a, b, 'reused cred');
  assert.equal(s.counts().routes, 1);
  assert.equal(s.edges.length - before, 2, 'pivots + lateral edges');
});

test('report: empty surface still renders all sections with a no-findings note', () => {
  const md = renderReport(new Surface(scope('T-empty')).toJSON());
  assert.match(md, /_No findings recorded._/);
  for (const sec of ['## Executive summary', '## Findings', '## Governance & scope', '## Remediation']) assert.ok(md.includes(sec), 'missing ' + sec);
});

test('classify: remediation of a finding-less surface is empty', () => {
  assert.deepEqual(remediation(new Surface(scope('T-norem')).toJSON()), []);
});

test('campaign: onEvent hook receives ordered, contiguous activity events', async () => {
  const seen = [];
  const c = new Campaign({ engine: {}, scope: scope('T-evt'), runAgent: mockAgent, hooks: { approve: async () => true, onEvent: (e) => seen.push(e) } });
  await c.run();
  assert.ok(seen.length > 0, 'events emitted');
  assert.deepEqual(seen.map((e) => e.seq), seen.map((_, i) => i), 'seq contiguous + ordered');
  assert.ok(seen.some((e) => e.kind === 'campaign.done'));
});

test('opsec: footprint accumulates across observations', () => {
  const o = new Opsec();
  o.observe({ toolCalls: 3, host: 'a' });
  o.observe({ toolCalls: 2, host: 'b', holds: 1 });
  const fp = o.posture().footprint;
  assert.equal(fp.toolCalls, 5);
  assert.equal(fp.hostsTouched, 2);
  assert.equal(fp.holds, 1);
});
