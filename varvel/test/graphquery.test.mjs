// VARVEL NL surface-graph query tests — natural-language questions over the surface.
//   node --test varvel/test/graphquery.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Surface } from '../engine/surface.mjs';
import { queryGraph } from '../engine/graphquery.mjs';

function demoSurface() {
  const s = new Surface({ engagement: 'Q', signedBy: 'x', cidrs: ['10.0.0.0/8'] });
  const web = s.host('10.0.0.5', { label: 'web-01' });
  s.service(web, 443, 'tcp', 'https');
  s.service(web, 22, 'tcp', 'ssh');
  s.endpoint(web, '/admin', 'GET');
  s.endpoint(web, '/api/users', 'GET');
  s.finding(web, { title: 'exposed .env', sev: 'crit', ref: 'F1', confidence: 'confirmed' });
  s.finding(web, { title: 'weak TLS ciphers', sev: 'low', ref: 'F2', confidence: 'suspected' });
  const db = s.host('10.0.0.9', { label: 'db-01' });
  s.service(db, 5432, 'tcp', 'postgres');
  s.finding(db, { title: 'default postgres creds', sev: 'high', ref: 'F3', confidence: 'confirmed' });
  return s.toJSON();
}
const S = demoSurface();
const q = (text) => queryGraph(S, text);

test('type intent: hosts / findings / endpoints / services', () => {
  assert.equal(q('show me all hosts').count, 2);
  assert.equal(q('list the findings').count, 3);
  assert.equal(q('what endpoints exist').count, 2);
  assert.equal(q('which services are exposed').count, 3); // https, ssh, postgres
});

test('severity filter', () => {
  const r = q('show critical findings');
  assert.equal(r.count, 1);
  assert.equal(r.matched[0].ref, 'F1');
  assert.equal(q('high severity findings').count, 1);
  assert.match(r.interpretation, /findings/);
  assert.match(r.interpretation, /crit/);
});

test('confidence filter', () => {
  assert.equal(q('confirmed findings').count, 2); // F1, F3
  assert.equal(q('suspected findings').count, 1); // F2
});

test('port filter', () => {
  const r = q('services on port 443');
  assert.equal(r.count, 1);
  assert.equal(r.matched[0].port, 443);
});

test('relationship: "on <host>" scopes to that host', () => {
  assert.equal(q('endpoints on web-01').count, 2);
  assert.equal(q('findings on db-01').count, 1);
  assert.equal(q('findings on db-01').matched[0].ref, 'F3');
  // combine host + severity
  assert.equal(q('critical findings on web-01').count, 1);
  assert.equal(q('critical findings on db-01').count, 0);
});

test('unknown host constraint is ignored, not an error', () => {
  const r = q('findings on nonexistent-host');
  assert.equal(r.count, 3, 'falls back to all findings rather than returning nothing');
});

test('empty / vague query returns nodes with an interpretation', () => {
  const r = q('');
  assert.ok(r.count >= 1);
  assert.equal(typeof r.interpretation, 'string');
});
