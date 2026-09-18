// VARVEL auto-remediation tests — triage + code-fix agent.
//   node --test varvel/test/remediate.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Surface } from '../engine/surface.mjs';
import { triage, codeFixBriefing, codeFixAgent } from '../engine/remediate.mjs';

function surf() {
  const s = new Surface({ engagement: 'R', signedBy: 'x', cidrs: ['10.0.0.0/8'] });
  const web = s.host('10.0.0.5', { label: 'web-01' });
  const f1 = s.finding(web, { title: 'exposed .env secrets file', sev: 'crit', ref: 'F1', confidence: 90 });
  s.finding(web, { title: 'exposed .env secrets file', sev: 'crit', ref: 'F1b', confidence: 90 }); // dup
  s.finding(web, { title: 'weak TLS ciphers', sev: 'low', ref: 'F2', confidence: 40 });
  s.finding(web, { title: 'unauthenticated content API allows homepage write', sev: 'high', ref: 'F3', confidence: 85 });
  s.exploit(f1, { title: 'exposed .env secrets file', ref: 'X1', state: 'proved' }); // makes F1 "exploited"
  return s.toJSON();
}
const S = surf();

test('triage dedups findings and ranks by exploitability', () => {
  const t = triage(S);
  assert.equal(t.count, 3, 'the duplicate .env is merged');
  // the proven-exploited crit should top the list
  assert.equal(t.items[0].title, 'exposed .env secrets file');
  assert.equal(t.items[0].exploited, true);
  assert.ok(t.items[0].score > t.items[t.items.length - 1].score, 'sorted by score desc');
  // low-sev unverified sits last
  assert.equal(t.items[t.items.length - 1].title, 'weak TLS ciphers');
});

test('triage attaches a concrete code-level fix + OWASP mapping per finding', () => {
  const t = triage(S);
  const env = t.items.find((i) => /\.env/.test(i.title));
  assert.match(env.fix, /rotate|secrets manager|out of the web root/i);
  assert.ok(env.owasp, 'OWASP category attached');
  const api = t.items.find((i) => /content API/.test(i.title));
  assert.match(api.fix, /authorization|server-side/i);
});

test('codeFixBriefing lists the ranked fixes and stays defensive', () => {
  const b = codeFixBriefing(triage(S).items, { repoDir: '/repo' });
  assert.match(b, /REMEDIATION/i);
  assert.match(b, /never exploit/i);
  assert.match(b, /exposed \.env/);
  assert.match(b, /\/repo/);
});

test('codeFixAgent drives the injected agent; no findings -> nothing to do', async () => {
  let seen = '';
  const runAgent = async ({ system, messages }) => { seen = messages[0].content; return { text: 'Fixed 3 issues: moved .env out of web root, added auth to the content API, updated TLS config.' }; };
  const r = await codeFixAgent(runAgent, { surface: S, openPr: true });
  assert.equal(r.ok, true);
  assert.equal(r.planned, 3);
  assert.match(r.summary, /Fixed/);
  assert.match(seen, /pull request|gh /i, 'PR instruction included when openPr');

  const empty = await codeFixAgent(runAgent, { surface: new Surface({ engagement: 'E', cidrs: [] }).toJSON() });
  assert.equal(empty.fixed, 0);
  assert.equal((await codeFixAgent(null, { surface: S })).ok, false, 'no agent -> not ok, returns plan');
});
