// VARVEL validator-gate tests — nothing is reported as proven that wasn't reproduced
// against an objective oracle. Hermetic: the re-read is injected (reReadImpl), no network.
//   node --test varvel/test/validator.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Campaign } from '../engine/campaign.mjs';
import { Surface, CONFIRM_AT } from '../engine/surface.mjs';
import { hasObjectiveOracle, extractMarker, validationUrl, GATE_NOTE, UNTESTABLE_NOTE } from '../engine/validator.mjs';
import { renderReport } from '../engine/report.mjs';

const jb = (o) => '```json\n' + JSON.stringify(o) + '\n```';
const scope = (e) => ({ engagement: e, signedBy: 'x', cidrs: ['10.0.0.0/8'] });
const noAgent = async () => ({ text: '', steps: 0 });

// A campaign with one http host + one finding, ready for validateFinding. Never run().
function seeded(eng, finding, { ghost } = {}) {
  const c = new Campaign({ engine: {}, scope: scope(eng), runAgent: noAgent, ghost });
  const hid = c.surface.host('10.0.0.5', { label: 'web' });
  c.surface.service(hid, 8080, 'tcp', 'http');
  const fid = c.surface.finding(hid, { title: 'admin panel', sev: 'high', confidence: 'confirmed', ...finding });
  return { c, hid, fid, node: c.surface.nodes.get(fid) };
}
const countingReRead = (resp) => {
  const calls = [];
  return { calls, impl: async (url, opts) => { calls.push({ url, opts }); return typeof resp === 'function' ? resp(url) : resp; } };
};

test('oracle heuristic: markers, read-backs, diffs, tool refs and repro steps count; bare claims do not', () => {
  // Each pinned class passes.
  assert.ok(hasObjectiveOracle({ evidence: 'planted marker vv-a1b2c3 was read back in the response' }));
  assert.ok(hasObjectiveOracle({ evidence: 'GET /admin returned the management console' }));
  assert.ok(hasObjectiveOracle({ evidence: 'differential: probe 200/912b vs baseline 404/120b' }));
  assert.ok(hasObjectiveOracle({ evidence: 'flagged by vulncheck, content-verified' }));
  assert.ok(hasObjectiveOracle({ evidence: 'reproduce with curl -i http://host/admin' }));
  assert.ok(hasObjectiveOracle({ evidence: 'post-auth content observed after login' }));
  assert.ok(hasObjectiveOracle({ ref: 'http://10.0.0.5:8080/admin' }), 'a cited URL is a read-back location');
  assert.ok(hasObjectiveOracle({ ref: '/admin/config' }), 'a cited path is a read-back location');
  // Bare claims / opaque refs / severity words are NOT oracles.
  for (const bad of [
    {},
    { evidence: 'it looks vulnerable' },
    { evidence: 'probably exploitable, high impact' },
    { ref: 'F-01' },
    { evidence: 'severity: critical, definitely real' },
  ]) assert.equal(hasObjectiveOracle(bad), false, JSON.stringify(bad));
});

test('extractMarker pulls the cited collision-proof marker', () => {
  assert.equal(extractMarker('response contained marker: vv-q7x9deadbeef'), 'vv-q7x9deadbeef');
  assert.equal(extractMarker('nonce=abc123XYZ echoed'), 'abc123XYZ');
  assert.equal(extractMarker('no token cited here'), null);
});

test('HARD INGEST RULE: a confirmed claim with no objective oracle is downgraded to suspected (+note), an oracled claim stands', async () => {
  const agent = async (opts) => {
    const c = opts.messages[0].content;
    if (c.startsWith('Enumerate')) return { text: jb({ hosts: [{ ip: '10.0.0.7', label: 'h' }] }), steps: 1 };
    if (c.startsWith('Vet')) return { text: jb({ findings: [
      { host: 'h', title: 'bare claim', sev: 'high', ref: 'B1', confidence: 'confirmed', evidence: 'it looks vulnerable' },
      { host: 'h', title: 'oracled claim', sev: 'high', ref: 'B2', confidence: 'confirmed', evidence: 'GET /admin returned the console; marker: vv-q7x9' },
    ] }), steps: 1 };
    return { text: 'ok', steps: 1 };
  };
  const st = await new Campaign({ engine: {}, scope: scope('VALGATE'), runAgent: agent, maxReplan: 0, hooks: { approve: async () => true } }).run();
  const nodes = st.surface.nodes;
  const bare = nodes.find((n) => n.label === 'bare claim');
  const oracled = nodes.find((n) => n.label === 'oracled claim');
  assert.equal(bare.confidence, 'suspected', 'no oracle -> downgraded, never deleted');
  assert.ok(bare.conf < CONFIRM_AT, 'numeric tier dropped below the confirm threshold');
  assert.ok((bare.notes || []).includes(GATE_NOTE), 'the gate note is appended');
  assert.equal(oracled.confidence, 'confirmed', 'a cited oracle keeps the confirmed tier');
  assert.equal(st.surface.counts.confirmed, 1);
  assert.ok(st.activity.some((a) => a.kind === 'validator.gate'), 'the downgrade is logged in the activity feed');
});

test('HARD INGEST RULE: a numeric confirmed-tier claim without an oracle is downgraded too', () => {
  const c = new Campaign({ engine: {}, scope: scope('VALNUM'), runAgent: noAgent });
  c._ingest('validate', { findings: [{ host: 'h', title: 'numeric claim', sev: 'crit', ref: 'N1', confidence: 95 }] });
  const n = [...c.surface.nodes.values()].find((x) => x.label === 'numeric claim');
  assert.equal(n.confidence, 'suspected');
  assert.ok(n.conf < CONFIRM_AT);
  assert.ok((n.notes || []).includes(GATE_NOTE));
});

test('validate command: cited marker reproduced -> validated (the paired read: real + control, both paced, both noise-charged)', async () => {
  const { c, node } = seeded('VALOK', { ref: 'B2', evidence: 'GET /admin returned the console; marker: vv-q7x9deadbeef' });
  let paced = 0;
  c.pacer = { pace: async () => { paced++; } };
  // v2: the mock must DIFFERENTIATE — marker page on the real path, 404 on the garbage control.
  const rr = countingReRead((url) => url.includes('/admin') ? { status: 200, len: 912, body: '<html>console vv-q7x9deadbeef</html>' } : { status: 404, len: 0, body: '' });
  const before = c.noise.status().spent;
  const r = await c.validateFinding(0, { reReadImpl: rr.impl });
  assert.equal(r.ok, true);
  assert.equal(r.state, 'validated');
  assert.match(r.oracle, /marker present/);
  assert.equal(node.validation.state, 'validated');
  assert.ok(node.validation.at, 'timestamp recorded');
  assert.ok(node.validation.validatedAt, 'v2: the staleness clock is set on validated findings');
  assert.equal(node.confidence, 'confirmed', 'a validated finding keeps its tier');
  assert.equal(rr.calls.length, 2, 'v2: exactly ONE request pair (real + control)');
  assert.equal(rr.calls[0].url, 'http://10.0.0.5:8080/admin', 'the re-read rides the cited path on the parent host');
  assert.match(rr.calls[1].url, /^http:\/\/10\.0\.0\.5:8080\/vrv[0-9a-f]{16}$/, 'the control is a garbage path of the same shape');
  assert.equal(node.validation.control.matched, false, 'the control read is on the record');
  assert.equal(node.validation.requests.length, 2, 'the record shows both requests');
  assert.match(r.control, /^control GET /, 'the validate output gains the control-read line');
  assert.equal(paced, 2, 'both requests were paced');
  assert.ok(c.noise.status().spent > before, 'the pair is charged to the noise budget');
  assert.ok(c.activity.some((a) => a.kind === 'validate' && a.data.state === 'validated'), 'validation event logged');
});

test('validate command: cited marker ABSENT on the re-read -> REFUTED, confidence flips to suspected (+note)', async () => {
  const { c, node } = seeded('VALREF', { ref: 'B3', evidence: 'GET /admin returned the console; marker: vv-q7x9deadbeef' });
  const rr = countingReRead({ status: 200, len: 400, body: '<html>ordinary page, no marker</html>' });
  const r = await c.validateFinding(0, { reReadImpl: rr.impl });
  assert.equal(r.state, 'refuted', 'REFUTED is a first-class outcome');
  assert.match(r.oracle, /ABSENT/);
  assert.equal(node.validation.state, 'refuted');
  assert.equal(node.confidence, 'suspected', 'refutation flips the confirmed claim');
  assert.ok(node.conf < CONFIRM_AT);
  assert.ok((node.notes || []).some((n) => /validator gate: refuted/.test(n)), 'refutation note appended');
  assert.equal(rr.calls.length, 2, 'v2: real + control pair');
});

test('validate command: no marker cited -> the differential decides (2xx vs garbage-404 validates, 404 refutes); a redirect is data, never followed', async () => {
  const ok = seeded('VALS1', { ref: '/admin' });
  const rr1 = countingReRead((url) => url.includes('/admin') ? { status: 200, len: 100, body: 'panel' } : { status: 404, len: 0, body: '' });
  assert.equal((await ok.c.validateFinding(0, { reReadImpl: rr1.impl })).state, 'validated');

  const gone = seeded('VALS2', { ref: '/admin' });
  const rr2 = countingReRead({ status: 404, len: 0, body: '' });
  const r2 = await gone.c.validateFinding(0, { reReadImpl: rr2.impl });
  assert.equal(r2.state, 'refuted', 'the endpoint no longer reproduces');
  assert.equal(gone.node.confidence, 'suspected');

  const redir = seeded('VALS3', { ref: '/admin' });
  const rr3 = countingReRead((url) => url.includes('/admin') ? { status: 301, len: 0, body: '' } : { status: 404, len: 0, body: '' });
  assert.equal((await redir.c.validateFinding(0, { reReadImpl: rr3.impl })).state, 'validated');
  assert.equal(rr3.calls.length, 2, 'v2: ONE pair even on a redirect — never followed');
});

test('validate command: non-http finding -> untestable, honestly, with ZERO requests', async () => {
  const c = new Campaign({ engine: {}, scope: scope('VALUNT'), runAgent: noAgent });
  const hid = c.surface.host('10.0.0.9', { label: 'db' });
  c.surface.service(hid, 5432, 'tcp', 'postgres'); // no http service
  c.surface.finding(hid, { title: 'weak creds', sev: 'high', ref: 'F-9', confidence: 'confirmed' });
  const rr = countingReRead({ status: 200, body: '' });
  const r = await c.validateFinding(0, { reReadImpl: rr.impl });
  assert.equal(r.state, 'untestable');
  assert.equal(r.oracle, UNTESTABLE_NOTE);
  assert.equal(rr.calls.length, 0, 'no automatic oracle -> no request at all');
});

test('validate command: out-of-scope re-read is refused fail-closed (zero requests)', async () => {
  const { c, node } = seeded('VALSCOPE', { ref: 'http://8.8.8.8/admin', evidence: 'GET /admin returned the console' });
  const rr = countingReRead({ status: 200, body: 'marker' });
  const r = await c.validateFinding(0, { reReadImpl: rr.impl });
  assert.equal(r.state, 'untestable');
  assert.match(r.oracle, /outside the signed scope/);
  assert.equal(rr.calls.length, 0, 'fail-closed: nothing left the wire');
  assert.equal(node.confidence, 'confirmed', 'a refusal is not a refutation');
  assert.ok(c.activity.some((a) => a.kind === 'validate.refused'), 'the refusal is logged');
});

test('validate command: ghost refusal (identity chain unverified) is fail-closed (zero requests)', async () => {
  const ghost = { assertEgress: async () => { const e = new Error('no verified chain'); e.ghostRefused = true; throw e; }, agents: () => null };
  const { c } = seeded('VALGHOST', { ref: '/admin' }, { ghost });
  const rr = countingReRead({ status: 200, body: '' });
  const r = await c.validateFinding(0, { reReadImpl: rr.impl });
  assert.equal(r.state, 'untestable');
  assert.match(r.oracle, /ghost/i);
  assert.equal(rr.calls.length, 0, 'fail-closed: the re-read never fired');
  assert.ok(c.activity.some((a) => a.kind === 'ghost.refused'), 'ghost refusal logged');
});

test('validate command: selector by ref / id; unknown selector errors without touching the finding', async () => {
  const { c, fid } = seeded('VALSEL', { ref: '/admin' });
  const rr = countingReRead((url) => url.includes('/admin') ? { status: 200, body: 'x' } : { status: 404, body: '' });
  const r = await c.validateFinding('/admin', { reReadImpl: rr.impl });
  assert.equal(r.state, 'validated', 'ref selector works');
  const r2 = await c.validateFinding(fid, { reReadImpl: rr.impl });
  assert.equal(r2.state, 'validated', 'node-id selector works');
  const bad = await c.validateFinding(99, { reReadImpl: rr.impl });
  assert.equal(bad.ok, false);
  assert.match(bad.error, /no such finding/);
});

test('report honesty: validated / claimed-unvalidated / refuted are surfaced per finding', async () => {
  const s = new Surface(scope('VALREP'));
  const h = s.host('10.0.0.5', { label: 'web' });
  const a = s.nodes.get(s.finding(h, { title: 'proven one', sev: 'high', confidence: 'confirmed', evidence: 'GET /x returned it' }));
  a.validation = { state: 'validated', oracle: 're-read http://10.0.0.5/x → HTTP 200', at: new Date().toISOString() };
  const b = s.nodes.get(s.finding(h, { title: 'busted one', sev: 'high', confidence: 'confirmed' }));
  b.validation = { state: 'refuted', oracle: 're-read → HTTP 200; cited marker ABSENT', at: new Date().toISOString() };
  b.confidence = 'suspected'; b.conf = 40; (b.notes = b.notes || []).push('validator gate: refuted');
  s.finding(h, { title: 'unchallenged one', sev: 'med', confidence: 'confirmed', evidence: 'GET /y returned it' });
  const md = renderReport(s.toJSON());
  assert.match(md, /1 validated · 1 claimed-unvalidated · 1 refuted · 0 untestable/, 'the summary counts every state');
  assert.match(md, /VALIDATED\*\* — re-read/, 'the oracle is quoted');
  assert.match(md, /REFUTED/, 'refuted shown as such');
  assert.match(md, /CLAIMED-UNVALIDATED\*\* — never reproduced by the validator gate/, 'unvalidated claims are labeled, not hidden');
});

test('validationUrl: absolute URL wins; cited path resolves against the parent host http service', () => {
  const s = new Surface(scope('VALURL'));
  const h = s.host('10.0.0.5', { label: 'web' });
  s.service(h, 8080, 'tcp', 'http');
  const f1 = s.nodes.get(s.finding(h, { title: 'a', ref: 'http://10.0.0.5:8080/secure', confidence: 'confirmed' }));
  assert.equal(validationUrl(f1, s), 'http://10.0.0.5:8080/secure');
  const f2 = s.nodes.get(s.finding(h, { title: 'b', evidence: 'GET /admin returned the console', confidence: 'confirmed' }));
  assert.equal(validationUrl(f2, s), 'http://10.0.0.5:8080/admin');
  const f3 = s.nodes.get(s.finding(h, { title: 'c', ref: 'F-77', confidence: 'confirmed' }));
  assert.equal(validationUrl(f3, s), null, 'opaque ref, no path -> no automatic oracle');
  // v6 host: the re-read URL must bracket the literal or it is not a URL at all
  const h6 = s.host('fd00::5', { label: 'web6' });
  s.service(h6, 8080, 'tcp', 'http');
  const f6 = s.nodes.get(s.finding(h6, { title: 'd', evidence: 'GET /admin returned the console', confidence: 'confirmed' }));
  assert.equal(validationUrl(f6, s), 'http://[fd00::5]:8080/admin', 'v6 host IP bracketed in the derived URL');
  assert.ok(new URL(validationUrl(f6, s)).hostname === '[fd00::5]', 'the derived URL actually parses');
  // v4 regression: unchanged byte-for-byte (pinned above at 209/211)
});
