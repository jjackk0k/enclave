// tlsinspect.test.mjs — hermetic tests for TLS-inspection detection + adaptation
// (lose-point #5: enterprise egress SSL-bump). Layers covered:
//   1. engine/tlsinspect.mjs   — the PURE classifier over fixture chains (bumped /
//      clean / self-signed / unknown-issuer / garbage) + posture aggregation.
//   2. policy matrix           — rankTransports inspection factor: fail-closed refusal,
//      adapt re-ranking (provably demotes http, promotes ghc), ignore warns.
//   3. channel integration     — failoverPlan consumes the pushed posture; agent-reported
//      check-in metadata (x-varvel-tlsi) intake + agentsView surface.
//   4. LIVE TLS fixtures       — local Node tls servers with REAL generated chains
//      (test/tlsi-fixtures.mjs, openssl-generated): a bump-class chain presented for a
//      SaaS name classifies inspected; a trusted chain classifies clean. No external
//      network — every byte stays on loopback.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import { mkdtempSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { classifyHandshake, aggregatePosture, normalizeTlsVerdict, DIRECT_TLS_WIRES, INSPECTION_TOLERANT_WIRES } from '../engine/tlsinspect.mjs';
import { parseRefs, probeTlsInspection, classifyUrlHandshake } from '../tools/tlsinspect.mjs';
import { gradeAgentTransports, rankTransports } from '../engine/transport-grade.mjs';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { Ghost } from '../engine/ghost.mjs';
import { Settings } from '../engine/settings.mjs';
import { TLSI_PUB_CA, TLSI_PUB_LEAF, TLSI_PUB_LEAF_KEY, TLSI_BUMP_CA, TLSI_BUMP_LEAF, TLSI_BUMP_LEAF_KEY, TLSI_SELF, TLSI_SELF_KEY } from './tlsi-fixtures.mjs';

// Test-side artifacts (settings write-through) live under varvel/.tmp — never os.tmpdir().
const TMP = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp');
mkdirSync(join(TMP, 'tlsi-test'), { recursive: true });
process.env.VARVEL_SETTINGS_FILE = join(TMP, 'tlsi-test', 'settings.json');

const SCOPE = { engagement: 'tlsi-eng-' + Date.now(), signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
import crypto from 'node:crypto';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A live TLS server on loopback serving the given chain. Returns { port, close }.
function tlsServe({ key, cert }) {
  return new Promise((resolve, reject) => {
    const srv = tls.createServer({ key, cert }, (s) => s.end());
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => resolve({ port: srv.address().port, close: () => new Promise((r) => srv.close(r)) }));
  });
}

// ---------- 1. the pure classifier ----------
test('classifier: a bump-class chain for a SaaS name => inspected, with evidence', () => {
  const c = classifyHandshake({
    host: 'api.github.com', expect: 'saas',
    chain: [
      { subject: 'api.github.com', issuer: 'Zscaler-Test-Inspection-Root' },
      { subject: 'Zscaler-Test-Inspection-Root', issuer: 'Zscaler-Test-Inspection-Root', selfSigned: true },
    ],
    authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  });
  assert.equal(c.verdict, 'inspected');
  assert.ok(c.evidence.some((e) => /KNOWN INSPECTOR.*Zscaler/i.test(e)), 'the matched product is named');
  assert.match(c.summary, /content visible to the enterprise egress proxy/);
});

test('classifier: unknown enterprise root on a SaaS reference => inspected (re-issue signature)', () => {
  const c = classifyHandshake({
    host: 'www.microsoft.com', expect: 'saas',
    chain: [{ subject: 'www.microsoft.com', issuer: 'Contoso Enterprise Root CA' }, { subject: 'Contoso Enterprise Root CA', issuer: 'Contoso Enterprise Root CA', selfSigned: true }],
    authorized: false, authorizationError: 'SELF_SIGNED_CERT_IN_CHAIN',
  });
  assert.equal(c.verdict, 'inspected');
  assert.ok(c.evidence.some((e) => /expectation violation/.test(e)));
});

test('classifier: public CA + authorized => clean; authorized via managed store says so honestly', () => {
  const pub = classifyHandshake({
    host: 'api.github.com', expect: 'saas',
    chain: [{ subject: 'api.github.com', issuer: 'DigiCert TLS Hybrid ECC SHA384 2020 CA1' }, { subject: 'DigiCert Global Root CA', issuer: 'DigiCert Global Root CA', selfSigned: true }],
    authorized: true,
  });
  assert.equal(pub.verdict, 'clean');
  assert.ok(pub.evidence.some((e) => /public CA/.test(e)));
  // A bump whose enterprise root sits in the client's OWN trust store presents
  // authorized:true — the classifier reports 'clean' AND records which store fact it
  // used (the honest limit; the evidence never hides it).
  const masked = classifyHandshake({
    host: 'api.github.com', expect: 'saas',
    chain: [{ subject: 'api.github.com', issuer: 'Contoso Enterprise Root CA' }, { subject: 'Contoso Enterprise Root CA', issuer: 'Contoso Enterprise Root CA', selfSigned: true }],
    authorized: true,
  });
  assert.equal(masked.verdict, 'clean');
  assert.ok(masked.evidence.some((e) => /trust store.*mask a bump/.test(e)), 'the masking limit is on the record');
});

test('classifier: untrusted chain on a non-SaaS reference => unknown (private PKI vs bump is not attributable)', () => {
  const c = classifyHandshake({
    host: 'intranet.contoso.local', expect: 'any',
    chain: [{ subject: 'intranet.contoso.local', issuer: 'Contoso Enterprise Root CA' }, { subject: 'Contoso Enterprise Root CA', issuer: 'Contoso Enterprise Root CA', selfSigned: true }],
    authorized: false, authorizationError: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  });
  assert.equal(c.verdict, 'unknown');
  assert.ok(c.evidence.some((e) => /not attributable/.test(e)));
});

test('classifier: cert problems without unknown-root shape are NOT bump evidence', () => {
  const c = classifyHandshake({
    host: 'api.github.com', expect: 'saas',
    chain: [{ subject: 'api.github.com', issuer: 'DigiCert TLS Hybrid ECC SHA384 2020 CA1' }],
    authorized: false, authorizationError: 'CERT_HAS_EXPIRED',
  });
  assert.equal(c.verdict, 'unknown');
  assert.ok(c.evidence.some((e) => /misconfiguration/.test(e)));
});

test('classifier: never throws on garbage — no chain, junk fields, null input', () => {
  for (const junk of [null, undefined, {}, { chain: 'junk', authorized: 'maybe' }, { chain: [null, 42, 'x'] }, { chain: [{ subject: {}, issuer: {} }] }]) {
    const c = classifyHandshake(junk);
    assert.equal(c.verdict, 'unknown');
    assert.ok(Array.isArray(c.evidence) && c.evidence.length >= 1, 'evidence always rides the verdict');
  }
});

// ---------- posture aggregation ----------
test('aggregatePosture: clean / tls-inspected / partial / unknown, SaaS refs only', () => {
  assert.equal(aggregatePosture([{ ref: 'a', saas: true, verdict: 'clean' }, { ref: 'b', saas: true, verdict: 'clean' }]).posture, 'clean');
  const insp = aggregatePosture([{ ref: 'a', saas: true, verdict: 'inspected' }, { ref: 'b', saas: true, verdict: 'inspected' }]);
  assert.equal(insp.posture, 'tls-inspected');
  assert.match(insp.reason, /enterprise egress proxy/);
  const partial = aggregatePosture([{ ref: 'a', saas: true, verdict: 'inspected' }, { ref: 'b', saas: true, verdict: 'clean' }]);
  assert.equal(partial.posture, 'partial');
  assert.match(partial.reason, /per-domain/, 'mixed is said plainly — selective bump is real');
  assert.equal(aggregatePosture([{ ref: 'a', saas: true, ok: false, verdict: 'unknown' }]).posture, 'unknown');
  assert.equal(aggregatePosture([]).posture, 'unknown');
  // our own listener (private ref) never decides the posture
  assert.equal(aggregatePosture([{ ref: '127.0.0.1:8971', saas: false, verdict: 'inspected' }, { ref: 'a', saas: true, verdict: 'clean' }]).posture, 'clean');
  // partial coverage is disclosed, not laundered into a full clean
  assert.match(aggregatePosture([{ ref: 'a', saas: true, verdict: 'clean' }, { ref: 'b', saas: true, verdict: 'unknown' }]).reason, /coverage is partial/);
});

// ---------- 2. policy matrix (rankTransports inspection factor) ----------
const NOW = 1_000_000_000;
function gradesFor(seen, current) {
  return gradeAgentTransports({ transportLastSeen: Object.fromEntries(seen.map((t) => [t, NOW - 100])), lastTransport: current }, { now: NOW, expectedMs: 5000 });
}

test('policy fail-closed: direct TLS wires refuse under inspection — listed, never ranked', () => {
  const grades = gradesFor(['http', 'dns'], 'http');
  const r = rankTransports({ grades, wireScores: {}, checkins: { http: 10, dns: 5 }, current: 'http', inspection: { posture: 'tls-inspected', policy: 'fail-closed' } });
  assert.deepEqual(r.ranking.map((x) => x.transport), ['dns'], 'only the inspection-tolerant wire ranks');
  const http = r.ineligible.find((x) => x.transport === 'http');
  assert.match(http.reason, /fail-closed/);
  assert.match(http.reason, /visible to the enterprise egress proxy/);
  assert.ok(r.ineligible.some((x) => x.transport === 'doh') && r.ineligible.some((x) => x.transport === 'ws'));
  assert.equal(r.recommendation.action, 'switch-recommended');
  assert.equal(r.recommendation.to, 'dns');
  assert.match(r.recommendation.reason, /tls-inspected/);
});

test('policy fail-closed: no tolerant wire => stand down, said honestly (never ride the inspected wire)', () => {
  const grades = gradesFor(['http'], 'http');
  const r = rankTransports({ grades, wireScores: {}, checkins: { http: 10 }, current: 'http', inspection: { posture: 'tls-inspected', policy: 'fail-closed' } });
  assert.equal(r.recommendation.action, 'stay');
  assert.match(r.recommendation.reason, /stand the agent down|never|must NOT be ridden/i);
});

test('policy adapt: re-ranking provably demotes http and promotes ghc, with visible weights', () => {
  const grades = gradesFor(['http', 'ghc'], 'http');
  const wireScores = { http: { score: 10 } };
  const checkins = { http: 30, ghc: 10 };
  const base = rankTransports({ grades, wireScores, checkins, current: 'http' });
  assert.equal(base.ranking[0].transport, 'http', 'baseline: http outranks (60+20-4=76 vs 60+10=70)');
  assert.equal(base.inspection, null, 'no posture, no factor');
  const r = rankTransports({ grades, wireScores, checkins, current: 'http', inspection: { posture: 'tls-inspected', policy: 'adapt' } });
  const http = r.ranking.find((x) => x.transport === 'http');
  const ghc = r.ranking.find((x) => x.transport === 'ghc');
  assert.equal(http.score, 76 - 40, 'direct wire takes the -40 inspection penalty');
  assert.equal(ghc.score, 70 + 20, 'inspection-tolerant wire takes the +20 bonus');
  assert.equal(r.ranking[0].transport, 'ghc', 'ghc promoted above http on the measured posture');
  assert.match(http.why, /inspection penalty 40/);
  assert.match(ghc.why, /inspection-COMPATIBLE, never inspection-proof/);
  assert.equal(r.recommendation.action, 'switch-recommended');
  assert.equal(r.recommendation.to, 'ghc');
  assert.match(r.recommendation.reason, /never inspection-proof/, 'adaptation never claims the inspection away');
});

test('policy ignore: ranking unchanged, warning carried loudly', () => {
  const grades = gradesFor(['http', 'ghc'], 'http');
  const args = { grades, wireScores: { http: { score: 10 } }, checkins: { http: 30, ghc: 10 }, current: 'http' };
  const base = rankTransports(args);
  const r = rankTransports({ ...args, inspection: { posture: 'partial', policy: 'ignore' } });
  assert.deepEqual(r.ranking.map((x) => [x.transport, x.score]), base.ranking.map((x) => [x.transport, x.score]), 'ignore = identical order and scores');
  assert.ok(r.warnings.some((w) => /policy=ignore.*overrode|operator overrode/.test(w)));
  assert.equal(r.recommendation.action, 'stay', 'no inspection-driven re-order under ignore');
});

test('posture clean/unknown is inert; operator pin still wins under inspection (with the exposure on record)', () => {
  const grades = gradesFor(['http', 'dns'], 'http');
  for (const posture of ['clean', 'unknown']) {
    const r = rankTransports({ grades, wireScores: {}, checkins: { http: 5, dns: 5 }, current: 'http', inspection: { posture, policy: 'fail-closed' } });
    assert.equal(r.inspection, null, 'posture ' + posture + ' carries no factor');
    assert.ok(r.ranking.some((x) => x.transport === 'http'), 'http still ranks');
  }
  const pinned = rankTransports({ grades, wireScores: {}, checkins: { http: 5, dns: 5 }, current: 'http', pinned: 'http', inspection: { posture: 'tls-inspected', policy: 'fail-closed' } });
  assert.equal(pinned.recommendation.action, 'stay');
  assert.equal(pinned.recommendation.pinned, true);
  assert.ok(pinned.warnings.some((w) => /pin holds a DIRECT TLS wire/.test(w)), 'the pinned exposure is on the record');
});

// ---------- 3. channel integration ----------
async function armed(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, port: ch.port, events };
}

test('failoverPlan consumes the pushed posture; the policy reads live from engagement settings', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull') } });
    const a = ch.agents.get(agentId);
    a.transportCheckins.dns = 4; a.transportLastSeen.dns = Date.now(); // dns delivery evidence
    let plan = ch.failoverPlan(agentId);
    assert.equal(plan.inspection, null, 'no posture pushed: no factor');
    assert.ok(plan.ranking.some((x) => x.transport === 'http'));

    ch.setTlsInspection('tls-inspected', { source: 'test' }); // policy defaults: fail-closed
    plan = ch.failoverPlan(agentId);
    assert.equal(plan.inspection.posture, 'tls-inspected');
    assert.ok(plan.ineligible.some((x) => x.transport === 'http' && /fail-closed/.test(x.reason)), 'fail-closed drops http from the ranking');
    assert.equal(plan.recommendation.action, 'switch-recommended');
    assert.equal(plan.recommendation.to, 'dns');

    Settings.for(SCOPE.engagement).set('tlsinspect.policy', 'adapt'); // live re-read
    plan = ch.failoverPlan(agentId);
    const http = plan.ranking.find((x) => x.transport === 'http');
    const dns = plan.ranking.find((x) => x.transport === 'dns');
    assert.ok(http && /inspection penalty/.test(http.why), 'adapt demotes http in the ranking');
    assert.ok(dns.score > http.score, 'dns (inspection-tolerant) outranks under adapt');

    Settings.for(SCOPE.engagement).set('tlsinspect.policy', 'ignore');
    plan = ch.failoverPlan(agentId);
    assert.ok(plan.warnings.some((w) => /policy=ignore/.test(w)));
    assert.ok(!/inspection penalty/.test((plan.ranking.find((x) => x.transport === 'http') || {}).why || ''), 'ignore: no factor applied');

    Settings.for(SCOPE.engagement).set('tlsinspect.policy', 'fail-closed'); // restore default
    assert.equal(ch.setTlsInspection('bogus-posture'), null, 'unrecognized posture clears the record, honestly');
    assert.equal(ch.failoverPlan(agentId).inspection, null);
    // agentsView carries both the channel posture and (below) the agent self-report
    assert.ok('tlsInspect' in ch.agentsView()[0] && 'tlsi' in ch.agentsView()[0]);
  } finally { await ch.disarm(); }
});

test('agent-reported metadata: x-varvel-tlsi rides check-ins, is stored + surfaced; garbage ignored', async () => {
  const { ch, port } = await armed();
  const dir = mkdtempSync(join(TMP, 'tlsi-agent-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    const agent = new SimAgent({ url: `http://127.0.0.1:${port}`, agentId, token, dir, interval: 120, jitter: 0, tlsi: true, tlsiClassifier: async () => ({ verdict: 'inspected' }) });
    const run = agent.run();
    try {
      await sleep(400);
      const a = ch.agents.get(agentId);
      assert.equal(a.tlsi.verdict, 'inspected', 'the agent observation is stored');
      assert.equal(a.tlsi.transport, 'http');
      const view = ch.agentsView()[0];
      assert.equal(view.tlsi.verdict, 'inspected', 'surfaced in the fleet view');
    } finally { agent.stop(); await run; }
    // garbage verdict: the header rides but normalizes to nothing — never stored
    const g2 = ch.registerAgent({});
    const bad = new SimAgent({ url: `http://127.0.0.1:${port}`, agentId: g2.agentId, token: g2.token, dir: mkdtempSync(join(TMP, 'tlsi-agent-bad-')), interval: 120, jitter: 0, tlsi: true, tlsiClassifier: async () => ({ verdict: 'loud-noises' }) });
    const run2 = bad.run();
    try { await sleep(300); assert.equal(ch.agents.get(g2.agentId).tlsi, undefined, 'a garbage verdict is ignored, not stored'); } finally { bad.stop(); await run2; }
  } finally { await ch.disarm(); }
});

// ---------- 4. live TLS fixtures (real generated chains on loopback) ----------
test('LIVE bump: a re-issued chain for a SaaS name classifies inspected through a real handshake', async () => {
  const bump = await tlsServe({ key: TLSI_BUMP_LEAF_KEY, cert: TLSI_BUMP_LEAF + TLSI_BUMP_CA });
  try {
    const r = await probeTlsInspection({ refs: [{ host: '127.0.0.1', port: bump.port, saas: true }] });
    assert.equal(r.ok, true);
    assert.equal(r.refs[0].verdict, 'inspected');
    assert.ok(r.refs[0].evidence.some((e) => /Zscaler/i.test(e)), 'real chain evidence names the bump issuer');
    assert.equal(r.posture, 'tls-inspected');
    // the agent-side leg (classifyUrlHandshake) sees the same bump on the same path
    const v = await classifyUrlHandshake('https://127.0.0.1:' + bump.port);
    assert.equal(v.verdict, 'inspected');
  } finally { await bump.close(); }
});

test('LIVE clean: a chain rooting in the client trust store classifies clean; self-signed SaaS is the bump shape', async () => {
  const pub = await tlsServe({ key: TLSI_PUB_LEAF_KEY, cert: TLSI_PUB_LEAF });
  const self = await tlsServe({ key: TLSI_SELF_KEY, cert: TLSI_SELF });
  try {
    const clean = await probeTlsInspection({ refs: [{ host: '127.0.0.1', port: pub.port, saas: true, ca: TLSI_PUB_CA }] });
    assert.equal(clean.refs[0].verdict, 'clean');
    assert.equal(clean.posture, 'clean');
    const bumped = await probeTlsInspection({ refs: [{ host: '127.0.0.1', port: self.port, saas: true }] });
    assert.equal(bumped.refs[0].verdict, 'inspected', 'a SaaS name on a self-signed wire = re-issue signature');
    // MIXED live: one bumped + one clean SaaS reference => 'partial', said plainly
    const mixed = await probeTlsInspection({ refs: [{ host: '127.0.0.1', port: self.port, saas: true }, { host: '127.0.0.1', port: pub.port, saas: true, ca: TLSI_PUB_CA }] });
    assert.equal(mixed.posture, 'partial');
  } finally { await pub.close(); await self.close(); }
});

test('probe never throws on handshake garbage: junk server, dead port, unparseable refs', async () => {
  // The junk server DRAINS inbound bytes (s.on('data')): a fixture that never reads the
  // ClientHello strands its own server-side socket on win32 when the client destroys
  // mid-garbage — close() would wait on it forever. Real garbage servers read or die.
  const junk = net.createServer((s) => { s.on('data', () => {}); s.write('this is not TLS at all'); s.end(); });
  await new Promise((r) => junk.listen(0, '127.0.0.1', r));
  try {
    const r = await probeTlsInspection({ refs: [{ host: '127.0.0.1', port: junk.address().port, saas: true }, { host: '127.0.0.1', port: 1, saas: true }], timeout: 1200 });
    assert.equal(r.ok, true, 'the probe itself resolves');
    assert.ok(r.refs.every((x) => x.verdict === 'unknown' && x.ok === false), 'garbage handshakes are honest failures');
    assert.equal(r.posture, 'unknown');
    assert.deepEqual(parseRefs(' ,, ,'), [], 'empty refs are skipped honestly');
    assert.deepEqual(parseRefs('api.github.com,127.0.0.1:8971').map((r) => [r.ref, r.saas]), [['api.github.com:443', true], ['127.0.0.1:8971', false]], 'refs parse with the private ref excluded from posture math');
    // v6 literal refs: URL brackets stripped before any dial/SNI; ULA/loopback classify private (not SaaS), public v6 is SaaS
    assert.deepEqual(parseRefs('[fd00::1]:4443,[::1],[2001:db8::9]').map((r) => [r.ref, r.host, r.saas]),
      [['fd00::1:4443', 'fd00::1', false], ['::1:443', '::1', false], ['2001:db8::9:443', '2001:db8::9', true]],
      'v6 refs lose their brackets and classify by the same private/public doctrine');
    assert.equal(classifyUrlHandshake('http://127.0.0.1:1') instanceof Promise, true);
    assert.equal(await classifyUrlHandshake('http://127.0.0.1:1'), null, 'http url: no TLS surface, no fabricated verdict');
    assert.equal(await classifyUrlHandshake('not a url'), null);
    assert.equal(normalizeTlsVerdict('INSPECTED'), 'inspected');
    assert.equal(normalizeTlsVerdict('garbage'), null);
  } finally { await new Promise((r) => junk.close(r)); }
});

// ---------- 5. ghost surface (hermetic, injected probe) ----------
test('Ghost.tlsCheck: path doctrine (chain-ridden when armed, direct when off) + status surface', async () => {
  const g = new Ghost();
  let seen;
  const r1 = await g.tlsCheck({ refs: 'api.github.com', probe: async (args) => { seen = args; return { ok: true, posture: 'clean', reason: 'test', refs: [{ ref: 'api.github.com:443', verdict: 'clean' }], at: 'now' }; } });
  assert.equal(seen.dial, undefined, 'ghost off: the probe dials direct (the path the enterprise bump sits on)');
  assert.equal(r1.path, 'direct');
  assert.equal(g.status().tlsInspect.posture, 'clean', 'additive status surface (the console ghost card reads this)');

  const g2 = new Ghost();
  g2.configure({ mode: 'required', chain: 'http://127.0.0.1:1' });
  const r2 = await g2.tlsCheck({ refs: 'api.github.com,127.0.0.1:8971', probe: async (args) => { seen = args; return { ok: true, posture: 'tls-inspected', reason: 'test', refs: [], at: 'now' }; } });
  assert.equal(typeof seen.dial, 'function', 'armed: public references ride the chain');
  const s = await seen.dial('127.0.0.1', 8971).catch(() => null);
  if (s) { s.on('error', () => {}); s.destroy(); }
  assert.ok(s === null || typeof s.destroy === 'function', 'private references still dial direct (the lab never rides the chain)');
  await assert.rejects(() => seen.dial('203.0.113.7', 443), /127\.0\.0\.1:1|timeout|refused/i, 'public references are pushed THROUGH the chain');
  assert.equal(r2.posture, 'tls-inspected');
  assert.equal(g2.status().tlsInspect.posture, 'tls-inspected');
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
