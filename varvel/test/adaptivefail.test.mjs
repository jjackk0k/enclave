// adaptivefail.test.mjs — the C2 SHAPING PACK part 4: ORACLE-GRADED ADAPTIVE FAILOVER.
// Per-wire measured detectability (beaconscore over the per-transport flow ring) feeds
// the preference ranking; crossing the threshold surfaces a switch recommendation.
// Hermetic: pure ranking tests inject everything; channel tests use loopback + directly
// seeded flow rings (the ring is the channel's observation store — seeding it IS the
// injected measurement). Same harness style as transportfail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gradeAgentTransports, rankTransports } from '../engine/transport-grade.mjs';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';
import { DnsTransport } from '../agents/dns-client.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function armed(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, port: ch.port, events };
}
// Seed a wire's observation ring: n events at a fixed gap (metronome => high beacon
// score) or jittered (=> low). This is the injected measurement the grader consumes.
function seedRing(a, wire, { n = 16, gap = 1000, jitter = 0, end = 1_000_000_000 } = {}) {
  a.flowTimes = a.flowTimes || [];
  let t = end - n * gap;
  let k = 0;
  for (let i = 0; i < n; i++) {
    t += gap + (jitter ? Math.round((Math.sin(i * 7.3) * jitter)) : 0);
    a.flowTimes.push({ t, bytes: 0, wire: wire });
    k++;
  }
  return k;
}

// ---------- rankTransports (pure) ----------
test('ranking formula: health 60/30/0 + success (cap 20) - 0.4*measured beacon score', () => {
  const now = 1_000_000_000, E = 5000;
  const grades = gradeAgentTransports({ transportLastSeen: { http: now - 100, dns: now - 100 }, lastTransport: 'http' }, { now, expectedMs: E });
  const r = rankTransports({
    grades,
    wireScores: { http: { score: 80, band: 'machine-metric' }, dns: { score: 10, band: 'human-ish' } },
    checkins: { http: 30, dns: 12 },
    current: 'http',
  });
  const http = r.ranking.find((x) => x.transport === 'http');
  const dns = r.ranking.find((x) => x.transport === 'dns');
  assert.equal(http.score, 60 + 20 - Math.round(0.4 * 80), '60 health + 20 capped success - 32 shape penalty');
  assert.equal(dns.score, 60 + 12 - Math.round(0.4 * 10));
  assert.ok(dns.score > http.score, 'the less beacon-like wire outranks');
  assert.match(http.why, /measured beacon score 80/);
  assert.equal(r.ranking[0].transport, 'dns');
});

test('eligibility is fail-closed: requirement-less and never-observed wires are listed, never ranked', () => {
  const now = 1_000_000_000, E = 5000;
  const grades = gradeAgentTransports({ transportLastSeen: { http: now - 100 }, lastTransport: 'http' }, { now, expectedMs: E });
  const r = rankTransports({ grades, wireScores: {}, checkins: { http: 5 }, eligible: { ghc: false, smb: false, doh: false }, current: 'http' });
  assert.deepEqual(r.ranking.map((x) => x.transport), ['http'], 'only the observed, eligible wire ranks');
  const ghc = r.ineligible.find((x) => x.transport === 'ghc');
  assert.match(ghc.reason, /ghc2\.enabled.*burner token/, 'the ghc constraint is named honestly');
  assert.match(r.ineligible.find((x) => x.transport === 'smb').reason, /enrolled pivot link/);
  assert.match(r.ineligible.find((x) => x.transport === 'dns').reason, /never observed/);
});

test('a wire with no shape evidence gets no penalty AND no claim (honest neutral)', () => {
  const now = 1_000_000_000, E = 5000;
  const grades = gradeAgentTransports({ transportLastSeen: { http: now - 100, dns: now - 100 }, lastTransport: 'http' }, { now, expectedMs: E });
  const r = rankTransports({ grades, wireScores: { dns: { score: null, band: 'insufficient-data' } }, checkins: { http: 5, dns: 5 }, current: 'http' });
  const dns = r.ranking.find((x) => x.transport === 'dns');
  assert.equal(dns.beaconScore, null);
  assert.match(dns.why, /no shape evidence — no penalty, no claim/);
});

test('threshold crossing recommends the re-order; operator pin always wins; no better wire means stay', () => {
  const now = 1_000_000_000, E = 5000;
  const grades = gradeAgentTransports({ transportLastSeen: { http: now - 100, dns: now - 100 }, lastTransport: 'http' }, { now, expectedMs: E });
  const wireScores = { http: { score: 85, band: 'machine-metric' }, dns: { score: 15, band: 'human-ish' } };
  const checkins = { http: 10, dns: 40 };
  // crossing: current wire measured machine-metric and a better-ranked wire exists
  let r = rankTransports({ grades, wireScores, checkins, current: 'http', threshold: 70 });
  assert.equal(r.recommendation.action, 'switch-recommended');
  assert.equal(r.recommendation.to, 'dns', 'dns: 60+20-6=74 vs http: 60+10-34=36');
  assert.match(r.recommendation.reason, />= threshold 70/);
  // pin: same numbers, but the operator pinned http — recommendation refuses to move
  r = rankTransports({ grades, wireScores, checkins, current: 'http', pinned: 'http', threshold: 70 });
  assert.equal(r.recommendation.action, 'stay');
  assert.equal(r.recommendation.pinned, true);
  assert.match(r.recommendation.reason, /manual override always wins/);
  assert.equal(r.ranking[0].transport, 'http', 'the pin ranks first unconditionally');
  // below threshold: stay
  r = rankTransports({ grades, wireScores: { http: { score: 40 } }, checkins, current: 'http', threshold: 70 });
  assert.equal(r.recommendation.action, 'stay');
  // crossing but nothing better: stay, and say so honestly
  r = rankTransports({ grades, wireScores: { http: { score: 85 }, dns: { score: 90 } }, checkins: { http: 40, dns: 1 }, current: 'http', threshold: 70 });
  assert.equal(r.recommendation.action, 'stay');
  assert.match(r.recommendation.reason, /no eligible alternative outranks it/);
});

// ---------- channel failoverPlan ----------
test('failoverPlan: per-wire measured scores drive the ranking; constraints gate the set', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    // real observed check-ins on both wires (delivery evidence + success history)
    const r1 = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull') } });
    assert.equal(r1.status, 204);
    const dns = new DnsTransport({ url: `http://127.0.0.1:${port}`, agentId, token });
    dns.seq = 1;
    await dns.pull();
    dns.close();
    const a = ch.agents.get(agentId);
    // injected measurement: http rings metronomic (beacon-like), dns rings jittered.
    // Reset the ring first so the real check-ins above don't interleave timestamps.
    a.flowTimes = [];
    seedRing(a, 'http', { n: 16, gap: 1000, jitter: 0, end: Date.now() });
    seedRing(a, 'dns', { n: 16, gap: 1000, jitter: 900, end: Date.now() });
    const plan = ch.failoverPlan(agentId);
    assert.ok(plan, 'plan exists');
    assert.equal(plan.current, 'dns', 'last observed wire');
    const http = plan.ranking.find((x) => x.transport === 'http');
    const dnse = plan.ranking.find((x) => x.transport === 'dns');
    assert.ok(http.beaconScore >= 70, 'http measured machine-metric (metronomic ring), got ' + http.beaconScore);
    assert.ok(dnse.beaconScore < http.beaconScore, 'dns measured less beacon-like');
    assert.ok(dnse.score > http.score, 'dns outranks http on the measured evidence');
    // eligibility: no ghc attached, no link enrolled, no doh/icmp arms on this channel
    assert.ok(plan.ineligible.some((x) => x.transport === 'ghc'));
    assert.ok(plan.ineligible.some((x) => x.transport === 'smb'));
    assert.ok(plan.ineligible.some((x) => x.transport === 'doh'));
    assert.ok(plan.ineligible.some((x) => x.transport === 'icmp'));
    // agentsView carries the plan (console/API surface per house style)
    assert.ok(ch.agentsView()[0].failover.ranking.length >= 2);
    assert.equal(ch.failoverPlan('no-such-agent'), null);
  } finally { await ch.disarm(); }
});

test('failoverPlan: current wire crossing the threshold surfaces switch-recommended', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull') } });
    const a = ch.agents.get(agentId);
    a.flowTimes = []; // reset so the real check-in above doesn't interleave the seeded series
    seedRing(a, 'http', { n: 16, gap: 800, jitter: 0, end: Date.now() });       // metronomic: machine-metric
    seedRing(a, 'dns', { n: 16, gap: 800, jitter: 700, end: Date.now() });      // jittered: human-ish
    a.lastTransport = 'http';                                  // current wire = the metronomic one
    a.transportCheckins.dns = 16;
    a.transportLastSeen.dns = Date.now();
    const plan = ch.failoverPlan(agentId);
    assert.equal(plan.recommendation.action, 'switch-recommended');
    assert.equal(plan.recommendation.to, 'dns');
    // an operator pin suppresses the recommendation even with the same measurements
    ch.setTransport(agentId, 'http');
    const pinned = ch.failoverPlan(agentId);
    assert.equal(pinned.recommendation.action, 'stay');
    assert.equal(pinned.recommendation.pinned, true);
  } finally { await ch.disarm(); }
});

// ---------- agent-side adoption with local constraint honesty ----------
test('sim agent adopts a channel-assigned transport with seq continuity (http -> dns)', async () => {
  const { ch, port, events } = await armed();
  const dir = mkdtempSync(join(tmpdir(), 'adopt-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    const agent = new SimAgent({ url: `http://127.0.0.1:${port}`, agentId, token, dir, interval: 150, jitter: 0 });
    const run = agent.run();
    try {
      await sleep(450); // a few http cycles (seq advances past 1)
      assert.equal(agent.transport, 'http');
      const httpSeq = agent.seq;
      ch.setTransport(agentId, 'dns');
      await sleep(700); // a reply carries x-varvel-transport; the agent adopts
      assert.equal(agent.transport, 'dns', 'adopted the assigned wire');
      assert.ok(agent._dns && agent._dns.seq >= httpSeq, 'seq never replayed across the leg switch');
      await sleep(500);
      const view = ch.agentsView()[0];
      assert.ok(view.transportCheckins.dns >= 1, 'the dns leg demonstrably checks in after adoption');
      assert.equal(view.assignedTransport.state, 'active', 'assigned -> active ONLY on observed wire evidence');
      assert.ok(events.some((e) => e.type === 'agent.transport-active' && e.transport === 'dns'));
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

test('sim agent refuses unworkable assignments honestly (smb without a link, ghc without config)', async () => {
  const { ch, port } = await armed();
  const dir = mkdtempSync(join(tmpdir(), 'adopt-no-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    const agent = new SimAgent({ url: `http://127.0.0.1:${port}`, agentId, token, dir, interval: 150, jitter: 0 });
    const run = agent.run();
    try {
      await sleep(300);
      ch.setTransport(agentId, 'smb');
      await sleep(500);
      assert.equal(agent.transport, 'http', 'smb IGNORED: no enrolled link on this agent');
      assert.ok(agent.log.some((l) => /adopt smb IGNORED: no enrolled link/.test(l.msg)));
      ch.setTransport(agentId, 'ghc');
      await sleep(500);
      assert.equal(agent.transport, 'http', 'ghc IGNORED: no dead-drop config');
      assert.ok(agent.log.some((l) => /adopt ghc IGNORED/.test(l.msg)));
      ch.setTransport(agentId, 'ws');
      await sleep(500);
      assert.equal(agent.transport, 'http', 'ws IGNORED: no sim leg (documented)');
      assert.ok(agent.log.some((l) => /adopt ws IGNORED: the sim agent has no local ws leg/.test(l.msg)));
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
