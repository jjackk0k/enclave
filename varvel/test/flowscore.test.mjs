// flowscore.test.mjs - gap#6: the flow-beacon self-test tier. scoreFlow feature math and
// bands, push-mode honesty, scoreProfileShape pre-deployment grading, the channel's flow
// ring (transportfail harness style), and the /api/channel/flow route. The honesty
// contract is pinned: insufficient data gets NO score, and everything reported is feature
// evidence, never a vendor verdict.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreFlow, scoreProfileShape } from '../engine/beaconscore.mjs';
import { preflight } from '../tools/floworacle.mjs';
import { CallbackChannel } from '../engine/callback.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
// Deterministic rand (same LCG family the malleable tests use): same seed -> same stream.
const lcg = (seed) => { let s = seed >>> 0; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; }; };
const series = (gaps) => { const t = [0]; for (const g of gaps) t.push(t[t.length - 1] + g); return t; };

// ---------- scoreFlow: bands, flags, fail-closed ----------
test('metronome (fixed 700ms, +/-0) scores machine-metric with the metronome flag', () => {
  const r = scoreFlow({ times: series(Array(64).fill(700)) });
  assert.equal(r.band, 'machine-metric');
  assert.ok(r.score >= 70);
  assert.ok(r.flagged.some((f) => /intervals metronomic: gapCV 0\.00/.test(f)), JSON.stringify(r.flagged));
  assert.equal(r.features.gapCV, 0);
  assert.equal(r.features.withinTenPct, 1);
  assert.equal(r.features.histConcentration, 1);
  assert.match(r.note, /never a vendor verdict/); // the tier says WHY: vendor weights are secret
});

test('+/-50% jitter scores strictly lower; bursty human-ish lower still', () => {
  const metro = scoreFlow({ times: series(Array(64).fill(700)) });
  const r = lcg(42);
  const jittered = scoreFlow({ times: series(Array.from({ length: 64 }, () => 700 + (r() * 2 - 1) * 350)) });
  assert.ok(jittered.score < metro.score, 'jitter ' + jittered.score + ' < metronome ' + metro.score);
  // human-ish: quick irregular bursts separated by long pauses (browsing tabs, not a timer)
  const humanish = scoreFlow({ times: series(Array.from({ length: 16 }, () => [200, 400, 600, 8000]).flat()) });
  assert.ok(humanish.score < jittered.score, 'human-ish ' + humanish.score + ' < jitter ' + jittered.score);
  assert.equal(humanish.band, 'human-ish');
});

test('fail-closed: fewer than 12 points -> insufficient-data, score null', () => {
  const r = scoreFlow({ times: series(Array(4).fill(700)) }); // 5 timestamps
  assert.equal(r.band, 'insufficient-data');
  assert.equal(r.score, null);
  assert.deepEqual(r.flagged, []);
  assert.match(r.note, /fewer than 12 points/);
});

test('near-constant payload sizes fire the sizeCV flag', () => {
  const r = scoreFlow({ times: series(Array(64).fill(700)), sizes: Array(65).fill(512) });
  assert.equal(r.features.sizeCV, 0);
  assert.ok(r.flagged.some((f) => /payload sizes near-constant: sizeCV/.test(f)), JSON.stringify(r.flagged));
  // no sizes at all -> sizeCV null (no evidence), never a fabricated number
  assert.equal(scoreFlow({ times: series(Array(64).fill(700)) }).features.sizeCV, null);
});

test("push mode: no gap metrics exist, and the honesty note says why that's the point", () => {
  const r = scoreFlow({ times: series(Array(64).fill(700)), mode: 'push' });
  assert.equal(r.features.gapMean, null);
  assert.equal(r.features.gapCV, null);
  assert.equal(r.features.withinTenPct, null);
  assert.equal(r.features.histConcentration, null);
  assert.ok(r.flagged.some((f) => /push transport: no polling periodicity exists to score/.test(f)), JSON.stringify(r.flagged));
  assert.ok(r.flagged.some((f) => /detectors fall back to duration\/byte\/fan-out features/.test(f)));
  assert.equal(typeof r.score, 'number'); // duration/byte facts only, on the same 0-100 scale
});

// ---------- scoreProfileShape: pre-deployment cadence grading ----------
test('scoreProfileShape is deterministic under a seeded rand', () => {
  const a = scoreProfileShape('web-browse', { rand: lcg(7) });
  const b = scoreProfileShape('web-browse', { rand: lcg(7) });
  assert.equal(a.score, b.score);
  assert.deepEqual(a.features, b.features);
});

test("metronomic 'update-check' grades worse than bursty 'web-browse'", () => {
  const update = scoreProfileShape('update-check', { rand: lcg(7) });
  const browse = scoreProfileShape('web-browse', { rand: lcg(7) });
  assert.ok(update.score > browse.score, 'update-check ' + update.score + ' should out-score (beacon-like) web-browse ' + browse.score);
  assert.ok(update.features.gapCV < browse.features.gapCV, 'the metronomic profile has the tighter dispersion');
});

test('floworacle preflight: unknown profile names get an honest error, not a fallback', () => {
  const bad = preflight('carrier-pigeon');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /unknown profile 'carrier-pigeon'/);
  assert.ok(bad.known.includes('web-browse'));
  const good = preflight('ops-tempo', { rand: lcg(3) });
  assert.equal(good.ok, true);
  assert.equal(good.profile, 'ops-tempo');
  assert.equal(good.band, scoreProfileShape('ops-tempo', { rand: lcg(3) }).band);
});

// ---------- channel flow ring (transportfail harness style) ----------
test('accepted checkins/pushes land in da.flowTimes (bounded 128) and agentsView carries flowScore', async () => {
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: () => {} });
  await ch.arm(0);
  try {
    const { agentId, token } = ch.registerAgent({ label: 'flow' });
    const da = ch.agents.get(agentId);
    assert.deepEqual(da.flowTimes, []);
    // a result PUSH carries its payload bytes onto the ring (dns-codec push path)
    const taskId = ch.task(agentId, 'shell', 'echo hi');
    const d = Buffer.from('result-payload-bytes').toString('base64');
    ch._dnsPayload({ a: agentId, s: 1, h: hmac(token, [agentId, 1, taskId, 0, 1, d].join(':')), t: taskId, k: 'push', i: 0, n: 1, d }, '127.0.0.1', 'icmp');
    assert.equal(da.flowTimes.length, 1);
    assert.equal(da.flowTimes[0].bytes, d.length);
    assert.ok(da.flowTimes[0].t > 0);
    // flood 130 more accepted pulls: the ring holds the LAST 128, drop-oldest
    for (let s = 2; s <= 131; s++) {
      ch._dnsPayload({ a: agentId, s, h: hmac(token, agentId + ':' + s + ':pull') }, '127.0.0.1', 'icmp');
    }
    assert.equal(da.checkins, 131);
    assert.equal(da.flowTimes.length, 128, 'bounded at MAX_FLOW_EVENTS');
    const view = ch.agentsView()[0];
    assert.equal(view.flowScore.features.points, 128);
    assert.equal(typeof view.flowScore.score, 'number');
    assert.equal(view.flowScore.mode, 'poll', 'last wire icmp -> poll cadence grading');
    assert.ok(Array.isArray(view.flowScore.flagged) && typeof view.flowScore.note === 'string');
    // the route backing: full result for a known agent, null for an unknown one
    const fv = ch.flowView(agentId);
    assert.equal(fv.agentId, agentId);
    assert.equal(fv.events, 128);
    assert.equal(ch.flowView('no-such-agent'), null);
  } finally { await ch.disarm(); }
});

// ---------- the route: 404 on unknown agent ----------
test('GET /api/channel/flow?agent=<unknown> answers 404', async () => {
  const serverFile = join(dirname(fileURLToPath(import.meta.url)), '..', 'server.mjs');
  const port = 39171;
  const proc = spawn(process.execPath, [serverFile], {
    env: { ...process.env, VARVEL_PORT: String(port), VARVEL_DEMO_PORT: '39172', VARVEL_HARD_PORT: '39173' },
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  try {
    await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('server.mjs did not report listening within 25s')), 25000);
      let buf = '';
      proc.stdout.on('data', (d) => {
        buf += d;
        if (buf.includes('VARVEL service on')) { clearTimeout(to); resolve(); }
      });
      proc.on('exit', () => reject(new Error('server.mjs exited before listening: ' + buf.slice(0, 200))));
    });
    // retry briefly: the log line precedes the demo-target boot, give routes a moment
    let r = null;
    for (let i = 0; i < 20; i++) {
      try {
        r = await fetch(`http://127.0.0.1:${port}/api/channel/arm`, { method: 'POST' }); // arm: flow evidence needs a channel
        if (r.ok) r = await fetch(`http://127.0.0.1:${port}/api/channel/flow?agent=no-such-agent`);
        break;
      } catch { await new Promise((x) => setTimeout(x, 250)); }
    }
    assert.ok(r, 'route answered');
    assert.equal(r.status, 404);
    const body = await r.json();
    assert.match(body.error, /no such agent/);
  } finally { proc.kill(); }
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as transportfail/dnstransport.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
