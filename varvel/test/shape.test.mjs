// shape.test.mjs — the C2 SHAPING PACK (parts 1-3): beacon shape knobs (jitterPct,
// batch/dwell windows, padding), the malleable profile library v2, and the
// oracle-graded self-measurement loop (claimed vs measured, divergence LOUD).
// Hermetic (loopback only, injected rand/now where the unit is pure), same harness
// style as transportfail/flowscore.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SHAPE_PROFILES, shapeProfile, nextGap, windowIndexAt, windowOffsetMs, windowFlushAt, expectedJa4h, expectedWireHeaders } from '../engine/malleable.mjs';
import { gradeShape } from '../engine/shapegrade.mjs';
import { ja4h } from '../engine/fingerprint.mjs';
import { preflightShapes } from '../tools/shapegrade.mjs';
import { CallbackChannel } from '../engine/callback.mjs';
import { SimAgent } from '../agents/sim-agent.mjs';

const SCOPE = { engagement: 'test', signedBy: 'test', cidrs: ['127.0.0.0/8'] };
const hmac = (token, msg) => crypto.createHmac('sha256', token).update(msg).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lcg = (seed) => { let s = seed >>> 0; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; }; };

async function armed(extra = {}) {
  const events = [];
  const ch = new CallbackChannel({ scope: SCOPE, onEvent: (t, o) => events.push({ type: t, ...o }), ...extra });
  await ch.arm(0);
  return { ch, port: ch.port, events };
}

// ---------- profile library v2 (pure) ----------
test('shape library: plain + 3 shaped profiles; unknown resolves null honestly', () => {
  for (const n of ['plain', 'cdn-asset', 'software-update', 'telemetry-beacon']) assert.ok(SHAPE_PROFILES[n], n + ' exists');
  assert.equal(shapeProfile('plain').name, 'plain');
  assert.equal(shapeProfile(null).name, 'plain');
  assert.equal(shapeProfile('carrier-pigeon'), null, 'unknown name -> null, never a silent reshape');
  const c = shapeProfile({ name: 'mine', cadence: { intervalMs: 5, jitterPct: 4 }, batch: { windowMs: 10 }, padding: { perCycle: 99 }, http: { pullPaths: ['/x'] } });
  assert.equal(c.cadence.intervalMs, 200, 'interval floor');
  assert.equal(c.cadence.jitterPct, 0.9, 'jitterPct capped');
  assert.equal(c.batch.windowMs, 1000, 'window floor');
  assert.equal(c.padding.perCycle, 8, 'pad rate capped');
  assert.equal(c.http.pushPaths[0], '/x', 'pushPaths inherit pullPaths when absent');
});

test('every shaped profile declares the full v2 contract: paths, headers, UA pool, cadence, expected class', () => {
  for (const n of ['cdn-asset', 'software-update', 'telemetry-beacon']) {
    const p = SHAPE_PROFILES[n];
    assert.ok(p.http.pullPaths.length >= 2 && p.http.pushPaths.length >= 1, n + ' path templates');
    assert.ok(p.http.headers.some(([h]) => h === 'user-agent'), n + ' UA header');
    assert.ok(p.http.uaPool.length >= 1, n + ' UA family');
    assert.ok(p.cadence.intervalMs > 0 && p.cadence.jitterPct > 0, n + ' cadence model with real jitter %');
    assert.ok(p.expect && typeof p.expect.ja4h === 'string', n + ' expected JA4H class declared');
    assert.match(p.expect.h2, /no native H2 control/, n + ' H2 limit stated honestly');
  }
});

// ---------- knob 1: real proportional jitter ----------
test('nextGap jitterPct: proportional to the interval, deterministic under injected rand', () => {
  const p = { intervalMs: 10000, jitterPct: 0.3, burst: { chance: 0, minN: 0, maxN: 0, gapMs: 0 } };
  assert.equal(nextGap(p, { rand: () => 0.5 }).gapMs, 10000, 'rand .5 = dead center');
  assert.equal(nextGap(p, { rand: () => 1 }).gapMs, 13000, 'rand 1 = +30% of interval');
  assert.equal(nextGap(p, { rand: () => 0 }).gapMs, 7000, 'rand 0 = -30% of interval');
  // legacy absolute jitterMs is untouched when jitterPct is absent (backward compat)
  const legacy = { intervalMs: 1000, jitterMs: 100, burst: { chance: 0, minN: 0, maxN: 0, gapMs: 0 } };
  assert.equal(nextGap(legacy, { rand: () => 1 }).gapMs, 1100);
});

// ---------- knob 2: batch/dwell windows ----------
test('batch window math: seeded flush points are deterministic, token-bound, inside the window', () => {
  const anchor = 1_000_000, windowMs = 3600000;
  assert.equal(windowIndexAt(anchor, windowMs, anchor - 5), 0, 'before anchor clamps to window 0');
  assert.equal(windowIndexAt(anchor, windowMs, anchor + windowMs * 2 + 3), 2);
  const f = windowFlushAt('tok', anchor, windowMs, 3);
  assert.equal(f, windowFlushAt('tok', anchor, windowMs, 3), 'same token+window -> same point (channel and agent agree with no coordination)');
  assert.ok(f >= anchor + 3 * windowMs && f < anchor + 4 * windowMs, 'the point lies inside its window');
  assert.notEqual(windowOffsetMs('tok', windowMs, 3), windowOffsetMs('tok', windowMs, 4), 'per-window re-randomized');
  assert.notEqual(windowOffsetMs('tok', windowMs, 3), windowOffsetMs('other', windowMs, 3), 'bound to the shared secret');
  assert.ok(windowFlushAt('tok', anchor, windowMs, 4) > f, 'monotonic across windows');
});

test('channel hold/drain: tasks are held until their window\'s flush point, then drain as a prefix', () => {
  const ch = new CallbackChannel({ scope: SCOPE });
  const { agentId, token } = ch.registerAgent({});
  const anchor = 1_000_000_000, windowMs = 60000;
  ch.setShapeProfile(agentId, { name: 'batchy', batch: { windowMs }, http: null, cadence: { intervalMs: 30000, jitterPct: 0.1 } });
  const a = ch.agents.get(agentId);
  a.shapeAt = anchor; // pinned anchor: pure time math from here
  const t1 = { taskId: 't1', kind: 'shell', data: 'a', queuedAt: anchor + 100 };              // window 0
  const t2 = { taskId: 't2', kind: 'shell', data: 'b', queuedAt: anchor + windowMs + 5 };      // window 1
  const t3 = { taskId: 't3', kind: 'shell', data: 'c', queuedAt: anchor + windowMs + 9000 };   // window 1
  a.tasks.push(t1, t2, t3);
  const flush0 = windowFlushAt(token, anchor, windowMs, 0);
  const flush1 = windowFlushAt(token, anchor, windowMs, 1);
  assert.equal(ch._drainDeliverable(a, flush0 - 1, 16).length, 0, 'before window 0\'s flush: everything held');
  const first = ch._drainDeliverable(a, flush0, 16);
  assert.deepEqual(first.map((t) => t.taskId), ['t1'], 'at flush 0: only window-0 tasks release (window-1 tasks still held)');
  assert.equal(ch._drainDeliverable(a, flush1 - 1, 16).length, 0, 'between flushes: held');
  const second = ch._drainDeliverable(a, flush1, 16);
  assert.deepEqual(second.map((t) => t.taskId), ['t2', 't3'], 'at flush 1: the window\'s held tasks flush as ONE burst');
  assert.equal(a.tasks.length, 0);
});

// ---------- knob 3: padding (audited as itself) ----------
test('padding dummies: authenticated pad envelopes are accepted, audited as agent.pad, never deliver tasks', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    ch.task(agentId, 'note', 'must-not-leak-into-a-pad');
    // a pad envelope: same path/shape as a pull, 'pad' HMAC context
    const r = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pad') } });
    assert.equal(r.status, 204, 'pad gets the uniform idle reply even with a task queued');
    assert.equal(ch.agents.get(agentId).tasks.length, 1, 'the queued task was NOT delivered on a pad');
    assert.equal(ch.agents.get(agentId).seq, 1, 'pads consume the strict sequence (they are real wire events)');
    assert.ok(events.some((e) => e.type === 'agent.pad' && e.padding === true && e.agentId === agentId), 'audited as itself: agent.pad');
    assert.ok(!events.some((e) => e.type === 'task.delivered'), 'no delivery event');
    assert.equal(ch.agents.get(agentId).flowTimes.length, 1, 'the flow ring counts the pad — the wire sees it, so our self-measurement must too');
    // a bad-auth pad-shaped forgery is still a 204-uniform rejection
    const r2 = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': '2', 'x-auth': 'forged' } });
    assert.equal(r2.status, 204);
    assert.ok(events.some((e) => e.type === 'checkin.rejected' && e.reason === 'bad-auth'));
  } finally { await ch.disarm(); }
});

test('padding on the codec wire: /d pad context accepted, audited, never delivers', async () => {
  const { ch, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    ch.task(agentId, 'note', 'held');
    const out = ch._dnsPayload({ a: agentId, s: 1, h: hmac(token, agentId + ':1:pad') }, '127.0.0.1', 'dns-codec');
    assert.equal(out, '', 'uniform empty reply');
    assert.equal(ch.agents.get(agentId).tasks.length, 1);
    assert.ok(events.some((e) => e.type === 'agent.pad' && e.transport === 'dns-codec'));
  } finally { await ch.disarm(); }
});

// ---------- shaped routes + adoption end-to-end ----------
test('setShapeProfile -> header -> sim agent adopts: shaped routes serve check-ins, measured JA4H equals the claim', async () => {
  const { ch, port, events } = await armed();
  const dir = mkdtempSync(join(tmpdir(), 'shape-e2e-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    assert.equal(ch.setShapeProfile('no-such-agent', 'cdn-asset'), null);
    assert.equal(ch.setShapeProfile(agentId, 'carrier-pigeon'), null, 'unknown profile refused honestly');
    const applied = ch.setShapeProfile(agentId, 'cdn-asset');
    assert.equal(applied.name, 'cdn-asset');
    assert.ok(events.some((e) => e.type === 'agent.shape' && e.shape === 'cdn-asset'), 'audited');
    const agent = new SimAgent({ url: `http://127.0.0.1:${port}`, agentId, token, dir, interval: 150, jitter: 0 });
    const run = agent.run();
    try {
      // adoption lands on the first reply; the adopted cadence is the profile's own
      // (4000ms ±40%), so task flow is polled for, never assumed on a fixed sleep.
      for (let i = 0; i < 30 && !(agent.shape && agent.shape.name === 'cdn-asset'); i++) await sleep(100);
      assert.equal(agent.shape && agent.shape.name, 'cdn-asset', 'agent adopted the shape live');
      const taskId = ch.task(agentId, 'note', 'shaped-task');
      let view = null;
      for (let i = 0; i < 80; i++) {
        await sleep(150);
        view = ch.tasksView(agentId)[0];
        if (view && view.status === 'resulted') break;
      }
      assert.equal(view.taskId, taskId);
      assert.equal(view.status, 'resulted', 'full round trip on the shaped routes');
      // the self-measurement money assertion: what the oracle observed on the shaped
      // routes IS what the profile claimed (exact JA4H strings, pull and push)
      const ring = ch.fpStatus().observations;
      const shaped = ring.filter((o) => o.route !== '/c');
      assert.ok(shaped.length >= 2, 'shaped-route observations exist');
      const claimPull = expectedJa4h('cdn-asset', { method: 'GET', ja4hFn: ja4h });
      const claimPush = expectedJa4h('cdn-asset', { method: 'POST', ja4hFn: ja4h });
      assert.ok(shaped.some((o) => o.ja4h === claimPull && o.route !== '/api/telemetry'), 'measured pull fingerprint == claimed');
      assert.ok(shaped.some((o) => o.ja4h === claimPush && o.route === '/api/telemetry'), 'measured push fingerprint == claimed');
      assert.ok(shaped.every((o) => o.agent === agentId), 'ring carries per-agent attribution');
      assert.equal(ch.agentsView()[0].shape, 'cdn-asset', 'agentsView surfaces the applied shape');
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

test('a shaped path from an UNSHAPED agent is just malformed (204-uniform)', async () => {
  const { ch, port } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    const r = await fetch(`http://127.0.0.1:${port}/assets/js/app.min.js`, { headers: { 'x-agent': agentId, 'x-seq': '1', 'x-auth': hmac(token, agentId + ':1:pull') } });
    assert.equal(r.status, 204);
    assert.equal(ch.agents.get(agentId).checkins, 0, 'not a check-in: the route is only live for agents with the shape applied');
  } finally { await ch.disarm(); }
});

test('shape clear: plain removes the shape and the agent clears live (byte-identical fallback)', async () => {
  const { ch, port } = await armed();
  const dir = mkdtempSync(join(tmpdir(), 'shape-clear-'));
  try {
    const { agentId, token } = ch.registerAgent({});
    // a fast custom shape keeps the adopted poll loop quick (the adopted cadence drives the loop)
    ch.setShapeProfile(agentId, { name: 'fast', cadence: { intervalMs: 300, jitterPct: 0.1 }, http: { pullPaths: ['/ping'], headers: [['user-agent', 'fast/1.0']], uaPool: ['fast/1.0'] } });
    const agent = new SimAgent({ url: `http://127.0.0.1:${port}`, agentId, token, dir, interval: 150, jitter: 0 });
    const run = agent.run();
    try {
      for (let i = 0; i < 30 && !(agent.shape && agent.shape.name === 'fast'); i++) await sleep(100);
      assert.equal(agent.shape && agent.shape.name, 'fast');
      const cleared = ch.setShapeProfile(agentId, 'plain');
      assert.equal(cleared.name, 'plain');
      assert.equal(ch.agents.get(agentId).shape, null);
      for (let i = 0; i < 30 && agent.shape !== null; i++) await sleep(100); // a reply carries x-varvel-shape: plain
      assert.equal(agent.shape, null, 'agent cleared the shape live');
      assert.ok(agent.log.some((l) => /shape cleared: plain/.test(l.msg)));
    } finally { agent.stop(); await run; }
  } finally { await ch.disarm(); }
});

test('batch window end-to-end: held tasks flush as ONE batched response at the seeded point', async () => {
  const { ch, port, events } = await armed();
  try {
    const { agentId, token } = ch.registerAgent({});
    const applied = ch.setShapeProfile(agentId, { name: 'dwell', batch: { windowMs: 1000 }, cadence: { intervalMs: 5000, jitterPct: 0.1 }, http: null });
    assert.equal(applied.name, 'dwell');
    const ids = [ch.task(agentId, 'note', 'a'), ch.task(agentId, 'note', 'b'), ch.task(agentId, 'note', 'c')];
    // poll on /c until the flush lands (the seeded point lies inside a 1s window;
    // 150ms polls cross it within ~2 windows)
    let batched = null, seq = 0;
    const deadline = Date.now() + 6000;
    while (Date.now() < deadline && !batched) {
      seq++;
      const r = await fetch(`http://127.0.0.1:${port}/c`, { headers: { 'x-agent': agentId, 'x-seq': String(seq), 'x-auth': hmac(token, agentId + ':' + seq + ':pull') } });
      if (r.status === 200) batched = await r.json();
      else await sleep(150);
    }
    assert.ok(batched, 'the flush arrived');
    assert.equal(batched.batch, true, 'multiple held tasks flush as one burst envelope');
    assert.deepEqual(batched.tasks.map((t) => t.taskId).sort(), ids.slice().sort(), 'all three held tasks in the burst');
    assert.ok(events.filter((e) => e.type === 'task.delivered' && e.batched === true).length === 3, 'every batched delivery audited as itself');
  } finally { await ch.disarm(); }
});

// ---------- part 3: the oracle-graded self-measurement loop ----------
test('gradeShape: measured JA4H matching the claim grades match; plain grades no-claim', () => {
  const s = shapeProfile('cdn-asset');
  const claim = expectedJa4h(s, { method: 'GET', ja4hFn: ja4h });
  const flow = { score: 8, band: 'human-ish', features: { points: 40 } };
  const r = gradeShape({ shape: 'cdn-asset', observations: [{ route: '/assets/js/app.min.js', ja4h: claim, agent: 'a1' }], flow, preFlight: { band: 'human-ish', score: 6 } });
  assert.equal(r.verdict, 'measures-as-claimed');
  assert.equal(r.divergent.length, 0);
  assert.equal(r.claimed.ja4hPull, claim);
  assert.match(r.note, /never a claim of undetectability/);
  const plain = gradeShape({ shape: 'plain', observations: [], flow: null });
  assert.equal(plain.verdict, 'no-claim', 'plain makes no claim to grade against');
});

test('gradeShape: divergence is LOUD — wrong fingerprint and band flips land in divergent[]', () => {
  const flow = { score: 82, band: 'machine-metric', features: { points: 40 } };
  const r = gradeShape({
    shape: 'cdn-asset',
    observations: [
      { route: '/assets/js/app.min.js', ja4h: 'ge11nnWRONG_xxxxxxxxxxxx_000000000000_000000000000' },
      { route: '/assets/css/site.css', ja4h: 'ge11nnOTHER_yyyyyyyyyyyy_000000000000_000000000000' },
    ],
    flow,
    preFlight: { band: 'human-ish', score: 6 },
  });
  assert.equal(r.verdict, 'divergent');
  assert.ok(r.divergent.some((d) => /JA4H DIVERGENCE/.test(d)), 'fingerprint mismatch is loud');
  assert.ok(r.divergent.some((d) => /JA4H INSTABILITY/.test(d)), 'two distinct fingerprints on the routes is loud');
  assert.ok(r.divergent.some((d) => /CADENCE DIVERGENCE/.test(d) && /trust the measured number/.test(d)), 'band flip is loud and says which number to trust');
  assert.equal(r.checks.find((c) => c.dim === 'cadence').verdict, 'divergent');
});

test('gradeShape: thin evidence is no-evidence/insufficient-data, never guessed', () => {
  const r = gradeShape({ shape: 'software-update', observations: [], flow: { band: 'insufficient-data', score: null }, preFlight: { band: 'mixed', score: 60 } });
  assert.equal(r.verdict, 'insufficient-data');
  assert.ok(r.checks.every((c) => c.verdict === 'no-evidence'));
  assert.equal(gradeShape({ shape: 'nope' }).ok, false);
});

test('preflightShapes: every profile carries its claim + cadence pre-flight grade', () => {
  const r = preflightShapes({ rand: lcg(11) });
  assert.equal(r.ok, true);
  assert.equal(r.profiles.plain.ja4hPull, null, 'plain claims nothing');
  for (const n of ['cdn-asset', 'software-update', 'telemetry-beacon']) {
    assert.ok(r.profiles[n].ja4hPull.startsWith('ge11nn'), n + ' pull claim');
    assert.ok(r.profiles[n].ja4hPush.startsWith('po11nn'), n + ' push claim');
    assert.ok(Number.isFinite(r.profiles[n].preFlight.score), n + ' cadence pre-flight');
  }
  // the honesty spread, pre-measurement: the service cadence must read more beacon-like
  assert.ok(r.profiles['software-update'].preFlight.score > r.profiles['cdn-asset'].preFlight.score, 'software-update is honestly the most beacon-like of the set');
});

test('expectedWireHeaders pins the runtime contract (undici append order, forced sec-fetch-mode)', () => {
  const names = expectedWireHeaders('cdn-asset', { method: 'GET' }).map(([n]) => n);
  assert.deepEqual(names, ['host', 'connection', 'user-agent', 'accept', 'accept-language', 'accept-encoding', 'cache-control', 'pragma', 'x-agent', 'x-seq', 'x-auth', 'sec-fetch-mode']);
  const post = expectedWireHeaders('cdn-asset', { method: 'POST' }).map(([n]) => n);
  assert.deepEqual(post.slice(-2), ['sec-fetch-mode', 'content-length'], 'content-length lands last on a push');
});

// Teardown grace: on win32, --test-force-exit can fire while sockets are still closing
// (libuv UV_HANDLE_CLOSING assert). Same guard as transportfail/dnstransport.
test('teardown grace for socket drain (win32 libuv assert guard)', async () => {
  await new Promise((r) => setTimeout(r, 600));
});
