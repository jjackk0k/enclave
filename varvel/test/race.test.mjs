// VARVEL race harness tests — pure oracle + live TOCTOU against chainyard.
//   node --test varvel/test/race.test.mjs
//
// The T4 lesson, pinned: a naive parallelism heuristic (≥2 success statuses in a
// burst) flags EVERY fixture here — including the properly-locked, idempotent
// control. The governed oracle (sequential-replay control + STATE readback) sorts
// them: raced / logic-bug / single-effect / inconclusive.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { classifyRace, naiveParallelFlag, raceProbe, RACE_CAPS } from '../tools/race.mjs';
import { createChainyardTarget, RACE_CANARY, GIFT_CANARY } from '../targets/chainyard.mjs';

// ——— pure oracle ———

test('classifyRace: concurrent-only violation = raced', () => {
  const r = classifyRace({ seqEffect: 1, parEffect: 6, intended: 1 });
  assert.equal(r.verdict, 'raced');
  assert.match(r.detail, /only under concurrency/);
});

test('classifyRace: sequential violation = logic-bug, NOT a race', () => {
  // the manhuaus-style distinction the T4 spec demands: a "violation" that also
  // occurs sequentially is a plain logic bug — the harness must say which.
  const r = classifyRace({ seqEffect: 2, parEffect: 6, intended: 1 });
  assert.equal(r.verdict, 'logic-bug');
  assert.match(r.detail, /WITHOUT concurrency/);
});

test('classifyRace: effect ≤ intended under both = single-effect (cleared)', () => {
  const r = classifyRace({ seqEffect: 1, parEffect: 1, intended: 1 });
  assert.equal(r.verdict, 'single-effect');
  // the idempotent decoy: N concurrent 200s (statuses look terrible) but ONE effect
  const r2 = classifyRace({ seqEffect: 1, parEffect: 1, intended: 1 });
  assert.equal(r2.verdict, 'single-effect', 'status codes cannot see state — effect count clears it');
});

test('classifyRace: unreadable readback = inconclusive (no claim without a control)', () => {
  assert.equal(classifyRace({ seqEffect: null, parEffect: 6, intended: 1 }).verdict, 'inconclusive');
  assert.equal(classifyRace({ seqEffect: 1, parEffect: null, intended: 1 }).verdict, 'inconclusive');
});

test('naiveParallelFlag: ≥2 success statuses in the burst = flag', () => {
  assert.equal(naiveParallelFlag({ responses: [{ status: 200 }, { status: 200 }, { status: 409 }] }), true);
  assert.equal(naiveParallelFlag({ responses: [{ status: 200 }, { status: 409 }] }), false);
  assert.equal(naiveParallelFlag({ responses: [null, null] }), false);
});

// ——— live against the chainyard race garden ———

async function withYard(fn) {
  const srv = createChainyardTarget();
  srv.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(base); }
  finally { await new Promise((r) => srv.close(r)); }
}

async function loginAsAlice(base) {
  return new Promise((resolve) => {
    const req = http.request(base + '/login', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' } }, (res) => {
      res.resume(); res.on('end', () => resolve(String(res.headers['set-cookie'] || '').split(';')[0]));
    });
    req.on('error', () => resolve(null));
    req.end('user=alice&pass=tenant-demo-2026');
  });
}

const FIXTURES = (cookie) => ({
  coupon: { request: { method: 'POST', path: '/api/coupons/redeem', headers: { cookie, 'content-type': 'application/json' }, body: '{"code":"WELCOME10"}' }, readback: { path: '/api/coupons/WELCOME10', effect: '"redemptions":(\\d+)' }, resetPath: '/lab/revert', concurrency: 6, attempts: 3 },
  wallet: { request: { method: 'POST', path: '/api/wallet/transfer', headers: { cookie, 'content-type': 'application/json' }, body: '{"to":"bob","amount":60}' }, readback: { path: '/api/wallet', effect: '"debits":(\\d+)' }, resetPath: '/lab/revert', concurrency: 3, attempts: 3 },
  giveaway: { request: { method: 'POST', path: '/api/giveaway/enter', headers: { cookie, 'content-type': 'application/json' }, body: '{}' }, readback: { path: '/api/giveaway', effect: '"yourEntries":(\\d+)' }, resetPath: '/lab/revert', concurrency: 6, attempts: 3 },
  gift: { request: { method: 'POST', path: '/api/gift/claim', headers: { cookie, 'content-type': 'application/json' }, body: '{"code":"GIFT-2026"}' }, readback: { path: '/api/gifts/GIFT-2026', effect: '"claims":(\\d+)' }, resetPath: '/lab/revert', concurrency: 6, attempts: 3 },
});

test('raceProbe: the three planted TOCTOU fixtures race (state readback proves it)', () => withYard(async (base) => {
  const cookie = await loginAsAlice(base);
  assert.ok(cookie);
  const f = FIXTURES(cookie);

  const coupon = await raceProbe(base, f.coupon);
  assert.equal(coupon.verdict, 'raced');
  assert.equal(coupon.rate, 1, 'deterministic in-lab (planted 90ms window)');
  assert.equal(coupon.sequential.effect, 1, 'sequential control: single redemption');
  assert.ok(coupon.concurrent.effect >= 2, 'burst duplicated the effect');
  assert.match(coupon.readbackBody, new RegExp(RACE_CANARY), 'readback carries the state marker');

  const wallet = await raceProbe(base, f.wallet);
  assert.equal(wallet.verdict, 'raced');
  assert.match(wallet.readbackBody, /"balance":-\d+/, 'overdrawn balance is the money shot');

  const giveaway = await raceProbe(base, f.giveaway);
  assert.equal(giveaway.verdict, 'raced');
  assert.ok(giveaway.concurrent.effect > giveaway.sequential.effect, 'entry limit bypassed only under concurrency');
}));

test('raceProbe: the SAFE control clears — naive flags it, the oracle does not', () => withYard(async (base) => {
  const cookie = await loginAsAlice(base);
  const gift = await raceProbe(base, FIXTURES(cookie).gift);
  assert.equal(gift.verdict, 'single-effect', 'locked + idempotent: one claim under both fire modes');
  assert.equal(gift.naiveWouldFlag, true, 'naive parallelism flags the all-200s burst anyway — the false positive');
  assert.equal(gift.concurrent.successes, 6, 'all six burst responses were 200 (idempotent replay)');
  assert.equal(gift.concurrent.effect, 1, 'but the state readback shows exactly one gift');
  assert.match(gift.readbackBody, new RegExp(GIFT_CANARY));
  assert.equal(gift.flaky, false);
}));

test('raceProbe: the discrimination proof, compressed', () => withYard(async (base) => {
  const cookie = await loginAsAlice(base);
  const f = FIXTURES(cookie);
  const results = {};
  for (const k of ['coupon', 'wallet', 'giveaway', 'gift']) results[k] = await raceProbe(base, f[k]);
  assert.deepEqual(Object.values(results).map((r) => r.naiveWouldFlag), [true, true, true, true], 'naive flags all four');
  assert.deepEqual(Object.values(results).map((r) => r.verdict), ['raced', 'raced', 'raced', 'single-effect'], 'oracle sorts them');
}));

test('raceProbe: caps clamp, never throws on an unreachable base', async () => {
  const r = await raceProbe('http://127.0.0.1:1', {
    request: { method: 'POST', path: '/api/coupons/redeem', body: '{}' },
    concurrency: 999, attempts: 999, readback: { path: '/x', effect: '"(\\d+)"' }, timeout: 250,
  });
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.concurrency, RACE_CAPS.maxConcurrency, 'concurrency clamped to the hard cap');
  assert.equal(r.attempts, RACE_CAPS.maxAttempts, 'attempts clamped to the hard cap');
  assert.equal(r.naiveWouldFlag, false);
});
