// VARVEL — 5-tier productivity ladder + axis lock-in tests (the anti-stuck upgrade).
//   node --test varvel/test/auditor-ladder.test.mjs
//
// Hermetic: pure functions only, no engine/campaign/agent dependencies. Verifies the
// green→critical ladder, each rung's governing action, monotonic escalation, and that
// axis lock-in catches the classic payload-fuzz loop WITHOUT false-positiving on
// genuinely varied targets.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { productivityTier, axisLockIn, productivity } from '../engine/auditor.mjs';

// ── productivityTier: the ladder ──────────────────────────────────────────────
test('productivityTier: clean signals -> green with no action', () => {
  const g = productivityTier();
  assert.equal(g.tier, 'green');
  assert.equal(g.action, '');
  assert.equal(g.score, 0);
  // a single stalled phase is still green (below the hint threshold): score 2 < 3
  assert.equal(productivityTier({ stuck: 1 }).tier, 'green');
});

test('productivityTier: mild stall -> yellow soft hint', () => {
  const y = productivityTier({ stuck: 1, unproductiveRecent: 1 }); // 2 + 1 = 3
  assert.equal(y.tier, 'yellow');
  assert.equal(y.action, 'hint');
  assert.equal(y.score, 3);
});

test('productivityTier: sustained no-progress -> orange triggers deep-think', () => {
  const o = productivityTier({ stuck: 2 }); // 4
  assert.equal(o.tier, 'orange');
  assert.equal(o.action, 'deep-think');
});

test('productivityTier: deep stall + a lie -> red demands a new hypothesis class', () => {
  const r = productivityTier({ stuck: 2, unproductiveRecent: 1, dishonest: 1 }); // 4 + 1 + 2 = 7
  assert.equal(r.tier, 'red');
  assert.equal(r.action, 'demand-new-hypothesis');
});

test('productivityTier: pinned -> critical rejects the next expensive repeat', () => {
  const c = productivityTier({ stuck: 3, unproductiveRecent: 1, dishonest: 1 }); // 6 + 1 + 2 = 9
  assert.equal(c.tier, 'critical');
  assert.equal(c.action, 'reject-next-repeat');
  assert.ok(c.score >= 9);
});

test('productivityTier: escalation is monotonic and boundaries claim the HIGHER tier', () => {
  const order = ['green', 'yellow', 'orange', 'red', 'critical'];
  const rank = (t) => order.indexOf(t);
  let prev = -1;
  for (let stuck = 0; stuck <= 6; stuck++) {
    const r = rank(productivityTier({ stuck }).tier);
    assert.ok(r >= prev, `tier must not de-escalate as stuck rises (stuck=${stuck})`);
    prev = r;
  }
  // exact boundary ownership: the higher rung owns 4, 7 and 9
  assert.equal(productivityTier({ stuck: 2 }).tier, 'orange');            // score 4 -> orange (not yellow)
  assert.equal(productivityTier({ unproductiveRecent: 7 }).tier, 'red');  // score 7 -> red    (not orange)
  assert.equal(productivityTier({ dishonest: 4, stuck: 0.5 }).tier, 'critical'); // 8 + 1 = 9 -> critical
});

test('productivityTier: axisRepeat feeds the ladder (weighted 1.5x)', () => {
  assert.equal(productivityTier({ axisRepeat: 1 }).tier, 'green');   // 1.5
  assert.equal(productivityTier({ axisRepeat: 2 }).tier, 'yellow');  // 3.0
  assert.equal(productivityTier({ axisRepeat: 3 }).tier, 'orange');  // 4.5
  assert.equal(productivityTier({ axisRepeat: 5 }).tier, 'red');     // 7.5
});

test('productivityTier: robust to garbage / negative input, never throws', () => {
  assert.equal(productivityTier({ stuck: -100, dishonest: NaN }).tier, 'green'); // negatives/NaN clamp to 0
  assert.equal(productivityTier({ stuck: 'x', unproductiveRecent: null }).tier, 'green');
  assert.doesNotThrow(() => productivityTier(undefined));
  assert.doesNotThrow(() => productivityTier({}));
});

// ── axisLockIn: the brute/fuzz-loop detector ──────────────────────────────────
test('axisLockIn: 3+ curls to the SAME login, only the payload varying -> LOCKED', () => {
  const steps = [
    { name: 'Bash', detail: 'curl http://t/login -d user=admin&pass=aaa' },
    { name: 'Bash', detail: 'curl http://t/login -d user=admin&pass=bbb' },
    { name: 'Bash', detail: 'curl http://t/login -d user=admin&pass=ccc' },
  ];
  const r = axisLockIn(steps);
  assert.equal(r.locked, true);
  assert.equal(r.count, 3);
  assert.match(r.axis, /http:\/\/t\/login/);           // the held-constant axis is reported
  assert.match(r.note, /change a DIFFERENT parameter/);
  assert.match(r.note, /not the same dial/);
});

test('axisLockIn: same tool, VARIED targets/paths -> NOT locked', () => {
  const steps = [
    { name: 'Bash', detail: 'curl http://t/login  -d user=admin&pass=aaa' },
    { name: 'Bash', detail: 'curl http://t/admin  -d user=admin&pass=aaa' },
    { name: 'Bash', detail: 'curl http://t/config -d user=admin&pass=aaa' },
  ];
  assert.equal(axisLockIn(steps).locked, false); // three distinct paths -> no single axis dominates
});

test('axisLockIn: same path, VARIED hosts -> NOT locked (real exploration, not a dial)', () => {
  const steps = [
    { name: 'Bash', detail: 'curl http://a/login -d pass=x' },
    { name: 'Bash', detail: 'curl http://b/login -d pass=x' },
    { name: 'Bash', detail: 'curl http://c/login -d pass=x' },
  ];
  assert.equal(axisLockIn(steps).locked, false);
});

test('axisLockIn: threshold is configurable', () => {
  const steps = [
    { name: 'Bash', detail: 'curl http://t/login -d pass=a' },
    { name: 'Bash', detail: 'curl http://t/login -d pass=b' },
  ];
  assert.equal(axisLockIn(steps).locked, false);                    // 2 < default threshold 3
  assert.equal(axisLockIn(steps, { threshold: 2 }).locked, true);   // 2 >= 2
});

test('axisLockIn: only the last `window` steps count (old repeats age out)', () => {
  const steps = [
    { name: 'Bash', detail: 'curl http://t/login -d pass=a' }, // the repeated login triplet...
    { name: 'Bash', detail: 'curl http://t/login -d pass=b' },
    { name: 'Bash', detail: 'curl http://t/login -d pass=c' },
    { name: 'Bash', detail: 'nmap 10.0.0.1' },                 // ...then 5 distinct, varied scans
    { name: 'Bash', detail: 'nmap 10.0.0.2' },
    { name: 'Bash', detail: 'nmap 10.0.0.3' },
    { name: 'Bash', detail: 'nmap 10.0.0.4' },
    { name: 'Bash', detail: 'nmap 10.0.0.5' },
  ];
  assert.equal(axisLockIn(steps, { window: 5 }).locked, false); // last 5 are all distinct scans
  const wide = axisLockIn(steps, { window: 8 });                // widen to catch the login triplet
  assert.equal(wide.locked, true);
  assert.match(wide.axis, /http:\/\/t\/login/);
});

test('axisLockIn: different TOOLS on the same target are different axes', () => {
  const steps = [
    { name: 'Bash', detail: 'curl http://t/login -d pass=a' },
    { name: 'WebFetch', detail: 'http://t/login' },
    { name: 'Read', detail: 'http://t/login' },
  ];
  assert.equal(axisLockIn(steps).locked, false);
});

test('axisLockIn: empty / short / malformed input -> not locked, never throws', () => {
  assert.equal(axisLockIn([]).locked, false);
  assert.equal(axisLockIn().locked, false);
  assert.equal(axisLockIn(null).locked, false);
  assert.equal(axisLockIn('nope').locked, false);
  // a single step can never reach threshold
  assert.equal(axisLockIn([{ name: 'Bash', detail: 'curl http://t/login -d pass=a' }]).locked, false);
  assert.doesNotThrow(() => axisLockIn([null, undefined, {}, { name: 'X' }, { detail: 'y' }]));
  assert.equal(axisLockIn([null, undefined, {}]).locked, false);
});

// ── integration: productivity() now surfaces a ladder tier ────────────────────
test('productivity: surfaces a ladder `tier` rolled up from the stuck + dishonest signals', () => {
  const clean = productivity([{ verdict: 'productive', realDelta: 2 }, { verdict: 'productive', realDelta: 1 }]);
  assert.equal(clean.tier, 'green');
  // existing fields remain intact (additive-only change)
  assert.equal(clean.stuckStreak, 0);
  assert.equal(clean.productive, 2);
  assert.ok('honestyRate' in clean && 'totalDelta' in clean && 'noProgress' in clean);

  const pinned = productivity([
    { verdict: 'no-progress', realDelta: 0 },
    { verdict: 'no-progress', realDelta: 0 },
    { verdict: 'dishonest-or-stalled', realDelta: 0 },
  ]); // stuckStreak 3, noProgress 2, dishonest 1 -> 3*2 + 2 + 1*2 = 10 -> critical
  assert.equal(pinned.tier, 'critical');
  assert.equal(pinned.phases, 3);
  assert.equal(pinned.dishonest, 1);
});
