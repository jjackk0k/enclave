// VARVEL opsec-watchdog tests — hermetic (fake budgets, no I/O).
//   node --test varvel/test/opsec-watchdog.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OpsecWatchdog } from '../engine/opsec-watchdog.mjs';
import { StealthBudget } from '../engine/budget.mjs';

const drive = (budget, kind, times) => { for (let i = 0; i < times; i++) budget.record(kind, 1); };

test('requires a budget; stays silent while the state is ok', () => {
  assert.throws(() => new OpsecWatchdog({}), /budget/);
  const events = [];
  const w = new OpsecWatchdog({ budget: new StealthBudget('quiet'), onEvent: (t, o) => events.push(o) });
  const b = w.budget;
  drive(b, 'http-fingerprint', 2); // tiny cost — stays ok
  assert.equal(w.check(), null);
  assert.equal(events.length, 0);
  assert.equal(w.latest(), null);
});

test('escalates with the budget: warn → critical → exhausted, each once, no spam', () => {
  const events = [];
  const b = new StealthBudget('normal'); // maxNoise 120
  const w = new OpsecWatchdog({ budget: b, onEvent: (t, o) => events.push(o), autoThrottle: false });
  // normal budget = 120 pts; web-content-scan costs 4/record → 15 recs = 60 (50% warn)
  drive(b, 'web-content-scan', 15);
  const a1 = w.check();
  assert.ok(a1 && a1.kind === 'budget-warn', 'warn fired at 50%');
  assert.ok(/passive sources, crawl/.test(a1.text), 'advises shifting to quiet kinds');
  assert.ok(/source IP/i.test(a1.text), 'the exposure no pacing fixes is named');
  assert.equal(w.check(), null, 'same state → silence');
  // to critical: 80% of 120 = 96 → +10 recs (100 pts)
  drive(b, 'web-content-scan', 10);
  const a2 = w.check();
  assert.ok(a2 && a2.kind === 'budget-critical');
  assert.equal(a2.throttled, false, 'autoThrottle off');
  // to exhausted: +5 recs = 120 (100%)
  drive(b, 'web-content-scan', 5);
  const a3 = w.check();
  assert.ok(a3 && a3.kind === 'budget-exhausted');
  assert.ok(/HITL/.test(a3.text));
  assert.equal(w.check(), null);
  assert.equal(events.filter((e) => e.kind === 'budget-warn').length, 1);
  assert.equal(events.filter((e) => e.kind === 'budget-critical').length, 1);
});

test('auto-throttle: entering critical widens the pacer gap ONCE, logged', () => {
  const events = [];
  const b = new StealthBudget('normal');
  let gap = 40;
  const fakePacer = { penalize() { gap *= 2; }, currentDelay() { return gap; } };
  const w = new OpsecWatchdog({ budget: b, pacer: () => fakePacer, onEvent: (t, o) => events.push({ type: t, ...o }), autoThrottle: true });
  drive(b, 'web-content-scan', 25); // 100 pts → critical (83%)
  const a = w.check();
  assert.ok(a && a.kind === 'budget-critical');
  assert.equal(a.throttled, true);
  assert.equal(gap, 80, 'gap doubled');
  assert.ok(/FIX APPLIED/.test(a.text));
  assert.ok(events.some((e) => e.type === 'opsec.watchdog.throttle'), 'throttle audited');
});

test('un-approved ceiling breach fires immediately, independent of state', () => {
  const events = [];
  const b = new StealthBudget('paranoid'); // peakCeiling 2
  const w = new OpsecWatchdog({ budget: b, onEvent: (t, o) => events.push(o), autoThrottle: false });
  b.record('exploit-attempt', 1); // loudness 5 > ceiling 2, no override → breach
  const a = w.check();
  assert.ok(a && a.kind === 'ceiling-breach');
  assert.equal(a.level, 'critical');
  assert.ok(/un-approved/.test(a.text));
  // HITL-authorized override does NOT trip the breach alarm
  const b2 = new StealthBudget('paranoid');
  const w2 = new OpsecWatchdog({ budget: b2, onEvent: () => {}, autoThrottle: false });
  b2.record('exploit-attempt', 1, { override: true });
  assert.equal(w2.check(), null, 'authorized override is not a breach');
});

test('getter pacer reaches a pacer assigned AFTER construction (the auto-calibration case)', () => {
  const b = new StealthBudget('normal');
  let p = null;
  const w = new OpsecWatchdog({ budget: b, pacer: () => p, onEvent: () => {}, autoThrottle: true });
  let gap = 10;
  drive(b, 'web-content-scan', 25);
  p = { penalize() { gap *= 3; }, currentDelay() { return gap; } }; // assigned late, like _calibrateStealth
  const a = w.check();
  assert.equal(a.throttled, true, 'late-assigned pacer still reached');
  assert.equal(gap, 30);
});
