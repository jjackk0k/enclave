// VARVEL enforced stealth-budget tests.
//   node --test varvel/test/budget.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { StealthBudget, BUDGET_PRESETS, budgetPreset, noiseCost } from '../engine/budget.mjs';
import { Campaign } from '../engine/campaign.mjs';

test('presets: quieter profile → lower noise cap and lower peak ceiling', () => {
  assert.ok(BUDGET_PRESETS.quiet.maxNoise < BUDGET_PRESETS.normal.maxNoise);
  assert.ok(BUDGET_PRESETS.paranoid.maxNoise < BUDGET_PRESETS.quiet.maxNoise);
  assert.ok(BUDGET_PRESETS.paranoid.peakCeiling < BUDGET_PRESETS.normal.peakCeiling);
  assert.equal(BUDGET_PRESETS.loud.maxNoise, Infinity);
});

test('budgetPreset: name lookup, object override, unknown→normal', () => {
  assert.equal(budgetPreset('quiet').label, 'quiet');
  assert.equal(budgetPreset('nope').label, 'normal');
  assert.equal(budgetPreset({ maxNoise: 5 }).maxNoise, 5);
});

test('noiseCost = loudness × count from the footprint model', () => {
  // http-fingerprint loudness 1, web-content-scan loudness 4, exploit-attempt loudness 5
  assert.equal(noiseCost('http-fingerprint'), 1);
  assert.equal(noiseCost('web-content-scan', 3), 12);
  assert.equal(noiseCost('exploit-attempt'), 5);
  assert.equal(noiseCost('not-a-real-kind'), 0);
});

test('check(): quiet ceiling blocks a loud exploit and flags escalation', () => {
  const b = new StealthBudget('quiet'); // peakCeiling 3, maxNoise 40
  const v = b.check('exploit-attempt'); // loudness 5 > 3
  assert.equal(v.ok, false);
  assert.equal(v.overCeiling, true);
  assert.equal(v.escalate, true);
  assert.match(v.reason, /above the quiet ceiling/);
  // a quiet recon fingerprint is fine
  assert.equal(b.check('http-fingerprint').ok, true);
});

test('check(): over remaining noise budget flags escalation without recording', () => {
  const b = new StealthBudget({ label: 'tiny', maxNoise: 10, peakCeiling: 5 });
  b.record('web-content-scan'); // cost 4, spent 4, remaining 6
  const v = b.check('web-content-scan', 2); // cost 8 > 6 remaining
  assert.equal(v.overBudget, true);
  assert.equal(v.escalate, true);
  assert.equal(b.spent(), 4, 'check() does not mutate spent');
});

test('record() accumulates spent; loud profile never blocks', () => {
  const b = new StealthBudget('loud');
  b.record('exploit-attempt'); b.record('pivot', 2); // 5 + 10
  assert.equal(b.spent(), 15);
  assert.equal(b.remaining(), Infinity);
  assert.equal(b.check('exploit-attempt').ok, true, 'no ceiling breach under loud');
});

test('status(): pct + state transitions + honest proof line', () => {
  const b = new StealthBudget({ label: 'q', maxNoise: 20, peakCeiling: 5 });
  assert.equal(b.status().state, 'ok');
  b.record('web-content-scan', 3); // 12/20 = 60% → warn
  assert.equal(b.status().state, 'warn');
  b.record('web-content-scan');    // 16/20 = 80% → critical
  assert.equal(b.status().state, 'critical');
  b.record('web-content-scan', 3); // 28/20 → clamped 100% → exhausted
  const s = b.status();
  assert.equal(s.state, 'exhausted');
  assert.equal(s.pct, 100);
  assert.equal(s.pctRaw, 140, 'raw pct is honest (not clamped)');
  assert.match(s.proof, /noise pts/);
  assert.equal(s.ceilingHonored, true, 'loudness-4 never breached the ceiling of 5');
  assert.equal(s.actualPeak, 4);
});

test('status() is HONEST about the budget TOTAL: over-budget never reads "stayed under"', () => {
  const b = new StealthBudget({ label: 'tiny', maxNoise: 10, peakCeiling: 5 });
  b.record('web-content-scan', 3); // cost 12 > 10, but loudness 4 ≤ ceiling 5
  const s = b.status();
  assert.equal(s.underBudget, false);
  assert.equal(s.overspent, 2);
  assert.equal(s.ceilingHonored, true);
  assert.doesNotMatch(s.proof, /Stayed under/, 'must NOT claim restraint it did not earn');
  assert.match(s.proof, /OVER the tiny budget/);
});

test('untracked kinds are counted so the proof cannot imply silence', () => {
  const b = new StealthBudget('quiet');
  b.record('totally-unknown-kind'); // not in the footprint model
  b.record('tcp-scan');
  const s = b.status();
  assert.equal(s.untracked, 1);
  assert.equal(s.actions, 1, 'only the tracked action is in events');
});

test('counts are floored to positive integers (no fractional or degenerate noise)', () => {
  assert.equal(noiseCost('tcp-scan', 2.9), 6);      // 3 × floor(2.9)=2
  assert.equal(noiseCost('tcp-scan', 0), 3);        // → 1
  assert.equal(noiseCost('tcp-scan', Infinity), 3); // → 1
  assert.equal(noiseCost('tcp-scan', -5), 3);       // → 1
});

test('status() is HONEST: a fired loud action is never reported as "ceiling honored"', () => {
  const b = new StealthBudget('quiet'); // ceiling 3
  b.record('http-fingerprint');         // loudness 1
  b.record('exploit-attempt');          // loudness 5, NO override → un-approved breach
  const s = b.status();
  assert.equal(s.ceilingHonored, false, 'a loudness-5 action breached the ceiling of 3');
  assert.equal(s.actualPeak, 5);
  assert.equal(s.breaches, 1);
  assert.equal(s.unauthorizedBreaches, 1);
  assert.equal(s.authorizedBreaches, 0);
  assert.match(s.proof, /exceeded the 3 ceiling/);
  assert.match(s.proof, /un-approved/);
});

test('override is recorded honestly: an authorized breach is not counted as un-approved', () => {
  const b = new StealthBudget('quiet');
  b.record('exploit-attempt', 1, { override: true }); // HITL-authorized over-ceiling noise
  const s = b.status();
  assert.equal(s.overrides, 1);
  assert.equal(s.authorizedBreaches, 1);
  assert.equal(s.unauthorizedBreaches, 0);
  assert.match(s.proof, /HITL-authorized/);
});

// --- per-engagement sizing + per-phase reserve (2026-08-26: wildcard recon exhausted 'normal' 120) ---

test('checkPhase: recon-phase spend is capped at 70% (reserve); validate+exploit keep the rest', () => {
  const b = new StealthBudget({ maxNoise: 100 });
  b.record('web-content-scan', 15); // 60 spent (loudness 4 × 15)
  const v = b.checkPhase('web-content-scan', 3, 'recon'); // +12 → 72 > 70 cap
  assert.equal(v.ok, false);
  assert.equal(v.overReserve, true);
  assert.equal(v.escalate, true);
  assert.equal(v.reserveCap, 70);
  assert.match(v.reason, /capped at 70%/);
  assert.match(v.reason, /validate\+exploit/);
  // the SAME action outside recon is fine (within the raw budget)
  assert.equal(b.checkPhase('web-content-scan', 3, 'validate').ok, true);
  assert.equal(b.check('web-content-scan', 3).ok, true, 'phase-less check is reserve-free — the reserve never tightens plain check()');
  // unlimited budgets never reserve
  const loud = new StealthBudget('loud');
  assert.equal(loud.checkPhase('exploit-attempt', 1, 'recon').ok, true);
});

test('campaign wiring: budget.maxNoise sizes the engagement ceiling; recon breach logs budget.reserve (not budget.exceed)', () => {
  const c = new Campaign({ engine: {}, scope: { engagement: 'BUDGET-SIZE-T', signedBy: 'x', cidrs: ['10.0.0.0/8'] }, stealth: 'normal', budget: { maxNoise: 33 } });
  assert.equal(c.noise.maxNoise, 33, 'the launch option sizes the noise ceiling on top of the preset');
  c.noise.record('tcp-scan', 5); // 15 spent; recon cap = 70% of 33 = 23.1
  c._noise({ kind: 'tcp-scan', count: 3 }); // +9 → 24 > 23.1 — over the RESERVE, within the raw budget
  assert.ok(c.activity.some((e) => e.kind === 'budget.reserve'), 'reserve breach is logged as budget.reserve');
  assert.ok(!c.activity.some((e) => e.kind === 'budget.exceed'), 'within the raw budget — not a full exceed');
  const evt = c.activity.find((e) => e.kind === 'budget.reserve');
  assert.equal(evt.data.phase, 'recon');
  assert.match(evt.data.reason, /capped at 70%/);
});

test('campaign wiring: validate-phase spend past the recon reserve logs NO reserve event', () => {
  const c = new Campaign({ engine: {}, scope: { engagement: 'BUDGET-SIZE-V', signedBy: 'x', cidrs: ['10.0.0.0/8'] }, stealth: 'normal', budget: { maxNoise: 40 } });
  c.noise.record('tcp-scan', 10); // 30 spent (75% — past the recon share)
  c.phaseIndex = 1; // validate
  c._noise({ kind: 'web-content-scan', count: 1 }); // +4 → 34 ≤ 40: the reserve does not bind validate
  assert.ok(!c.activity.some((e) => e.kind === 'budget.reserve'), 'validate+exploit keep the reserved 30%');
  assert.ok(!c.activity.some((e) => e.kind === 'budget.exceed'), 'and still within the raw budget');
});
