// VARVEL footprint-reducer / OPSEC-advisor tests.
//   node --test varvel/test/footprint-advisor.test.mjs
//
// Hermetic: builds inputs with scoreFootprint() (the real detection model) rather than
// stubbing shapes, so the advisor is exercised against exactly what opsec.mjs emits.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scoreFootprint, footprintFor } from '../engine/footprint.mjs';
import { footprintAdvisor, reductionBriefing, targetLevel } from '../engine/footprint-advisor.mjs';

const RISK_ORDER = ['none', 'low', 'moderate', 'elevated', 'high', 'critical'];

// A realistic mix: quiet recon (loudness 1) + two loud activities (loudness 4 and 5).
function loudMix() {
  return scoreFootprint([
    { kind: 'http-fingerprint', count: 3 }, // loudness 1 — quiet, must NOT appear in the plan
    { kind: 'web-content-scan', count: 2 }, // loudness 4 — loud
    { kind: 'exploit-attempt', count: 1 },  // loudness 5 — loudest
  ]);
}

test('plans a reduction for each loud activity, using its profile’s quieter alternative', () => {
  const detection = loudMix();
  const advice = footprintAdvisor({ posture: { detection } }, { target: 'lab.internal' });

  const ids = advice.plan.map((p) => p.id);
  assert.ok(ids.includes('web-content-scan'), 'loud web scan is planned');
  assert.ok(ids.includes('exploit-attempt'), 'loud exploit attempt is planned');
  assert.ok(!ids.includes('http-fingerprint'), 'quiet fingerprinting is NOT planned');

  // Loudest first, and each item quotes the profile's real signal + quieter guidance.
  assert.equal(advice.plan[0].id, 'exploit-attempt', 'loudest activity leads the plan');
  for (const p of advice.plan) {
    const fp = footprintFor(p.id);
    assert.ok(p.loudness >= 3, 'only loud activities are planned');
    assert.equal(p.issue, fp.signals[0], 'issue is the activity’s first defender-visible signal');
    assert.equal(p.quieter, fp.quieter, 'quieter alternative comes straight from the footprint profile');
    assert.ok(typeof p.quieter === 'string' && p.quieter.length, 'quieter alternative is present');
    // Reduction is a real fraction: > 0 (there is savings) but < 1 (never full elimination).
    assert.ok(p.estReduction > 0 && p.estReduction < 1, 'estReduction is a partial fraction, never invisibility');
  }
  // Louder activities get a higher estimated saving.
  assert.ok(advice.plan[0].estReduction >= advice.plan[1].estReduction, 'louder → higher estReduction');
});

test('projects a lower score/risk and a positive reducible amount', () => {
  const detection = loudMix();
  const advice = footprintAdvisor({ posture: { detection } });

  assert.equal(advice.currentScore, detection.weighted, 'currentScore reflects the live footprint');
  assert.equal(advice.currentRisk, detection.risk);
  assert.ok(advice.projectedScore < advice.currentScore, 'projected score is lower than current');
  assert.ok(advice.reducible > 0, 'there is risk to reduce');
  assert.equal(advice.reducible, Math.round((advice.currentScore - advice.projectedScore) * 10) / 10);

  // Projected risk tier is quieter than (or equal to) current; here it strictly drops.
  assert.ok(
    RISK_ORDER.indexOf(advice.projectedRisk) < RISK_ORDER.indexOf(advice.currentRisk),
    'quieting the loud activities lowers the risk tier',
  );
  assert.ok(typeof advice.summary === 'string' && advice.summary.length, 'a one-line summary is produced');
});

test('accepts the detection object directly, not only the full opsec.toJSON()', () => {
  const detection = loudMix();
  const viaPosture = footprintAdvisor({ posture: { detection } });
  const viaDetection = footprintAdvisor(detection); // raw scoreFootprint() result
  assert.deepEqual(
    viaDetection.plan.map((p) => p.id),
    viaPosture.plan.map((p) => p.id),
    'same plan whether given the wrapper or the detection directly',
  );
  assert.equal(viaDetection.currentScore, viaPosture.currentScore);
});

test('empty / no-detection / garbage input → none, empty plan, never throws', () => {
  const expectNone = (v, label) => {
    const a = footprintAdvisor(v);
    assert.equal(a.currentRisk, 'none', `${label}: risk none`);
    assert.deepEqual(a.plan, [], `${label}: empty plan`);
    assert.equal(a.summary, 'No noisy activity yet.', `${label}: summary`);
    assert.equal(a.reducible, 0, `${label}: nothing reducible`);
  };
  expectNone(undefined, 'undefined');
  expectNone(null, 'null');
  expectNone({}, 'empty object');
  expectNone(42, 'number');
  expectNone('nope', 'string');
  expectNone([], 'array');
  expectNone({ posture: { detection: scoreFootprint([]) } }, 'scored-but-empty');
});

test('all-quiet activity → nothing to reduce, but reports the real (low) risk', () => {
  const detection = scoreFootprint([{ kind: 'http-fingerprint', count: 20 }, { kind: 'tls-probe', count: 5 }]);
  const advice = footprintAdvisor({ posture: { detection } });
  assert.deepEqual(advice.plan, [], 'no loud activity to plan against');
  assert.notEqual(advice.currentRisk, 'none', 'there was activity — risk is low, not none');
  assert.equal(advice.projectedScore, advice.currentScore, 'nothing to project down');
  assert.equal(advice.reducible, 0);
  assert.equal(reductionBriefing(advice), '', 'no briefing when nothing is reducible');
});

test('reductionBriefing names the loudest activity + the quieter/lower-noise framing', () => {
  const advice = footprintAdvisor({ posture: { detection: loudMix() } }, { target: 'lab.internal' });
  const brief = reductionBriefing(advice);

  assert.ok(brief.length, 'a briefing is produced when there is something to reduce');
  assert.ok(brief.includes(footprintFor('exploit-attempt').label), 'mentions the loudest activity by label');
  assert.match(brief, /quieter/i, 'uses "quieter" framing');
  assert.match(brief, /lower-noise/i, 'uses "lower-noise" framing');
  assert.match(brief, /HIGH|ELEVATED|CRITICAL/, 'states the current risk tier');
  assert.ok(brief.toLowerCase().includes('projected'), 'states the projected outcome');
});

test('reductionBriefing shows at most the top 3 moves even when the plan is longer', () => {
  const detection = scoreFootprint([
    { kind: 'exploit-attempt' }, // 5
    { kind: 'pivot' },           // 5
    { kind: 'web-content-scan' },// 4
    { kind: 'auth-attempt' },    // 4
    { kind: 'file-drop' },       // 4
  ]);
  const advice = footprintAdvisor({ posture: { detection } });
  assert.equal(advice.plan.length, 5, 'every loud activity is in the plan');
  const brief = reductionBriefing(advice);
  const numbered = brief.match(/\n\s+\d+\.\s/g) || [];
  assert.equal(numbered.length, 3, 'briefing is capped at the top 3 moves');
});

test('reductionBriefing: empty/no-plan input → empty string, never throws', () => {
  assert.equal(reductionBriefing(null), '');
  assert.equal(reductionBriefing(undefined), '');
  assert.equal(reductionBriefing({}), '');
  assert.equal(reductionBriefing({ plan: [] }), '');
});

test('targetLevel maps a risk to a realistic quieter target', () => {
  assert.equal(targetLevel('critical'), 'moderate');
  assert.equal(targetLevel('high'), 'moderate');
  assert.equal(targetLevel('elevated'), 'low');
  assert.equal(targetLevel('moderate'), 'low');
  assert.equal(targetLevel('low'), 'low');
  assert.equal(targetLevel('none'), 'low');
  assert.equal(targetLevel(undefined), 'low');
});

test('boundary: advice + briefing are transparency, never evasion / anti-forensics', () => {
  const advice = footprintAdvisor({ posture: { detection: loudMix() } }, { target: 'lab.internal' });
  const blob = (JSON.stringify(advice) + '\n' + reductionBriefing(advice)).toLowerCase();
  assert.ok(
    !/(evade|evasion|bypass|undetectable|anti-forensic|conceal|cover your tracks|hide (the |our |your )?activity)/.test(blob),
    'no evasion / anti-forensics language anywhere in the output',
  );
  // Positive framing: this is about reducing needless noise, and everything stays logged.
  assert.match(blob, /quieter|lower-noise|noise/, 'framed as reducing noise');
  assert.match(blob, /logged and attributable/, 'reaffirms activity stays logged and attributable');
});
