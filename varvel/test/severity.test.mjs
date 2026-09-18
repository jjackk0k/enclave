// severity.test.mjs — hermetic unit tests for engine/severity.mjs (no I/O).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SEVS, normSev, riskLevel, sevRank } from '../engine/severity.mjs';

test('normSev: every platform dialect -> canonical', () => {
  assert.deepEqual(SEVS, ['crit', 'high', 'med', 'low', 'info']);
  assert.equal(normSev('crit'), 'crit');
  assert.equal(normSev('critical'), 'crit'); // the cvepacks dialect
  assert.equal(normSev('CRITICAL'), 'crit');
  assert.equal(normSev('medium'), 'med');    // the vulncheck/fuzz dialect
  assert.equal(normSev('moderate'), 'med');
  assert.equal(normSev('informational'), 'info');
  assert.equal(normSev('NONSENSE'), 'med');  // unknown -> medium, NEVER dropped to info
  assert.equal(normSev(undefined), 'med');
  assert.equal(normSev(''), 'med');
});

test('riskLevel: triage roll-up (crit+high→high, med+low→medium, info→info)', () => {
  assert.equal(riskLevel('crit'), 'high');
  assert.equal(riskLevel('high'), 'high');
  assert.equal(riskLevel('med'), 'medium');
  assert.equal(riskLevel('low'), 'medium');
  assert.equal(riskLevel('info'), 'info');
  assert.equal(riskLevel('critical'), 'high'); // via normalization
});

test('sevRank: most-severe-first ordering', () => {
  assert.ok(sevRank('crit') < sevRank('high'));
  assert.ok(sevRank('high') < sevRank('med'));
  assert.ok(sevRank('med') < sevRank('low'));
  assert.ok(sevRank('low') < sevRank('info'));
});
