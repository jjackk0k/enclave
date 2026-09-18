// VARVEL detection-footprint tests — the OPSEC "what does a defender see" model.
//   node --test varvel/test/footprint.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FOOTPRINTS, footprintFor, scoreFootprint } from '../engine/footprint.mjs';
import { Opsec } from '../engine/opsec.mjs';

test('every footprint profile is complete and well-formed', () => {
  for (const [id, fp] of Object.entries(FOOTPRINTS)) {
    assert.ok(fp.label, `${id} has a label`);
    assert.ok(fp.category, `${id} has a category`);
    assert.ok(Number.isInteger(fp.loudness) && fp.loudness >= 1 && fp.loudness <= 5, `${id} loudness 1-5`);
    assert.ok(['low', 'med', 'high'].includes(fp.attribution), `${id} attribution set`);
    assert.ok(Array.isArray(fp.signals) && fp.signals.length, `${id} has signals`);
    assert.ok(Array.isArray(fp.detectedBy) && fp.detectedBy.length, `${id} has detectedBy`);
    assert.ok(Array.isArray(fp.exposes) && fp.exposes.length, `${id} has exposes`);
    assert.ok(typeof fp.quieter === 'string' && fp.quieter.length, `${id} has quieter guidance`);
  }
});

test('footprintFor resolves ids and aliases; unknown -> null', () => {
  assert.equal(footprintFor('web-content-scan').id, 'web-content-scan');
  assert.equal(footprintFor('webscan').id, 'web-content-scan', 'alias resolves');
  assert.equal(footprintFor('recon').id, 'tcp-scan', 'alias resolves');
  assert.equal(footprintFor('artifact').id, 'file-drop');
  assert.equal(footprintFor('nonsense'), null);
  assert.equal(footprintFor(''), null);
  assert.equal(footprintFor(undefined), null);
});

test('honesty: no profile claims to be undetectable', () => {
  for (const fp of Object.values(FOOTPRINTS)) {
    const blob = JSON.stringify(fp).toLowerCase();
    assert.ok(!/undetectable|invisible to|evade detection|bypass detection|anti-forensic/.test(blob), `${fp.label} makes no evasion claim`);
  }
});

test('scoreFootprint: empty -> no risk', () => {
  const s = scoreFootprint([]);
  assert.equal(s.events, 0);
  assert.equal(s.risk, 'none');
  assert.equal(s.peakLoudness, 0);
});

test('scoreFootprint: a loud scan dominates the risk and tops the loudest list', () => {
  const s = scoreFootprint([
    { kind: 'http-fingerprint', count: 3 }, // loudness 1
    { kind: 'web-content-scan' },           // loudness 4
    { kind: 'exploit-attempt' },            // loudness 5
  ]);
  assert.equal(s.peakLoudness, 5);
  assert.ok(['high', 'critical'].includes(s.risk), 'a level-5 action pushes risk high');
  assert.equal(s.loudest[0].id, 'exploit-attempt', 'loudest first');
  assert.ok(s.detectedBy.length > 3, 'detection surface is unioned across activities');
  assert.ok(s.exposes.some((e) => /payload/i.test(e)), 'exploit exposure surfaced');
  assert.ok(s.byCategory.recon >= 4 && s.byCategory.exploit >= 1, 'category rollup');
});

test('scoreFootprint: many quiet actions stay low risk', () => {
  const s = scoreFootprint([{ kind: 'http-fingerprint', count: 50 }, { kind: 'tls-probe', count: 20 }]);
  assert.ok(['low', 'moderate'].includes(s.risk), 'volume of quiet actions is not "loud"');
  assert.equal(s.peakLoudness, 1);
});

test('Opsec integration: activities score into posture; a dropped artifact is a file-drop', () => {
  const o = new Opsec();
  o.act({ kind: 'tcp-scan', host: '10.0.0.1' });
  o.act({ kind: 'web-content-scan', host: '10.0.0.1' });
  o.act({ kind: 'bogus-activity' }); // ignored — unknown kind
  o.record({ host: '10.0.0.1', kind: 'file', path: '/tmp/poc', cleanup: 'rm -f /tmp/poc' });

  const j = o.toJSON();
  assert.equal(j.activities.length, 3, 'tcp-scan + web-content-scan + file-drop (bogus ignored)');
  assert.ok(j.activities.every((a) => a.detectedBy.length && a.quieter), 'each activity carries its profile');
  assert.ok(j.posture.detection.risk !== 'none', 'posture reflects the footprint');
  assert.ok(j.posture.detection.loudest.some((l) => l.id === 'web-content-scan'));
  // file-drop came from record()
  assert.ok(j.activities.some((a) => a.id === 'file-drop' && a.host === '10.0.0.1'));
});
