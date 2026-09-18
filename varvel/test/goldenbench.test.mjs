// VARVEL goldenbench tests — fixture-driven coverage of the golden recall/precision
// bench (engine/goldenbench.mjs + tools/goldenbench.mjs): manifest parse, recall math,
// precision math, skip semantics, loud-miss, plus a live-corpus end-to-end over the
// real manifest (corpus-absent entries SKIP; the repo fixture is the always-present
// positive).   node --test test/goldenbench.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { validateManifest, matchHit, gradeEntry, summarize, DEFAULT_FORBID } from '../engine/goldenbench.mjs';
import { goldenbench, loadManifest, DEFAULT_MANIFEST } from '../tools/goldenbench.mjs';

const MIRROR_ROOT = 'C:/Users/Jack/Downloads/varvel-kimi/research/madara-site/wp-content/plugins/madara-core';
const tmp = (name) => join(tmpdir(), `varvel-goldenbench-${name}-${process.pid}`);

const cand = (over) => ({ ref: 'a.php:10', impactClass: 'option-overwrite', reachability: 'unauth', sev: 'crit', confidence: 'high', handler: 'h', score: 100, rank: 1, ...over });
const report = (candidates, stats = {}) => ({ root: 'x', candidates, scannedFiles: 1, skipped: [], gaps: stats.gaps || [], stats: { functions: 1, registrations: 1, unresolvedCallbacks: stats.unresolvedCallbacks ?? 0 } });

// --- manifest parse/validate -------------------------------------------------------

test('manifest parse: valid manifest normalizes entries, applies defaults', () => {
  const { entries, errors } = validateManifest({
    plugins: [
      { id: 'p1', root: 'r1', expectation: 'must-hit', hits: [{ ref: 'a.php:3', class: 'option-overwrite' }] },
      { id: 'p2', root: 'r2', expectation: 'must-stay-clean' },
    ],
  });
  assert.deepEqual(errors, []);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].hits[0].minReachability, 'unauth', 'default minReachability');
  assert.deepEqual(entries[1].forbid, DEFAULT_FORBID, 'default forbid = CONFIRMED band');
});

test('manifest parse: malformed entries collected in errors[], valid siblings survive, never throws', () => {
  const { entries, errors } = validateManifest({
    plugins: [
      { id: 'ok', root: 'r', expectation: 'must-hit', hits: [{ ref: 'a.php:3', class: 'sqli' }] },
      { id: 'no-root', expectation: 'must-hit', hits: [{ ref: 'a.php:3', class: 'sqli' }] },
      { id: 'bad-expectation', root: 'r', expectation: 'maybe' },
      { id: 'no-hits', root: 'r', expectation: 'must-hit' },
      { id: 'bad-ref', root: 'r', expectation: 'must-hit', hits: [{ ref: 'a.php', class: 'sqli' }] },
      { id: 'bad-reach', root: 'r', expectation: 'must-hit', hits: [{ ref: 'a.php:3', class: 'sqli', minReachability: 'root' }] },
      { id: 'bad-forbid', root: 'r', expectation: 'must-stay-clean', forbid: { confidence: 'certain' } },
      'not-an-object',
    ],
  });
  assert.equal(entries.length, 1, 'only the valid entry survives');
  assert.equal(entries[0].id, 'ok');
  assert.equal(errors.length, 7, 'every malformed entry named in errors[]');
  assert.ok(errors.every((e) => /plugins\[\d+\]/.test(e)), 'errors name the entry index');
  assert.deepEqual(validateManifest(null).errors, ['manifest is not a JSON object']);
  assert.deepEqual(validateManifest({}).errors, ['manifest.plugins is not an array']);
});

// --- recall math --------------------------------------------------------------------

test('recall math: exact ref+class at/above reachability is a hit; downgrade and miss fail loudly', () => {
  const hit = { ref: 'a.php:10', class: 'option-overwrite', minReachability: 'unauth' };
  assert.deepEqual(matchHit(hit, [cand({})]).found, true);
  assert.equal(matchHit(hit, [cand({})]).reachOk, true);

  const downgraded = matchHit(hit, [cand({ reachability: 'admin-gated' })]);
  assert.equal(downgraded.found, true, 'ref still found…');
  assert.equal(downgraded.reachOk, false, '…but below the expected reachability');

  const drifted = matchHit(hit, [cand({ ref: 'a.php:55' })]);
  assert.equal(drifted.found, false);
  assert.equal(drifted.nearMiss.ref, 'a.php:55', 'line drift recorded as near miss, not silence');

  assert.equal(matchHit(hit, [cand({ impactClass: 'sqli' })]).found, false, 'same line, wrong class ≠ hit');
  assert.equal(matchHit({ ...hit, minReachability: 'subscriber' }, [cand({ reachability: 'unauth' })]).reachOk, true, 'above expectation passes');

  const entry = { id: 'p', root: 'r', expectation: 'must-hit', hits: [hit, { ref: 'b.php:2', class: 'file-delete', minReachability: 'unauth' }] };
  const graded = gradeEntry(entry, report([cand({})]));
  assert.equal(graded.status, 'fail');
  assert.equal(graded.recall.expected, 2);
  assert.equal(graded.recall.found, 1);
  assert.deepEqual(graded.recall.missed, ['b.php:2'], 'the missed ref is NAMED');
  assert.ok(graded.failures.some((f) => /MISS: pinned ref b\.php:2/.test(f)), 'loud miss names the ref');
});

// --- precision math ------------------------------------------------------------------

test('precision math: forbid-band candidates violate; sub-band counted honestly, never hidden', () => {
  const entry = { id: 'clean', root: 'r', expectation: 'must-stay-clean', forbid: { ...DEFAULT_FORBID } };
  const pass = gradeEntry(entry, report([
    cand({ confidence: 'medium', sev: 'crit' }),           // unauth but medium confidence — below band
    cand({ reachability: 'subscriber' }),                  // high conf but not unauth
    cand({ sev: 'low', confidence: 'low', reachability: 'unknown', impactClass: 'sqli' }),
  ]));
  assert.equal(pass.status, 'pass');
  assert.equal(pass.precision.violations.length, 0);
  assert.deepEqual(pass.precision.unauthByConfidence, { high: 0, medium: 1, low: 0 }, 'sub-band unauth counted by confidence');
  assert.equal(pass.precision.bySeverity.crit, 2);
  assert.equal(pass.precision.bySeverity.low, 1);

  const fail = gradeEntry(entry, report([cand({})]));
  assert.equal(fail.status, 'fail');
  assert.equal(fail.precision.violations.length, 1);
  assert.ok(fail.failures.some((f) => /CONFIRMED-BAND HIT.*a\.php:10/.test(f)), 'violation names the ref');

  const custom = gradeEntry({ ...entry, forbid: { reachability: 'unauth', confidence: 'medium', severity: 'high' } }, report([cand({ confidence: 'medium', sev: 'crit' })]));
  assert.equal(custom.status, 'fail', 'a tightened forbid band catches medium confidence');
});

test('summarize: verdict FAIL on any fail/error, skips never fail; per-class + gap counts recorded', () => {
  const results = [
    { id: 'hit-ok', status: 'pass', expectation: 'must-hit', recall: { expected: 1, found: 1, missed: [] }, hits: [{ ref: 'a.php:1', class: 'option-overwrite', found: true, reachOk: true }], measured: { scannedFiles: 1, candidates: 1, gapsReported: 0, unresolvedCallbacks: 0 } },
    { id: 'gone', status: 'skip', expectation: 'must-hit', reason: 'corpus absent: /nope' },
    { id: 'clean-ok', status: 'pass', expectation: 'must-stay-clean', precision: { violations: [] }, measured: { scannedFiles: 5, candidates: 3, gapsReported: 2, unresolvedCallbacks: 7 } },
  ];
  const t = summarize(results);
  assert.equal(t.verdict, 'PASS');
  assert.deepEqual(t.recall, { expected: 1, found: 1, missed: 0, pct: 100 });
  assert.deepEqual(t.gaps['clean-ok'], { reported: 2, unresolvedCallbacks: 7 }, 'per-plugin gap counts ride the totals');
  assert.deepEqual(t.byClass['option-overwrite'], { expected: 1, found: 1, missed: [] });

  const bad = summarize([...results, { id: 'hit-miss', status: 'fail', expectation: 'must-hit', recall: { expected: 1, found: 0, missed: ['x.php:9'] }, hits: [{ ref: 'x.php:9', class: 'sqli', found: false, reachOk: false }], measured: { scannedFiles: 1, candidates: 0, gapsReported: 0, unresolvedCallbacks: 0 } }]);
  assert.equal(bad.verdict, 'FAIL');
  assert.equal(bad.recall.pct, 50);
  assert.deepEqual(bad.byClass['sqli'].missed, ['hit-miss:x.php:9'], 'per-class misses name plugin:ref');
});

// --- tool wrapper: skip semantics + loud miss + never-throw --------------------------

test('tool: corpus-absent entries SKIP with a named reason and never fail the bench', () => {
  const dir = tmp('skip');
  try {
    mkdirSync(dir, { recursive: true });
    const manifest = join(dir, 'm.json');
    writeFileSync(manifest, JSON.stringify({ plugins: [
      { id: 'ghost', root: join(dir, 'no-such-plugin'), expectation: 'must-hit', skipNote: 'cleaned .tmp', hits: [{ ref: 'a.php:1', class: 'sqli' }] },
    ] }));
    const r = goldenbench({ manifestPath: manifest });
    assert.equal(r.entries[0].status, 'skip');
    assert.match(r.entries[0].reason, /corpus absent:.*cleaned \.tmp/s, 'skip reason names the root and the note');
    assert.equal(r.verdict, 'PASS', 'a skip never fails the bench');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('tool: loud miss — a pinned ref the scanner no longer finds FAILs with the ref named', () => {
  const dir = tmp('miss');
  try {
    mkdirSync(dir, { recursive: true });
    const manifest = join(dir, 'm.json');
    writeFileSync(manifest, JSON.stringify({ plugins: [
      { id: 'fixture', root: 'test/fixtures/goldenbench/golden-sink', expectation: 'must-hit',
        hits: [{ ref: 'golden-sink.php:999', class: 'option-overwrite', minReachability: 'unauth' }] },
    ] }));
    const r = goldenbench({ manifestPath: manifest });
    assert.equal(r.verdict, 'FAIL');
    assert.equal(r.entries[0].status, 'fail');
    assert.deepEqual(r.entries[0].recall.missed, ['golden-sink.php:999']);
    assert.ok(r.entries[0].hits[0].nearMiss, 'real sink recorded as a near miss (line drift honesty)');
    assert.match(r.entries[0].failures[0], /MISS: pinned ref golden-sink\.php:999/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('tool: unreadable/invalid manifest lands in errors[], never throws', () => {
  const missing = goldenbench({ manifestPath: tmp('no-manifest') + '.json' });
  assert.equal(missing.verdict, 'FAIL');
  assert.ok(missing.errors.some((e) => /manifest unreadable/.test(e)));

  const dir = tmp('garbage');
  try {
    mkdirSync(dir, { recursive: true });
    const manifest = join(dir, 'm.json');
    writeFileSync(manifest, '{ not json');
    const r = goldenbench({ manifestPath: manifest });
    assert.equal(r.verdict, 'FAIL');
    assert.ok(r.errors.some((e) => /not valid JSON/.test(e)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('loadManifest: repo default manifest parses clean with zero errors', () => {
  const { entries, errors } = loadManifest(DEFAULT_MANIFEST);
  assert.deepEqual(errors, [], `default manifest must validate: ${errors.join('; ')}`);
  assert.ok(entries.length >= 5, 'fixture + madara + three negative goldens');
  assert.ok(entries.some((e) => e.id === 'golden-sink-fixture'), 'corpus-independent positive present');
});

// --- end-to-end over the live corpus (the bench against its own manifest) ------------

test('end-to-end: default manifest — fixture always hits; madara hits when the mirror is present; negatives stay below the CONFIRMED band', () => {
  const r = goldenbench();
  const byId = Object.fromEntries(r.entries.map((e) => [e.id, e]));

  const fx = byId['golden-sink-fixture'];
  assert.equal(fx.status, 'pass', `fixture entry must always pass; failures: ${(fx.failures || []).join('; ')}`);
  assert.equal(fx.recall.found, 1);

  const madara = byId['madara-core'];
  if (existsSync(MIRROR_ROOT)) {
    assert.equal(madara.status, 'pass', `madara pins must hold on this host; failures: ${(madara.failures || []).join('; ')}`);
    assert.equal(madara.recall.found, 3, 'all three madara sinks found');
    assert.ok(madara.measured.scannedFiles > 100, 'a vacuous pass proves nothing');
  } else {
    assert.equal(madara.status, 'skip', 'mirror absent → skip, never fail');
  }

  for (const id of ['angie-1.1.12', 'sg-ai-studio-1.2.9', 'rank-math-1.0.274.1']) {
    const e = byId[id];
    assert.ok(e.status === 'pass' || e.status === 'skip', `${id}: graded clean or honestly skipped (got ${e.status}: ${(e.failures || []).join('; ')})`);
  }
  assert.equal(r.verdict, 'PASS', `bench must pass over today\\'s corpus; errors: ${r.errors.join('; ')}`);
});
