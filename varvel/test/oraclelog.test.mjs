// VARVEL oraclelog tests — append-only persistence for the oracle family
// (engine/oraclelog.mjs). Hermetic: every write lands in a tmp VARVEL_ORACLE_DIR.
// The doctrines under test: every verdict/score lands on disk with a timestamp and its
// agent/program context; the store is APPEND-ONLY (a second write never disturbs the
// first); the statestore SECRET_FIELDS redaction applies at any depth; a persistence
// failure returns { ok:false } and NEVER throws (the tool run is unaffected).
//   node --test test/oraclelog.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { recordDetoracleVerdict, recordShapegradeScore, readOracleRecords, oracleStoreFile, ORACLE_STORES } from '../engine/oraclelog.mjs';

const freshDir = () => mkdtempSync(join(tmpdir(), 'varvel-oraclelog-'));

test('detoracle verdicts persist: one JSONL line per verdict, append-only, with context', () => {
  process.env.VARVEL_ORACLE_DIR = freshDir();
  const cal = { calibrated: false, baselineTrusted: false, channels: { onDemandConviction: true, onAccessWrite: 'silent' }, reasons: ['EICAR write silent'], offline: true, at: '2026-08-25T12:18:10.087Z' };
  const r1 = recordDetoracleVerdict({ agentId: 'agent-1', op: 'calibrate', engagement: 'range-eng', verdict: cal });
  assert.equal(r1.ok, true);
  const r2 = recordDetoracleVerdict({ agentId: 'agent-1', op: 'assess', verdict: { verdict: 'clean', newDetections: 0 } });
  assert.equal(r2.ok, true);
  assert.equal(r1.file, r2.file, 'one store per tool, appended');

  const lines = readFileSync(r1.file, 'utf8').trim().split('\n');
  assert.equal(lines.length, 2, 'append-only: both verdicts survived');
  const rec1 = JSON.parse(lines[0]);
  const rec2 = JSON.parse(lines[1]);
  assert.equal(rec1.tool, 'detoracle');
  assert.equal(rec1.op, 'calibrate');
  assert.equal(rec1.agentId, 'agent-1');
  assert.equal(rec1.engagement, 'range-eng');
  assert.ok(Number.isFinite(Date.parse(rec1.ts)), 'a timestamp rides every record');
  assert.deepEqual(rec1.verdict.channels, { onDemandConviction: true, onAccessWrite: 'silent' }, 'calibration channels persist with the verdict');
  assert.equal(rec2.op, 'assess');
  assert.equal(rec2.verdict.verdict, 'clean');
});

test('shapegrade scores persist with the full report; readOracleRecords reads them back', () => {
  process.env.VARVEL_ORACLE_DIR = freshDir();
  const grade = { ok: true, profile: 'cdn-asset', verdict: 'measures-as-claimed', divergent: [], preFlight: { band: 'web-browse', score: 81 }, flow: { band: 'web-browse', score: 79 } };
  const r = recordShapegradeScore({ agentId: 'agent-9', program: 'acme-bbp', grade });
  assert.equal(r.ok, true);
  const back = readOracleRecords('shapegrade');
  assert.equal(back.ok, true);
  assert.equal(back.records.length, 1);
  assert.equal(back.records[0].tool, 'shapegrade');
  assert.equal(back.records[0].agentId, 'agent-9');
  assert.equal(back.records[0].program, 'acme-bbp');
  assert.equal(back.records[0].grade.preFlight.score, 81, 'the score rides the record');
  assert.ok(back.file.endsWith(ORACLE_STORES.shapegrade.file));
  assert.equal(oracleStoreFile('shapegrade'), back.file);
});

test('redaction: SECRET_FIELDS keys are blanked at ANY depth; the caller object is untouched', () => {
  process.env.VARVEL_ORACLE_DIR = freshDir();
  const verdict = { verdict: 'detected', evidence: { probeResult: 'ok', cookie: 'live-cookie-value', nested: { token: 'tok-value', note: 'fine' } }, note: 'plain text stays' };
  const r = recordDetoracleVerdict({ agentId: 'a', op: 'assess', verdict });
  assert.equal(r.ok, true);
  const line = readFileSync(r.file, 'utf8').trim();
  assert.ok(!line.includes('live-cookie-value') && !line.includes('tok-value'), 'secret values never reach disk');
  const rec = JSON.parse(line);
  assert.equal(rec.verdict.evidence.cookie, '[REDACTED]');
  assert.equal(rec.verdict.evidence.nested.token, '[REDACTED]');
  assert.equal(rec.verdict.evidence.probeResult, 'ok', 'non-secret fields pass through');
  assert.equal(verdict.evidence.cookie, 'live-cookie-value', 'the in-memory verdict keeps full fidelity (redaction copies)');
});

test('failure doctrine: an unwritable store returns { ok:false } and NEVER throws', () => {
  const blocker = join(mkdtempSync(join(tmpdir(), 'varvel-oraclelog-block-')), 'a-file');
  writeFileSync(blocker, 'x');
  process.env.VARVEL_ORACLE_DIR = join(blocker, 'inside-a-file'); // mkdir must fail
  let r;
  assert.doesNotThrow(() => { r = recordDetoracleVerdict({ agentId: 'a', op: 'assess', verdict: { verdict: 'clean' } }); });
  assert.equal(r.ok, false);
  assert.match(r.error, /NOT persisted/);
});

test('input doctrine: no agentId or no verdict object is a loud refusal, not an empty row', () => {
  process.env.VARVEL_ORACLE_DIR = freshDir();
  assert.equal(recordDetoracleVerdict({ op: 'assess', verdict: { verdict: 'clean' } }).ok, false);
  assert.equal(recordDetoracleVerdict({ agentId: 'a', op: 'assess' }).ok, false);
  assert.equal(recordShapegradeScore({ agentId: 'a' }).ok, false);
  const back = readOracleRecords('detoracle');
  assert.equal(back.records.length, 0, 'refusals write nothing');
});

test('readOracleRecords: missing store is honest-unreadable; malformed lines are counted, never fatal', () => {
  process.env.VARVEL_ORACLE_DIR = freshDir();
  const missing = readOracleRecords('detoracle');
  assert.equal(missing.ok, false);
  const file = oracleStoreFile('detoracle');
  writeFileSync(file, '{"ts":"2026-08-25T00:00:00.000Z","tool":"detoracle"}\n{ not json\n');
  const back = readOracleRecords('detoracle');
  assert.equal(back.ok, true);
  assert.equal(back.records.length, 1);
  assert.equal(back.malformed, 1, 'the malformed line is counted, not silently swallowed');
});
