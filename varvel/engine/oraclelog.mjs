// VARVEL — oraclelog: append-only persistence for the oracle family's verdicts and
// scores (the training-data flywheel's missing rung, 2026-08-25).
//
// Why it exists: tools/detoracle.mjs calibrate()/assess() and tools/shapegrade.mjs
// gradeLive() RETURN their verdicts — nothing ever wrote them down, so the detoracle's
// calibration history and every claimed-vs-measured shape grade evaporated with the
// process, and tools/tracetap.mjs's harvester reported both classes as permanent
// gaps[]. This module is the disk rung: one JSON object per line, APPEND-ONLY, never
// rewritten, never compacted (a training corpus is a ledger — edits would fabricate
// history).
//
// Stores (the bountyline/h1watch discipline: varvel/data/<tool>/, env-overridden at
// call time so tests isolate):
//   <root>/detoracle-verdicts.jsonl — { ts, tool:'detoracle', op:'assess'|'calibrate',
//     agentId, engagement, program, verdict:<the full calibrate()/assess() result —
//     channels + baselineTrusted + reasons ride inside it, untouched> }
//   <root>/shapegrade-scores.jsonl  — { ts, tool:'shapegrade', op:'gradeLive', agentId,
//     engagement, program, grade:<the full gradeLive() report — checks, divergent,
//     preFlight/flow scores, untouched> }
//
// REDACTION (the statestore doctrine, engine/statestore.mjs SECRET_FIELDS): any object
// KEY named secret|token|cookie (case-insensitive) with a string value lands as
// [REDACTED] — at ANY depth. Over-redaction is the safe direction for training data;
// tracetap re-redacts free text at harvest with its wider vocabulary. The verdicts this
// store carries are Defender-event counts and fingerprint comparisons — no secret
// material is expected here at all; the redactor is the belt for that suspenders.
//
// FAILURE DOCTRINE: a persistence failure NEVER breaks the tool run — recordX() returns
// { ok:false, error } and the caller surfaces it on the result object (honestly, named),
// never thrown, never silently dropped.

import { appendFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SECRET_FIELDS, REDACTED } from './statestore.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
// Persistence root: varvel/data/oracle (the settings.mjs/bountyline sibling discipline),
// evaluated at call time so tests isolate via VARVEL_ORACLE_DIR.
const ROOT = () => process.env.VARVEL_ORACLE_DIR || join(__dir, '..', 'data', 'oracle');

// The two stores, keyed by the vocabulary tracetap harvests.
export const ORACLE_STORES = {
  detoracle: { file: 'detoracle-verdicts.jsonl', source: 'detoracle-verdict', eventType: 'oracle-verdict' },
  shapegrade: { file: 'shapegrade-scores.jsonl', source: 'shapegrade-score', eventType: 'shape-grade' },
};
export const oracleStoreFile = (store) => join(ROOT(), (ORACLE_STORES[store] || {}).file || 'unknown.jsonl');

// Deep redactor: SECRET_FIELDS key names (case-insensitive) with string values become
// the REDACTED mark at any depth. Objects/arrays are copied, never mutated in place —
// the caller's in-memory verdict keeps its full fidelity for the console.
function redactSecrets(v) {
  if (Array.isArray(v)) return v.map(redactSecrets);
  if (v && typeof v === 'object') {
    const out = {};
    for (const [k, val] of Object.entries(v)) {
      if (SECRET_FIELDS.includes(String(k).toLowerCase()) && typeof val === 'string' && val) out[k] = REDACTED;
      else out[k] = redactSecrets(val);
    }
    return out;
  }
  return v;
}

function appendRecord(store, record) {
  try {
    const spec = ORACLE_STORES[store];
    if (!spec) return { ok: false, error: 'unknown oracle store: ' + String(store) };
    const file = oracleStoreFile(store);
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, JSON.stringify(record) + '\n');
    return { ok: true, file };
  } catch (e) {
    return { ok: false, error: 'oracle verdict persistence failed (the tool run is unaffected; the verdict was NOT persisted): ' + String((e && e.message) || e) };
  }
}

// Persist one detoracle verdict (an assess() or calibrate() result — op says which).
// The verdict object is stored WHOLE: calibration channels, baselineTrusted splits,
// reasons, evidence snippets — the harvester and the flywheel read the same record the
// operator saw. Context fields are the agent graded and (when known) the engagement /
// bounty program the grade belongs to.
export function recordDetoracleVerdict({ agentId, op = 'assess', engagement = null, program = null, verdict } = {}) {
  if (!agentId) return { ok: false, error: 'recordDetoracleVerdict needs agentId (the graded agent) — the verdict was NOT persisted' };
  if (!verdict || typeof verdict !== 'object') return { ok: false, error: 'recordDetoracleVerdict needs the verdict object — nothing persisted' };
  return appendRecord('detoracle', {
    ts: new Date().toISOString(),
    tool: 'detoracle',
    op: String(op),
    agentId: String(agentId),
    engagement: engagement || null,
    program: program || null,
    verdict: redactSecrets(verdict),
  });
}

// Persist one shapegrade score (a gradeLive() report). ok:false gradeLive results
// (channel dark, no such agent) are NOT scores — the caller persists ok:true reports
// only; this function records whatever it is handed and trusts that contract.
export function recordShapegradeScore({ agentId, engagement = null, program = null, grade } = {}) {
  if (!agentId) return { ok: false, error: 'recordShapegradeScore needs agentId (the graded agent) — the score was NOT persisted' };
  if (!grade || typeof grade !== 'object') return { ok: false, error: 'recordShapegradeScore needs the grade report object — nothing persisted' };
  return appendRecord('shapegrade', {
    ts: new Date().toISOString(),
    tool: 'shapegrade',
    op: 'gradeLive',
    agentId: String(agentId),
    engagement: engagement || null,
    program: program || null,
    grade: redactSecrets(grade),
  });
}

// Tolerant reader for the stores (tests + operators; tracetap keeps its own counting
// reader because it must count redactions per file). Malformed lines are SKIPPED and
// COUNTED, never fatal and never silently swallowed — the count says how many.
export function readOracleRecords(store) {
  const file = oracleStoreFile(store);
  let lines;
  try { lines = readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()); } catch { return { ok: false, file, records: [], malformed: 0, error: 'unreadable (no such store yet?)' }; }
  const records = [];
  let malformed = 0;
  for (const line of lines) {
    try { records.push(JSON.parse(line)); } catch { malformed += 1; }
  }
  return { ok: true, file, records, malformed };
}
