// VARVEL — tracetap: the fine-tune trace harvester (the Spark LoRA flywheel's intake).
// Exports fine-tune-ready JSONL from VARVEL's OWN records — one JSONL line per harvested
// unit:
//   { source, ts, kind, messages[], labels{ validated, stale, severity?, oracleScores? },
//     meta{ program?, campaignId? } }
// Units whose message structure is unrecoverable are exported as { kind:'event' } records
// — NEVER silently dropped, and never dressed up as conversations they were not.
//
// WHAT EXISTS (discovered 2026-08-24 — harvest what is real, name the rest in gaps[]):
//   * mission checkpoints  <dataDir>/*.mission.json  (engine/missions.mjs via
//     engine/kimi-runagent.mjs): full Anthropic-block conversations (text / tool_use /
//     tool_result) + a digest-led tool ledger — the GOLD SFT rows. -> kind 'mission'.
//   * statestore findings  <dataDir>/*.state.json    (engine/statestore.mjs): validation
//     is the STRING vocabulary (claimed|validated|refuted|untestable) — no validatedAt is
//     carried, so staleness is honestly UNKNOWN here (staleKnown:false).
//   * campaign surfaces    <dataDir>/*.surface.json  (engine/store.mjs saveSurface):
//     finding nodes carry the validator OBJECT { state, oracle, validatedAt } — the true
//     validator-gate readiness (validated && !stale via engine/validator.mjs isStale).
//   * failure ledgers      <dataDir>/*.failures.json (store.mjs): the approaches that did
//     NOT work — negative examples. They carry no engagement field (the store keys are
//     one-way hashes), so --campaign cannot match them; that is noted, not hidden.
//   * hash-chained audit   ../../poc/enforcement-seam/audit-ledger.jsonl (the Enclave
//     seam's appendAudit: prev_hash/entry_hash per line) + varvel/data/*.jsonl tool logs
//     (wafbypass-audit, mcp-audit) — event streams -> kind 'event'.
//   * oracle verdict stores varvel/data/oracle/*.jsonl (engine/oraclelog.mjs, persisted
//     since 2026-08-25): every detoracle calibration/assessment verdict (channels +
//     baselineTrusted inside) and every shapegrade gradeLive score -> kind 'event' with
//     labels.oracleScores. Absent stores are named in gaps[], never fabricated around.
//
// REDACTION (absolute): the statestore SECRET_FIELDS doctrine (secret|token|cookie field
// names -> [REDACTED]) + the bountyreport free-text patterns (cookies, authorization,
// bearer, JWT, key=value secrets). Redactions are COUNTED per file and the counts are
// printed — the VALUES never are.
//
// Direct-run: node tools/tracetap.mjs [--since <iso>] [--campaign <id>] [--validated-only] [--out <file.jsonl>] [--seam-ledger <file.jsonl>] [--tools <dir>]
//   --out writes the JSONL and prints the summary JSON to stdout; without --out the JSONL
//   goes to stdout and the summary to stderr (stdout stays valid JSONL either way).
//   --seam-ledger / --tools point the harvest at non-default stores (exports of other
//   installs, tests); the oracle stores ride UNDER --tools (data/oracle convention).

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync, realpathSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dataDir } from '../engine/store.mjs';
import { isStale } from '../engine/validator.mjs';
import { redactEvidence } from '../tools/bountyreport.mjs';
import { REDACTED } from '../engine/statestore.mjs';
import { ORACLE_STORES } from '../engine/oraclelog.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
// The Enclave seam's hash-chained audit ledger (same SEAM location tools/program.mjs uses).
const DEFAULT_SEAM_LEDGER = join(__dir, '..', '..', 'poc', 'enforcement-seam', 'audit-ledger.jsonl');
const DEFAULT_TOOL_DATA = join(__dir, '..', 'data');

// --- redaction ------------------------------------------------------------------------------
// Field-name doctrine: engine/statestore.mjs SECRET_FIELDS (secret|token|cookie) UNION the
// bountyreport secret vocabulary (password|session|jwt|api-key|authorization|cf_clearance|
// sid) applied to structured KEYS — over-redaction is the safe direction for training
// data; free text goes through bountyreport's REDACTION_RULES. The counts are the receipt.
const SECRET_KEY_RE = /\b(?:secret|token|cookie|password|passwd|session|jwt|api[-_]?key|auth(?:orization)?|cf[-_]?clearance|sid)\b/i;

function makeRedactor(counts, file) {
  const bump = (n = 1) => { counts.perFile[file] = (counts.perFile[file] || 0) + n; counts.total += n; };
  const walk = (v) => {
    if (typeof v === 'string') { const r = redactEvidence(v); if (r.redactions) bump(r.redactions); return r.text; }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        if (SECRET_KEY_RE.test(k) && typeof val === 'string' && val) { bump(); out[k] = REDACTED; }
        else out[k] = walk(val);
      }
      return out;
    }
    return v;
  };
  return walk;
}

// --- small helpers ----------------------------------------------------------------------------
const readJson = (p) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return undefined; } };
const listDir = (d) => { try { return readdirSync(d); } catch { return null; } };
const tsOf = (...cands) => { for (const c of cands) { const t = Date.parse(c || ''); if (Number.isFinite(t)) return new Date(t).toISOString(); } return null; };

// The validator gate as labels, for the two record vocabularies that exist:
//   surface finding  — validation is an OBJECT { state, validatedAt } -> true staleness.
//   statestore finding — validation is a STRING -> staleness honestly unknown.
function findingLabels(f, { now, staleDays }) {
  const val = f && f.validation;
  if (val && typeof val === 'object') {
    const state = String(val.state || 'claimed');
    const stale = state === 'validated' ? isStale(val, { now, staleDays }) : false;
    return { validated: state === 'validated' && !stale, stale, severity: f.sev || null, validationState: state };
  }
  const state = typeof val === 'string' ? val : 'claimed';
  return { validated: state === 'validated', stale: false, staleKnown: false, severity: f.sev || null, validationState: state };
}

// --- the harvest --------------------------------------------------------------------------------
export function harvest({ dataDir: dataDirOpt, seamLedger, toolDataDir, oracleDir, since, campaign, validatedOnly = false, now, staleDays = 30 } = {}) {
  const nowMs = now === undefined ? Date.now() : (typeof now === 'number' ? now : Date.parse(now));
  const DIR = dataDirOpt || dataDir();
  const SEAM = seamLedger === undefined ? DEFAULT_SEAM_LEDGER : seamLedger;
  const TOOLDATA = toolDataDir === undefined ? DEFAULT_TOOL_DATA : toolDataDir;
  // The oracle stores live UNDER the tool data dir (data/oracle) — an explicit
  // toolDataDir (tests, exports of other installs) carries its own oracle subdir.
  const ORACLE = oracleDir === undefined ? join(TOOLDATA, 'oracle') : oracleDir;
  const units = [];
  const counts = { total: 0, perFile: {} };
  const gaps = [];
  const notes = [
    'surface findings and statestore findings can BOTH describe one finding (different vocabularies) — they are harvested as separate records, never merged (merging would fabricate a preference)',
    'failure-ledger records carry no engagement field (store keys are one-way hashes) — --campaign cannot match them',
  ];
  const sources = { missions: 0, surfaceFindings: 0, stateFindings: 0, failures: 0, auditEvents: 0, oracleVerdicts: 0, shapeScores: 0 };

  // -- pass 1: state files + surfaces (also builds the engagement -> gate index for mission labels)
  const engagementGate = new Map(); // engagement -> { validatedFindings }
  const bumpGate = (eng, labels) => {
    if (!eng) return;
    const g = engagementGate.get(eng) || { validatedFindings: 0 };
    if (labels.validated) g.validatedFindings += 1;
    engagementGate.set(eng, g);
  };

  const files = listDir(DIR);
  if (!files) {
    gaps.push(`no VARVEL data dir at ${DIR} — no mission checkpoints, state stores, surfaces, or failure ledgers to harvest`);
  }
  for (const f of files || []) {
    const p = join(DIR, f);
    if (f.endsWith('.state.json')) {
      const st = readJson(p);
      if (!st || typeof st !== 'object') { gaps.push(`state file ${f} is unparseable — skipped, not dropped silently`); continue; }
      const redact = makeRedactor(counts, p);
      for (const finding of Array.isArray(st.findings) ? st.findings : []) {
        const labels = findingLabels(finding, { now: nowMs, staleDays });
        const eng = finding && finding.provenance && finding.provenance.engagement;
        bumpGate(eng, labels);
        units.push({ source: 'statestore-finding', ts: tsOf(finding.lastSeen, finding.firstSeen), kind: 'event', eventType: 'finding', event: redact(finding), labels, meta: { campaignId: eng || null, ref: finding.ref || null } });
        sources.stateFindings += 1;
      }
    } else if (f.endsWith('.surface.json')) {
      const sf = readJson(p);
      if (!sf || typeof sf !== 'object') { gaps.push(`surface file ${f} is unparseable — skipped, not dropped silently`); continue; }
      const eng = sf.scope && sf.scope.engagement;
      const redact = makeRedactor(counts, p);
      for (const n of Array.isArray(sf.nodes) ? sf.nodes : []) {
        if (!n || n.type !== 'finding') continue;
        const labels = findingLabels(n, { now: nowMs, staleDays });
        bumpGate(eng, labels);
        units.push({ source: 'surface-finding', ts: tsOf(n.validation && (n.validation.validatedAt || n.validation.at)), kind: 'event', eventType: 'finding', event: redact({ label: n.label, sev: n.sev, ref: n.ref, confidence: n.confidence, evidence: n.evidence, validation: n.validation }), labels, meta: { campaignId: eng || null, ref: n.ref || null } });
        sources.surfaceFindings += 1;
      }
    } else if (f.endsWith('.failures.json')) {
      const fl = readJson(p);
      if (!Array.isArray(fl)) { gaps.push(`failure ledger ${f} is unparseable — skipped, not dropped silently`); continue; }
      const redact = makeRedactor(counts, p);
      for (const failure of fl) {
        units.push({ source: 'failure-ledger', ts: tsOf(failure && failure.at), kind: 'event', eventType: 'failure', event: redact(failure), labels: {}, meta: {} });
        sources.failures += 1;
      }
    }
  }

  // -- pass 2: mission checkpoints (the conversations) — labels ride the engagement gate index
  for (const f of files || []) {
    if (!f.endsWith('.mission.json')) continue;
    const p = join(DIR, f);
    const cp = readJson(p);
    if (!cp || typeof cp !== 'object' || !cp.missionId) { gaps.push(`mission checkpoint ${f} is unparseable — skipped, not dropped silently`); continue; }
    const redact = makeRedactor(counts, p);
    const eng = cp.engagement || null;
    const gate = (eng && engagementGate.get(eng)) || { validatedFindings: 0 };
    const labels = { validated: gate.validatedFindings > 0, validatedFindings: gate.validatedFindings };
    const meta = { missionId: cp.missionId, campaignId: eng };
    const ts = tsOf(cp.updated, cp.created);
    if (Array.isArray(cp.msgs) && cp.msgs.length && cp.msgs.every((m) => m && (m.role === 'user' || m.role === 'assistant'))) {
      units.push({ source: 'mission', ts, kind: 'mission', messages: redact(cp.msgs), labels, meta });
    } else {
      // Unrecoverable message structure -> an event record, NEVER silently dropped.
      units.push({ source: 'mission', ts, kind: 'event', eventType: 'mission-checkpoint', event: redact({ missionId: cp.missionId, engagement: eng, status: cp.status || null, objective: cp.objective || null, turnsTotal: cp.turnsTotal || 0, note: 'message structure unrecoverable — the checkpoint survived as an event record' }), labels, meta });
    }
    sources.missions += 1;
  }

  // -- pass 3: audit logs (the hash-chained seam ledger + tool JSONL logs) -> event units
  const ledgers = [];
  if (SEAM && existsSync(SEAM)) ledgers.push({ path: SEAM, hashChained: true });
  else if (SEAM) gaps.push(`no hash-chained audit ledger at ${SEAM} — the Enclave seam writes it during governed runs`);
  const toolFiles = TOOLDATA && existsSync(TOOLDATA) ? (listDir(TOOLDATA) || []).filter((x) => x.endsWith('.jsonl')) : null;
  if (!toolFiles) gaps.push(`no tool data dir at ${TOOLDATA} — no tool audit JSONL (wafbypass-audit / mcp-audit) to harvest`);
  else if (!toolFiles.length) gaps.push(`no tool audit JSONL logs under ${TOOLDATA} (wafbypass-audit.jsonl / mcp-audit.jsonl are written on tool use)`);
  for (const x of toolFiles || []) ledgers.push({ path: join(TOOLDATA, x), hashChained: false });
  for (const { path: lp, hashChained } of ledgers) {
    let lines;
    try { lines = readFileSync(lp, 'utf8').split('\n').filter((l) => l.trim()); } catch { lines = null; }
    if (!lines) { gaps.push(`audit ledger ${lp} is unreadable — skipped, not dropped silently`); continue; }
    const redact = makeRedactor(counts, lp);
    lines.forEach((line, i) => {
      let ev;
      try { ev = JSON.parse(line); } catch { ev = { raw: line.slice(0, 500), parseGap: true }; }
      units.push({ source: 'audit:' + basename(lp), ts: tsOf(ev && ev.ts), kind: 'event', eventType: 'audit', event: redact(ev), labels: {}, meta: { hashChained, line: i + 1 } });
      sources.auditEvents += 1;
    });
  }

  // -- pass 4: oracle verdict stores (engine/oraclelog.mjs; persisted since 2026-08-25) ----
  // detoracle-verdicts.jsonl (calibrations + assessments, channels inside) and
  // shapegrade-scores.jsonl (gradeLive reports). Each line -> an event unit whose labels
  // carry oracleScores (the flywheel's label slot, per the header contract). An ABSENT
  // store is a named gap — the honest 'nothing graded yet' state — never fabricated rows.
  if (ORACLE && !existsSync(ORACLE)) {
    gaps.push(`no oracle verdict store at ${ORACLE} — detoracle/shapegrade verdicts persist there (engine/oraclelog.mjs) the first time a grade runs via tools/cli.mjs`);
  } else if (ORACLE) {
    for (const [storeKey, spec] of Object.entries(ORACLE_STORES)) {
      const p = join(ORACLE, spec.file);
      if (!existsSync(p)) { gaps.push(`no ${spec.file} under ${ORACLE} — no ${storeKey} ${storeKey === 'detoracle' ? 'verdicts' : 'scores'} persisted yet (the store appears on the first grade)`); continue; }
      let lines;
      try { lines = readFileSync(p, 'utf8').split('\n').filter((l) => l.trim()); } catch { lines = null; }
      if (!lines) { gaps.push(`oracle store ${p} is unreadable — skipped, not dropped silently`); continue; }
      const redact = makeRedactor(counts, p);
      lines.forEach((line, i) => {
        let rec;
        try { rec = JSON.parse(line); } catch { rec = null; }
        if (!rec || typeof rec !== 'object') { gaps.push(`oracle store ${spec.file} line ${i + 1} is unparseable — skipped, not dropped silently`); return; }
        const v = rec.verdict && typeof rec.verdict === 'object' ? rec.verdict : null;
        const g = rec.grade && typeof rec.grade === 'object' ? rec.grade : null;
        const oracleScores = storeKey === 'detoracle'
          ? { op: rec.op || null, verdict: v ? (v.verdict ?? null) : null, calibrated: v && v.calibrated !== undefined ? v.calibrated : null, baselineTrusted: v && v.baselineTrusted !== undefined ? v.baselineTrusted : null, channels: v && v.channels ? v.channels : null }
          : { profile: g ? (g.profile ?? null) : null, verdict: g ? (g.verdict ?? null) : null, divergent: g && Array.isArray(g.divergent) ? g.divergent.length : null, flowBand: g && g.flow ? g.flow.band ?? null : null, preFlight: g && g.preFlight ? g.preFlight : null };
        units.push({
          source: spec.source,
          ts: tsOf(rec.ts),
          kind: 'event',
          eventType: spec.eventType,
          event: redact(rec),
          labels: { oracleScores },
          meta: { agentId: rec.agentId || null, campaignId: rec.engagement || rec.program || null, program: rec.program || null, line: i + 1 },
        });
        if (storeKey === 'detoracle') sources.oracleVerdicts += 1; else sources.shapeScores += 1;
      });
    }
  }

  // -- filters (per unit, after harvest) ----------------------------------------------------------
  const sinceMs = since !== undefined ? Date.parse(since) : undefined;
  if (since !== undefined && !Number.isFinite(sinceMs)) gaps.push(`--since '${since}' is not a parseable timestamp — the filter was IGNORED (a bad date must not silently filter everything)`);
  const dropped = { since: 0, campaign: 0, validatedOnly: 0 };
  const kept = units.filter((u) => {
    if (since !== undefined && Number.isFinite(sinceMs)) {
      const t = Date.parse(u.ts || '');
      if (!Number.isFinite(t) || t < sinceMs) { dropped.since += 1; return false; }
    }
    if (campaign !== undefined) {
      const c = String(campaign);
      if (String((u.meta && u.meta.campaignId) || '') !== c && String((u.meta && u.meta.missionId) || '') !== c) { dropped.campaign += 1; return false; }
    }
    if (validatedOnly && !(u.labels && u.labels.validated === true)) { dropped.validatedOnly += 1; return false; }
    return true;
  });

  const byKind = {};
  let validated = 0;
  for (const u of kept) { byKind[u.kind] = (byKind[u.kind] || 0) + 1; if (u.labels && u.labels.validated === true) validated += 1; }
  const summary = {
    ok: true,
    units: kept.length,
    byKind,
    validated,
    notValidated: kept.length - validated,
    redactions: { total: counts.total, perFile: counts.perFile },
    filters: { since: since || null, campaign: campaign || null, validatedOnly },
    dropped,
    sources,
    notes,
    gaps,
  };
  return { units: kept, summary };
}

// --- direct-run CLI -------------------------------------------------------------------------------
const isMain = (() => { try { return process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();

if (isMain) {
  const a = process.argv.slice(2);
  const opt = (flag) => { const i = a.indexOf(flag); return i !== -1 && a[i + 1] && !a[i + 1].startsWith('--') ? a[i + 1] : undefined; };
  const { units, summary } = harvest({
    since: opt('--since'),
    campaign: opt('--campaign'),
    seamLedger: opt('--seam-ledger'),
    toolDataDir: opt('--tools'),
    validatedOnly: a.includes('--validated-only'),
  });
  const jsonl = units.map((u) => JSON.stringify(u)).join('\n') + (units.length ? '\n' : '');
  const out = opt('--out');
  if (out) {
    try { mkdirSync(dirname(out), { recursive: true }); } catch {}
    writeFileSync(out, jsonl);
    summary.out = out;
    console.log(JSON.stringify(summary, null, 1));
  } else {
    process.stdout.write(jsonl);
    process.stderr.write(JSON.stringify(summary, null, 1) + '\n');
  }
}
