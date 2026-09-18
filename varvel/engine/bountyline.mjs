// VARVEL — bountyline: the autonomous bounty pipeline (bounty revenue up to the send click).
// One state machine per program, persisted under varvel/data/bountyline/ (roster.json +
// programs/<id>.json + ledger.json), glued from the two rungs that already exist:
// tools/program.mjs (scope intake -> signed scope) and tools/bountyreport.mjs (findings ->
// submission-ready markdown). This module is the PIPELINE, not a submitter:
//
//   imported -> scoped -> hunted -> triaged -> reported -> QUEUED-FOR-SEND -> operator marks outcome
//
// HARD RULES (the revenue-safe doctrine):
//   1. THE PIPELINE NEVER SUBMITS. There is no network code path in this module — no fetch,
//      no http, no submission API, not behind a flag, not anywhere. 'queued' is the end of
//      the line: a report file + a submission checklist for the operator's send click.
//      test/bountyline.test.mjs pins this with a static scan of this file.
//   2. AUTOMATION GATE AS CODE: a program's automation policy (full|human-cadence|
//      prohibited) is derived from the program's OWN policy text at intake and defaults to
//      PROHIBITED when the text is silent (the safe direction — same doctrine as
//      tools/program.mjs's ambiguous-group rule). run REFUSES prohibited programs and names
//      the policy; human-cadence forces the conservative campaign mapping (CADENCE_MAP
//      below); full runs on the engagement's own settings floor.
//   3. SCOPE GUARD: run refuses when no signed scope is on record ('no-signed-scope') — a
//      hunt without a signed engagement scope is unscoped testing, and unscoped testing is
//      never automated.
//   4. TRANSITIONS ARE LEGAL OR LOUD: every state move goes through TRANSITIONS; anything
//      else refuses 'illegal-transition' naming from -> to and the allowed set.
//   5. THE LEDGER NEVER CONVERTS: payout totals are per-currency; goal progress (£3332.50)
//      counts GBP only. No invented exchange rates, ever.
//   6. Reports on disk obey the cookie-never-reaches-report doctrine — drafting reuses
//      tools/bountyreport.mjs's redactor, so persisted markdown carries [REDACTED], never
//      the secret.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname, basename, extname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isStale } from './validator.mjs';
import { Settings } from './settings.mjs';
import { normalizeFindings, bountyReport } from '../tools/bountyreport.mjs';
// The NOVELTY GATE (novelcore: PURE — no network, no I/O; the network half is
// tools/novelgate.mjs). Born from semrush #2666357 (DUPLICATE, 2026-08-31): edge-gate
// behavior filed as an application bug. draftReports runs the offline gate per finding
// and REFUSES blocked drafts; queueProgram refuses reports that never passed through it.
import { classifyWeakness, parseHttpEvidence, assess, renderNoveltySection, parseNoveltySection } from './novelcore.mjs';
// REPLAYABLE-EVIDENCE BINDING (winner-copyables build, Tool 2): a drafted finding whose
// campaign evidence carries captured request/response pairs (the authzsweep bundle shape)
// gets a self-contained replay bundle emitted NEXT to the report — replay.json + a
// one-command replay.sh through the ghost chain. EMIT ONLY: no network here (the
// pipeline-never-submits pin stands); the runner is the operator's command.
import { planFromPairs, emitBundle } from '../tools/replaybind.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
// The Enclave enforcement seam — SAME location tools/program.mjs signs from. Scope
// fixtures are VERIFIED with the seam's own verifySession when it is importable; a seam
// that is absent degrades the recording to 'shape-only' with the gap named, never silent.
const SEAM = join(__dir, '..', '..', 'poc', 'enforcement-seam');

// Persistence root: varvel/data/bountyline (the settings.mjs sibling discipline), evaluated
// at call time so tests isolate via VARVEL_BOUNTYLINE_DIR.
const ROOT = () => process.env.VARVEL_BOUNTYLINE_DIR || join(__dir, '..', 'data', 'bountyline');
const ROSTER_FILE = () => join(ROOT(), 'roster.json');
const LEDGER_FILE = () => join(ROOT(), 'ledger.json');
const programFile = (id) => join(ROOT(), 'programs', id + '.json');

export const STATES = ['imported', 'scoped', 'hunted', 'triaged', 'reported', 'queued'];
// The legal moves. queued -> scoped is the NEXT ROUND: a fresh signed scope (operator act)
// archives the finished round and reopens hunting. Everything else is a refusal.
export const TRANSITIONS = {
  imported: ['scoped', 'reported'], // 'reported' = the manual source-review lane (recordManualReport — evidence-on-disk gated)
  scoped: ['scoped', 'hunted'], // re-recording the scope pre-hunt is a same-state update
  hunted: ['triaged'],
  triaged: ['reported'],
  reported: ['queued'],
  queued: ['scoped'],
};
export const OUTCOMES = ['submitted', 'duplicate', 'informative', 'resolved', 'paid'];
export const AUTOMATION_POLICIES = ['full', 'human-cadence', 'prohibited'];
export const GOAL_GBP = 3332.5;

// THE CADENCE MAP — automation gate -> campaign knobs, as code (Campaign constructor
// shapes: engine/campaign.mjs { stealth, budget:{ maxSteps }, reconOpts:{ crawl, vuln } }):
//   full           -> {} : the engagement's own settings floor governs (no ceiling added).
//   human-cadence  -> the conservative ceiling: stealth 'paranoid' (the slowest enforced
//                     pacing profile), the step budget quartered (200 -> 50), crawl pages
//                     25 -> 5, vuln probes 20 -> 3 (the settings-schema floor). A
//                     human-paced program never gets louder than a careful operator.
//   prohibited     -> no mapping exists: run refuses before settings are ever built.
export const CADENCE_MAP = {
  full: {},
  'human-cadence': { stealth: 'paranoid', budget: { maxSteps: 50 }, reconOpts: { crawl: { maxPages: 5 }, vuln: { maxProbes: 3 } } },
};

// --- small persisted-store helpers (the store.mjs discipline: readJson fallback, write-through) ---
const readJson = (p, fb) => { try { return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fb; } catch { return fb; } };
const writeJson = (p, obj) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n'); };
const iso = (now) => (now === undefined ? new Date().toISOString() : (typeof now === 'number' ? new Date(now).toISOString() : String(now)));
const ms = (now) => (now === undefined ? Date.now() : (typeof now === 'number' ? now : Date.parse(now)));
const round2 = (n) => Math.round(n * 100) / 100;
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

// --- automation policy derivation ------------------------------------------------------
// The intake carries the program's policy/safe-harbor text; the policy speaks or it
// doesn't. Order matters: prohibited first (the safe direction wins ties), then
// human-cadence (a rate-limited 'allowed' is human-cadence, not full), then full, then
// the DEFAULT — human-cadence with basis 'default-silent' (operator rule 2026-08-29:
// silence never excludes; the conservative ceiling is the honest floor).
const AUTOMATION_RES = [
  { policy: 'prohibited', re: /\b(?:automated|automatic)\s+(?:scanning|scans?|tools?|testing)\s+(?:are\s+|is\s+)?(?:prohibited|forbidden|not\s+(?:allowed|permitted)|banned)\b/i },
  { policy: 'prohibited', re: /\b(?:prohibited?|forbidden|banned|do\s+not\s+(?:use|run)|don't\s+(?:use|run))\b[^.\n]{0,60}\b(?:automated|automatic|scanners?)\b/i },
  { policy: 'prohibited', re: /\bno\s+(?:automated\s+)?(?:scanning|scanners)\b/i },
  { policy: 'human-cadence', re: /\brate[- ]?limits?\b|\b\d+\s*(?:rps|requests?\s+per\s+(?:second|minute))\b|\bno\s+more\s+than\s+\d+\b[^.\n]{0,40}\brequests?\b|\bhuman[- ]?paced\b|\blow[- ]?and[- ]?slow\b|\bthrottl/i },
  { policy: 'full', re: /\bautomated\s+(?:scanning|scans?|tools?|testing)\s+(?:are\s+|is\s+)?(?:allowed|permitted|encouraged|welcome)\b/i },
  { policy: 'full', re: /\b(?:we\s+)?(?:allow|permit|encourage|welcome)s?\s+automated\b/i },
];

// deriveAutomation(intake) -> { policy, basis, evidence } — basis is 'policy-text' when the
// program's own words decided (evidence quotes the deciding phrase), 'default-silent' when
// they did not (silence maps to the conservative human-cadence ceiling, honestly named).
export function deriveAutomation(intake) {
  const text = [intake && intake.policy, intake && intake.safeHarbor].filter(Boolean).join('\n');
  if (text.trim()) {
    for (const r of AUTOMATION_RES) {
      const m = text.match(r.re);
      if (m) return { policy: r.policy, basis: 'policy-text', evidence: m[0].replace(/\s+/g, ' ').slice(0, 160) };
    }
  }
  // OPERATOR RULE (Jack, 2026-08-29): a SILENT policy no longer excludes the program.
  // What VARVEL runs is not a dumb scanner — it is gated, signed-scope, human-paced AI
  // (one request in flight, ~1 req/1.3s, HITL-gated) — wire-indistinguishable from the
  // careful human researcher every program already allows. Silence = human-cadence.
  return { policy: 'human-cadence', basis: 'default-silent', evidence: 'the policy text never speaks on automation — operator rule 2026-08-29: gated, scoped, human-paced AI is human-equivalent, so silence maps to the conservative human-cadence ceilings (never exclusion)' };
}

// --- roster / per-program state ---------------------------------------------------------
export function loadRoster() {
  const r = readJson(ROSTER_FILE(), null);
  return r && Array.isArray(r.programs) ? r : { programs: [] };
}

export function loadProgram(id) {
  if (!ID_RE.test(String(id || ''))) return null;
  const rec = readJson(programFile(id), null);
  return rec && rec.id === id ? rec : null;
}

function saveProgram(rec) {
  writeJson(programFile(rec.id), rec);
  const roster = loadRoster();
  const ix = roster.programs.findIndex((p) => p.id === rec.id);
  const entry = { id: rec.id, handle: rec.handle, platform: rec.platform, state: rec.state, automation: rec.automation.policy, reports: (rec.reports || []).length, updatedAt: rec.updatedAt };
  if (ix === -1) roster.programs.push(entry); else roster.programs[ix] = entry;
  writeJson(ROSTER_FILE(), roster);
}

// THE one legal-move check. Every transition in the pipeline goes through here; the
// refusal names from -> to and the allowed set, loudly.
function transition(rec, to, { now, note } = {}) {
  const allowed = TRANSITIONS[rec.state] || [];
  if (!allowed.includes(to)) {
    return { ok: false, error: 'illegal-transition', reason: `${rec.id} is '${rec.state}' — cannot move to '${to}' (allowed from '${rec.state}': ${allowed.length ? allowed.join(', ') : 'none'})`, state: rec.state, allowed };
  }
  const from = rec.state;
  if (from === 'queued' && to === 'scoped') {
    // A fresh round: archive the finished one (reports on disk are never deleted — the
    // archive keeps their paths honest) and reset the downstream pipeline.
    rec.rounds = [...(rec.rounds || []), { closedAt: iso(now), hunt: rec.hunt || null, triage: rec.triage || null, reports: rec.reports || [], queue: rec.queue || null }];
    rec.hunt = null; rec.triage = null; rec.reports = []; rec.queue = null;
  }
  rec.state = to;
  rec.updatedAt = iso(now);
  rec.history = [...(rec.history || []), { at: iso(now), from, to, note: note || null }];
  return { ok: true, from, to };
}

// --- signed-scope verification -----------------------------------------------------------
// Shape first (the session-fixture contract program.mjs signs: session_id, principal,
// workspace, engagementScope, sig — non-empty CIDR CSV), then the seam's own verifySession
// when importable. A forged sig refuses 'scope-signature-invalid'; an absent seam records
// 'shape-only' with the gap named (the hook still verifies at enforcement time — fail-closed
// there even when the seam is out of this process's reach).
export async function verifyScopeFixture(scopePath, { seamDir = SEAM } = {}) {
  let fx;
  try { fx = JSON.parse(readFileSync(scopePath, 'utf8')); }
  catch (e) { return { ok: false, error: 'unreadable-scope', reason: `cannot read/parse the signed scope at ${scopePath}: ${(e && e.message) || e}` }; }
  const missing = ['session_id', 'principal', 'workspace', 'engagementScope', 'sig'].filter((f) => !fx || typeof fx[f] !== 'string' || !fx[f]);
  if (missing.length) return { ok: false, error: 'scope-shape-invalid', reason: `the scope fixture is missing/empty field(s): ${missing.join(', ')} — the signed-session shape is { session_id, principal, workspace, engagementScope, sig }` };
  let util = null;
  try { util = await import(pathToFileURL(join(seamDir, 'util.mjs')).href); } catch { util = null; }
  if (!util || typeof util.verifySession !== 'function') {
    return { ok: true, verification: 'shape-only', gap: 'the Enclave seam is not importable from here — the fixture shape checked out but the signature is UNVERIFIED (the PreToolUse hook re-verifies at enforcement time)' };
  }
  if (!util.verifySession(fx)) return { ok: false, error: 'scope-signature-invalid', reason: `the signed scope at ${scopePath} FAILS the seam's verifySession — refusing to record a forged/tampered scope` };
  return { ok: true, verification: 'seam-verified' };
}

// --- the pipeline verbs ------------------------------------------------------------------

// addProgram: import a tools/program.mjs intake record onto the roster. The record's own
// policy text sets the automation policy (default prohibited); --automation is an explicit
// operator override, recorded as such. Re-adding a handle refuses — the roster is not a
// silent upsert.
export async function addProgram({ intakePath, scopePath, automation, now, seamDir } = {}) {
  if (!intakePath) return { ok: false, error: 'bad-intake', reason: 'add needs the path of a program.mjs intake record (the normalized import --out file)' };
  const intake = readJson(intakePath, null);
  if (!intake || intake.ok !== true || !intake.program || !intake.program.handle) {
    return { ok: false, error: 'bad-intake', reason: `${intakePath} is not a successful program.mjs intake record (need { ok:true, program:{ handle } } — run: program import <fixture> --platform <p> --out <record>)` };
  }
  const id = String(intake.program.handle).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
  if (!ID_RE.test(id)) return { ok: false, error: 'bad-intake', reason: `handle '${intake.program.handle}' does not reduce to a roster id` };
  if (loadProgram(id)) return { ok: false, error: 'already-on-roster', reason: `'${id}' is already on the roster (state '${loadProgram(id).state}') — the pipeline moves it forward; it never silently re-imports` };
  let pol = deriveAutomation(intake);
  if (automation !== undefined) {
    if (!AUTOMATION_POLICIES.includes(automation)) return { ok: false, error: 'unknown-automation', reason: `automation must be one of ${AUTOMATION_POLICIES.join('|')}` };
    pol = { policy: automation, basis: 'operator-override', evidence: `operator set --automation ${automation} (policy text said: ${pol.policy}, ${pol.basis})` };
  }
  const rec = {
    id, handle: intake.program.handle, name: intake.program.name || intake.program.handle,
    platform: intake.platform || 'generic', url: intake.program.url || null,
    engagement: intake.program.handle, intakePath, signedScopePath: null, scopeVerification: null,
    automation: pol, state: 'imported', createdAt: iso(now), updatedAt: iso(now),
    history: [{ at: iso(now), from: null, to: 'imported', note: `intake record ${intakePath}` }],
    hunt: null, triage: null, reports: [], queue: null, rounds: [],
  };
  if (scopePath) {
    const v = await verifyScopeFixture(scopePath, { seamDir });
    if (!v.ok) return { ...v, id };
    rec.signedScopePath = scopePath; rec.scopeVerification = v.verification;
    const t = transition(rec, 'scoped', { now, note: `signed scope recorded at add time (${v.verification})${v.gap ? ' — ' + v.gap : ''}` });
    if (!t.ok) return t;
  }
  saveProgram(rec);
  return { ok: true, program: rec };
}

// recordScope: the operator act imported -> scoped (also scoped -> scoped re-record, and
// queued -> scoped to open a fresh round). Anything else is an illegal transition.
export async function recordScope(id, scopePath, { now, seamDir } = {}) {
  const rec = loadProgram(id);
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${id}' on the roster` };
  if (!scopePath) return { ok: false, error: 'no-scope-path', reason: 'recordScope needs the signed-scope fixture path (program import --sign --out …)' };
  const v = await verifyScopeFixture(scopePath, { seamDir });
  if (!v.ok) return { ...v, id };
  const t = transition(rec, 'scoped', { now, note: `signed scope recorded (${v.verification})${v.gap ? ' — ' + v.gap : ''}` });
  if (!t.ok) return { ...t, id };
  rec.signedScopePath = scopePath; rec.scopeVerification = v.verification;
  saveProgram(rec);
  return { ok: true, id, state: rec.state, verification: v.verification, ...(v.gap ? { gap: v.gap } : {}) };
}

// runProgram: THE AUTOMATION GATE. Refuses prohibited programs (naming the policy and its
// evidence), refuses a scopeless run ('no-signed-scope'), and maps the policy to campaign
// knobs (CADENCE_MAP). With --campaign/--report artifacts it records the hunt
// (scoped -> hunted); without them it returns the gated RUN PLAN and changes nothing —
// the pipeline never claims a hunt it cannot point to.
export async function runProgram(id, { scopePath, campaignArtifact, reportArtifact, now, seamDir, operatorAck } = {}) {
  const rec = loadProgram(id);
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${id}' on the roster` };
  // Explicit prohibition text still gates — but the OPERATOR (Jack) is the gate, not the
  // code: --operator-ack "note" acknowledges the program's literal words, forces the
  // human-cadence ceilings, and writes the acknowledgement into the run plan (audited).
  if (rec.automation.policy === 'prohibited' && !operatorAck) {
    return { ok: false, error: 'automation-prohibited', id, policy: rec.automation, reason: `run REFUSED: ${id}'s automation policy is 'prohibited' (${rec.automation.basis}: ${rec.automation.evidence}) — no campaign is scheduled or run against this program; hunt it by hand, get the policy changed, or the operator explicitly acknowledges with --operator-ack "note" (human-cadence ceilings forced, ack audited in the run plan)` };
  }
  const ackedProhibited = rec.automation.policy === 'prohibited'; // reached only WITH operatorAck
  if (ackedProhibited) console.log(`OPERATOR ACK (audited): ${id} is policy-prohibited; operator override — ${String(operatorAck).slice(0, 200)} — human-cadence ceilings FORCED`);
  if (scopePath) {
    const s = await recordScope(id, scopePath, { now, seamDir });
    if (!s.ok) return s;
  }
  const cur = loadProgram(id); // re-read: recordScope may have moved it
  if (!cur.signedScopePath) {
    return { ok: false, error: 'no-signed-scope', id, reason: `run REFUSED: no signed scope on record for ${id} — sign the normalized scope (program import --sign) and record it (bountyline add/run --scope) before any campaign; automation never runs unscoped` };
  }
  const effectivePolicy = ackedProhibited ? 'human-cadence' : cur.automation.policy; // ack override NEVER loosens — it pins the conservative ceiling
  const cadence = CADENCE_MAP[effectivePolicy];
  const runPlan = {
    scopeFixture: cur.signedScopePath,
    engagement: cur.engagement,
    policy: cur.automation.policy,
    ...(ackedProhibited ? { operatorAck: String(operatorAck).slice(0, 200), effectivePolicy } : {}),
    campaign: JSON.parse(JSON.stringify(cadence)),
    note: effectivePolicy === 'human-cadence'
      ? (ackedProhibited ? 'operator-ack override on a policy-prohibited program — the conservative human-cadence ceiling is FORCED and the ack is audited in this plan' : 'human-cadence: the conservative ceiling is FORCED (stealth paranoid, maxSteps 50, crawl 5 pages, vuln 3 probes) — these are ceilings under the engagement settings, never loosened by the pipeline')
      : 'full: the engagement settings floor governs — the pipeline adds no ceiling',
  };
  if (!campaignArtifact) {
    return { ok: true, gated: true, id, state: cur.state, runPlan, note: 'gate passed — this is the plan a scheduler launches; the hunt is recorded when the campaign artifacts land (run --campaign <surface.json> [--report <report.md>])' };
  }
  if (!existsSync(campaignArtifact) || !readJson(campaignArtifact, null)) {
    return { ok: false, error: 'unreadable-hunt-artifact', id, reason: `the campaign artifact ${campaignArtifact} does not exist or is not parseable JSON — the pipeline records hunts it can point to, never claims` };
  }
  if (reportArtifact && !existsSync(reportArtifact)) {
    return { ok: false, error: 'unreadable-report-artifact', id, reason: `the report artifact ${reportArtifact} does not exist` };
  }
  const t = transition(cur, 'hunted', { now, note: `campaign artifact ${campaignArtifact}` });
  if (!t.ok) return { ...t, id };
  cur.hunt = { campaignArtifact, reportArtifact: reportArtifact || null, at: iso(now), cadence: cur.automation.policy };
  saveProgram(cur);
  return { ok: true, hunted: true, id, state: cur.state, hunt: cur.hunt, runPlan };
}

// readinessOf: the validator gate as one boolean — validated && !stale (engine/validator
// isStale; 'stale' is a rendering of validated, and stale is NOT ready).
function readinessOf(f, { nowMs, staleDays }) {
  const val = f && f.validation && typeof f.validation === 'object' ? f.validation : null;
  const state = val ? String(val.state || 'claimed') : 'claimed';
  const stale = state === 'validated' ? isStale(val, { now: nowMs, staleDays }) : false;
  return { state, stale, ready: state === 'validated' && !stale };
}

function loadHuntFindings(rec, { nowMs, staleDays }) {
  const doc = readJson(rec.hunt && rec.hunt.campaignArtifact, null);
  if (!doc) return { ok: false, error: 'unreadable-hunt-artifact', reason: `the recorded campaign artifact ${rec.hunt && rec.hunt.campaignArtifact} is gone or unparseable — the pipeline does not invent findings` };
  const norm = normalizeFindings(doc);
  if (!norm.ok) return { ok: false, error: norm.error, reason: norm.reason };
  const findings = norm.findings.map((f, index) => ({ finding: f, index, ...readinessOf(f, { nowMs, staleDays }) }));
  return { ok: true, doc, findings };
}

// triageProgram: hunted -> triaged. Findings split by validator readiness; the RECORD is
// counts only (the split is recomputed deterministically at draft time from the artifact).
export function triageProgram(id, { now, staleDays } = {}) {
  const rec = loadProgram(id);
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${id}' on the roster` };
  const sd = staleDays !== undefined ? staleDays : Settings.for(rec.engagement || rec.id).get('validator.staleDays');
  const t = transition(rec, 'triaged', { now, note: 'validator-readiness triage' });
  if (!t.ok) return { ...t, id };
  const h = loadHuntFindings(rec, { nowMs: ms(now), staleDays: sd });
  if (!h.ok) { // the transition already moved the state — roll it back honestly
    rec.state = t.from; rec.history.pop(); rec.updatedAt = iso(now);
    saveProgram(rec);
    return { ...h, id, state: rec.state };
  }
  const ready = h.findings.filter((f) => f.ready).length;
  rec.triage = { ready, notReady: h.findings.length - ready, total: h.findings.length, at: iso(now), source: rec.hunt.campaignArtifact, staleDays: sd };
  saveProgram(rec);
  return { ok: true, id, state: rec.state, ready, notReady: rec.triage.notReady, total: rec.triage.total };
}

const slug = (s) => String(s || 'finding').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48) || 'finding';

// Resolve the replay base URL for a finding from the campaign surface doc: the finding's
// host node, then its http(s) service child for the scheme+port. Fallback https://<host>
// is NAMED as an assumption in the bundle plan (never silent).
function replayBaseFor(doc, finding) {
  const host = finding && finding.host;
  if (!host) return null;
  const nodes = Array.isArray(doc && doc.nodes) ? doc.nodes : [];
  const hostNode = nodes.find((n) => n && n.type === 'host' && (n.ip === host || n.label === host));
  const svc = hostNode && nodes.find((n) => n && n.type === 'service' && n.host === hostNode.id && /^(https?):(\d+)$/.test(n.label || ''));
  if (svc) {
    const m = /^(https?):(\d+)$/.exec(svc.label);
    const port = Number(m[2]);
    const omit = (m[1] === 'https' && port === 443) || (m[1] === 'http' && port === 80);
    return { base: `${m[1]}://${host}${omit ? '' : ':' + port}`, assumed: false };
  }
  return { base: `https://${host}`, assumed: true };
}

// draftReports: triaged -> reported. ONE bountyreport markdown per READY finding, written
// under programs/<id>/reports/ — the redactor inside bountyreport is what persists, so
// secrets land on disk as [REDACTED] (the cookie-never-reaches-report doctrine).
export function draftReports(id, { now, staleDays, researcher } = {}) {
  const rec = loadProgram(id);
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${id}' on the roster` };
  const sd = staleDays !== undefined ? staleDays : Settings.for(rec.engagement || rec.id).get('validator.staleDays');
  const t = transition(rec, 'reported', { now, note: 'bountyreport drafts' });
  if (!t.ok) return { ...t, id };
  const rollback = (r) => { rec.state = t.from; rec.history.pop(); rec.updatedAt = iso(now); saveProgram(rec); return { ...r, id, state: rec.state }; };
  if (!rec.triage || rec.triage.ready < 1) {
    return rollback({ ok: false, error: 'no-ready-findings', reason: 'triage recorded ZERO validator-ready findings — there is nothing payable to draft; validate more findings or hunt again' });
  }
  const h = loadHuntFindings(rec, { nowMs: ms(now), staleDays: sd });
  if (!h.ok) return rollback(h);
  const platform = ['hackerone', 'bugcrowd', 'generic'].includes(rec.platform) ? rec.platform : 'generic';
  const reports = [];
  const blocked = [];
  for (const f of h.findings.filter((x) => x.ready)) {
    // THE NOVELTY GATE (offline half) runs BEFORE any markdown is persisted. A BLOCKED
    // finding is skipped with the reason named — never drafted, never silently dropped
    // (the blocked list lands in the result and the program record).
    const ftext = [f.finding.label, f.finding.title, f.finding.evidence].filter(Boolean).join('\n');
    const klass = classifyWeakness(ftext);
    const blocks = parseHttpEvidence(f.finding.evidence);
    const edgeInput = blocks.find((b) => [302, 401, 403].includes(b.status)) || blocks[0] || null;
    const gate = assess({
      klass, platform,
      draftText: ftext,
      status: edgeInput && edgeInput.status, headers: edgeInput && edgeInput.headers,
      hacktivity: null, // PENDING — the network half is tools/novelgate.mjs check; the queue checklist carries the command
      dedupMatches: [],
    });
    if (gate.verdict === 'BLOCKED') {
      blocked.push({ index: f.index, label: f.finding.label || f.finding.title || 'finding', klass, reasons: gate.reasons });
      continue;
    }
    const r = bountyReport(h.doc, { platform, index: f.index, researcher, staleDays: sd, now: ms(now) });
    if (!r.ok) return rollback({ ok: false, error: r.error, reason: `bountyreport refused finding #${f.index}: ${r.reason}` });
    const host = f.finding.host || null;
    const command = `node tools/novelgate.mjs check --program ${rec.id} --host ${host || '<host>'} --weakness ${klass} --draft <this report> --status <N> --headers <h.json>`;
    // REPLAYABLE-EVIDENCE BINDING: findings whose campaign evidence carries captured
    // request/response pairs (the authzsweep bundle shape — normalizeFindings preserves
    // node.authz) get a replay bundle emitted next to the report, and the report body
    // references it. EMIT ONLY — no network in the pipeline; the runner is the
    // operator's one command. A finding without captured pairs simply has no bundle
    // (named in the section), never a fabricated one.
    let replay = null;
    let replaySection = '';
    const pairs = f.finding && f.finding.authz && f.finding.authz.bundle && f.finding.authz.bundle.pairs;
    if (Array.isArray(pairs) && pairs.length) {
      const rb = replayBaseFor(h.doc, f.finding);
      if (rb) {
        const plan = planFromPairs(pairs, { base: rb.base, program: rec.id, finding: { title: r.finding.label, ref: f.finding.ref || null, sev: f.finding.sev || null }, now });
        if (plan.ok) {
          const rdir = join(ROOT(), 'programs', id, 'reports', 'replay', `${String(reports.length + 1).padStart(2, '0')}-${slug(r.finding.label)}`);
          const em = emitBundle(plan.plan, { outDir: rdir });
          if (em.ok) {
            replay = { dir: em.dir, legs: em.requests, controls: em.controls, baseAssumed: rb.assumed };
            replaySection = `\n\n## Replay bundle\n\n- **One-command reproduction:** \`node tools/replaybind.mjs run ${JSON.stringify(em.dir)}\` (or \`bash ${join(em.dir, 'replay.sh')}\`) — every request rides the ghost chain and carries the attestation header.\n- **${em.requests} leg(s), ${em.controls} control(s)** — each leg asserts it REPRODUCES ITS CAPTURE (status equal, body marker present); a leg that no longer reproduces is reported fixed-or-changed, never hidden.\n- Credentials are **redacted-but-referenced** — the replay resolves them from the session broker at run time; no secret is inlined in the bundle.${rb.assumed ? `\n- Base URL **assumed** as \`${rb.base}\` (no service node pinned the scheme/port in the campaign artifact) — verify before replaying.` : ''}\n`;
          }
        }
      }
    }
    const md = r.md + replaySection + renderNoveltySection(gate, { program: rec.id, host, command });
    const file = join(ROOT(), 'programs', id, 'reports', `${String(reports.length + 1).padStart(2, '0')}-${slug(r.finding.label)}.md`);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, md);
    reports.push({ path: file, finding: r.finding, redactions: r.redactions, readiness: r.readiness, novelty: { verdict: gate.verdict, klass, hacktivity: 'PENDING' }, ...(replay ? { replay } : {}) });
  }
  if (!reports.length && blocked.length) {
    return rollback({ ok: false, error: 'novelty-blocked', reason: `every ready finding FAILED the novelty gate — ${blocked.map((b) => `[${b.klass}] ${b.label}: ${b.reasons[0]}`).join('; ')}. No impact proof, no submission.` , blocked });
  }
  rec.reports = reports;
  if (blocked.length) rec.noveltyBlocked = blocked;
  saveProgram(rec);
  return { ok: true, id, state: rec.state, reports, ...(blocked.length ? { blocked } : {}) };
}

// THE SUBMISSION CHECKLIST — queued-for-send means the OPERATOR's send click, never ours.
const checklist = (rec, reportPath) => [
  `Read ${basename(reportPath)} end-to-end — the honesty footer lists every unverified gap; resolve or consciously accept each`,
  'Confirm the submission-readiness line reads READY (validator-gate validated and fresh)',
  `Confirm the scope attestation matches the signed scope on record (${rec.signedScopePath})`,
  `Log in to ${rec.platform === 'generic' ? 'the program' : rec.platform} and submit the report BY HAND — VARVEL never submits: no network submission code path exists in this pipeline, by design`,
  `Record the platform's act: bountyline mark ${rec.id} submitted|duplicate|informative|resolved|paid`,
];

// queueProgram: reported -> queued. Report file path + checklist per report. THIS IS THE
// END OF THE LINE — there is no submit verb, no transport, no flag.
export function queueProgram(id, { now } = {}) {
  const rec = loadProgram(id);
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${id}' on the roster` };
  const t = transition(rec, 'queued', { now, note: 'queued for the operator send click' });
  if (!t.ok) return { ...t, id };
  if (!(rec.reports || []).length) {
    rec.state = t.from; rec.history.pop(); rec.updatedAt = iso(now); saveProgram(rec);
    return { ok: false, error: 'no-reports', id, state: rec.state, reason: 'nothing to queue — draft first' };
  }
  for (const rep of rec.reports) {
    if (!existsSync(rep.path)) {
      rec.state = t.from; rec.history.pop(); rec.updatedAt = iso(now); saveProgram(rec);
      return { ok: false, error: 'report-missing', id, state: rec.state, reason: `the drafted report ${rep.path} is gone from disk — re-draft before queueing` };
    }
    // THE NOVELTY GATE IS MANDATORY: a report that never passed through it (no novelty
    // section) is refused; a BLOCKED verdict is refused. PENDING/UNVERIFIABLE hacktivity
    // is queued but carried LOUDLY into the checklist — fail-loud, never a silent skip.
    const gate = parseNoveltySection(readFileSync(rep.path, 'utf8'));
    if (!gate.present) {
      rec.state = t.from; rec.history.pop(); rec.updatedAt = iso(now); saveProgram(rec);
      return { ok: false, error: 'novelty-gate-missing', id, state: rec.state, reason: `${basename(rep.path)} carries NO novelty-gate section — the report never passed through novelgate. Re-draft (the pipeline embeds it) or run: node tools/novelgate.mjs check --program ${id} --draft <draft.md> --annotate, then recordManualReport again` };
    }
    if (gate.verdict === 'BLOCKED') {
      rec.state = t.from; rec.history.pop(); rec.updatedAt = iso(now); saveProgram(rec);
      return { ok: false, error: 'novelty-blocked', id, state: rec.state, reason: `${basename(rep.path)} is BLOCKED by the novelty gate — no impact proof, no submission. The document exists for the record; it is not queueable.` };
    }
  }
  rec.queue = { at: iso(now), items: rec.reports.map((rep) => {
    const gate = parseNoveltySection(readFileSync(rep.path, 'utf8'));
    const items = [...checklist(rec, rep.path)];
    if (gate.verdict === 'UNVERIFIABLE') items.unshift('The novelty gate could NOT verify duplicates (hacktivity search failed) — re-run tools/novelgate.mjs check until it answers CLEAR/REVIEW-NEEDED, or consciously accept the duplicate risk in the mark note');
    else items.unshift('Resolve the report\'s Novelty check section end-to-end: read every REVIEW-NEEDED candidate and rule out a duplicate BEFORE the send click — a duplicate burns program goodwill (semrush #2666357)');
    // Replayable evidence (winner-copyables Tool 2): a drafted bundle must be re-run
    // before the send click — evidence that no longer reproduces is fixed-or-changed,
    // and submitting stale evidence burns the program.
    if (rep.replay) items.splice(1, 0, `Replay the evidence bundle BEFORE the send click: node tools/replaybind.mjs run ${rep.replay.dir} — every leg must reproduce its capture; a FIXED-OR-CHANGED leg means re-validate, do not submit stale evidence`);
    return { report: rep.path, finding: rep.finding, checklist: items, novelty: { verdict: gate.verdict }, ...(rep.replay ? { replay: rep.replay } : {}) };
  }) };
  saveProgram(rec);
  return { ok: true, id, state: rec.state, queue: rec.queue, note: 'QUEUED-FOR-SEND — the pipeline never submits; the send click is the operator\'s' };
}

// markOutcome: the operator's record of the platform's act, appended to the ledger. 'paid'
// requires amount+currency; an amount on any other outcome is refused (honest bookkeeping).
// The report must be one the pipeline actually queued (current round or an archived one —
// a late payout still books against the round that earned it).
export function markOutcome(id, outcome, { amount, currency, report, note, now } = {}) {
  const rec = loadProgram(id);
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${id}' on the roster` };
  if (!OUTCOMES.includes(outcome)) return { ok: false, error: 'unknown-outcome', reason: `outcome must be one of ${OUTCOMES.join('|')}` };
  const queuedReports = [
    ...((rec.queue && rec.queue.items) || []),
    ...(rec.rounds || []).flatMap((r) => (r.queue && r.queue.items) || []),
  ].map((i) => i.report);
  if (!queuedReports.length) return { ok: false, error: 'nothing-queued', reason: `${id} has no queued reports to mark — the pipeline order is the point (… -> reported -> queued -> mark)` };
  let rep = report;
  if (rep) {
    const hit = queuedReports.find((p) => p === rep || basename(p) === rep);
    if (!hit) return { ok: false, error: 'unknown-report', reason: `${rep} is not a report this pipeline queued for ${id} (queued: ${queuedReports.map((p) => basename(p)).join(', ')})` };
    rep = hit;
  } else if (queuedReports.length === 1) rep = queuedReports[0];
  else return { ok: false, error: 'which-report', reason: `${id} has ${queuedReports.length} queued reports — name one with --report (${queuedReports.map((p) => basename(p)).join(', ')})` };
  const event = { at: iso(now), program: id, report: rep, outcome };
  if (outcome === 'paid') {
    const amt = Number(amount);
    const cur = String(currency || '').toUpperCase();
    if (!Number.isFinite(amt) || amt <= 0) return { ok: false, error: 'paid-needs-amount', reason: "outcome 'paid' needs --amount <positive number> --currency <ISO 4217, e.g. GBP>" };
    if (!/^[A-Z]{3}$/.test(cur)) return { ok: false, error: 'paid-needs-currency', reason: "outcome 'paid' needs --currency as an ISO 4217 code (GBP, USD, EUR, …)" };
    event.amount = round2(amt); event.currency = cur;
  } else if (amount !== undefined || currency !== undefined) {
    return { ok: false, error: 'amount-only-on-paid', reason: `an amount/currency rides ONLY a 'paid' outcome — '${outcome}' carries none (book the payout when it lands)` };
  }
  if (note) event.note = String(note).slice(0, 300);
  const ledger = readJson(LEDGER_FILE(), []);
  ledger.push(event);
  writeJson(LEDGER_FILE(), ledger);
  return { ok: true, event, totals: ledgerTotals() };
}

// recordManualReport: the operator act for SOURCE-REVIEW findings — the Wordfence lane,
// where the "hunt" is privemap over a local mirror and the report is a hand-built,
// code-evidenced PoC doc, never a campaign artifact. imported|scoped -> reported, gated on
// the finished report existing on disk (the pipeline records acts it can point to, never
// claims). queue + mark then record the operator's send click exactly as in the hunt lane.
export function recordManualReport(id, { reportPath, finding, now } = {}) {
  const rec = loadProgram(id);
  if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${id}' on the roster` };
  if (!reportPath || !existsSync(reportPath)) {
    return { ok: false, error: 'report-missing', reason: `recordManualReport needs the finished report doc on disk (--file <path>) — got '${reportPath || 'none'}'; the pipeline records acts it can point to, never claims` };
  }
  const t = transition(rec, 'reported', { now, note: `manual source-review report recorded: ${reportPath}` });
  if (!t.ok) return { ...t, id };
  rec.reports = [{
    path: reportPath,
    finding: { label: finding || basename(reportPath, extname(reportPath)) },
    redactions: [],
    readiness: { manual: true, note: 'source-review finding recorded by the operator — hunt-lane validator gate not applicable; the evidence standard is the code-cited PoC doc on disk' },
  }];
  saveProgram(rec);
  return { ok: true, id, state: rec.state, reports: rec.reports };
}

// --- the ledger ---------------------------------------------------------------------------
export function loadLedger() {
  const l = readJson(LEDGER_FILE(), []);
  return Array.isArray(l) ? l : [];
}

// Totals per currency + counts by outcome + the goal line. GBP progress toward £3332.50;
// every other currency is totaled separately and NEVER converted (no invented rates).
export function ledgerTotals() {
  const events = loadLedger();
  const byOutcome = {};
  const totals = {};
  for (const e of events) {
    byOutcome[e.outcome] = (byOutcome[e.outcome] || 0) + 1;
    if (e.outcome === 'paid' && e.currency && Number.isFinite(e.amount)) totals[e.currency] = round2((totals[e.currency] || 0) + e.amount);
  }
  const gbp = totals.GBP || 0;
  return {
    events: events.length,
    byOutcome,
    totals,
    goal: { currency: 'GBP', target: GOAL_GBP, paid: gbp, pct: round2((gbp / GOAL_GBP) * 100) },
    note: 'non-GBP totals are NEVER converted — no invented exchange rates; goal progress counts GBP only',
  };
}

export function ledgerLines() {
  const t = ledgerTotals();
  const L = [];
  L.push(`bounty ledger — ${t.events} event(s)`);
  for (const o of OUTCOMES) if (t.byOutcome[o]) L.push(`  ${o}: ${t.byOutcome[o]}`);
  for (const [cur, amt] of Object.entries(t.totals).sort()) L.push(`  paid ${cur}: ${amt.toFixed(2)}${cur === 'GBP' ? '' : ' (NOT converted — no invented rates)'}`);
  L.push(`goal £${GOAL_GBP.toFixed(2)} — GBP paid £${t.goal.paid.toFixed(2)} (${t.goal.pct}%)`);
  return L;
}

// --- the API summary -----------------------------------------------------------------------
export function bountylineSummary() {
  const roster = loadRoster();
  const pipeline = {};
  for (const p of roster.programs) pipeline[p.state] = (pipeline[p.state] || 0) + 1;
  return { ok: true, programs: roster.programs, pipeline, ledger: ledgerTotals() };
}
