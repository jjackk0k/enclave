// VARVEL — persist: the GOVERNED PERSISTENCE TIER's DETECTION PAIRING + operator loop
// (roadmap #8). The signature move, applied to the classic detection moment:
//
//   persist-install  →  detoracle verdict on the install  →  persist-remove (verified)
//
// in ONE governed motion. A persistence install is exactly where a range's Defender/EDR
// gets its best look at an agent — Run-key writes, scheduled-task registration, and
// startup-folder .lnk creation are all heavily instrumented — so the platform never
// installs blind: snapshot/diff/classify around the install, then MANDATORY verified
// removal. The cleanup-proof doctrine is enforced in code: cleanupVerified aggregates
// ONLY techniques whose removal was proven by re-read, and a run whose removal did not
// verify is reported as a loud loose end (treat the host as STILL PERSISTED), never a
// quiet pass.
//
// HONESTY CONTRACT (same as detoracle's): 'clean' means "no detection observed in this
// window, on this host, with this Defender config" — NEVER a claim of undetectability.
// A REFUSED install (engagement gate off, agent flag off, bad spec) is refused:true,
// verdict 'unknown' — no install ran, so no detectability claim exists.
//
// taskAgent(agentId, kind, data) -> result-preview string — injectable (the detoracle
// pattern): the CLI wires it to the live channel API, tests wire a script.

import { parsePersistSpec, PERSIST_ALL_TECHNIQUES, postureFromMeasurements, rankPersistTechniques, PERSIST_TELEMETRY, PERSIST_TRIGGER_MODELS } from '../engine/persist.mjs';
import { buildSnapshotCommand, parseSnapshot, classify, SETTLE_MS } from './detoracle.mjs';
import { buildAuditCommand, parsePosture } from './rangehard.mjs';

export { SETTLE_MS };
export { rankPersistTechniques, PERSIST_TELEMETRY, PERSIST_TRIGGER_MODELS };

// A refusal is loud plain text by contract (agents/persist.mjs, the PS agent cases, and
// the channel gate's THROWN GOVERNANCE error which the API task path surfaces).
const REFUSED_RE = /(?:^|\b)(?:TASKING REFUSED|persist-\w+ (?:REFUSED|REJECTED)|persist-\w+ refused)/i;

// Parse an agent persist result body. Returns the evidence object, or null when the
// body is not the evidence JSON (refusal text, truncation, foreign body). Never throws.
export function parsePersistResult(raw) {
  try {
    const p = JSON.parse(String(raw || ''));
    if (p && typeof p === 'object' && typeof p.op === 'string' && (p.op === 'audit' ? Array.isArray(p.entries) : p.techniques && typeof p.techniques === 'object')) return p;
  } catch { /* refusal text / truncated preview — carried raw in evidence */ }
  return null;
}

// Per-technique one-line truth for reports: state + location + what was proven.
function techniqueTruth(t, ev) {
  return {
    state: String(ev.state || 'unknown'),
    location: ev.location || null,
    targetSha256: ev.targetSha256 || null,
    preExisted: ev.preExisted === true,
    overwriteJournaled: ev.overwriteJournaled === true,
    installVerified: ev.installVerified === true,
    removalVerified: ev.removalVerified === true,
    journalRestored: ev.journalRestored === true,
    note: ev.note || null, error: ev.error || null,
  };
}

export async function assessPersist({ taskAgent, agentId, techniques = ['startup'], name = null, settleMs = SETTLE_MS }) {
  if (typeof taskAgent !== 'function') throw new TypeError('persist.assessPersist needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('persist.assessPersist needs agentId');
  // The same spec gate the channel runs — refuse a bad technique list BEFORE any task
  // rides the wire (throws TypeError/RangeError, loud and operator-readable).
  const spec = parsePersistSpec('persist-install', JSON.stringify({ techniques, name }));
  const data = JSON.stringify({ techniques: spec.techniques, name: spec.name });

  // ---- 1. snapshot BEFORE, then install ----
  const snapCmd = buildSnapshotCommand();
  const beforeRaw = await taskAgent(agentId, 'shell', snapCmd);
  const before = parseSnapshot(beforeRaw);
  const inRaw = await taskAgent(agentId, 'persist-install', data);
  const ins = parsePersistResult(inRaw);
  if (!ins) {
    const refused = inRaw == null || REFUSED_RE.test(String(inRaw));
    return {
      verdict: 'unknown', refused, cleanupVerified: false,
      note: refused
        ? 'persist-install was REFUSED by governance (engagement persist.enabled gate, agent --persist flag, or spec) — nothing installed, so there is NOTHING to detect. This is the gate working, not a measurement.'
        : 'persist-install returned no parseable evidence (channel preview truncation or host noise) — persistence state UNKNOWN, reported honestly; nothing was removed by this loop. Run persist-status directly before drawing any conclusion.',
      installed: null, probe: null, removed: null, statusAfter: null,
      evidence: { install: String(inRaw ?? '(no result — tasking refused or agent gone)').slice(0, 400) },
      settleMs, at: new Date().toISOString(),
    };
  }
  const installed = { state: ins.state, pid: ins.pid ?? null, techniques: {} };
  for (const t of spec.techniques) installed.techniques[t] = ins.techniques[t] ? techniqueTruth(t, ins.techniques[t]) : { state: 'missing-from-result' };
  const installedTechs = spec.techniques.filter((t) => ins.techniques[t] && ins.techniques[t].state === 'installed');

  // ---- 2. detoracle verdict on the INSTALL moment ----
  let probe = null;
  let verdict = 'unknown';
  if (installedTechs.length) {
    await new Promise((r) => setTimeout(r, settleMs));
    const afterRaw = await taskAgent(agentId, 'shell', snapCmd);
    const after = parseSnapshot(afterRaw);
    const v = classify(before, after, {});
    verdict = v.verdict;
    probe = {
      newDetections: v.newDetections, newActions: v.newActions, note: v.note,
      evidence: { before: beforeRaw, after: afterRaw },
    };
  } else {
    verdict = 'unknown';
  }

  // ---- 3. persist-remove (MANDATORY once anything installed) — verified, or LOUD ----
  let removed = null;
  let cleanupVerified = false;
  let reRaw = null;
  if (installedTechs.length) {
    reRaw = await taskAgent(agentId, 'persist-remove', JSON.stringify({ techniques: installedTechs }));
    const re = parsePersistResult(reRaw);
    if (re) {
      removed = { state: re.state, techniques: {} };
      cleanupVerified = true;
      for (const t of installedTechs) {
        const ev = re.techniques[t];
        removed.techniques[t] = ev ? techniqueTruth(t, ev) : { state: 'missing-from-result' };
        if (!ev || ev.removalVerified !== true) cleanupVerified = false;
      }
    } else {
      removed = { state: 'unparseable-result', techniques: {} };
    }
  }
  const stRaw = await taskAgent(agentId, 'persist-status', data);
  const st = parsePersistResult(stRaw);
  const statusAfter = st ? { state: st.state, pid: st.pid ?? null, techniques: Object.fromEntries(Object.entries(st.techniques).map(([t, ev]) => [t, techniqueTruth(t, ev)])) } : null;

  const note = !installedTechs.length
    ? 'install returned WITHOUT any technique reaching state installed — nothing persisted; see the per-technique evidence (a clobber-refusal or verify failure is reported, never dressed up).'
    : cleanupVerified
      ? 'installed ' + installedTechs.length + ' technique(s), measured the install window (' + verdict + '), then removed every one with re-read-VERIFIED absence — the host is provably back to its pre-install state.'
      : 'CLEANUP-PROOF FAILED: the removal leg DID NOT fully verify — treat the host as STILL PERSISTED and investigate (loud, not hidden). The engagement cannot be called clean until persist-remove verifies and persist-audit sweeps clean.';

  return {
    verdict, refused: false, cleanupVerified,
    note, installed, probe, removed, statusAfter,
    evidence: {
      install: String(inRaw || '').slice(0, 600),
      remove: reRaw == null ? null : String(reRaw || '').slice(0, 600),
      status: String(stRaw || '').slice(0, 600),
    },
    techniques: spec.techniques,
    settleMs, at: new Date().toISOString(),
  };
}

// ——— EDR-AWARE SELECTION (stage 2) ———
// The operator-facing selector: measure the target's posture over the EXISTING
// governed channel (kind 'shell', read-only queries — zero new guest code), then rank
// the technique set (classic + deep) by PREDICTED INSTALL-TIME VISIBILITY. Two probes:
//   1. buildPersistPostureCommand — which logs answer (Sysmon presence above all), the
//      audit-policy subcategories that gate Security 4657/4698, and whether a SACL is
//      readable on the watched keys.
//   2. rangehard's buildAuditCommand — Defender RTP/behavior state + the ASR summary.
// Verdict phrasing inherits the honesty contract: 'lower predicted visibility against
// the measured posture', NEVER 'undetectable'. An unreachable range or an unreadable
// axis is stated — never assumed blind.

// The Registry / Other-Object-Access audit subcategory GUIDs (stable, documented
// constants — used instead of names so no nested-quote escaping rides the channel).
const AUDIT_SUBCATEGORY_REGISTRY = '{0CCE921E-69AE-11D9-BED3-505054503030}';
const AUDIT_SUBCATEGORY_OTHER_OBJECT = '{0CCE9227-69AE-11D9-BED3-505054503030}';

// One compact posture snapshot as a single marker-prefixed JSON line. Read-only:
// Get-WinEvent -ListLog (does the log exist + answer), auditpol /get (subcategory
// effectiveness), Get-Acl -Audit (SACL readability — unelevated reads fail, which lands
// as an HONEST null = 'unknown', never as 'no SACL').
export function buildPersistPostureCommand() {
  const body =
    `$logs=@{}; foreach($l in @('Microsoft-Windows-Sysmon/Operational','Security','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-TaskScheduler/Operational')){ try { $null=Get-WinEvent -ListLog $l -ErrorAction Stop; $logs[$l]=$true } catch { $logs[$l]=$false } }; `
    + `$audit=@{registry=$null;otherObjectAccess=$null}; `
    + `try { $r=(auditpol /get /subcategory:'${AUDIT_SUBCATEGORY_REGISTRY}' /r | ConvertFrom-Csv).'Inclusion Setting'; if ($null -ne $r) { $audit.registry=([string]$r -match 'Success') } } catch {}; `
    + `try { $r=(auditpol /get /subcategory:'${AUDIT_SUBCATEGORY_OTHER_OBJECT}' /r | ConvertFrom-Csv).'Inclusion Setting'; if ($null -ne $r) { $audit.otherObjectAccess=([string]$r -match 'Success') } } catch {}; `
    + `$sacl=$null; try { $a=Get-Acl -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Audit -ErrorAction Stop; $sacl=(@($a.GetAuditRules($true,$false,[Security.Principal.NTAccount]'Everyone')).Count -gt 0) } catch { $sacl=$null }; `
    + `Write-Output ('PERSISTPOSTURE ' + (@{logs=@{sysmon=$logs['Microsoft-Windows-Sysmon/Operational'];security=$logs['Security'];defender=$logs['Microsoft-Windows-Windows Defender/Operational'];taskScheduler=$logs['Microsoft-Windows-TaskScheduler/Operational']};audit=$audit;saclOnKey=$sacl} | ConvertTo-Json -Compress))`;
  return 'powershell -NoProfile -Command "' + body + '"';
}

// Parse the PERSISTPOSTURE line. Fail-closed: no marker / bad JSON -> null (a posture
// is never guessed). Tri-state booleans pass through as true/false/null.
export function parsePersistPosture(text) {
  const m = /PERSISTPOSTURE (\{.*\})/s.exec(String(text || ''));
  if (!m) return null;
  let o;
  try { o = JSON.parse(m[1]); } catch { return null; }
  if (!o || typeof o !== 'object' || !o.logs || typeof o.logs !== 'object') return null;
  const tri = (v) => (v === true ? true : v === false ? false : null);
  return {
    logs: { sysmon: tri(o.logs.sysmon), security: tri(o.logs.security), defender: tri(o.logs.defender), taskScheduler: tri(o.logs.taskScheduler) },
    audit: { registry: o.audit ? tri(o.audit.registry) : null, otherObjectAccess: o.audit ? tri(o.audit.otherObjectAccess) : null },
    saclOnKey: tri(o.saclOnKey),
  };
}

// THE SELECTOR. taskAgent(agentId, kind, data) -> result string | null — injectable
// (the detoracle pattern): the CLI wires it to the live channel API, tests wire a
// script. Returns the posture as measured + the ranking; never throws on a governed
// refusal — a range that does not answer produces NO ranking (guesswork refused).
export async function selectPersistTechniques({ taskAgent, agentId, techniques = PERSIST_ALL_TECHNIQUES } = {}) {
  if (typeof taskAgent !== 'function') throw new TypeError('persist.selectPersistTechniques needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('persist.selectPersistTechniques needs agentId');
  const at = new Date().toISOString();

  const posRaw = await taskAgent(agentId, 'shell', buildPersistPostureCommand());
  if (posRaw == null) {
    return { reachable: false, posture: null, ranking: [], recommended: null, note: 'the range did not answer the posture probe (unreachable or tasking refused) — NO ranking produced: a ranking without a measured posture would be guesswork, refused', evidence: null, at };
  }
  const persistPosture = parsePersistPosture(posRaw);
  if (!persistPosture) {
    return { reachable: true, posture: null, ranking: [], recommended: null, note: 'posture unreadable (no parseable PERSISTPOSTURE line) — NO ranking produced (fail-closed, never assumed)', evidence: String(posRaw).slice(0, 400), at };
  }
  // rangehard's Defender/ASR read fills the behavior/RTP/ASR axes; unreachable there
  // just leaves those axes 'unknown' (stated per row), never blocks the ranking.
  let rangehardPosture = null;
  let rangehardEvidence = null;
  try {
    const rhRaw = await taskAgent(agentId, 'shell', buildAuditCommand());
    rangehardEvidence = rhRaw == null ? null : String(rhRaw).slice(0, 400);
    if (rhRaw != null) rangehardPosture = parsePosture(rhRaw);
  } catch { rangehardPosture = null; }

  const posture = postureFromMeasurements({ persistPosture, rangehard: rangehardPosture ? { posture: rangehardPosture } : null });
  const ranked = rankPersistTechniques(posture, { techniques });
  return {
    reachable: true,
    posture,
    ranking: ranked.ranking,
    recommended: ranked.recommended,
    note: ranked.note + (rangehardPosture ? '' : ' Defender behavior/RTP axes UNMEASURED (the rangehard probe did not answer) — those signals sit in the unknown bucket, stated per row.'),
    evidence: { posture: String(posRaw).slice(0, 400), rangehard: rangehardEvidence },
    at,
  };
}
