// VARVEL — evasion: the EVASION INTERNALS TIER's DETECTION PAIRING + operator loop
// (stage 1, doctrine 2026-08-12). The signature move, applied to the evasion tier:
//
//   evasion-enable  →  verify  →  detoracle probe  →  evasion-restore  →  verify restored
//
// in ONE governed motion, with the tier's honesty contract enforced in code:
// a detoracle verdict measured while the agent's own monitoring path is patched is
// phrased EXACTLY as 'monitoring neutralized (self-reported, patch-verified)' — NEVER
// as 'clean' (detoracle.honestVerdict owns the phrasing; this tool owns the loop).
//
// THE LOOP:
//   1. evasion-enable {techniques} over the governed channel. A REFUSAL is reported as
//      refused:true, verdict 'unknown' (the gate working is not a measurement). A patch
//      that did not byte-verify / flip-prove is reported with its evidence, honestly.
//   2. OPTIONAL probe leg: detoracle snapshot → probeCommand → snapshot → classify.
//      The raw classify verdict is kept as evidence; the REPORTED verdict passes
//      through honestVerdict({monitoringNeutralized:true}) — 'clean' becomes
//      'unmonitored' with the neutralized phrase; a 'detected' that still fired passes
//      through untouched (the patch covers the agent's own process, not every sensor).
//      NOTE the probe is the OPERATOR's technique to grade (e.g. an inline-dotnet load
//      — the agent's own AMSI path is what stage 1 neutralizes; a 'shell' probe runs
//      in cmd.exe, a DIFFERENT process the patch does not cover — the diff stays
//      meaningful and the phrasing stays honest either way).
//   3. evasion-restore — ALWAYS attempted once enable returned patched (the cleanup
//      doctrine is not optional): original bytes back, re-read-verified, the AMSI
//      flip-BACK measured. restoreVerified aggregates ONLY the techniques that enable
//      actually patched (a never-patched technique has nothing to prove).
//   4. evasion-status AFTER the restore: the agent's live, re-read self-report closes
//      the loop (restored / untouched — anything else lands in the report as-is).
//
// taskAgent(agentId, kind, data) -> result-preview string — injectable (the detoracle
// pattern): the CLI wires it to the live channel API, tests wire a script.

import { parseEvasionSpec, EVASION_TECHNIQUES } from '../engine/evasion.mjs';
import { buildSnapshotCommand, parseSnapshot, classify, honestVerdict, SETTLE_MS, MONITORING_NEUTRALIZED_PHRASE } from './detoracle.mjs';

export { SETTLE_MS, MONITORING_NEUTRALIZED_PHRASE };

// A refusal is loud plain text by contract (agents/evasion.mjs, the PS agent cases, and
// the channel gate's THROWN GOVERNANCE error which the API task path surfaces).
const REFUSED_RE = /(?:^|\b)(?:TASKING REFUSED|evasion-\w+ (?:REFUSED|REJECTED)|evasion-\w+ refused)/i;

// Parse an agent evasion result body. Returns the evidence object, or null when the
// body is not the evidence JSON (refusal text, truncation, foreign body). Never throws.
export function parseEvasionResult(raw) {
  try {
    const p = JSON.parse(String(raw || ''));
    if (p && typeof p === 'object' && typeof p.op === 'string' && p.techniques && typeof p.techniques === 'object') return p;
  } catch { /* refusal text / truncated preview — carried raw in evidence */ }
  return null;
}

// Per-technique one-line truth for reports: state + the hashes + what was proven.
function techniqueTruth(t, ev) {
  return {
    state: String(ev.state || 'unknown'),
    originalSha256: ev.originalSha256 || null,
    patchedSha256: ev.patchedSha256 || null,
    restoredSha256: ev.restoredSha256 || null,
    byteVerified: ev.byteVerified === true,
    restoreVerified: ev.restoreVerified === true,
    flipProven: !!(ev.verify && ev.verify.flipProven === true),
    flipBackProven: !!(ev.verify && ev.verify.flipBackProven === true),
    note: ev.note || null, error: ev.error || null,
  };
}

export async function assessEvasion({ taskAgent, agentId, techniques = ['amsi'], probeCommand = null, settleMs = SETTLE_MS }) {
  if (typeof taskAgent !== 'function') throw new TypeError('evasion.assessEvasion needs a taskAgent(agentId, kind, data)');
  if (!agentId) throw new TypeError('evasion.assessEvasion needs agentId');
  // The same spec gate the channel runs — refuse a bad technique list BEFORE any task
  // rides the wire (throws TypeError/RangeError, loud and operator-readable).
  const spec = parseEvasionSpec('evasion-enable', JSON.stringify({ techniques }));
  const data = JSON.stringify({ techniques: spec.techniques });

  // ---- 1. enable (+ measured verification) ----
  const enRaw = await taskAgent(agentId, 'evasion-enable', data);
  const en = parseEvasionResult(enRaw);
  if (!en) {
    const refused = enRaw == null || REFUSED_RE.test(String(enRaw));
    return {
      verdict: 'unknown', refused, monitoringNeutralized: false, phrase: null,
      note: refused
        ? 'evasion-enable was REFUSED by governance (engagement exec.evasion gate, agent --evasion flag, or spec) — nothing patched, so there is NOTHING to phrase. This is the gate working, not a measurement.'
        : 'evasion-enable returned no parseable evidence (channel preview truncation or host noise) — patch state UNKNOWN, reported honestly; nothing was probed or restored by this loop. Query evasion-status directly before drawing any conclusion.',
      enabled: null, probe: null, restored: null, statusAfter: null, restoreVerified: false,
      evidence: { enable: String(enRaw ?? '(no result — tasking refused or agent gone)').slice(0, 400) },
      settleMs, at: new Date().toISOString(),
    };
  }
  const enabled = { state: en.state, pid: en.pid ?? null, techniques: {} };
  for (const t of spec.techniques) enabled.techniques[t] = en.techniques[t] ? techniqueTruth(t, en.techniques[t]) : { state: 'missing-from-result' };
  const patchedTechs = spec.techniques.filter((t) => en.techniques[t] && en.techniques[t].state === 'patched');

  // ---- 2. optional detoracle probe leg (verdict phrased under the contract) ----
  let probe = null;
  let verdict = 'unknown';
  let phrase = null;
  if (probeCommand) {
    const snapCmd = buildSnapshotCommand();
    const beforeRaw = await taskAgent(agentId, 'shell', snapCmd);
    const before = parseSnapshot(beforeRaw);
    const probeResult = await taskAgent(agentId, 'shell', String(probeCommand));
    await new Promise((r) => setTimeout(r, settleMs));
    const afterRaw = await taskAgent(agentId, 'shell', snapCmd);
    const after = parseSnapshot(afterRaw);
    const raw = classify(before, after, {});
    const phrased = honestVerdict(raw, { monitoringNeutralized: patchedTechs.length > 0 });
    verdict = phrased.verdict;
    phrase = phrased.rawVerdict ? MONITORING_NEUTRALIZED_PHRASE : null;
    probe = {
      command: String(probeCommand).slice(0, 300),
      rawVerdict: raw.verdict, note: phrased.note,
      newDetections: phrased.newDetections, newActions: phrased.newActions,
      evidence: { before: beforeRaw, after: afterRaw, probeResult: String(probeResult || '').slice(0, 300) },
    };
  } else {
    // No probe: the verdict is about the PATCH alone (byte-verify + the AMSI flip),
    // not about a technique graded under it. Stated plainly.
    verdict = patchedTechs.length === spec.techniques.length ? 'unmonitored' : 'unknown';
    phrase = patchedTechs.length ? MONITORING_NEUTRALIZED_PHRASE : null;
  }
  const monitoringNeutralized = patchedTechs.length > 0;

  // ---- 3. restore (mandatory once anything patched) + 4. status after ----
  let restored = null;
  let restoreVerified = false;
  let reRaw = null;
  if (patchedTechs.length) {
    reRaw = await taskAgent(agentId, 'evasion-restore', JSON.stringify({ techniques: patchedTechs }));
    const re = parseEvasionResult(reRaw);
    if (re) {
      restored = { state: re.state, techniques: {} };
      restoreVerified = true;
      for (const t of patchedTechs) {
        const ev = re.techniques[t];
        restored.techniques[t] = ev ? techniqueTruth(t, ev) : { state: 'missing-from-result' };
        if (!ev || ev.restoreVerified !== true) restoreVerified = false;
      }
    } else {
      restored = { state: 'unparseable-result', techniques: {} };
    }
  }
  const stRaw = await taskAgent(agentId, 'evasion-status', '{}');
  const st = parseEvasionResult(stRaw);
  const statusAfter = st ? { state: st.state, pid: st.pid ?? null, techniques: Object.fromEntries(Object.entries(st.techniques).map(([t, ev]) => [t, techniqueTruth(t, ev)])) } : null;

  const note = !patchedTechs.length
    ? 'enable returned WITHOUT any technique reaching state patched — nothing was neutralized; see the per-technique evidence (a byte-verify or flip failure is reported, never dressed up).'
    : phrase
      ? MONITORING_NEUTRALIZED_PHRASE + ' — detoracle readings from this window are NOT clean readings; the restore leg ' + (restoreVerified ? 're-wrote the original bytes and re-verified them (flip-back measured).' : 'DID NOT fully verify — treat the agent as still-patched and investigate (loud, not hidden).')
      : 'patched + verified, but no probeCommand was given — no technique was graded under neutralization this run.';

  return {
    verdict, refused: false, monitoringNeutralized, phrase,
    note, enabled, probe, restored, statusAfter, restoreVerified,
    evidence: {
      enable: String(enRaw || '').slice(0, 600),
      restore: reRaw == null ? null : String(reRaw || '').slice(0, 600),
      status: String(stRaw || '').slice(0, 600),
    },
    techniques: spec.techniques, allTechniques: EVASION_TECHNIQUES,
    settleMs, at: new Date().toISOString(),
  };
}
