// VARVEL — execasm: the in-memory execution tier's DETECTION PAIRING (the signature move:
// capability + measured detectability in one operator motion).
//
//   execute-assembly  →  detoracle verdict
//
// Flow (the detoracle doctrine, verbatim — snapshot/diff/classify, no guest code, no EDR
// tampering, ever):
//   1. snapshot BEFORE (Defender threat count, 1116/1117 event counts, RTP state)
//   2. task the agent with kind 'inline-dotnet' — the assembly executes IN THE AGENT
//      PROCESS'S OWN MEMORY (engine/inlineexec.mjs governs; AMSI may scan the load —
//      that scan is exactly what step 3 measures)
//   3. settle, snapshot AFTER, classify into clean/detected/blocked/unmonitored.
//
// HONESTY CONTRACT (same as detoracle's): 'clean' means "no detection observed in this
// window, on this host, with this Defender config" — NEVER a claim of undetectability.
// A REFUSED execution (engagement gate off, agent gate off, over-cap) is reported as
// refused:true with verdict 'unknown' — no probe ran, so no detectability claim exists.
// There is no probeAlive liveness leg here: the probe runs INSIDE the agent process, so
// "did the probe process die" does not map (the agent living on is the design, not
// evidence of a non-kill).
//
// taskAgent(agentId, kind, data) -> result-preview string — injectable (the detoracle
// pattern): the CLI wires it to the live channel API, tests wire a script.

import { buildSnapshotCommand, parseSnapshot, classify, SETTLE_MS } from './detoracle.mjs';
import { INLINE_DOTNET_KIND } from '../engine/inlineexec.mjs';

export { SETTLE_MS };

// A refusal is loud plain text by contract (agents/inlineexec.mjs + the channel gate).
const REFUSED_RE = /(?:^|\b)(?:TASKING REFUSED|inline-dotnet (?:REFUSED|REJECTED)|inline-dotnet refused)/i;

export async function assessInlineExec({ taskAgent, agentId, spec, settleMs = SETTLE_MS }) {
  if (typeof taskAgent !== 'function') throw new TypeError('execasm.assessInlineExec needs a taskAgent(agentId, kind, data)');
  if (!agentId || !spec) throw new TypeError('execasm.assessInlineExec needs agentId and a spec ({assemblyB64,args?,entryPoint?} or its JSON string)');
  const data = typeof spec === 'string' ? spec : JSON.stringify(spec);
  const snapCmd = buildSnapshotCommand();
  const beforeRaw = await taskAgent(agentId, 'shell', snapCmd);
  const before = parseSnapshot(beforeRaw);
  const execRaw = await taskAgent(agentId, INLINE_DOTNET_KIND, data);
  const refused = execRaw == null || REFUSED_RE.test(String(execRaw));
  // Best-effort parse of the hash-first execution JSON (the API preview path truncates
  // at 120 chars — an unparseable blob is reported as raw preview, never guessed at).
  let execution = null;
  try {
    const p = JSON.parse(String(execRaw));
    if (p && typeof p === 'object') {
      execution = {
        sha256: p.sha256 || null, bytes: p.bytes ?? null, entryPoint: p.entryPoint ?? null,
        exitCode: p.exitCode ?? null, timedOut: p.timedOut === true,
        stdoutPreview: String(p.stdout ?? '').slice(0, 400), stderrPreview: String(p.stderr ?? '').slice(0, 400),
      };
    }
  } catch { /* truncated preview or plain text — carried raw in evidence */ }
  if (refused) {
    return {
      verdict: 'unknown', refused: true, newDetections: 0, newActions: 0,
      note: 'the in-memory execution was REFUSED by governance (engagement exec.inMemory gate, agent flag, or size cap) — nothing ran, so there is NOTHING to detect. This is the gate working, not a clean verdict.',
      execution, evidence: { before: beforeRaw, after: null, execResult: String(execRaw ?? '(no result — tasking refused or agent gone)').slice(0, 400) },
      settleMs, at: new Date().toISOString(),
    };
  }
  await new Promise((r) => setTimeout(r, settleMs));
  const afterRaw = await taskAgent(agentId, 'shell', snapCmd);
  const after = parseSnapshot(afterRaw);
  const v = classify(before, after, {});
  return {
    ...v, refused: false, execution,
    evidence: { before: beforeRaw, after: afterRaw, execResult: String(execRaw || '').slice(0, 400) },
    settleMs, at: new Date().toISOString(),
  };
}
