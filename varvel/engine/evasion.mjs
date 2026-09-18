// VARVEL — the EVASION INTERNALS TIER, stage 1 (governed): governance core.
//
// DOCTRINE (2026-08-12, operator directive): the platform's old absolute no-evasion
// rule is LIFTED. Evasion is now a capability — shipped the VARVEL way: default-OFF,
// double-gated, fully audited, REVERSIBLE (every patch restorable — cleanup doctrine),
// and MEASURED by the detection oracle rather than claimed.
//
// Stage 1 scope (PowerShell-agent level, NO native code): in-memory, OWN-PROCESS-ONLY
// patches for the PS range agent:
//   - amsi: the well-published in-memory AmsiScanBuffer patch (amsi.dll) — script and
//     content scans submitted BY THE AGENT PROCESS are neutralized in-process.
//   - etw:  the well-published in-memory EtwEventWrite noop (ntdll.dll) — the agent
//     process's own ETW event writes return success-and-do-nothing.
// VERIFY + RESTORE machinery (mandatory): original bytes are snapshotted BEFORE the
// write; after the write the patch is PROVEN (bytes re-read and compared, and for AMSI
// the official Microsoft test string is scanned before AND after — blocked -> clear is
// measured, never assumed); restore() writes the original bytes back and re-verifies.
// status() reports patched/restored/failed honestly, with the evidence.
//
// HARD BOUNDARY (permanent): own process only. NOTHING here touches another process,
// the kernel, or on-disk bytes. Sleepmask-class memory encryption and UDRL need a
// NATIVE compiled loader — PS/Node agents cannot do them (the pending native-agent
// decision, stated plainly in docs/AGENT-GUIDE.md).
//
// Governance (three seams, all fail-closed — mirrors engine/inlineexec.mjs):
//   1. ENGAGEMENT GATE — settings key 'exec.evasion' (default OFF). The channel refuses
//      to queue evasion-* unless the engagement explicitly enabled it. Refusal is loud
//      and audited (task.refused), never a silent drop.
//   2. SPEC GATE — the task data must parse: known kind, known techniques, deduped,
//      capped. Refused BEFORE queueing.
//   3. AUDIT — a queued evasion task emits 'evasion.task' with the sha256 of the PATCH
//      RECIPE per technique (the recipe is well-known public tradecraft; the hash pins
//      exactly which bytes were ordered). When the agent's result arrives, the intake
//      emits 'evasion.applied' / 'evasion.restored' / 'evasion.status' carrying the
//      sha256 of the ORIGINAL and PATCHED byte regions plus the verification evidence —
//      the accountability trail (what was written where, provably, and that it was
//      put back).

import { createHash } from 'node:crypto';
import { Settings } from './settings.mjs';

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export const EVASION_KIND_ENABLE = 'evasion-enable';
export const EVASION_KIND_RESTORE = 'evasion-restore';
export const EVASION_KIND_STATUS = 'evasion-status';
export const EVASION_KINDS = new Set([EVASION_KIND_ENABLE, EVASION_KIND_RESTORE, EVASION_KIND_STATUS]);
export const EVASION_TECHNIQUES = ['amsi', 'etw'];

// The patch recipes — the well-published, public in-memory neutralizations (stage 1 is
// x86/x64 safe byte sequences at the export's entry). The channel NEVER ships patch
// bytes to the agent: the recipe lives agent-side; the channel side keeps this copy for
// ONE purpose — the audit hash (recipeSha256) pinned into 'evasion.task' at queue time.
//   amsi: AmsiScanBuffer := mov eax, 0x80070057 ; ret   (E_INVALIDARG — the scan call
//         fails before content is ever evaluated; the canonical public patch class)
//   etw:  EtwEventWrite  := mov eax, 0 ; ret            (ERROR_SUCCESS — a success noop)
export const EVASION_RECIPES = {
  amsi: { dll: 'amsi.dll', export: 'AmsiScanBuffer', patchHex: 'b857000780c3', bytes: 6, note: 'mov eax,0x80070057; ret — in-memory AmsiScanBuffer neutralization (well-published public tradecraft)' },
  etw: { dll: 'ntdll.dll', export: 'EtwEventWrite', patchHex: 'b800000000c3', bytes: 6, note: 'mov eax,0; ret — in-memory EtwEventWrite success-noop (well-published public tradecraft)' },
};
for (const t of Object.keys(EVASION_RECIPES)) {
  const r = EVASION_RECIPES[t];
  r.patchBytes = Buffer.from(r.patchHex, 'hex');
  r.recipeSha256 = sha256(r.patchBytes);
}

// Parse + validate an evasion task-data string for the given kind. Returns
// { kind, techniques } — techniques is a deduped subset of EVASION_TECHNIQUES, or null
// for restore-with-no-data (meaning: restore whatever THIS agent has patched — the
// agent is the only one who knows its live patch state). THROWS (TypeError/RangeError)
// with a loud, operator-readable reason. Pure: no I/O, no settings — the same parse
// runs server-side (pre-queue refusal) and agent-side (pre-execution refusal).
export function parseEvasionSpec(kind, data) {
  kind = String(kind || '');
  if (!EVASION_KINDS.has(kind)) throw new TypeError('evasion: unknown kind ' + JSON.stringify(kind) + ' (want one of ' + [...EVASION_KINDS].join(', ') + ')');
  const raw = String(data ?? '').trim();
  if (kind === EVASION_KIND_STATUS) {
    if (raw && raw !== '{}') throw new TypeError('evasion-status takes no task data (got ' + raw.slice(0, 40) + ')');
    return { kind, techniques: null };
  }
  if (kind === EVASION_KIND_RESTORE && (!raw || raw === '{}')) return { kind, techniques: null }; // restore-all-patched
  let spec;
  try { spec = JSON.parse(raw); } catch {
    throw new TypeError(kind + ': task data is not valid JSON (want {"techniques":["amsi","etw"]})');
  }
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError(kind + ': task data must be a JSON object');
  if (!Array.isArray(spec.techniques)) throw new TypeError(kind + ': techniques must be an array (subset of ' + EVASION_TECHNIQUES.join(', ') + ')');
  const techniques = [...new Set(spec.techniques.map((t) => String(t).toLowerCase().trim()))];
  if (!techniques.length) throw new TypeError(kind + ': techniques is empty — nothing to do');
  if (techniques.length > EVASION_TECHNIQUES.length) throw new RangeError(kind + ': ' + techniques.length + ' techniques is over the ' + EVASION_TECHNIQUES.length + ' cap');
  for (const t of techniques) {
    if (!EVASION_TECHNIQUES.includes(t)) throw new TypeError(kind + ': unknown technique ' + JSON.stringify(t) + ' (stage 1 ships ' + EVASION_TECHNIQUES.join(', ') + ' only — own-process, in-memory, nothing else)');
  }
  return { kind, techniques };
}

// The engagement gate. Returns { ok: true } or { ok: false, reason } — fail-CLOSED on
// any settings-layer error (a gate that cannot read its setting does not patch).
export function evasionGate(engagement) {
  let on = false;
  try { on = Settings.for(engagement || 'default').get('exec.evasion') === true; } catch { on = false; }
  if (!on) {
    return {
      ok: false,
      reason: "engagement setting 'exec.evasion' is OFF — the evasion tier is disabled. "
        + "An operator must explicitly enable it for engagement '" + (engagement || 'default') + "' "
        + "(POST /api/settings {key:'exec.evasion', value:true}) before evasion tasks will queue, and the agent must "
        + "have been launched with its own evasion flag. Nothing patched.",
    };
  }
  return { ok: true };
}

// PatchRegion — the PURE byte-math twin of the agent-side machinery, run over a fake
// memory region (a Buffer). The PowerShell side does the identical dance against real
// process memory (VirtualProtect + Marshal read/write); this class pins the contract
// hermetically: snapshot BEFORE (never write what you cannot restore), patch == exact
// length == verified re-read, restore == the snapshot bytes back == verified re-read.
export class PatchRegion {
  constructor(bytes) {
    if (!Buffer.isBuffer(bytes) && !Array.isArray(bytes) && !(bytes instanceof Uint8Array)) throw new TypeError('PatchRegion needs the region bytes (Buffer/byte array)');
    this.mem = Buffer.from(bytes);
    this._snapshot = null; // Buffer | null — the ONLY restore source
  }
  // Snapshot the region exactly as it lies NOW. Returns { bytes, sha256 }.
  snapshot() {
    this._snapshot = Buffer.from(this.mem);
    return { bytes: Buffer.from(this._snapshot), sha256: sha256(this._snapshot) };
  }
  // Write patchBytes over the region and PROVE the write (re-read compare). The patch
  // must cover exactly the snapshotted span — a short write would leave a franken-
  // function, a long one would clobber the next instruction. Returns { patchedSha256 }.
  patch(patchBytes) {
    if (!this._snapshot) throw new Error('evasion patch REFUSED: no snapshot — the cleanup doctrine forbids writing bytes that cannot be restored');
    const p = Buffer.from(patchBytes);
    if (p.length !== this._snapshot.length) throw new RangeError('evasion patch REFUSED: patch is ' + p.length + ' bytes but the snapshotted region is ' + this._snapshot.length + ' — exact-span writes only');
    p.copy(this.mem, 0);
    if (!this.verify(p)) throw new Error('evasion patch FAILED: the re-read does not match the patch bytes — the write did not take (nothing claimed)');
    return { patchedSha256: sha256(p) };
  }
  // Re-read compare against an expected byte string. Pure observation.
  verify(expected) { return this.mem.equals(Buffer.from(expected)); }
  // Write the SNAPSHOT back and PROVE the restore (re-read compare == original bytes).
  // Returns { restoredSha256, restoreVerified } — restoreVerified is always true on
  // return; a failed restore THROWS (a lie about restoration is worse than a failure).
  restore() {
    if (!this._snapshot) throw new Error('evasion restore REFUSED: no snapshot exists — nothing was ever patched here');
    this._snapshot.copy(this.mem, 0);
    if (!this.mem.equals(this._snapshot)) throw new Error('evasion restore FAILED: the re-read does not match the original bytes — the region is NOT restored (loud failure, not a quiet lie)');
    return { restoredSha256: sha256(this._snapshot), restoreVerified: true };
  }
}

// Parse an agent evasion result body into the channel-side audit event, or null when
// the body is not a parseable evasion evidence JSON (a loud-text refusal, truncation,
// or a foreign body — the ledger preview already carries those; no event is fabricated
// from unverifiable data). Used by CallbackChannel._intakeResult.
export function parseEvasionEvidence(body) {
  let p;
  try { p = JSON.parse(String(body || '')); } catch { return null; }
  if (!p || typeof p !== 'object' || typeof p.op !== 'string' || !p.techniques || typeof p.techniques !== 'object') return null;
  const event = p.op === 'enable' ? 'evasion.applied' : p.op === 'restore' ? 'evasion.restored' : p.op === 'status' ? 'evasion.status' : null;
  if (!event) return null;
  const techniques = {};
  for (const [name, ev] of Object.entries(p.techniques)) {
    if (!ev || typeof ev !== 'object') continue;
    techniques[name] = {
      state: String(ev.state || 'unknown'),
      originalSha256: ev.originalSha256 || null,
      patchedSha256: ev.patchedSha256 || null,
      restoredSha256: ev.restoredSha256 || null,
      byteVerified: ev.byteVerified === true,
      restoreVerified: ev.restoreVerified === true,
      flipProven: !!(ev.verify && ev.verify.flipProven === true),
    };
  }
  // NO EVIDENCE, NO EVENT: an empty technique map means the body carried no per-
  // technique truth at all (a runner-level failure envelope, a truncated preview) —
  // the audit stream never fabricates an applied/restored claim from that.
  if (Object.keys(techniques).length === 0) return null;
  return { event, fields: { op: p.op, state: String(p.state || 'unknown'), pid: p.pid ?? null, techniques } };
}
