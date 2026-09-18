// VARVEL — the in-memory execution tier (gap #4 remainder): governance core.
//
// What this is: the 'inline-dotnet' task kind executes an authorized .NET assembly
// IN THE AGENT PROCESS'S OWN MEMORY — [Reflection.Assembly]::Load(byte[]) + entry-point
// invoke, output captured, result riding the normal governed task/result path. This is
// the standard nation-grade capability (Cobalt's execute-assembly class), built the
// VARVEL way: gated, audited, measured.
//
// Governance (three seams, all fail-closed):
//   1. ENGAGEMENT GATE — settings key 'exec.inMemory' (default OFF). The channel refuses
//      to queue inline-dotnet unless the engagement explicitly enabled it. Refusal is
//      loud and audited (task.refused), never a silent drop.
//   2. SPEC GATE — the task data must parse: valid base64, non-empty, at most
//      MAX_INLINE_ASSEMBLY_BYTES. Refused BEFORE queueing; nothing oversize ever rides
//      the wire.
//   3. AUDIT — a queued inline-dotnet task emits 'exec.inline-dotnet' with the sha256 of
//      the assembly BYTES. The bytes never hit disk anywhere; the hash is the whole
//      accountability trail (what ran, provably, after the fact).
//
// DOCTRINE (2026-08-12, operator directive): the old absolute no-evasion rule is LIFTED
// for the governed evasion tier ONLY (engine/evasion.mjs — default-OFF, double-gated,
// patch-verified, restorable, detoracle-measured). BY DEFAULT nothing is patched: the
// assembly loads in the agent's OWN process and AMSI/Defender may scan the byte[] load —
// detectability is MEASURED by the detection oracle (tools/detoracle.mjs via
// tools/execasm.mjs), never dodged silently.
//
// Size cap rationale: 1 MiB of assembly ≈ 1.4 MB of base64 inside the task JSON — well
// under the channel's 4 MB body cap, and the honest ceiling for the governed transports
// (http/ws/smb carry it fine; the 96-byte-chunk codec wires — dns/icmp — would fragment
// it into thousands of queries, so those carriers are documented as impractical, not
// blocked). Legitimate inline tooling (seatbelt-class recon, hunters) fits in 1 MiB.

import { createHash } from 'node:crypto';
import { Settings } from './settings.mjs';

export const INLINE_DOTNET_KIND = 'inline-dotnet';
export const MAX_INLINE_ASSEMBLY_BYTES = 1024 * 1024; // 1 MiB — see the header rationale
export const MAX_INLINE_ARGS = 64;
export const MAX_INLINE_ARG_LEN = 4096;

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// Parse + validate an inline-dotnet task-data string. Returns
// { bytes, b64, sha256, args, entryPoint } or THROWS (TypeError/RangeError) with a loud,
// operator-readable reason. Pure: no I/O, no settings — the same parse runs server-side
// (pre-queue refusal) and agent-side (pre-execution refusal).
export function parseInlineSpec(data) {
  let spec;
  try { spec = JSON.parse(String(data ?? '')); } catch {
    throw new TypeError('inline-dotnet: task data is not valid JSON (want {"assemblyB64":"<base64>","args":[],"entryPoint"?})');
  }
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) throw new TypeError('inline-dotnet: task data must be a JSON object');
  const b64 = String(spec.assemblyB64 || '');
  if (!b64) throw new TypeError('inline-dotnet: assemblyB64 is required (base64 of the .NET assembly bytes)');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) throw new TypeError('inline-dotnet: assemblyB64 is not valid base64');
  const bytes = Buffer.from(b64, 'base64');
  if (!bytes.length) throw new TypeError('inline-dotnet: assemblyB64 decodes to zero bytes — nothing to execute');
  if (bytes.length > MAX_INLINE_ASSEMBLY_BYTES) {
    throw new RangeError('inline-dotnet: assembly is ' + bytes.length + ' bytes — over the ' + MAX_INLINE_ASSEMBLY_BYTES + '-byte cap (nothing executed)');
  }
  if (spec.args !== undefined && !Array.isArray(spec.args)) throw new TypeError('inline-dotnet: args must be an array when given');
  const args = (spec.args || []).map(String);
  if (args.length > MAX_INLINE_ARGS) throw new RangeError('inline-dotnet: ' + args.length + ' args is over the ' + MAX_INLINE_ARGS + '-arg cap');
  for (const a of args) if (a.length > MAX_INLINE_ARG_LEN) throw new RangeError('inline-dotnet: an arg exceeds the ' + MAX_INLINE_ARG_LEN + '-char cap');
  const entryPoint = spec.entryPoint == null ? '' : String(spec.entryPoint).slice(0, 300);
  return { bytes, b64, sha256: sha256(bytes), args, entryPoint };
}

// The engagement gate. Returns { ok: true } or { ok: false, reason } — fail-CLOSED on any
// settings-layer error (a gate that cannot read its setting does not run). engagement
// comes from the channel's signed scope, so the gate follows the engagement the channel
// was armed under.
export function inlineDotnetGate(engagement) {
  let on = false;
  try { on = Settings.for(engagement || 'default').get('exec.inMemory') === true; } catch { on = false; }
  if (!on) {
    return {
      ok: false,
      reason: "engagement setting 'exec.inMemory' is OFF — in-memory execution is disabled. "
        + "An operator must explicitly enable it for engagement '" + (engagement || 'default') + "' "
        + "(POST /api/settings {key:'exec.inMemory', value:true}) before inline-dotnet tasks will queue. Nothing executed.",
    };
  }
  return { ok: true };
}
