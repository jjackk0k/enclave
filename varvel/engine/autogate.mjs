// VARVEL — autogate: operator PRE-AUTHORIZATION for the sigil (HITL) gates.
//
// The problem (Jack, 2026-08-27): the exploit/post-ex phases hold for a human
// countersignature — correctly — but an operator who steps away turns every gated
// campaign into a parked process. The answer is NOT a standing auto-approve (that is
// the gate's abolition by another name). It is a GRANT: a time-boxed, phase-allowlisted,
// count-capped, scope-bound delegation the operator mints deliberately, the way a human
// deputy would be briefed — "for the rest of today, on the signed engagement, these two
// phases, at most N times."
//
// Strict-as-a-human, encoded (each rule is a check in decide(), none is optional):
//   1) SIGNED SCOPE ONLY — a campaign whose scope carries no signer or no CIDRs is
//      never auto-approved. A human countersigns fire at targets somebody signed for;
//      nobody deputizes fire at the unsigned.
//   2) PHASE ALLOWLIST — a grant names its phases, and the only phases a grant may ever
//      name are the sigil-gated pair (exploit, postex). Recon/validate were never gated;
//      nothing else becomes auto-approvable by editing a file.
//   3) HARD EXPIRY — every grant carries expiresAt; creation caps at MAX_HOURS (24).
//      Pre-authorization is a TODAY mechanism, never a standing one.
//   4) COUNT CAP — maxGrants bounds total auto-approvals; a human who approved 8 phases
//      without looking would stop at 8. Exhaustion refuses, loudly.
//   5) FULL AUDIT — every decided auto-gate (approved AND refused) appends one JSONL
//      line to data/autogate-log.jsonl, and the campaign event feed carries
//      gate.auto / gate.auto.refused. The operator reviews the whole trail on return.
//   6) INSTANT REVOCATION — `cli.mjs autogate revoke` deletes the file; the very next
//      gate falls through to the human hook. No restart, no cache.
//
// What autogate does NOT do (honesty, named): it does not judge individual actions
// inside a phase — the Enclave's L2 hook still gates every tool call (scope, DLP,
// audit), the validator still fail-closes out-of-scope re-reads, and the noise budget
// still counts gated-phase traffic. A refusal here NEVER blocks the human path: any
// non-approval falls through to hooks.approve unchanged. And the read-modify-write on
// `used` is not transactional — concurrent campaigns on one box could over-spend the
// cap by a race; the cap is a seatbelt, not a security boundary (single-operator
// doctrine: campaigns serialize per engagement in practice).
//
// No model call anywhere in this module. Fail-closed everywhere: a missing, malformed,
// expired, exhausted, or mis-scoped grant is simply not an approval.

import { readFileSync, writeFileSync, appendFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const FILE = () => process.env.VARVEL_AUTOGATE_FILE || join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'autogate.json');
const LOG = () => process.env.VARVEL_AUTOGATE_LOG || join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'autogate-log.jsonl');

export const paths = () => ({ file: FILE(), log: LOG() });

export const MAX_HOURS = 24;   // a grant is a work-shift delegation, never a regime
export const MAX_GRANTS = 32;  // the cap on the cap itself
export const GATED_PHASES = ['exploit', 'postex']; // the only phases a grant may name

// Build a grant object, validated. Throws (loudly, at CREATION time — never silently
// clamp a delegation) on anything outside the doctrine bounds.
export function createGrant({ hours = 12, max = 8, phases = GATED_PHASES, principal = 'operator', note = '', now = Date.now() } = {}) {
  const h = Number(hours);
  if (!Number.isFinite(h) || h <= 0 || h > MAX_HOURS) throw new RangeError(`hours must be 1..${MAX_HOURS} — pre-authorization is a TODAY mechanism`);
  const m = Number(max);
  if (!Number.isInteger(m) || m < 1 || m > MAX_GRANTS) throw new RangeError(`max must be an integer 1..${MAX_GRANTS}`);
  const ph = (Array.isArray(phases) ? phases : [phases]).map((s) => String(s).trim()).filter(Boolean);
  if (!ph.length) throw new TypeError('phases must name at least one gated phase');
  const bad = ph.filter((p) => !GATED_PHASES.includes(p));
  if (bad.length) throw new TypeError(`phases ${bad.join(', ')} are not sigil-gated — a grant may only name ${GATED_PHASES.join(', ')}`);
  const who = String(principal || '').trim();
  if (!who) throw new TypeError('principal must name the operator delegating');
  return {
    id: 'ag-' + randomBytes(4).toString('hex'),
    principal: who,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + h * 3600000).toISOString(),
    phases: [...new Set(ph)],
    maxGrants: m,
    used: 0,
    note: String(note || ''),
  };
}

// Shape-validated load. Missing or malformed = null = no grant = the default state.
export function loadGrant(file = FILE()) {
  let g;
  try { g = JSON.parse(readFileSync(file, 'utf8')); } catch { return null; }
  if (!g || typeof g !== 'object') return null;
  if (typeof g.id !== 'string' || !g.id) return null;
  if (typeof g.principal !== 'string' || !g.principal) return null;
  if (!Number.isFinite(Date.parse(g.expiresAt || ''))) return null;
  if (!Array.isArray(g.phases) || !g.phases.length || g.phases.some((p) => typeof p !== 'string')) return null;
  if (!Number.isInteger(g.maxGrants) || g.maxGrants < 1) return null;
  if (!Number.isInteger(g.used) || g.used < 0) return null;
  return g;
}

export function saveGrant(grant, file = FILE()) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(grant, null, 2));
}

export function revokeGrant(file = FILE()) {
  try { rmSync(file); return true; } catch { return false; }
}

function audit(entry, logFile = LOG()) {
  try { mkdirSync(dirname(logFile), { recursive: true }); appendFileSync(logFile, JSON.stringify(entry) + '\n'); } catch { /* audit must never break the gate */ }
}

// The decision, pure: given a grant, a phase, and the campaign's scope — approve or
// name the single refusal reason. Scope-signed means a SIGNER and at least one CIDR:
// the running server sources both from the HMAC-signed session token (engine/identity).
export function decide(grant, phaseId, scope, { now = Date.now() } = {}) {
  if (!grant.phases.includes(phaseId)) return { ok: false, reason: 'phase-not-allowlisted' };
  if (now >= Date.parse(grant.expiresAt)) return { ok: false, reason: 'expired' };
  if (grant.used >= grant.maxGrants) return { ok: false, reason: 'exhausted' };
  const signed = !!(scope && scope.signedBy && Array.isArray(scope.cidrs) && scope.cidrs.length);
  if (!signed) return { ok: false, reason: 'unsigned-scope' };
  return { ok: true };
}

// The gate-side entry point (Campaign._approve): load, decide, and when a grant EXISTS,
// audit the decision either way — a refused auto-gate with a grant on file is exactly
// what the operator wants to see on return. No grant on file is the default state and
// writes nothing. Approvals spend from the cap BEFORE returning.
export function autoApprove(phaseId, scope, { now = Date.now(), file = FILE(), logFile = LOG() } = {}) {
  const grant = loadGrant(file);
  if (!grant) return { ok: false, reason: 'no-grant' };
  const d = decide(grant, phaseId, scope, { now });
  const entry = {
    at: new Date(now).toISOString(), grant: grant.id, phase: phaseId,
    engagement: (scope && scope.engagement) || null,
    decision: d.ok ? 'approved' : 'refused', reason: d.ok ? null : d.reason,
  };
  if (d.ok) {
    grant.used += 1;
    try { saveGrant(grant, file); } catch { /* a lost spend re-prompts the human — fail-closed is preserved either way */ }
    entry.remaining = grant.maxGrants - grant.used;
  }
  audit(entry, logFile);
  return d.ok ? { ok: true, grant: grant.id, remaining: entry.remaining } : { ok: false, reason: d.reason, audited: true };
}

// Operator-facing status: none | active | expired | exhausted, with what's left.
export function statusGrant({ now = Date.now(), file = FILE() } = {}) {
  const grant = loadGrant(file);
  if (!grant) return { state: 'none', read: 'no grant on file — sigil gates are human-only' };
  const remaining = grant.maxGrants - grant.used;
  const state = now >= Date.parse(grant.expiresAt) ? 'expired' : remaining <= 0 ? 'exhausted' : 'active';
  return {
    state, grant, remaining,
    read: state === 'active'
      ? `grant ${grant.id} active until ${grant.expiresAt} — phases ${grant.phases.join('/')}, ${remaining} approval(s) left, signed scope only`
      : `grant ${grant.id} is ${state} — sigil gates are human-only again`,
  };
}
