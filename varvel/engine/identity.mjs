// VARVEL — operator identity (the console handoff).
//
// When VARVEL is opened FROM the Enclave console, the console hands off the operator
// exactly the way every other governed module receives it: two environment variables,
// `ENCLAVE_SESSION` (path to the signed session token) and `ENCLAVE_WORKSPACE_DIR`.
// Nothing about the operator is caller-supplied or typed into VARVEL — the identity is
// the cryptographically-signed one the Enclave already trusts.
//
// This module READS that identity and uses it to (a) show the operator who they are,
// (b) source the campaign's engagement scope from the SIGNED `engagementScope`, and
// (c) hand the agent a read-only "inform" block. It follows the Enclave's load-bearing
// rule to the letter: **clearance INFORMS, it never AUTHORIZES.** VARVEL surfaces the
// identity; the Enclave hook (which every live tool call already crosses) is the only
// thing that authorizes. If there is no session, VARVEL still opens — standalone/demo,
// with NO operator and no fabricated identity (lenient by design).

import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const __dir = dirname(fileURLToPath(import.meta.url));
const SEAM = join(__dir, '..', '..', 'poc', 'enforcement-seam'); // the Enclave enforcement seam

function unbound(source) {
  return { bound: false, verified: false, source, principal: null, sessionId: null, workspace: null, role: null, clearance: null, licenses: [], engagementScope: '', cidrs: [] };
}

function resolveAttrs(entities, principal) {
  if (!Array.isArray(entities)) return null;
  const e = entities.find((x) => x && x.uid && x.uid.type === 'User' && x.uid.id === principal);
  return e ? e.attrs || {} : null;
}

// Read the bound operator from the environment (the console handoff). Async because it
// loads the Enclave's own signature primitive — VARVEL verifies with the SAME code the
// hook uses, so its view can never drift from what's enforced.
export async function readOperator(env = process.env) {
  const sessionPath = env.ENCLAVE_SESSION;
  if (!sessionPath) return unbound('standalone'); // opened directly, not from the console

  let token;
  try { token = JSON.parse(readFileSync(sessionPath, 'utf8')); }
  catch { return unbound('session-unreadable'); }
  if (!token || !token.principal) return unbound('session-malformed');

  let verifySession, entities;
  try {
    ({ verifySession } = await import(pathToFileURL(join(SEAM, 'util.mjs')).href));
    entities = JSON.parse(readFileSync(join(SEAM, 'policy', 'entities.json'), 'utf8'));
  } catch {
    // Enclave core not reachable — trust nothing, present as unverified but name the principal.
    return { ...unbound('enclave-core-absent'), bound: true, principal: token.principal, sessionId: token.session_id || null, workspace: token.workspace || null };
  }

  const verified = !!verifySession(token);
  const attrs = verified ? resolveAttrs(entities, token.principal) : null; // only trust attrs for a verified binding
  const cidrs = String(token.engagementScope || '').split(',').map((s) => s.trim()).filter(Boolean);
  return {
    bound: true,
    verified,
    source: 'enclave-session',
    principal: token.principal,
    sessionId: token.session_id || null,
    workspace: token.workspace || null,
    role: attrs ? attrs.role || null : null,
    clearance: attrs ? (attrs.clearance ?? null) : null,
    licenses: attrs ? attrs.licenses || [] : [],
    engagementScope: token.engagementScope || '',
    cidrs,
  };
}

// Derive VARVEL's campaign scope from a VERIFIED operator's SIGNED engagement scope.
// Returns null when there is no trustworthy scope (standalone, unverified, or empty) —
// VARVEL still opens; there is simply nothing to target until a signed scope exists.
export function scopeForCampaign(op) {
  if (!op || !op.bound || !op.verified || !op.cidrs.length) return null;
  return {
    engagement: op.workspace || 'engagement',
    signedBy: `${op.principal} · ${op.role || 'operator'} · L${op.clearance ?? '?'}`,
    cidrs: op.cidrs.slice(),
    fromIdentity: true,
  };
}

// The read-only context VARVEL hands the agent — same shape/spirit as the Enclave's
// session-context "inform" block. It states facts; it grants nothing.
export function informBlock(op) {
  if (!op || !op.bound) {
    return '# VARVEL session — standalone (no bound operator). No engagement scope is in effect; the Enclave still governs every live tool call.';
  }
  const L = op.clearance == null ? '?' : `L${op.clearance}`;
  return [
    '# VARVEL session context — READ-ONLY, informational. This is NOT authorization.',
    `Operator: ${op.principal}${op.role ? ' · ' + op.role : ''} · clearance ${L}${op.verified ? '' : ' (UNVERIFIED session)'}`,
    op.licenses.length ? `Certifications: ${op.licenses.join(', ')}` : 'Certifications: (none on record)',
    `Workspace / engagement: ${op.workspace || '(none)'}`,
    `Signed engagement scope: ${op.cidrs.length ? op.cidrs.join(', ') : '(none — no offensive scope granted)'}`,
    'These facts INFORM how you work; they authorize nothing. Every tool call is checked',
    'server-side by the Enclave against the signed identity — you cannot argue past, reword,',
    'or bypass a denial. Operate only within the signed scope.',
  ].join('\n');
}

// Compact view for the console header / GET /api/identity (never leaks the signature).
export function publicIdentity(op) {
  return {
    bound: !!(op && op.bound),
    verified: !!(op && op.verified),
    source: op ? op.source : 'standalone',
    principal: op ? op.principal : null,
    role: op ? op.role : null,
    clearance: op ? op.clearance : null,
    licenses: op ? op.licenses : [],
    workspace: op ? op.workspace : null,
    scope: op ? op.cidrs : [],
  };
}
