// util.mjs — small primitives shared by the hook: session signing/verification,
// CIDR scope checks, and the hash-chained audit ledger.

import { createHmac, createHash } from 'node:crypto';
import { appendFileSync, readFileSync, existsSync } from 'node:fs';
import { inCidr, inAnyCidr } from '../../varvel/engine/ipaddr.mjs';

// --- Session binding -----------------------------------------------------------
// DEMO ONLY: sessions are signed with an HMAC and a fixed key so the PoC is
// self-contained. In production this is an asymmetric signature from the IdP
// (short-lived, DPoP-bound) — the verification step is identical in spirit:
// the hook trusts the SIGNED session, never the tool input or the model.
const DEMO_KEY = 'enclave-demo-session-key-not-for-production';

export function canonicalSession(s) {
  return [s.session_id, s.principal, s.workspace, s.engagementScope || ''].join('|');
}
export function signSession(s) {
  return 'hmac-sha256:' + createHmac('sha256', DEMO_KEY).update(canonicalSession(s)).digest('hex');
}
export function verifySession(s) {
  if (!s || !s.sig) return false;
  const expected = signSession(s);
  // constant-length compare
  return s.sig.length === expected.length && s.sig === expected;
}

// --- CIDR (IPv4 + IPv6) ----------------------------------------------------------
// Scope math is SHARED with the VARVEL engine (varvel/engine/ipaddr.mjs): one
// audited implementation for every scope decision on the platform — dual-stack,
// family-strict (a v4 CIDR never matches a v6-native address), strict masks (the
// old bits>32 shift-wrap is gone: out-of-range masks are rejected, never coerced).
export const ipInCidr = (ip, cidr) => inCidr(ip, cidr);
export const ipInAnyScope = (ip, scope) => inAnyCidr(ip, scope);

// --- Hash-chained audit ledger -------------------------------------------------
// Each line embeds the SHA-256 of the previous line, so any edit/reorder/delete
// breaks the chain and is detectable. This mirrors the WORM+Merkle ledger in
// docs/security-architecture.md, minus the external anchoring.
export function ledgerTip(path) {
  if (!existsSync(path)) return 'GENESIS';
  const lines = readFileSync(path, 'utf8').trim().split('\n').filter(Boolean);
  if (!lines.length) return 'GENESIS';
  return JSON.parse(lines[lines.length - 1]).entry_hash;
}
export function appendAudit(path, event) {
  const prev_hash = ledgerTip(path);
  const record = { ...event, prev_hash };
  const entry_hash = createHash('sha256').update(prev_hash + JSON.stringify(record)).digest('hex');
  appendFileSync(path, JSON.stringify({ ...record, entry_hash }) + '\n');
  return entry_hash;
}
export function verifyLedger(path) {
  if (!existsSync(path)) return { ok: true, count: 0 };
  const lines = readFileSync(path, 'utf8').trim().split('\n').filter(Boolean);
  let prev = 'GENESIS';
  for (let i = 0; i < lines.length; i++) {
    const rec = JSON.parse(lines[i]);
    const { entry_hash, ...body } = rec;
    if (body.prev_hash !== prev) return { ok: false, brokenAt: i, reason: 'prev_hash mismatch' };
    const recomputed = createHash('sha256').update(prev + JSON.stringify(body)).digest('hex');
    if (recomputed !== entry_hash) return { ok: false, brokenAt: i, reason: 'entry_hash mismatch' };
    prev = entry_hash;
  }
  return { ok: true, count: lines.length };
}
