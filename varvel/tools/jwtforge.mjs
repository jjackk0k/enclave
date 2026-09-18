// VARVEL — native JWT toolkit for authorized engagements (shelf→native port #1).
//
// Origin: the k2.7 Axiom breach run wrote three generations of Python JWT minters on the
// fly (shelved: mint_token / mint_sandbox_admin / forge_token). This is the reviewed,
// tested, honest native port — the first full shelf→native cycle. What it does:
//
//   decode   — inspect a captured token: header/payload, alg, expiry, and the red flags
//              a red team looks for (alg=none, kid injection shapes, missing exp)
//   sign     — mint a correctly-signed HS256 token with a RECOVERED key (the Axiom chain:
//              key leaked from a client bundle → forge role:"admin")
//   verify   — confirm a candidate key actually validates a captured token (timing-safe),
//              so a "key recovered" claim is content-verified before it's reported
//
// Boundaries (the VARVEL line, offensive edition): this tool mints tokens ONLY with keys
// the operator already holds (recovered via recon) — it is not a brute-forcer and has no
// key-guessing path. Use is governed by the Enclave hook + signed scope like every other
// action, and offensive use belongs to the HITL-gated exploit phase.

import { createHmac, timingSafeEqual } from 'node:crypto';

// ——— base64url (JWT flavor: no padding) ———
export function b64uEncode(input) {
  return Buffer.from(typeof input === 'string' ? input : input).toString('base64url');
}
export function b64uDecode(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

// ——— decode + inspect (recon) ———
// Returns { header, payload, signature, alg, expired, issues } — never throws on junk;
// a malformed token reports validShape:false. Pure inspection, no trust decisions here.
export function decodeJwt(token) {
  const parts = String(token || '').split('.');
  // signature MAY be empty — that's exactly the alg=none shape we must not reject early
  if (parts.length !== 3 || !parts[0] || !parts[1]) return { validShape: false, issues: ['not a 3-part JWT'] };
  let header, payload;
  try { header = JSON.parse(b64uDecode(parts[0])); } catch { return { validShape: false, issues: ['bad header encoding'] }; }
  try { payload = JSON.parse(b64uDecode(parts[1])); } catch { return { validShape: false, issues: ['bad payload encoding'] }; }
  const issues = [];
  const alg = header.alg || null;
  if (!alg || /^none$/i.test(alg)) issues.push('alg=none — an acceptance check is warranted (strip the signature and replay)');
  if (header.kid && /(\.\.|[/\\]|'|--|;)/.test(String(header.kid))) issues.push('suspicious kid value — possible key-confusion/injection shape');
  if (!payload.exp) issues.push('no exp claim — token may never expire');
  const expired = payload.exp ? payload.exp * 1000 < Date.now() : null;
  return { validShape: true, header, payload, signature: parts[2], alg, expired, issues };
}

// ——— sign (exploit aid) ———
// Mint a correctly-signed HS256 JWT with a key the operator RECOVERED. `claims` is the
// full payload object (set sub/role/iss/exp yourself — this tool asserts nothing about
// what a legitimate claim set is; the engagement does).
export function signHs256(claims, key, { header = {} } = {}) {
  if (!key || typeof key !== 'string') throw new TypeError('signHs256: a recovered signing key (string) is required');
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw new TypeError('signHs256: claims must be an object');
  const h = b64uEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT', ...header }));
  const p = b64uEncode(JSON.stringify(claims));
  const sig = createHmac('sha256', key).update(h + '.' + p).digest('base64url');
  return h + '.' + p + '.' + sig;
}

// ——— verify (content-verified honesty) ———
// Timing-safe check that a candidate key validates a captured token. This is what turns
// "I think the leaked key works" into a CONFIRMED finding before the forge is attempted.
export function verifyHs256(token, key) {
  if (!key || typeof key !== 'string') return false;
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return false;
  const expected = createHmac('sha256', key).update(parts[0] + '.' + parts[1]).digest('base64url');
  const a = Buffer.from(expected), b = Buffer.from(parts[2]);
  return a.length === b.length && timingSafeEqual(a, b);
}
