// sd-jwt.mjs — Selective Disclosure JWT (RFC 9901, published Nov 2025), with holder
// Key Binding. The issuer signs a credential where sensitive claims are salted-hash
// digests in `_sd`; the values live in "Disclosures" the HOLDER keeps and reveals
// selectively. A Key-Binding JWT (bound to the holder's key via `cnf`) proves the
// presenter IS the holder and stops presentation replay.  node:crypto only.
//
// Note: SD-JWT reveals/hides a claim atomically — no native "≥" predicate. To prove
// "clearance ≥ L3" without leaking the exact level, issue tier BOOLEANS (clearance_l3_plus)
// as separate disclosable claims and reveal only the minimal one. (Range proofs = BBS+/ZKP.)

import { randomBytes, createHash } from 'node:crypto';
import { signJWS, verifyJWS, b64url, jwkOf, keyFromJwk } from './jws.mjs';

const digest = s => b64url(createHash('sha256').update(s).digest());

/** Issue. `disclosable` = selectively-disclosable claims. `holderPubKey` enables key binding. */
export function issue({ issuerKey, subject, disclosable = {}, alwaysVisible = {}, holderPubKey = null }) {
  const disclosures = {};
  const _sd = [];
  for (const [name, value] of Object.entries(disclosable)) {
    const salt = b64url(randomBytes(16)); // 128-bit salt, unique per disclosure
    const ds = b64url(Buffer.from(JSON.stringify([salt, name, value])));
    disclosures[name] = ds;
    _sd.push(digest(ds));
  }
  _sd.sort(); // don't leak claim order
  const payload = { sub: subject, ...alwaysVisible, _sd, _sd_alg: 'sha-256' };
  if (holderPubKey) payload.cnf = { jwk: jwkOf(holderPubKey) };
  return { sdjwt: signJWS({ typ: 'sd+jwt' }, payload, issuerKey.privateKey), disclosures };
}

/** Holder builds a presentation revealing only `reveal`; `kb` appends a Key-Binding JWT. */
export function present({ sdjwt, disclosures, reveal, kb = null }) {
  const selected = reveal.map(n => disclosures[n]).filter(Boolean);
  let pres = [sdjwt, ...selected].join('~') + '~';
  if (kb) {
    const sd_hash = digest(pres);
    pres += signJWS({ typ: 'kb+jwt' }, { aud: kb.aud, nonce: kb.nonce, iat: kb.iatSec, sd_hash }, kb.holderKey.privateKey);
  }
  return pres;
}

/** Verify issuer signature + revealed disclosures, and (if `kb`) the holder key binding. */
export function verify({ presentation, issuerPubKey, kb = null }) {
  const endsTilde = presentation.endsWith('~');
  const segments = presentation.split('~');
  const kbjwt = endsTilde ? null : segments.pop();
  const parts = segments.filter(Boolean);

  const v = verifyJWS(parts[0], issuerPubKey);
  if (!v) return { valid: false, reason: 'bad issuer signature' };

  const sd = new Set(v.payload._sd || []);
  const revealed = {};
  for (const d of parts.slice(1)) {
    if (!sd.has(digest(d))) return { valid: false, reason: 'a disclosure is not in _sd (forged/tampered)' };
    const [, name, value] = JSON.parse(Buffer.from(d, 'base64url').toString());
    revealed[name] = value;
  }

  if (kb) {
    if (!v.payload.cnf?.jwk) return { valid: false, reason: 'credential is not key-bound (no cnf)' };
    if (!kbjwt) return { valid: false, reason: 'key binding required but no KB-JWT presented' };
    const kv = verifyJWS(kbjwt, keyFromJwk(v.payload.cnf.jwk));
    if (!kv || kv.header.typ !== 'kb+jwt') return { valid: false, reason: 'bad holder key-binding signature' };
    if (kv.payload.aud !== kb.expectedAud || kv.payload.nonce !== kb.expectedNonce) return { valid: false, reason: 'KB aud/nonce mismatch (replay?)' };
    if (kb.nowSec - kv.payload.iat > (kb.maxAgeSec || 120)) return { valid: false, reason: 'stale key-binding proof' };
    const presented = [parts[0], ...parts.slice(1)].join('~') + '~';
    if (kv.payload.sd_hash !== digest(presented)) return { valid: false, reason: 'sd_hash mismatch (presentation altered)' };
  }

  const { _sd, _sd_alg, cnf, ...visible } = v.payload;
  return { valid: true, subject: v.payload.sub, revealed, visible, keyBound: !!kb, hiddenCount: (v.payload._sd || []).length - parts.slice(1).length };
}
