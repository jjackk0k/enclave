// dpop.mjs — DPoP, Demonstrating Proof-of-Possession (RFC 9449). A stolen bearer
// token can be replayed by anyone; a DPoP-bound token can't. The client holds a
// key; each request carries a DPoP proof JWT signed by that key (with the public
// JWK in its header) and covering the method+URL. The access token is bound to the
// key's thumbprint (cnf.jkt), so the token only works when presented WITH a proof
// from the matching key. node:crypto only.

import { randomBytes } from 'node:crypto';
import { signJWS, verifyJWS, headerOf, jwkOf, keyFromJwk, thumbprint } from './jws.mjs';

/** The key's JWK thumbprint — what an access token is bound to (cnf.jkt). */
export const keyThumbprint = key => thumbprint(jwkOf(key.publicKey));

/** Client creates a DPoP proof for a specific request. `ath` binds a token hash. */
export function makeProof({ key, htm, htu, iatSec, ath }) {
  return signJWS(
    { typ: 'dpop+jwt', jwk: jwkOf(key.publicKey) },
    { htm, htu, iat: iatSec, jti: randomBytes(12).toString('base64url'), ...(ath ? { ath } : {}) },
    key.privateKey,
  );
}

/**
 * Server verifies a DPoP proof for the expected method/URL, optionally that it's
 * bound to `expectedJkt` (the token's cnf.jkt), with freshness + replay protection.
 */
export function verifyProof(proof, { htm, htu, expectedJkt, nowSec, seenJtis, maxAgeSec = 60 }) {
  let header;
  try { header = headerOf(proof); } catch { return { valid: false, reason: 'unparseable' }; }
  if (header.typ !== 'dpop+jwt' || !header.jwk) return { valid: false, reason: 'not a DPoP proof' };

  const v = verifyJWS(proof, keyFromJwk(header.jwk)); // signature must match the embedded key
  if (!v) return { valid: false, reason: 'bad signature' };
  const p = v.payload;
  if (p.htm !== htm || p.htu !== htu) return { valid: false, reason: 'method/URL mismatch (htm/htu)' };
  if (typeof p.iat !== 'number' || nowSec - p.iat > maxAgeSec) return { valid: false, reason: 'stale proof' };
  if (seenJtis) { if (seenJtis.has(p.jti)) return { valid: false, reason: 'replay (jti already seen)' }; seenJtis.add(p.jti); }

  const proofJkt = thumbprint(header.jwk);
  if (expectedJkt && proofJkt !== expectedJkt) return { valid: false, reason: 'key-binding mismatch (jkt): token not held by this key' };
  return { valid: true, jkt: proofJkt, payload: p };
}
