// jws.mjs — a minimal JOSE toolkit (EdDSA / Ed25519) built on node:crypto, no deps.
// Ed25519 gives fixed 64-byte signatures, so there's no ECDSA DER↔JOSE conversion to
// get wrong. EdDSA is a registered JWS algorithm (RFC 8037); ES256 is also common in
// production — the flows are identical.

import { sign, verify, generateKeyPairSync, createPublicKey, createHash } from 'node:crypto';

export const b64url = buf => Buffer.from(buf).toString('base64url');
export const b64urlJson = obj => b64url(Buffer.from(JSON.stringify(obj)));
export const fromB64urlJson = s => JSON.parse(Buffer.from(s, 'base64url').toString());

export function genKey() { return generateKeyPairSync('ed25519'); }

export function signJWS(header, payload, privateKey) {
  const h = b64urlJson({ alg: 'EdDSA', ...header });
  const p = b64urlJson(payload);
  const input = h + '.' + p;
  const sig = b64url(sign(null, Buffer.from(input), privateKey));
  return input + '.' + sig;
}

export function verifyJWS(jws, publicKey) {
  const parts = String(jws).split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  let ok = false;
  try { ok = verify(null, Buffer.from(h + '.' + p), publicKey, Buffer.from(s, 'base64url')); } catch { return null; }
  return ok ? { header: fromB64urlJson(h), payload: fromB64urlJson(p) } : null;
}

export const headerOf = jws => fromB64urlJson(String(jws).split('.')[0]);
export const jwkOf = publicKey => publicKey.export({ format: 'jwk' });      // Ed25519 → {kty:'OKP',crv:'Ed25519',x}
export const keyFromJwk = jwk => createPublicKey({ key: jwk, format: 'jwk' });
// RFC 7638 JWK thumbprint (OKP: members crv,kty,x in lexicographic order)
export const thumbprint = jwk => b64url(createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest());
