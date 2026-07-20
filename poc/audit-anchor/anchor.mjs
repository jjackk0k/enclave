// anchor.mjs — publish a Merkle root to an EXTERNAL transparency log, signed by an
// independent authority. This is what makes the audit externally verifiable: the
// root is signed by a key Enclave does NOT hold and appended to a log outside
// Enclave's control (stands in for a transparency log — RFC 6962 / Trillian /
// Sigstore Rekor — or an RFC 3161 timestamp authority). Anyone with the authority's
// public key can later prove whether a given ledger state was the one anchored.

import { generateKeyPairSync, sign, verify } from 'node:crypto';

/** The external notary / transparency-log authority's keypair (Enclave never has the private key). */
export function makeAuthority() {
  return generateKeyPairSync('ed25519');
}

/** Sign + anchor a root. `tsIso` is passed in (no Date.* here). */
export function anchorRoot({ rootHex, count, tsIso, privateKey }) {
  const statement = { root: rootHex, count, ts: tsIso };
  const sig = sign(null, Buffer.from(JSON.stringify(statement)), privateKey).toString('hex');
  return { ...statement, sig };
}

/** Verify an anchor was signed by the authority (and not forged by Enclave). */
export function verifyAnchor(anchor, publicKey) {
  if (!anchor || !anchor.sig) return false;
  const { sig, ...statement } = anchor;
  try { return verify(null, Buffer.from(JSON.stringify(statement)), publicKey, Buffer.from(sig, 'hex')); }
  catch { return false; }
}
