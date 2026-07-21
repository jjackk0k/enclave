// spiffe.mjs — SPIFFE workload identity between backend components, as JWT-SVIDs.
// A SPIFFE ID is `spiffe://<trust-domain>/<path>`. Here each component gets a short-
// lived JWT-SVID (subject = its SPIFFE ID) signed by the trust domain's key; a peer
// verifies it against the trust bundle and authorizes on the SPIFFE ID (path == the
// principal). No secrets on disk; rotate by re-issuing before `exp`.
//
// Production note: the canonical SPIFFE form is the X.509-SVID (SPIFFE ID in the cert's
// URI SAN) used for mTLS — which needs a cert library (@peculiar/x509 / OpenSSL) and a
// custom node:tls checkServerIdentity (Node ignores URI SANs by default). JWT-SVID is
// the pure-node path and demonstrates the same identity + authz properties.

import { signJWS, verifyJWS } from './jws.mjs';

/** The trust domain (SPIRE server, in production) issues a short-lived SVID. */
export function issueSVID({ trustDomainKey, spiffeId, audience, iatSec, ttlSec = 3600 }) {
  return signJWS({ typ: 'JWT' }, { sub: spiffeId, aud: audience, iat: iatSec, exp: iatSec + ttlSec }, trustDomainKey.privateKey);
}

/** A peer verifies a presented SVID against the trust bundle + authorizes the SPIFFE ID. */
export function verifySVID(svid, trustBundlePubKey, { expectedAudience, authorizedIds, nowSec }) {
  const v = verifyJWS(svid, trustBundlePubKey);
  if (!v) return { valid: false, reason: 'not signed by the trust domain' };
  if (expectedAudience && v.payload.aud !== expectedAudience) return { valid: false, reason: 'wrong audience' };
  if (v.payload.exp && nowSec > v.payload.exp) return { valid: false, reason: 'SVID expired' };
  if (authorizedIds && !authorizedIds.includes(v.payload.sub)) return { valid: false, reason: `unauthorized SPIFFE ID (${v.payload.sub})` };
  return { valid: true, spiffeId: v.payload.sub };
}
