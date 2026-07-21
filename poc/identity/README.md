# PoC — identity hardening (SD-JWT · DPoP · SPIFFE)

The enforcement seam proved *what* gates access; this hardens *how identity is carried* — turning the demo's HMAC session into standards-based verifiable credentials, sender-constrained tokens, and workload identity between components. Real `node:crypto`, no dependencies.

## Run it

```bash
npm run demo
```

```
  1) SD-JWT clearance credential  — reveal the minimum, prove you hold it
     ✓ verifier learns clearance≥L3=true, and NOT the exact level / name / licenses (4 claims stay hidden)
     ✓ another verifier selectively gets exact clearance=L3 + licenses
     ✓ replayed presentation rejected (KB aud/nonce mismatch)
     ✓ forged "clearance=L5" disclosure rejected (not in _sd)
  2) DPoP-bound access token  — a stolen token is useless without the key
     ✓ legit request: proof key matches token binding (jkt) → allowed
     ✓ same proof replayed → rejected (jti already seen)
     ✓ stolen token used with attacker's key → rejected (jkt mismatch)
  3) SPIFFE workload identity  — the broker proves who it is to the PDP
     ✓ PDP authenticates the broker's SVID
     ✓ attacker self-signs the same SPIFFE ID → rejected (not signed by the trust domain)
     ✓ an unauthorized component → rejected
  IDENTITY: PASS ✓
```

## What each piece does

**SD-JWT clearances** ([`sd-jwt.mjs`](sd-jwt.mjs)) — **RFC 9901** (published Nov 2025). A clearance/license credential where each claim is a salted-hash digest; the holder reveals only what a given verifier needs. Two patterns matter here:
- **Prove "clearance ≥ L3" without leaking the exact level** — SD-JWT reveals claims atomically (no range predicate), so tiers are issued as **boolean claims** (`clearance_l3_plus: true`) and only the minimal one is disclosed.
- **Holder key binding (KB-JWT)** — the credential embeds the holder's key (`cnf`); a presentation carries a KB-JWT over a verifier `nonce`+`aud`, so a captured presentation **can't be replayed**. (This is the part most SD-JWT intros omit.)

**DPoP** ([`dpop.mjs`](dpop.mjs)) — **RFC 9449**. The access token is bound to a client-held key via `cnf.jkt`; each request carries a DPoP proof signed by that key. A stolen token used with a different key is rejected on the **jkt mismatch**, and replays are caught by a **jti** cache + `iat` window.

**SPIFFE** ([`spiffe.mjs`](spiffe.mjs)) — components carry short-lived **JWT-SVIDs** (`sub = spiffe://…`) signed by the trust domain; a peer verifies against the trust bundle and authorizes on the SPIFFE ID. A self-signed SVID fails (not signed by the trust domain); an unauthorized component's ID is rejected.

## Honest scope / production path

Real crypto and standards-correct flows, but these are compact PoCs. In production:
- **SD-JWT:** use **`@sd-jwt/core` + `@sd-jwt/sd-jwt-vc`** (OpenWallet Foundation); add decoy digests and a status list for revocation.
- **DPoP:** **`jose`** (`EmbeddedJWK` + `calculateJwkThumbprint`) on the resource server, **`dpop`** / **`oauth4webapi`** on the client; enforce the server `DPoP-Nonce` dance and `htu` normalization.
- **SPIFFE:** the canonical form is the **X.509-SVID** (SPIFFE ID in the cert's URI SAN) for **mTLS**, issued/rotated by **SPIRE** — which needs a cert lib (`@peculiar/x509` / OpenSSL) and a custom `node:tls` `checkServerIdentity` (Node ignores URI SANs by default).

Maps to [`docs/security-architecture.md`](../../docs/security-architecture.md) §4.
