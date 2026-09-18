---
name: JWT attacks
category: auth
keywords: [jwt, jwks, token, bearer, alg, none, hs256, rs256, kid, signature, claims, session]
---
JSON Web Tokens fail when the server trusts attacker-controllable header fields or verifies signatures weakly, letting an attacker forge or tamper with a token's claims.

## Where to look
- `Authorization: Bearer` headers, session cookies, and any three-part base64url `xxx.yyy.zzz` value.
- Decode the header/payload (they are not encrypted) and read `alg`, `kid`, `iss`, `exp`, and role/privilege claims.

## How to detect (tools + signals)
- alg:none — does the server accept an unsigned token (alg set to "none", signature stripped)? If a tampered claim is honored, verification is broken.
- Weak HMAC secret — attempt an offline dictionary check against the signature with `jwt_tool` or `hashcat` (mode 16500) using wordlists you are authorized to use.
- alg confusion (RS256 → HS256) — does the server verify an HS256 token using the public key as the HMAC secret?
- `kid` abuse — path traversal or SQL in the `kid` header pointing key selection at attacker-controlled data.

## How to confirm
- Flip a claim (e.g. a role or user id) and show the server acts on the forged value while returning success.
- Record which weakness enabled it (none/weak-secret/confusion/kid) — that is the finding, and it dictates the fix.

## Common variations
- Missing `exp` / no expiry; accepting expired tokens; `jku`/`x5u` pointing at an attacker JWKS URL.
- Token stored client-side and never invalidated server-side (see the auth-bypass playbook for session handling).
