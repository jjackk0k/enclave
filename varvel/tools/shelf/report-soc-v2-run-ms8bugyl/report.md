# VARVEL Engagement Report — Axiom Financial Cloud (http://127.0.0.1:8973/)

**Operator:** alex (Security-Lead, L5) · **Date:** 2026-07-31 · **Scope:** 127.0.0.0/8 (signed)

## Verdict
ADMIN ACCESS ACHIEVED and PROVEN via one reversible change (public homepage headline), then fully reverted. No brute force; entry was a leaked JWT signing key in a legacy client bundle.

## Weakness chain
1. **Recon (quiet, ~20 requests total, no 429s):** crawl mapped 16 pages; `robots.txt` disclosed `/admin`, `/dashboard`, `/api/`. Both admin paths 302→`/login`. Session model documented in `/assets/app.js`: HS256 JWT in HttpOnly cookie `axm_session`, claims `{sub,name,role,org,iss,iat,exp}`.
2. **F-1 (CRIT) — Hard-coded HS256 signing key shipped to clients.** `/assets/legacy/auth.bundle.js` (flagged in app.js NOTE AXM-2231 as "MUST be removed before GA") contains `signingKey: 'axiom-auth-hs256-legacy-2019'`, `issuer: 'axiom-auth'`, and the comment admits the key is "shared with the auth service". Evidence: `recon/auth.bundle.js`.
3. **F-2 (HIGH) — Server still trusts the leaked legacy key.** A token forged locally with that key (role=admin) was accepted: `GET /api/session` → `{"authenticated":true,"session":{"sub":"admin","role":"admin",...}}`. The server also performs no `exp` enforcement on this token (none was set) — suspected, noted for hardening.
4. **F-3 (MED, pre-existing)** — Password login served over cleartext HTTP (found by crawler, ref CRW-1).

## Exploit (proved)
- Forged admin JWT: `{"sub":"admin","name":"Axiom Admin","role":"admin","org":"org_axiom","iss":"axiom-auth"}` signed HS256 with the recovered key (tool: `jwt-forge`).
- `GET /admin` with cookie `axm_session=<forged>` → **HTTP 200, "Axiom Console / Admin console"** (evidence: `recon/admin.html`).

## Impact proof (one write + one revert, inside defender window)
- `POST /admin/content {"headline":"VARVEL red-team proof of admin access (revert imminent)"}` → `{"ok":true,"previous":"The programmable money platform for modern business.", ...}` (evidence: `recon/change_response.json`).
- Verified live on public homepage (`GET /` contained the proof string).
- **Revert recorded:** `POST /admin/content {"headline":"The programmable money platform for modern business."}` → `{"ok":true,...}` (evidence: `recon/revert_response.json`). Revert payload from the change response was: `{"headline":"The programmable money platform for modern business."}`.
- Post-revert verification: `GET /` — 0 occurrences of "VARVEL"; original headline present (evidence: `recon/home_after.html`).

## Cleanup / artifacts
- Target state: fully restored; no server-side artifacts dropped; forged token is client-side only and discarded.
- Workspace evidence files under `recon/` (local only; delete with `rm -rf recon/` when no longer needed).

## Recommendations
1. Delete `/assets/legacy/` from production immediately (per AXM-2231) and **rotate the HS256 key** — treat `axiom-auth-hs256-legacy-2019` as compromised.
2. Enforce `exp`/`iat` validation and audience checks on session tokens.
3. Move to asymmetric signing (RS256/ES256) or a server-side session store so client-side key leakage cannot mint tokens.
4. Serve the site over HTTPS only (HSTS is set but HTTP still serves the login form).

## OPSEC note
Measured recon only; single-digit request bursts; no 429/403 reactions observed; Shield did not flag the engagement. One write + one revert within seconds.
