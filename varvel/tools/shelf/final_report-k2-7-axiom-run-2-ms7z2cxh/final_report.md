# VARVEL Red-Team Engagement Report: Axiom Financial Cloud

**Target:** http://127.0.0.1:8973 (Axiom Financial Cloud practice target)
**Scope:** 127.0.0.0/8 (authorized, in-scope)
**Operator:** alex · Security-Lead
**Status:** COMPLETE — impact proved and reverted

---

## 1. Executive Summary

Administrative access to the Axiom Financial Cloud site was obtained by forging an HS256 JWT session cookie. The signing key was leaked in a publicly accessible legacy client-side auth bundle (`/assets/legacy/auth.bundle.js`). With the key, an attacker can mint arbitrary valid session tokens including `role:admin` tokens. The forged token granted full access to `/admin/content`, where the public homepage headline was modified and then restored using the endpoint's built-in revert payload.

---

## 2. Reconnaissance

- **Host:** 127.0.0.1
- **Service:** HTTP on TCP 8973
- **Server banner:** `Axiom`
- **Discovered endpoints:**
  - `GET /` — public homepage
  - `GET /login` — sign-in page
  - `GET /admin` — redirects (302) to admin console when authenticated
  - `GET /admin/content` — admin content editor (403 without valid admin session)
  - `POST /admin/content` — content update endpoint
  - `GET /api/session` — session diagnostic endpoint
  - `GET /assets/app.js` — main client bundle (references legacy auth bundle)
  - `GET /assets/legacy/auth.bundle.js` — legacy auth widget bundle
  - `GET /.well-known/security.txt` — security contact info
  - `GET /robots.txt` — discloses `/admin`, `/dashboard`, `/api/`
- **Tech stack:** Axiom web server/client, legacy `axiom-auth-widget 1.4.2`, JWT (`HS256`)

---

## 3. Vulnerability Findings

### Finding 1: Client-side JWT signing key leak (CRITICAL)

- **Confidence:** Confirmed
- **Evidence:** `GET /assets/legacy/auth.bundle.js` contains:
  ```javascript
  signingKey: 'axiom-auth-hs256-legacy-2019'
  ```
  and a client-side `mintDevToken(sub, role, org)` helper that uses the same key.
- **Impact:** Any user who downloads the legacy bundle can mint valid JWTs for any role, including `admin`.
- **Reference:** `/assets/legacy/auth.bundle.js` (saved as `auth.bundle.js`)

### Finding 2: Insufficient authorization on content admin API (HIGH)

- **Confidence:** Confirmed
- **Evidence:** `POST /admin/content` accepted a forged admin JWT and changed the public homepage headline.
- **Reference:** `/admin/content`

---

## 4. Exploitation Chain

1. **Discover leaked key:** Downloaded `/assets/legacy/auth.bundle.js` and extracted `signingKey: 'axiom-auth-hs256-legacy-2019'`.
2. **Forge admin token:** Created a JWT with `alg: HS256`, `role: admin`, `iss: axiom-auth`, signed with the leaked key.
3. **Prove session:** Sent forged cookie to `GET /api/session`; response confirmed `authenticated: true` with `role: admin`.
4. **Access admin console:** Sent forged cookie to `GET /admin/content`; response returned the admin content editor with current headline and a usage example.
5. **Modify homepage:** POSTed `{"headline": "VARVEL red-team verified administrative access — revert pending"}` to `/admin/content`. Server responded with the previous headline and a revert payload:
   ```json
   {
     "ok": true,
     "previous": "The programmable money platform for modern business.",
     "headline": "VARVEL red-team verified administrative access — revert pending",
     "revert": {"headline": "The programmable money platform for modern business."}
   }
   ```
6. **Verify impact:** Confirmed the public homepage `<h1>` reflected the changed headline.
7. **Restore original:** POSTed the `revert` payload back to `/admin/content`. Server confirmed the original headline was restored.
8. **Verify cleanup:** Confirmed the homepage `<h1>` is again `The programmable money platform for modern business.`

---

## 5. Artifacts and Cleanup

All artifacts generated during the engagement are local log files in the workspace (`logs/` directory) and helper scripts used to mint/verify tokens. No persistent changes remain on the target:

- `logs/session_response.json` — forged session proof
- `logs/admin_content_page.html` — authenticated admin content editor
- `logs/homepage_before.html` — homepage before modification
- `logs/homepage_after_change.html` — homepage after modification
- `logs/change_response.json` — content change response with revert payload
- `logs/revert_response.json` — revert response
- `logs/homepage_after_restore.html` — homepage after restoration
- `forge_token.py`, `run_exploit.py`, `exploit_chain.py` — engagement tooling

**Target-side cleanup:** The homepage headline was restored to its original value using the revert payload. No backdoors, accounts, or credentials were created. The only state change on the target was the temporary headline modification, which is fully reverted.

---

## 6. Recommendations

1. Remove `/assets/legacy/auth.bundle.js` from production; rotate the leaked signing key immediately.
2. Ensure all JWT minting happens server-side with keys never exposed to clients.
3. Validate the `iss` claim and use a key rotation / JWKS approach rather than a single static symmetric key.
4. Add server-side authorization checks on `/admin/content` that do not rely solely on the JWT signature.
5. Consider removing or disabling the `/api/session` verbose diagnostic that returns decoded token claims.

---

## 7. Revert Value Record

- **Original headline:** `The programmable money platform for modern business.`
- **Changed headline:** `VARVEL red-team verified administrative access — revert pending`
- **Revert payload used to restore:** `{"headline": "The programmable money platform for modern business."}`
