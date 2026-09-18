# Red Team Engagement Report — MercadoLibre
## VARVEL Governed Assessment

**Date:** Engagement Closeout  
**Operator:** marcus (Red-Team-Lead · L4)  
**Scope:** 3.33.182.45/32, 15.197.170.90/32, 13.224.68.14/32, 13.224.68.42/32, 13.224.68.76/32, 13.224.68.61/32  
**Target Hosts:** www.mercadolibre.com.ar, api.mercadolibre.com (via scoped CDN edge infrastructure)

---

## 1. Executive Summary

This engagement assessed the attack surface of MercadoLibre CDN edge nodes and associated web properties. No critical or high-severity vulnerabilities were identified. The assessment surfaced one medium-severity configuration finding related to TLS certificate scope, four low-severity web-security header and cookie-flag gaps, and one informational server-banner disclosure. All findings are configuration-level and can be remediated without code changes. A clickjacking proof-of-concept artifact was generated during testing and is tracked for cleanup.

**Testing Limitation:** During the final synthesis phase, the sealed execution environment was unavailable. As a result, live re-verification via curl, rendercheck, cfride, or origin-intel tools could not be performed. Findings presented below are those documented during earlier active phases of the engagement and are reported as observed during that window.

---

## 2. Scope & Methodology

- **Reconnaissance:** Passive and active mapping of endpoints served by the scoped IPs.
- **Validation:** Header analysis, cookie inspection, TLS certificate review, and web-application configuration checks.
- **Exploitation / Post-Exploitation:** Proof-of-concept development for clickjacking; no exploitation of user data or disruptive testing was performed.

All testing remained within the signed IP scope. No real user data was accessed, and no outage-inducing activity was conducted.

---

## 3. Findings by Severity

| Severity | Finding | Host |
|----------|---------|------|
| **Medium** | Overly broad TLS wildcard certificate | www.mercadolibre.com.ar |
| **Low** | Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors) | www.mercadolibre.com.ar |
| **Low** | Cookie `_d2id` missing `HttpOnly` flag | www.mercadolibre.com.ar |
| **Low** | Cookie `_mldataSessionId` missing `HttpOnly` and `SameSite` flags | www.mercadolibre.com.ar |
| **Low** | Cookie `in_app` missing `HttpOnly` flag | www.mercadolibre.com.ar |
| **Info** | Web server version disclosure (Tengine) | www.mercadolibre.com.ar |

---

## 4. Detailed Findings & Evidence

### 4.1 MEDIUM — Overly Broad Wildcard TLS Certificate
- **Description:** The endpoint presents a wildcard TLS certificate (`*.mercadolibre.com.ar`) that is valid for an overly broad namespace. If the corresponding private key is shared across a large surface area, compromise of any single subdomain or tenant property could undermine trust for the entire wildcard scope.
- **Evidence:** TLS handshake observed during reconnaissance returned a wildcard SAN covering `*.mercadolibre.com.ar`.
- **Impact:** Key-exposure or mis-issuance events affecting one property could impact perceived trust across all subdomains under the wildcard.
- **Remediation (Priority 1):**
  - Migrate to certificates with narrowly scoped Subject Alternative Names (SANs) for each production subdomain.
  - If wildcards must be retained, ensure strict key segregation per environment (prod vs. non-prod) and monitor Certificate Transparency (CT) logs for unauthorized subdomains.

### 4.2 LOW — Missing Clickjacking Protection
- **Description:** The target endpoint does not return an `X-Frame-Options` header or a `Content-Security-Policy` with `frame-ancestors`, allowing the site to be embedded in third-party iframes.
- **Evidence:** HTTP response headers lacked `X-Frame-Options`. A proof-of-concept HTML page (`clickjacking-poc.html`) was created to demonstrate embeddability.
- **Impact:** Attackers could trick users into interacting with the application through a transparent overlay, leading to unintended actions.
- **Remediation (Priority 2):**
  - Add `X-Frame-Options: DENY` or `SAMEORIGIN` to all responses.
  - Alternatively, or additionally, deploy `Content-Security-Policy: frame-ancestors 'self';` (or a specific allow-list).

### 4.3 LOW — Cookie `_d2id` Missing HttpOnly Flag
- **Description:** The `_d2id` cookie is set without the `HttpOnly` attribute, making it accessible to JavaScript via `document.cookie`.
- **Evidence:** Set-Cookie header observed: `_d2id=<value>; ...` (no `HttpOnly` present).
- **Impact:** Increases the impact of cross-site scripting (XSS) by allowing script-based exfiltration of this identifier.
- **Remediation (Priority 3):**
  - Append `HttpOnly` to the `_d2id` cookie directive unless client-side JavaScript explicitly requires access to it.

### 4.4 LOW — Cookie `_mldataSessionId` Missing HttpOnly and SameSite
- **Description:** The `_mldataSessionId` cookie lacks both `HttpOnly` and `SameSite` attributes.
- **Evidence:** Set-Cookie header observed: `_mldataSessionId=<value>; ...` (neither `HttpOnly` nor `SameSite` present).
- **Impact:** Session or state tokens are more susceptible to XSS theft and cross-site request forgery (CSRF) via cross-origin POST/GET requests.
- **Remediation (Priority 4):**
  - Add `HttpOnly` to prevent JavaScript access.
  - Add `SameSite=Lax` at minimum (or `SameSite=Strict` if cross-site POST navigation is not required).

### 4.5 LOW — Cookie `in_app` Missing HttpOnly Flag
- **Description:** The `in_app` cookie is set without the `HttpOnly` attribute.
- **Evidence:** Set-Cookie header observed: `in_app=<value>; ...` (no `HttpOnly` present).
- **Impact:** Similar to Section 4.3 — broadens the blast radius of any XSS vector.
- **Remediation (Priority 5):**
  - Append `HttpOnly` to the `in_app` cookie directive.

### 4.6 INFO — Server Version Disclosure (Tengine)
- **Description:** HTTP responses disclose the use of `Tengine` (an Nginx fork) in the `Server` header.
- **Evidence:** `Server: Tengine` observed in responses.
- **Impact:** Informational only; provides minor assistance to attackers fingerprinting the software stack.
- **Remediation (Priority 6):**
  - Remove or genericize the `Server` header at the CDN / origin layer (e.g., `Server: web-server`).

---

## 5. Artifacts & Cleanup

| Artifact | Location | Description | Cleanup Action |
|----------|----------|-------------|----------------|
| Clickjacking PoC | `clickjacking-poc.html` | HTML page embedding target in an iframe to demonstrate missing framing protections | Remove file from workspace after client review |

**Note:** The PoC artifact contains no malicious payload and performs no automated interaction; it is a static HTML file for demonstration purposes. It should be deleted from the engagement workspace once the client has acknowledged the finding.

---

## 6. Prioritized Remediation Roadmap

1. **Immediate (0–14 days):** Scope review of the wildcard TLS certificate; reduce wildcard coverage or enforce strict key-management boundaries.
2. **Short-term (15–30 days):** Deploy `X-Frame-Options` and/or CSP `frame-ancestors` to eliminate clickjacking risk.
3. **Short-term (15–30 days):** Harden cookie flags (`HttpOnly`, `SameSite`) on `_d2id`, `_mldataSessionId`, and `in_app`. These are typically one-line configuration changes at the application or CDN layer.
4. **Ongoing / Best Practice:** Remove or mask the `Server` banner to reduce fingerprinting surface.

---

## 7. Conclusion

The scoped MercadoLibre edge infrastructure did not yield any critical or high-severity exploitable vulnerabilities during this engagement. The identified issues are common, well-understood web-security configuration gaps. Remediating the medium-severity TLS wildcard finding and the low-severity header/cookie issues will measurably reduce the application's attack surface. No persistent implants, malicious modifications, or data access occurred during testing.

---

*Report generated by VARVEL autonomous operator.*  
*Scope honored: 3.33.182.45/32, 15.197.170.90/32, 13.224.68.14/32, 13.224.68.42/32, 13.224.68.76/32, 13.224.68.61/32.*
