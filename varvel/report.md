# Post-Exploitation Report: MercadoLibre

## Target
- www.mercadolibre.com.ar
- api.mercadolibre.com

## Confirmed Findings (Provided)
1. TLS: overly broad wildcard certificate [med]
2. Missing clickjacking protection (X-Frame-Options / frame-ancestors) [low]
3. Cookie "_d2id" set without HttpOnly [low]
4. Cookie "_mldataSessionId" set without HttpOnly, SameSite [low]
5. Cookie "in_app" set without HttpOnly [low]
6. Version disclosure: Tengine [info]

## Artifacts Created
1. `clickjacking-poc.html` — Proof-of-concept HTML page demonstrating that www.mercadolibre.com.ar can be embedded in an iframe due to missing X-Frame-Options and CSP frame-ancestors directives.

## Limitation
- Execution environment (Bash/shell) is currently unavailable ("no sealed container is running"). 
- As a result, objective verification via curl, rendercheck, or cfride could not be performed.
- The PoC file was written to the workspace but could not be tested against the live target.

## Cleanup
- Remove `clickjacking-poc.html` from workspace.
