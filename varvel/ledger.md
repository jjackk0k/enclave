# Post-Exploitation Artifact Ledger — semrush
# Operator: marcus | Phase: post-exploitation
# Timestamp: current turn

## Infrastructure Status
- Bash/shell execution is UNAVAILABLE in this workload ("no sealed container is running").
- All remote probes (curl, cfcheck, cfride, originintel, etc.) are BLOCKED.
- Workspace file I/O (Read/Write/Edit) remains functional.

## Confirmed Findings Provided for Impact Demonstration
1. Missing Referrer-Policy header [info]
2. Version disclosure: nginx [info]
3. TLS: overly broad wildcard certificate [med]
4. Cookie "GCLB" set without Secure, SameSite [low]
5. Missing X-Content-Type-Options: nosniff [info]
6. Missing Content-Security-Policy header [low]
7. Cookie "ga_exp_0f461fe866144ef8a837d356" set without HttpOnly, Secure [low]
8. Cookie "PHPSESSID" set without SameSite [low]
9. Cookie "SSO-JWT" set without SameSite [low]
10. Cookie "GCLB" set without Secure, SameSite [low] (duplicate)

## Targets
- www.semrush.com
- mcp.semrush.com
- portal.myinsights.io
- ai-search.semrush.com

## Attempted Hypotheses & Verdicts
1. Chain cookie/header gaps with exposed API/admin endpoints (CSRF/XSS)
   - Status: UNTESTED. Cannot reach remote targets to probe /api, /graphql, /admin, /swagger.
2. Leverage TLS wildcard or nginx version disclosure for origin access
   - Status: UNTESTED. Cannot inspect certificates or perform originintel.
3. Confirm non-exploitable (passive-only) verdict via negative controls
   - Status: UNTESTED. Requires live endpoint interaction to run garbage/control payloads.

## Artifacts Dropped on Client/Target Systems
- NONE. No files, accounts, config changes, or persistent markers were placed on any in-scope host.
- All activity confined to this local workspace ledger.

## OPSEC Notes
- No outbound traffic generated due to execution environment failure.
- No risk of target outage, WAF trigger, or session pollution.
- Recommendation: Re-run post-ex phase after restoring sealed container to perform governed remote validation.
