# Zomato MCP Server (mcp-server.zomato.com) — OAuth/DCR/MCP Probe — 2026-08-31

**Scope:** Tier 1 in-scope. All traffic via ghost `socks5://10.64.0.1:1080`, header `X-HackerOne: varvel`, fail-closed.
**Accounts:** A `varvel-zom-a-sl0i@emalupe.com` (uid 447585412), B `varvel-zom-b-qpbw@emalupe.com` (uid 447585565) — both provisioned/verified 2026-08-31.
**Verdict: CLEAN.** No finding met the bar (captured bytes + working differential). No submission drafted.
Raw captures: `.tmp/mcp-flow-*.json`, `.tmp/mcp-pkce-own-pair-1.json`, `.tmp/mcp-pkce-acctB-1.json`, `.tmp/mcp-token-t*.json`, `.tmp/mcp-tools-A.json`, `.tmp/mcp-cross-account.json`, `.tmp/mcp-idor-probe.json`, `.tmp/mcp-tools-list-full.txt`.

## AS metadata
- Issuer `https://mcp-server.zomato.com/`; endpoints `/authorize`, `/token`, `/register`
- Grants: `authorization_code`, `refresh_token`; PKCE `code_challenge_methods_supported: ["S256"]`
- Token endpoint auth methods include `"none"` (public client)

## Probe matrix (tried → exact response)

| # | Hypothesis | Action | Exact response | Verdict |
|---|-----------|--------|----------------|---------|
| 1 | DCR abuse (attacker redirect_uris, localhost, junk) | `POST /register` with hostile metadata | HTTP 200, **static** `client_id fd37dd28-254b-42b7-a55a-c85369d625c8`, `client_secret "Z-MCP"`, echoes caller's redirect_uris. Stateless facade — nothing is actually registered | Odd, harmless (public client; no privileged client creatable) |
| 2 | redirect_uri validation at authorize | `GET /authorize?...redirect_uri=<attacker>` | 307 → `/consent?login_challenge=<hex>&...&redirect_uri=<verbatim>` — carried unvalidated at this hop | Deferred to verify-otp |
| 3 | redirect_uri bypass ×7 | Full chain (authorize→consent→login→OTP→verify-otp) with: trycloudflare tunnel, `claude.ai.evil.example.com`, userinfo trick `claude.ai@tunnel`, path traversal `/api/mcp/auth_callback/../../cb`, scheme downgrade `http://`, trailing dot `claude.ai.`, decoy param `?next=https://claude.ai/...` | All 7: HTTP 403 `{"error":"Invalid redirect_uri parameter"}` | CLEAN — exact-match allowlist |
| 4 | allowlist control | Same chain, `https://claude.ai/api/mcp/auth_callback` | HTTP 200 `{"redirect_uri":"https://claude.ai/api/mcp/auth_callback?code=<code>&state=..."}` | Baseline confirmed |
| 5 | PKCE enforcement | `/token` with real code + missing verifier / wrong verifier / bogus client_id / correct RFC7636 verifier | All wrong variants: 400 `{"error":"Missing or invalid code_verifier for token exchange"}` (PKCE checked before client lookup). Correct verifier on fresh code: **HTTP 200 token** | CLEAN — PKCE enforced |
| 6 | Code reuse | Second redemption of same code | 500 `{"error":"Failed to exchange token"}` | CLEAN — single use |
| 7 | Refresh grant | `grant_type=refresh_token` | 400 demanding `code_verifier`; with any value (even `x`) → 200 new access token | Nonstandard spec deviation; refresh_token still required — no security impact |
| 8 | Scope coercion | Requested `scope=mcp:tools` | Granted `scope:"offline openid"` (token still valid at `/mcp`) | Cosmetic |
| 9 | `/mcp` unauth | `POST /mcp` without token | 401 | CLEAN |
| 10 | MCP with token (A) | `initialize`, `tools/list` | 200 SSE. Server `ZomatoMcpServer 3.1.0`, protocol `2025-03-26`. 10 tools: `get_restaurants_for_keyword`, `get_restaurant_menu_by_categories`, `get_menu_items_listing`, `get_saved_addresses_for_user`, `bind_user_number`, `bind_user_number_verify_code`, `create_cart`, `checkout_cart`, `get_order_history`, `get_order_tracking_info` | Catalogued |
| 11 | Cross-account read | A-token and B-token: `get_saved_addresses_for_user`, `get_order_tracking_info`, `get_order_history` | Both accounts: own (empty) data, `success:true`. No tool accepts a `user_id`/identity param — tools are token-scoped | CLEAN (see caveat) |
| 12 | IDOR via address_id | `get_order_history` with fabricated ids `1,2,100,1000000,55000000,99999999,nonexistent` under both tokens | Identical for A and B: `{"error_code":"INVALID_ADDRESS_ID","error_message":"Could not resolve the provided address ID to a valid location."}` (2 probes empty = transport timeouts, neighbors consistent). Small-integer guesses unresolvable → IDs non-sequential | CLEAN — no oracle |
| 13 | Cross-account cart | `checkout_cart` with fabricated cart_id under both tokens | Identical: `{"success":false,"message":"Please create a cart before checkout."}` | CLEAN — no oracle |

## Caveats (honest limits)
- Both test accounts have **no seeded data** (no saved addresses, no orders; no tool exists to add an address, and placing a real COD order to seed one was judged disproportionate). The strong-form test — B's token reading A's *actual* address_id — was therefore not executable. Mitigating facts: no tool takes a user identifier; the only cross-account handle is `address_id`, which is non-sequential and only obtainable from the victim's own token-bound `get_saved_addresses_for_user`.
- `bind_user_number` (phone binding) was not exercised — requires SMS to a real number; self-scope only by design.
- The one reproducible quirk worth reporting as informational only: the token endpoint demands a `code_verifier` field on `refresh_token` grants but accepts any value.

## Findings
None. All hypotheses CLEAN or odd-but-harmless. Nothing meets the submission bar (captured bytes + working differential). No draft written.
