# Zomato — Writes-Window Test: client-supplied user_id / cross-account writes — 2026-08-31

**Window scope:** writes only to own accounts A (uid 447585412) / B (uid 447585565). No third-party object touched.
**Transport:** ghost `socks5://10.64.0.1:1080` + `X-HackerOne: varvel`, fail-closed; `x-zomato-csrft` = session `csrf` cookie.
**Verdict: CLEAN — no finding. No submission drafted, novelty gate not applicable (gate runs only on drafts).**

## Lead 1 — `POST /webroutes/order/cart` client-supplied `user_id` (multipart form)

Field shape harvested from live browser traffic (`.tmp/zom-seed7-traffic.json`): `user_id, res_id, voucher_code, payment_method_type, payment_method_id, card_bin, address_id, entityId, entityType, userLatitude, userLongitude, deliverySubzoneId, placeId, placeType, placeName, cellId, isOrderLocation, cityId, postback_params`.

Matrix (res_id 6284 Bangla Sweet House, Connaught Place subzone 104 / DSZ 505 context):

| Caller | user_id sent | Exact response |
|--------|-------------|----------------|
| A session | 447585412 (own) | 200 `{"status":"failed","message":"Something went wrong, please try again."}` |
| B session | 447585565 (own) | 200 same |
| **B session** | **447585412 (A's) — DECISIVE** | 200 same |
| B session | 999999999 (garbage) | 200 same |
| B session | (omitted) | 200 same |
| unauth | 447585412 | **401** `{"message":"Unauthorized request! Please refresh the page."}` |

No differential obtainable: the endpoint fails identically for every authenticated shape including the legitimate own-account baseline — it is a cart bootstrap that cannot complete on web (ordering is app-only), so no object was ever created on any account. The `user_id` field is accepted but never observably honored; the unauth control correctly 401s. Residual (untestable-in-window): whether a fully-itemized app-flow cart POST would honor a swapped user_id — no baseline exists to build it from web.

Sibling probe: `POST /webroutes/dote/cart` → 200 `{"status":"failed","message":"Please login to continue"}` even with valid session+CSRF (dote family wants different auth context); GET → 405.

## Lead 2 — cross-account edit of A's address via `POST /webroutes/order/address` (write counterpart of the CLEAN read test)

| Step | Caller | Payload key | Exact response | A's readback |
|------|--------|------------|----------------|--------------|
| Positive control | A session | `is_edit:true, address_id:1037093544` | 200, address book now contains **new id 1037153399** (edit = recreate semantics) | id 1037153399 |
| **DECISIVE** | **B session** | same body, `address_id:1037093544`, landmark "EDITED-BY-B-SESSION" | 200 — response lists **B's own book with new id 1037153411** | **unchanged: still only 1037153399** |
| Garbage control | B session | `address_id:9999999999` | 200, silently creates another address on B (id 1037153424) — no error for foreign/nonexistent id | unchanged |
| Unauth control | none | A's address_id | 401 `Unauthorized request!` | unchanged |

**Proof of session-scoping:** the server never honors the supplied `address_id` for targeting. B's "edit of A's address" created a new object in B's own book; A's book was byte-identical before/after (id 1037153399, same fields). Cross-account write: impossible on this endpoint. Quirk (informational): foreign/garbage `address_id` values are silently ignored instead of rejected — a robustness smell, not a vuln.

## Findings
None. Both write-side leads CLEAN with captured bytes (`.tmp/cart-userid-matrix.json`, `.tmp/dote-cart-probe.json`, `.tmp/addr-edit-matrix.json`). No draft → novelty gate not run.

## Cleanup
All test objects deleted via harvested `POST /webroutes/order/deleteAddress` (`{"address_id":...}` → `Address removed successfully`):
- B: 1037153411, 1037153424 (created by the decisive/garbage tests) — deleted
- A: 1037153399 (the edited successor of seeded 1037093544, which edit-semantics had already replaced) — deleted
- Final state verified: `GET /webroutes/order/address` → `{"addresses":[]}` for BOTH accounts (`.tmp/addr-cleanup.json`).

Left behind / notes: MCP OAuth access+refresh tokens for A and B remain valid (~30-day expiry, minted 2026-08-31) — no revocation endpoint exercised. No carts, orders, or third-party objects were ever created.
