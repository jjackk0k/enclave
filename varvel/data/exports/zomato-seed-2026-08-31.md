# Zomato — Account Seeding + Decisive Cross-Account Test — 2026-08-31

**Scope:** zomato.com web + mcp-server.zomato.com (Tier 1, in scope). All traffic ghost `socks5://10.64.0.1:1080` + `X-HackerOne: varvel`, fail-closed.
**Accounts:** A `varvel-zom-a-sl0i@emalupe.com` (uid 447585412), B `varvel-zom-b-qpbw@emalupe.com` (uid 447585565).
**Verdict: CLEAN — provable, not assumed.** No finding; no submission drafted.

## 1. Seeding (what worked)

**Web UI could not seed**: online ordering is mobile-app-only ("Online ordering is only supported on the mobile app" banner on restaurant order pages); the Add-Address modal (harvested at `/users/varvel-alpha-447585412/addresses`) uses label-less inputs and its map-pin flow silently resolved to the Manchester locus with `delivery_subzone_id: 0`, which the server rejects.

**Working method — curl replay of the harvested endpoint** (all routes harvested from live traffic / the app's own JS bundle `zwstatic.zomato.com/main-*.js`, none guessed):

1. `GET /webroutes/location/get?lat=28.6315&lon=77.2167&is_address_flow=true` → resolved Connaught Place: `entityId(subzone_id)=104`, `deliverySubzoneId=505`, `placeId=ChIJH1Zdzkn9DDkR0EMMLJdhI_I`, `o2Serviceable=true`. (Manchester gave `deliverySubzoneId=0` → server-side reject `missing params: [delivery_subzone_id]`.)
2. `POST /webroutes/order/address` (JSON, session cookie + `x-zomato-csrft` header = `csrf` cookie value). Validation oracle taught the schema stepwise: first `missing params: [delivery_subzone_id]`, then `missing params: [address, alias]`. Final accepted body:
   `{"address_id":0,"subzone_id":104,"subzone_name":"Hanuman Road Area, Connaught Place, Delhi","delivery_subzone_id":505,"lat":28.632,"lon":77.217,"place_id":"ChIJH1Zdzkn9DDkR0EMMLJdhI_I","place_type":"GOOGLE_PLACE","place_name":"Hanuman Road Area, Connaught Place, Delhi","place_cell_id":0,"is_edit":false,"address":"1 YWCA Building, Ashoka Road","area":"Hanuman Road Area, Connaught Place","landmark":"Ashoka Road","alias":"home"}`
   → **HTTP 200, address id `1037093544` persisted** (verified via `GET /webroutes/user/address?page=1`, `GET /webroutes/order/address`, and MCP `get_saved_addresses_for_user` — all three surfaces return it).

**Harvested endpoint set** (from browser traffic + bundle): `/webroutes/user/address`, `/webroutes/order/address`, `/webroutes/location/get`, `/webroutes/location/search`, `/webroutes/order/cart`, `/webroutes/order/autoVerifyPhone`, `/webroutes/dote/{address,cart,home,orderDetails,placeOrder}`.

**Notable observation (untested, writes were OFF):** the browser's `POST /webroutes/order/cart` sends `user_id=447585412` as a **client-supplied multipart form field**. Cross-account cart writes via swapped user_id were not tested (write prohibition). Flagged for a future explicitly-authorized write window.

## 2. Three-way cross-account matrix (exact responses)

### MCP tools (`POST /mcp`, JSON-RPC `tools/call`)

| Test | Caller | Target object | Exact response | Verdict |
|------|--------|--------------|----------------|---------|
| Positive control | A token | `get_order_history address_id=1037093544` (A's real address) | `{"order_history":{"has_more":false,"order_history_items":[]},"success":true}` | resolves for owner |
| **DECISIVE** | B token | same `address_id=1037093544` | `{"error_code":"INVALID_ADDRESS_ID","error_message":"Could not resolve the provided address ID to a valid location.","success":false}` | **ownership-scoped — B cannot resolve A's address** |
| Isolation | B token | `get_saved_addresses_for_user` | `{"addresses":[],"success":true}` | own scope only |
| Garbage control | A token | `address_id=0000000000` | `INVALID_ADDRESS_ID` | clean |
| Adjacent-ID probe | A token | `address_id=1037093545` (±1, other-user territory) | `INVALID_ADDRESS_ID` | no resolution oracle |
| Unauth control | no token | any `tools/call` | HTTP 401 `{"error":"invalid_token","error_description":"Authentication required"}` | enforced |

Same-address differential is the proof: A resolves `1037093544` → `success:true`; B gets `INVALID_ADDRESS_ID` for the identical ID. Address IDs are ownership-scoped at resolution time.

(Token hygiene note: B's original access token was invalidated when its refresh token was exercised earlier — evidence of refresh rotation. B-side tests used the refreshed token.)

### Web endpoints (session cookies)

| Test | Caller | Endpoint | Exact response | Verdict |
|------|--------|----------|----------------|---------|
| Positive control | A cookies | `GET /webroutes/user/address?page=1` | 200, `SECTION_USER_ADDRESS count:1` with full object (id, lat/lon, delivery_subzone 505) | owner sees own |
| Isolation | B cookies | same | 200, `count:0` | own scope only |
| Decoy param | B cookies | same + `&user_id=447585412` | 200, `count:0` (param ignored) | no leak |
| Unauth control | none | same | **401** `{"status":"failed","message":"You are not authorized."}` | enforced |
| Positive control 2 | A cookies | `GET /webroutes/order/address` | 200, `addresses:[{id:1037093544,...}]` | owner sees own |
| Isolation 2 | B cookies | same | 200, `{"addresses":[]}` | own scope only |
| Unauth 2 | none | same | 200 `{"addresses":[]}` | empty-but-200, no data |

## 3. Findings

**None.** No cross-account read or resolve path exists on either surface; the differential is captured in bytes (`.tmp/mcp-threeway-*.json`, `.tmp/web-threeway.json`).

Informational-only observations (not submissions):
- `GET /webroutes/order/address` returns 200 + empty list to anonymous callers instead of 401 (like `/webroutes/user/address` does). No data exposed.
- Token endpoint requires a `code_verifier` field on `refresh_token` grants but accepts any value (from the earlier MCP probe).
- Client-supplied `user_id` in `POST /webroutes/order/cart` — untested (writes OFF).

Raw captures: `.tmp/zom-seed{7,8,9,10,11}-traffic.json`, `.tmp/zom-addr-traffic-{1..5}.json`, `.tmp/loc-get-cp.json`, `.tmp/mcp-threeway-{1,2,3}.json`, `.tmp/web-threeway.json`, `.tmp/zmain.js` (bundle), screenshots `.tmp/zom-seed*-*.png`.
