# deploy — the control plane as real services

Turns the PoCs into a **deployable, networked control plane** (three hardened services):

| Service | Role |
|---|---|
| **pdp** | Cedar authorization decisions — the PEP calls it over the network (`ENCLAVE_PDP_URL`) |
| **broker** | deny-all egress + API-key injection — sandboxes reach the network only through it |
| **upstream** | a stand-in for `api.anthropic.com` (the broker forwards here, key injected) |

## Run it *(requires Docker)*

```bash
docker compose up -d --build      # build + start (all hardened: read-only, cap-drop ALL, non-root, healthchecks)
node smoke.mjs                    # verify PDP + broker over HTTP
docker compose down              # tear down
```

Expected:

```
  Cedar PDP (authorization):
  ✓ health → {"ok":true,"cedar":"4.11.2"}
  ✓ sam · deleteFiles (under-cleared)  = deny
  ✓ dana · deleteFiles (own workspace) = allow
  ✓ marcus · networkScan (off-scope)   = deny
  Egress broker (deny-all + key injection):
  ✓ api.anthropic.com: broker injects key, upstream receives it → 200 · upstreamSawKey=true
  ✓ pastebin.com: exfil denied → 403
  DEPLOY-SMOKE: PASS ✓
```

## Point the enforcement seam at the deployed PDP

```bash
ENCLAVE_PDP_URL=http://127.0.0.1:8990  node ../poc/enforcement-seam/demo.mjs   # still 20/20
```

The PEP now calls the *deployed* Cedar service for every decision (fail-closed if it's unreachable), exactly as production would over mTLS.

## Production notes

- The container is hardened (`read_only`, `cap_drop: ALL`, `no-new-privileges`, non-root `USER node`) and has a health check.
- In production: front with **mTLS** (SPIFFE SVIDs, see [`../poc/identity`](../poc/identity)), run ≥2 replicas behind a load balancer, ship policies via a signed bundle, and put the audit ledger on WORM storage.
- The **egress broker** ([`../poc/egress-broker`](../poc/egress-broker)) deploys the same way (a small server entrypoint + its own service); compose it alongside the PDP as the control plane grows.
