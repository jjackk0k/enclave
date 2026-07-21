# deploy — the control plane as real services

Turns the PoCs into **deployable networked services**. The first is the **Cedar PDP**: the enforcement seam's Policy Decision Point, containerized so the PEP (the PreToolUse hook) calls it over the network — the production shape (`ENCLAVE_PDP_URL`), instead of in-process.

## Run it *(requires Docker)*

```bash
docker compose up -d --build      # build + start the PDP service (hardened: read-only, cap-drop, non-root)
node smoke.mjs                    # verify it makes the right decisions over HTTP
docker compose down              # tear down
```

Expected:

```
deployed PDP: {"ok":true,"cedar":"4.11.2"}
  sam · deleteFiles (under-cleared)  → deny   (expect deny)
  dana · deleteFiles (own workspace) → allow  (expect allow)
  marcus · networkScan (off-scope)   → deny   (expect deny)
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
