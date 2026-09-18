# VARVEL demo target — "Acme Robotics"

A self-contained, **authorized** practice target so the whole VARVEL pipeline can be
demonstrated end-to-end against a realistic site — no external host, no API key, no
Docker. It ships with the platform and boots automatically alongside the service.

- Code: [`targets/demo-corp.mjs`](../targets/demo-corp.mjs)
- Runs on: `http://127.0.0.1:8972` (localhost only; override with `VARVEL_DEMO_PORT`)
- Breach it: `POST /api/breach-demo`, or the **“Breach the Acme demo target”** button
  on the console’s Settings page.

## What it is

An ordinary-looking small-company site (home / products / about / careers / portal)
that carries the exposures a sloppy real deployment leaks. It is a **target**, not an
exploit kit — every weakness is a *misconfiguration to be discovered*, the kind
VARVEL's native scanner is built to find.

| Planted exposure | Path | Detected as | Sev |
|---|---|---|---|
| Exposed git repo | `/.git/HEAD`, `/.git/config` | exposed .git repository | high |
| Secrets file | `/.env` | exposed environment/secrets file | **crit** |
| Backup dir listing | `/backup/` | directory listing enabled | med |
| Database dump | `/backup/db.sql` | exposed database dump | high |
| App config | `/config.json` | config file exposed | low |
| Over-permissive CORS | `/api/*` | CORS reflects arbitrary Origin w/ credentials | high |
| Missing headers | all | missing CSP / X-Frame-Options | low |
| Info leak | `/robots.txt` | discloses `/admin` `/backup` `/internal` | — |
| Unauth portal | `/admin` | reachable management page (leaks its content API in a comment) | — |
| **Broken access control (write)** | `POST /admin/api/banner` | unauthenticated content change — the "change something" surface | high |

There is also a hidden hint in the page HTML comment and an `internalApi` reference
in `config.json`, so recon has realistic breadcrumbs to follow.

## How VARVEL breaches it

`POST /api/breach-demo` starts a **real**, recon-only campaign (`reconOnly: true`,
`tooledRecon: true`) pointed at the target. No mock agent, no fabricated hosts —
VARVEL's own native tools do the work:

```
recon (TCP + service/version + HTTP fingerprint)   → finds nginx on :8972
  └─ webScan (content discovery + soft-404 baseline) → .git / .env / db.sql / listing / config
```

The result is a genuine attack-surface graph and a client-ready report, both live in
the console. A representative run: **1 host · 22 surface nodes · 6 confirmed findings
(1 critical) · honesty rate 100%**.

Because `reconOnly` stops after discovery, the surface is 100% real (no downstream
agent fiction). The exploit / post-ex phases — proving impact — are the governed,
HITL-gated, live-agent path (needs an API key + the Enclave hook).

## Why this matters

It is the difference between *unit-testing tools against mocks* and *demonstrating the
platform actually breaches a realistic target*. The end-to-end proof is locked in
[`test/breach.test.mjs`](../test/breach.test.mjs): it boots the target on an ephemeral
port, runs recon + webscan + the HTTP analyzer against it, and asserts every planted
exposure is recovered. Fully hermetic, part of CI.

## Changing something — the modify surface

`POST /admin/api/banner {"banner":"..."}` changes the homepage headline with **no auth
check** (broken access control). It's the "change some info on the website" surface:

```bash
# read → change → the homepage reflects it → revert (leave it clean)
curl http://127.0.0.1:8972/admin/api/banner
curl -X POST http://127.0.0.1:8972/admin/api/banner -H 'content-type: application/json' -d '{"banner":"BREACHED — authorized test"}'
curl http://127.0.0.1:8972/            # <h1> now shows the new banner
curl -X POST http://127.0.0.1:8972/admin/api/banner -H 'content-type: application/json' -d '{"banner":"Industrial automation, done right."}'
```

The write response includes a `revert` step, and `/admin` leaks the endpoint in an HTML
comment as a realistic breadcrumb. The change is benign, capped at 200 chars, and fully
reversible — a minimum, reversible proof of impact, recorded for cleanup. Locked in
`test/breach.test.mjs`.

## Running the LIVE VARVEL AI against it (breach + modify) — one click

The deterministic `breach-demo` proves the *tools* work. To have the **agent** breach and
modify it end to end (recon → validate → exploit → post-ex → report), it's now one action:

- **"Run live AI breach (demo)"** on the console Settings page, or `POST /api/campaign/live-demo`.

It's self-contained. The run uses a **bundled, loopback-scoped signed identity** —
`poc/enforcement-seam/session/demo.json` (principal `demo`, L4, OSCP/OSEP/CRTO, scope
`127.0.0.0/8` **only**) — so the Enclave authorizes offensive actions against the demo and
*nothing else*. Native tooled recon seeds the surface; the agent then validates, and (once
you countersign the HITL gate) exploits via `POST /admin/api/banner`, records the revert as
an OPSEC artifact, and cleans up. VARVEL relays your countersignature to the Enclave's
approval context so the gated action is permitted.

**Readiness** is shown live on Settings (and at `GET /api/live/readiness`): backend
(Kimi K3 / a key), the policy hook, the signed session, and the container tier. Two things
gate a *full* agent run:

1. **A model backend** — subscribe to Kimi K3 (`k3 --sub`) or set `VARVEL_API_KEY` /
   `ANTHROPIC_API_KEY`. (The k3 free tier works but is flaky; agent phases may error — the
   campaign catches it and continues, so recon still lands.)
2. **Network reachability for the agent's tools** — the governed agent runs `Bash`
   (`curl`/`nmap`) **inside the sealed container**; on a host-tier box (Docker off) that
   shell is refused fail-closed. Native recon still reaches the demo on the host, but the
   agent's own network tools need the container tier (or the Claude-CLI backend, which runs
   host-side under the same hook).

See `docs/AGENT-GUIDE.md` for exactly what the AI is told to do (the operating manual it
runs under — the concise version is injected into every live run).

## Boundary

The demo target is authorized and localhost-only. VARVEL's native tools do **discovery
and detection only** — no exploitation, no credential brute force. The one write path
(`/admin/api/banner`) lives on the *target*, is benign and reversible, and is exercised
only under the governed, HITL-gated exploit phase — countersigned and enforced by the
Enclave (L2). VARVEL orchestrates; it never ships weaponized exploits or C2.
