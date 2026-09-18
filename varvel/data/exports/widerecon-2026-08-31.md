# widerecon catch-list — 2026-08-31T21:15:52.741Z

Chain: `socks5://10.64.0.1:1080` · programs swept: 3/3 · hosts: 7 · catches: 6 · requests: 19 intel / 12 target-contact

> **NOTHING-TESTED** — widerecon is recon-only: every catch above was ENUMERATED, never TESTED. The campaign coverage gate (engine/coverage.mjs) treats this list as QUEUED surface; a catch becomes real only through the validator path (captured bytes + differential). Unknowns are marked UNKNOWN, never guessed.

## Ranked catches

| score | program | host | kinds | first seen | software (version-disclosed) |
| --- | --- | --- | --- | --- | --- |
| 79 | zomato | www.zomans.com | api-heavy, idor-candidate | 2011-04-30 | — |
| 79 | zomato | zomans.com | api-heavy, idor-candidate | 2011-04-29 | — |
| 56 | semrush | investors.semrush.com | api-heavy, idor-candidate | 2021-03-24T00:00:00 | — |
| 30 | zomato | zomato.com | — | UNKNOWN | — |
| 10 | localizejs | api.localizestaging.com | edge-walled | UNKNOWN | — |
| 0 | localizejs | localizestaging.com | edge-walled | UNKNOWN | — |

## Per-program notes

- **zomato** — SWEPT; roots: zomato.com, zomans.com; hosts: 3; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated
- **semrush** — SWEPT; roots: investors.semrush.com, workflows.semrush.com; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: socks5 10.64.0.1 refused CONNECT web.archive.org:443 (code 6) — is the ghost chain (socks5://10.64.0.1:1080) up?
- **localizejs** — SWEPT; roots: localizestaging.com, api.localizestaging.com; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: socks5 10.64.0.1 refused CONNECT web.archive.org:443 (code 6) — is the ghost chain (socks5://10.64.0.1:1080) up?; wayback: unreachable: socks5 10.64.0.1 refused CONNECT web.archive.org:443 (code 6) — is the ghost chain (socks5://10.64.0.1:1080) up?

## Limitations (stated, not hidden)

- crt.sh sees only certificate-logged names — hosts never issued a logged cert are invisible
- wayback CDX coverage is whatever the crawler archived — absence of a capture is NOT absence of a host
- a disclosed version is a HYPOTHESIS input, not a vulnerability — see tools/cvelane.mjs and the validator bar
- no system catches everything: this sweep trades depth for coverage-gated breadth; the per-program untested ledger is the honest remainder
- SMOKE RUN: breadth caps were reduced (--max-roots 2 --max-hosts 6 --max-fingerprint 2) to fit the execution window — the cadence floors (human-cadence >=5s target-contact) were NOT reduced
