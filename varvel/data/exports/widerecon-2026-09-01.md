# widerecon catch-list — 2026-09-01T22:41:31.296Z

Chain: `socks5://10.64.0.1:1080` · programs swept: 16/21 · hosts: 99 · catches: 85 · requests: 253 intel / 189 target-contact

> **NOTHING-TESTED** — widerecon is recon-only: every catch above was ENUMERATED, never TESTED. The campaign coverage gate (engine/coverage.mjs) treats this list as QUEUED surface; a catch becomes real only through the validator path (captured bytes + differential). Unknowns are marked UNKNOWN, never guessed.

## SKIPPED-POLICY (never probed — zero requests)

- **wordpress** — hard-pinned automation-prohibited program (wordpress) — listed SKIPPED-POLICY, zero requests
- **udemy** — hard-pinned automation-prohibited program (udemy) — listed SKIPPED-POLICY, zero requests

## Ranked catches

| score | program | host | kinds | first seen | software (version-disclosed) |
| --- | --- | --- | --- | --- | --- |
| 100 | alsco | sandbox-royal.securegateway.com | soft-env, api-heavy, idor-candidate, jsminer-fodder | 2025-02-07 | — |
| 83 | zomato | www.hyperpure.com | api-heavy, spa, ai-surface, jsminer-fodder, idor-candidate | 2018-11-24 | — |
| 83 | zomato | www.zomato.com | api-heavy, ai-surface, version-disclosed, idor-candidate | 2010-11-20 | astro/5.16.6 |
| 79 | smtp2go | app.smtp2go.com | api-heavy, idor-candidate | 2015-09-19 | — |
| 79 | zomato | www.zomans.com | api-heavy, idor-candidate | 2011-04-30 | — |
| 79 | zomato | zomans.com | api-heavy, idor-candidate | 2011-04-29 | — |
| 75 | mercadolibre | www.mercadopago.com.ec | api-heavy, idor-candidate | 2022-06-07 | — |
| 73 | zomato | www.district.in | api-heavy, ai-surface, idor-candidate | 2024-11-16 | — |
| 67 | mercadolibre | www.mercadolibre.com.do | api-heavy, jsminer-fodder, idor-candidate | 2007-01-05 | — |
| 67 | mercadolibre | www.mercadolibre.com.ec | api-heavy, jsminer-fodder, idor-candidate | 2001-04-01 | — |
| 67 | mercadolibre | www.mercadolibre.com.gt | api-heavy, jsminer-fodder, idor-candidate | 2015-10-18 | — |
| 67 | mercadolibre | www.mercadolibre.com.ni | api-heavy, jsminer-fodder, idor-candidate | 2011-03-03 | — |
| 67 | mercadolibre | www.mercadolibre.com.py | api-heavy, jsminer-fodder, idor-candidate | 2015-11-21 | — |
| 67 | mercadolibre | www.mercadolibre.com.sv | api-heavy, jsminer-fodder, idor-candidate | 2016-04-18 | — |
| 61 | zomato | district.in | api-heavy, idor-candidate | 2014-12-17 | — |
| 61 | sheer_bbp | my.sheer.com | api-heavy, idor-candidate | 2023-10-31 | — |
| 61 | mercadolibre | www.mercadolibre.co.cr | api-heavy, idor-candidate | 2006-12-05 | — |
| 61 | mercadolibre | www.mercadolibre.com.bo | api-heavy, idor-candidate | 2015-06-17 | — |
| 61 | sheer_bbp | www.sheer.com | api-heavy, idor-candidate | 2024-05-24 | — |
| 61 | visa | www.visa.com.ge | api-heavy, idor-candidate | 2015-03-30 | — |
| 60 | zomato | jumbo-test.blinkit.com | soft-env, fresh-subdomain | 2026-07-09T00:00:00 | — |
| 59 | visa | www.visa.com.ru | api-heavy, edge-walled, ai-surface, jsminer-fodder, idor-candidate | 2000-06-20 | — |
| 58 | smtp2go | api.smtp2go.com | idor-candidate | 2020-10-25 | — |
| 58 | modern_treasury | app.moderntreasury.com | api-heavy | 2019-08-20 | — |
| 58 | zomato | runnr.in | api-heavy | 2016-04-15 | — |
| 57 | zomato | api.grofers.com | api-heavy, idor-candidate | 2014-11-02 | — |
| 56 | semrush | investors.semrush.com | api-heavy, idor-candidate | 2021-04-19 | — |
| 56 | visa | www.visa.com.hk | api-heavy, idor-candidate | 2000-10-18 | — |
| 51 | zomato | www.runnr.in | api-heavy, idor-candidate | 2021-10-25 | — |
| 51 | visa | www.visa.com.br | api-heavy, edge-walled, jsminer-fodder, idor-candidate | 1998-12-05 | — |
| 51 | visa | www.visa.com.tw | api-heavy, edge-walled, jsminer-fodder, idor-candidate | 2000-10-27 | — |
| 50 | localizejs | app.localizestaging.com | api-heavy, edge-walled, ai-surface | 2021-12-14 | — |
| 48 | zomato | e9ede35a-9f54-424a-a6ac-734fdb545016-uat.blinkit.com | soft-env | 2025-02-25T00:00:00 | — |
| 48 | alsco | sandbox.securegateway.com | soft-env | UNKNOWN | — |
| 47 | smtp2go | www.smtp2go.com | api-heavy, edge-walled, jsminer-fodder, idor-candidate | 2007-01-11 | — |
| 47 | visa | www.visa.com.au | api-heavy, edge-walled, jsminer-fodder, idor-candidate | 1998-12-01 | — |
| 47 | visa | www.visa.com.az | api-heavy, edge-walled, jsminer-fodder, idor-candidate | 2014-03-20 | — |
| 47 | visa | www.visa.com.mx | api-heavy, edge-walled, jsminer-fodder, idor-candidate | 2000-05-10 | — |
| 46 | localizejs | assets.localizestaging.com | api-heavy | 2020-02-27 | — |
| 46 | zomato | grofers.com | api-heavy | 2014-03-02 | — |
| 46 | visa | visa.com.ru | api-heavy | 2006-08-14 | — |
| 46 | mercadolibre | www.mercadolivre.com | api-heavy | 1999-11-27 | — |
| 46 | visa | www.visa.com.cy | api-heavy | 2002-02-05 | — |
| 41 | bykea | bykea.com | api-heavy, edge-walled, idor-candidate | 2016-11-13 | — |
| 41 | localizejs | cdn.localizestaging.com | api-heavy, edge-walled, idor-candidate | 2020-02-27 | — |
| 41 | mergify | dashboard.mergify.com | api-heavy, edge-walled, idor-candidate | 2022-02-24 | — |
| 41 | hubspot | developers.hubspot.com | api-heavy, edge-walled, idor-candidate | 2010-06-17 | — |
| 41 | hubspot | offers.hubspot.com | api-heavy, edge-walled, idor-candidate | 2012-09-01 | — |
| 37 | visa | bd.visa.com | api-heavy, edge-walled, jsminer-fodder, idor-candidate | 2012-07-29 | — |
| 34 | wolt | corporate.wolt.com | — | UNKNOWN | — |
| 34 | frontegg | portal.au.frontegg.com | — | UNKNOWN | — |
| 31 | bykea | www.bykea.com | api-heavy, edge-walled, idor-candidate | 2017-03-31 | — |
| 30 | zomato | api2.grofers.com | — | UNKNOWN | — |
| 30 | wolt | authentication.wolt.com | — | UNKNOWN | — |
| 30 | modern_treasury | cdn.moderntreasury.com | — | UNKNOWN | — |
| 30 | wolt | drive.wolt.com | — | UNKNOWN | — |
| 30 | zomato | hyperpure.com | — | UNKNOWN | — |
| 30 | zomato | mcp-server.zomato.com | — | UNKNOWN | — |
| 30 | wolt | ops.wolt.com | — | UNKNOWN | — |
| 30 | smtp2go | smtp2go.com | — | UNKNOWN | — |
| 30 | trip_com | trip.com | — | UNKNOWN | — |
| 30 | visa | visa.com.au | — | UNKNOWN | — |
| 30 | visa | visa.com.jm | — | UNKNOWN | — |
| 30 | mercadolibre | www.mercadolibre.com.hn | — | UNKNOWN | — |
| 30 | mercadolibre | www.mercadolibre.com.pa | — | UNKNOWN | — |
| 30 | visa | www.visa.com.hr | — | UNKNOWN | — |
| 30 | zomato | zomato.com | — | UNKNOWN | — |
| 28 | bykea | api.bykea.net | edge-walled | 2025-07-24 | — |
| 26 | zomato | blinkit.com | api-heavy, edge-walled | 2021-12-22T00:00:00 | — |
| 26 | homebargains | hackerone-m1rtuq8orz.hbstaging.website | api-heavy, edge-walled | 2023-02-05 | — |
| 26 | localizejs | localizestaging.com | api-heavy, edge-walled | 2016-12-22 | — |
| 18 | bykea | geocode-beta.bykea.net | soft-env, edge-walled | UNKNOWN | — |
| 18 | bykea | leaflet-map.bykea.net | edge-walled | 2025-02-11 | — |
| 13 | mergify | api.mergify.com | edge-walled | 2023-10-27 | — |
| 10 | frontegg | api.au.frontegg.com | edge-walled | UNKNOWN | — |
| 10 | localizejs | api.localizestaging.com | edge-walled | UNKNOWN | — |
| 6 | homebargains | signin-hackerone.hbstaging.website | edge-walled, jsminer-fodder | UNKNOWN | — |
| 3 | zomato | www.blinkit.com | edge-walled | 2000-03-03 | — |
| 0 | hubspot | app.hubspot.com | edge-walled | UNKNOWN | — |
| 0 | hubspot | hubspot.com | edge-walled | UNKNOWN | — |
| 0 | zomato | jumbo.blinkit.com | edge-walled | 2022-01-25T00:00:00 | — |
| 0 | zomato | lambda.blinkit.com | edge-walled | 2022-01-25T00:00:00 | — |
| 0 | bykea | maps.bykea.net | edge-walled | UNKNOWN | — |
| 0 | bykea | nominatim.bykea.net | edge-walled | UNKNOWN | — |
| 0 | bykea | tomoe.bykea.net | edge-walled | UNKNOWN | — |

## Per-program notes

- **wordfence-madara** — NO-DOMAIN-ROOTS; roots: none; hosts: 0; dropped-out-of-scope: 0; errors: intake: the intake carries no in-scope DOMAIN roots (CIDRs/app-store ids only, or nothing signed) — nothing passive to enumerate
- **visa** — SWEPT; roots: bd.visa.com, www.visa.com.br, www.visa.com.mx, www.visa.com.tw, visa.com.ru, visa.com.au, www.visa.com.az, www.visa.com.cy, www.visa.com.ge, www.visa.com.hk, www.visa.com.hr, visa.com.jm; hosts: 14; dropped-out-of-scope: 86; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms
- **wordpress** — SKIPPED-POLICY; roots: none; hosts: 0; dropped-out-of-scope: 0; errors: policy: hard-pinned automation-prohibited program (wordpress) — listed SKIPPED-POLICY, zero requests
- **semrush** — SWEPT; roots: investors.semrush.com, workflows.semrush.com; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms
- **trip_com** — SWEPT; roots: trip.com; hosts: 1; dropped-out-of-scope: 0; errors: crt.sh: unreachable: timeout after 20000ms; wayback: unreachable: timeout after 20000ms
- **bykea** — SWEPT; roots: com.bykea.pk, com.bykea.pk.partner, bykea.com, maps.bykea.net, leaflet-map.bykea.net, nominatim.bykea.net, geocode-beta.bykea.net, api.bykea.net, tomoe.bykea.net; hosts: 10; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: unreachable: timeout after 20000ms; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 404 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms
- **blend-labs** — NO-DOMAIN-ROOTS; roots: none; hosts: 0; dropped-out-of-scope: 0; errors: intake: the intake carries no in-scope DOMAIN roots (CIDRs/app-store ids only, or nothing signed) — nothing passive to enumerate
- **agoda-public** — NO-DOMAIN-ROOTS; roots: none; hosts: 0; dropped-out-of-scope: 0; errors: intake: the intake carries no in-scope DOMAIN roots (CIDRs/app-store ids only, or nothing signed) — nothing passive to enumerate
- **localizejs** — SWEPT; roots: localizestaging.com, api.localizestaging.com, cdn.localizestaging.com, app.localizestaging.com; hosts: 10; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: unreachable: timeout after 20000ms; wayback: HTTP 503 — URLs were NOT fabricated; crt.sh: HTTP 404 — names were NOT fabricated
- **smtp2go** — SWEPT; roots: smtp2go.com, app.smtp2go.com, api.smtp2go.com; hosts: 4; dropped-out-of-scope: 0; errors: crt.sh: HTTP 404 — names were NOT fabricated; crt.sh: unreachable: timeout after 20000ms; crt.sh: HTTP 404 — names were NOT fabricated
- **mergify** — SWEPT; roots: api.mergify.com, dashboard.mergify.com; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated
- **frontegg** — SWEPT; roots: api.au.frontegg.com, portal.au.frontegg.com; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: unreachable: timeout after 20000ms; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms
- **modern_treasury** — SWEPT; roots: app.moderntreasury.com, cdn.moderntreasury.com; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms
- **homebargains** — SWEPT; roots: signin-hackerone.hbstaging.website, hackerone-m1rtuq8orz.hbstaging.website; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: HTTP 404 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated
- **udemy** — SKIPPED-POLICY; roots: none; hosts: 0; dropped-out-of-scope: 0; errors: policy: hard-pinned automation-prohibited program (udemy) — listed SKIPPED-POLICY, zero requests
- **sheer_bbp** — SWEPT; roots: www.sheer.com, my.sheer.com; hosts: 2; dropped-out-of-scope: 2; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated
- **alsco** — SWEPT; roots: sandbox.securegateway.com, sandbox-royal.securegateway.com; hosts: 2; dropped-out-of-scope: 0; errors: crt.sh: unreachable: timeout after 20000ms; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated
- **zomato** — SWEPT; roots: zomato.com, zomans.com, runnr.in, blinkit.com, mcp-server.zomato.com, hyperpure.com, grofer.io, grofers.com, www.district.in, api2.grofers.com, api.grofers.com, district.in; hosts: 24; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 404 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 404 — names were NOT fabricated; crt.sh: HTTP 404 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 404 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: unreachable: timeout after 20000ms
- **hubspot** — SWEPT; roots: hubspot.com, app.hubspot.com, offers.hubspot.com, developers.hubspot.com; hosts: 4; dropped-out-of-scope: 0; errors: crt.sh: unreachable: timeout after 20000ms; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated
- **mercadolibre** — SWEPT; roots: www.mercadopago.com.ec, www.mercadolivre.com, www.mercadolibre.com.sv, www.mercadolibre.com.py, www.mercadolibre.com.pa, www.mercadolibre.com.ni, www.mercadolibre.com.hn, www.mercadolibre.com.gt, www.mercadolibre.com.ec, www.mercadolibre.com.do, www.mercadolibre.com.bo, www.mercadolibre.co.cr; hosts: 12; dropped-out-of-scope: 11; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: unreachable: timeout after 20000ms; crt.sh: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated
- **wolt** — SWEPT; roots: authentication.wolt.com, corporate.wolt.com, drive.wolt.com, ops.wolt.com, com.wolt.android, com.wolt.courierapp; hosts: 6; dropped-out-of-scope: 0; errors: crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated; wayback: unreachable: timeout after 20000ms; crt.sh: HTTP 502 — names were NOT fabricated; crt.sh: HTTP 502 — names were NOT fabricated

## Limitations (stated, not hidden)

- crt.sh sees only certificate-logged names — hosts never issued a logged cert are invisible
- wayback CDX coverage is whatever the crawler archived — absence of a capture is NOT absence of a host
- a disclosed version is a HYPOTHESIS input, not a vulnerability — see tools/cvelane.mjs and the validator bar
- no system catches everything: this sweep trades depth for coverage-gated breadth; the per-program untested ledger is the honest remainder
