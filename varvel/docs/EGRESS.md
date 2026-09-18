# VARVEL egress runbook (Ghost Mode)

Cloudflare's `cf_clearance` binds to **exit IP + User-Agent**. Field lesson (2026-08):
the mint browser and the verify fetch exited through **different Mullvad IPs**
(rotation), the cookies were "issued but unproven", and **24/24 follow-up requests
were challenged**. This runbook is how you know *before* an engagement whether your
exit is stable, what class it is, and whether it is the exit you pinned.

**2026-09-01 — national-adversary tier shipped:** multi-hop chain plumbing with
per-hop health (`probeHops`), a ghost-level traffic shaper the campaign pacer is
policed by, an operator-declared exit **rotation set** with fail-closed enforcement,
a correlation-resistance self-report (`ghost.substatus()`), and a per-engagement
egress audit record. All additive and backward-compatible; every knob below.

## The pre-engagement check

`ghost.exitCheck()` (engine/egresscheck.mjs, additive on the ghost status) measures
three things and **never throws**:

- **Stability** — samples the exit IP through the configured chain 3 times, ~1s
  apart. Verdict `stable` (all identical) or `rotating` (every distinct exit listed,
  with the cf_clearance warning). `unknown` when no sample succeeded.
- **Class** — best-effort org/ASN via the free ipinfo.io feed **through the chain**
  (3s cap, skipped silently when offline), classified by org-name heuristic:
  `vpn` / `datacenter` / `residential-ish` / `unknown`. This is a **free-feed
  heuristic** — paid proxy/VPN classification feeds are NOT covered. Datacenter class
  raises an advisory for CF-class engagements.
- **Pin** — expected exit from `ghost.expectExit` (settings) or
  `VARVEL_GHOST_EXPECT_EXIT` (env). Default mode: a mismatch is a **loud warning**.
  Strict mode (`ghost.pinStrict=true`): a mismatch **fails the check closed**
  (`ok:false`, reason naming expected vs actual) and drops ghost verification, so
  `required` mode refuses public egress until the chain exits via the pinned IP.
  Default off.

## (a) Pinning one Mullvad server

In the Mullvad app: **Settings → VPN settings → location → pick a specific server
(e.g. `se-got-wg-001`), not just a city/country.** City-level selection lets Mullvad
load-balance you across that city's relays — that is the rotation that killed the
engagement above. Then pin it in VARVEL:

```
ghost.expectExit = <that server's public exit IP>   # or VARVEL_GHOST_EXPECT_EXIT
```

Run the exit check before minting any clearance. If the verdict is `rotating`, the
app is not pinned to one server — fix that first. For CF-class engagements, mint and
ride on the SAME single-hop chain to the SAME pinned exit (`chainEgressId` keys the
vault for exactly this reason).

**When rotation is acceptable:** non-CF ops — ordinary recon, scanning, banner work
against targets without clearance-class bot defense. A rotating exit is even mildly
useful there. It is only clearance-cookie workflows (and anything else that binds
session state to source IP) that demand a pinned, stable exit.

## (b) Multihop trade-offs

Multihop (Mullvad bridge mode / entry≠exit) costs latency and adds a failure domain,
and buys little passage value: Cloudflare scores the **exit** IP, not the path. More
importantly, **multi-hop chains are REFUSED (fail-closed) by the mint/ride tier** —
a browser rides exactly ONE proxy hop (`--proxy-server`), so minting through hop 1 of
a 2-hop chain would bind `cf_clearance` to the wrong exit (the chain exits at the
LAST hop). Use multihop only when the entry/exit split itself is the point, and never
for clearance mint/ride.

**Chain plumbing (2026-09-01):** the ghost engine runs N-hop chains natively — the
chain string is an ordered comma-separated list (`socks5://entry,http://relay,socks5://exit`),
iterative CONNECT/socks5 per hop, DNS resolved by the LAST hop only. `verify()` always
proves the FINAL exit differs from the operator baseline, whatever the hop count.
`ghost.probeHops()` (per-hop health in `status().hopHealth`, 15s-cached) probes hop *k*
**through** hops 0..k-1 and marks hops downstream of a dead hop `ok:null` *unprobed* —
never guessed. Adding real hops is **operator config**: Mullvad app → Bridges/multihop,
or additional proxies in the chain string. Hop *independence* (different providers /
jurisdictions / no shared logging) is also operator-side and is not measurable from the
app layer — `substatus()` says exactly that.

## (c) DAITA

Mullvad's **DAITA** (Defense against AI-guided Traffic Analysis) is free in the app
(VPN settings → DAITA). It pads and reshapes flow timing so traffic-analysis models
can't match your entry/exit flows. Turn it on for engagements where the adversary or
their ISP could plausibly run flow correlation; it does not affect exit-IP stability
or clearance binding either way. DAITA is VPN-layer and therefore **invisible to
VARVEL** — `substatus()` grades it UNVERIFIED, never claimed.

## (c2) Ghost-level traffic shaping (the app-layer half)

`ghost.shaper = { minDelayMs, jitterMs, padTo: null|'mtu' }` — arm via
`configure({ shaper })`, `Ghost.setShaper()`, or env `VARVEL_GHOST_SHAPER` (JSON).
When armed, **every campaign pacer is policed by it**: the shared emission clock's gap
is *floored* at `minDelayMs + jitter`-shaped spacing (it can slow traffic, never speed
it up), and `padTo:'mtu'` adds an **admitted** `x-pad` header sized toward a ~1460-byte
envelope to blunt coarse size features.

**The honest ceiling:** true constant-rate padding (fixed inter-packet timing, fixed
cell size — what actually resists flow correlation) is **impossible at the app
layer**. That is VPN-layer territory (DAITA). The shaper raises the correlation cost
of the operator→first-hop flow's timing/size pattern; it does not defeat a national
adversary, and nothing in the platform claims it does. There is also **no app-layer
cover traffic** — idle windows are silent, and `substatus()` says so.

## (c3) Exit rotation policy (the operator-declared set)

Declare the exits an engagement may use:

```
VARVEL_GHOST_EXIT_SET="135.136.21.33,135.136.21.34"   # env, comma-separated
ghost.setExitSet([...])                                # or engine API / configure({exitSet})
```

`ghost.exitCheck()` then verifies the chain exits **inside the set** (`setMatch`
true/false/null=unproven), alongside the single-exit pin. Doctrine:

- An exit **outside the set**: loud warning by default; **fail-closed** under
  `ghost.pinStrict` (the gate drops verification — it can only ever close, never open).
- A **pin outside the set** is a policy contradiction — named even when the pin matches
  the observed exit, fail-closed under pinStrict. Campaigns pin **any one member** of
  the set (`ghost.expectExit` as before).
- **Rotation inside the set** is in-policy (`setMatch:true`) but still surfaces the
  `rotating` warning — in-policy rotation still breaks `cf_clearance`-class binding.
- Unparseable set entries are **dropped and named** (`setDropped`) — a typo'd set is
  never silently narrower than the operator believes; an all-garbage set is refused.
- The **audit ledger** records the egress each engagement rides: every campaign build
  logs `ghost.engagement` (canonical egress id, hop count, verified exit IP, the pin/set
  policy in force, shaper state) into the campaign activity stream. Proxy credentials
  and the operator baseline IP never enter the ledger.

## (c4) Correlation-resistance self-measurement

`ghost.substatus()` (also additive in `status().substatus`) grades the current chain
against the ISP-level-adversary checklist: mode, verification, hop count, DNS-at-last-
proxy (code-level, test-pinned), exit class, pin/set policy, stability, shaping, cover
traffic, TLS fingerprint, IPv6 leak surface, and a flow-correlation rollup. Grades are
`pass | warn | fail | unverified`; the rollup is conservative (any fail ⇒ fail;
anything unmeasured ⇒ at best warn). **Anything unverifiable is marked UNVERIFIED and
never asserted** — DAITA, hop independence, the operator's split-tunnel/IPv6 settings,
and the TLS fingerprint of governed HTTP are all genuinely invisible to the app layer
and are reported as such.

### Residual-risk model, in plain language

Against a national/ISP-level adversary that can observe **both** the operator→VPN flow
and the VPN→target flow: single-hop VPN with no shaping is **low-resistance** — timing
and volume correlation is cheap, and the exit ASN is trivially classified as VPN/hosting.
Each layer raises cost but none is decisive from this codebase: multi-hop splits trust
across operators (if the hops are actually independent), the ghost shaper + DAITA deform
timing/size features, and the rotation set + pin make exit identity a *declared, audited*
policy rather than an accident. What remains **operator-side** (outside the code, listed
so no one claims otherwise): Mullvad Bridges/multihop selection, DAITA, dedicated proxy
infrastructure, split-tunnel/in-tunnel-IPv6 settings, and any genuinely residential
egress (paid, per §(d)). The platform's job is to make every one of those residua
*visible and honestly graded* — that is what `substatus()` is for.


## (d) The zero-spend boundary

Residential egress is what actually passes Cloudflare-class scoring cleanly — and it
is a **paid capability the operator has rejected**. This is an **accepted platform
limitation** for CF-class passage: from a datacenter-class exit (all Mullvad exits
are datacenter-hosted) you should expect elevated challenge rates, and no amount of
pinning changes the exit's *class*. Pinning fixes stability; it does not buy
reputation. If an engagement truly requires residential passage, that is a scope/cost
decision for the operator, not something VARVEL will silently approximate.
