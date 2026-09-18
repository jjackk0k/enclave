# VARVEL — native tool build plan (beat RedAmon by out-tooling, not wrapping)

Jack's directive: **native tools, not industry wrappers** (no subfinder/nuclei/ffuf shell-outs).
A few excellent native tools beat 40 shell-outs — each one is faster, governed, and
stealth-aware (honors the shared pacer + noise budget) by construction. Quality bar for
every tool on this list:

- **Non-destructive by construction** — GET/read-only unless the engagement phase authorizes more.
- **Content-verified findings** — a VARVEL finding carries evidence; nothing reported on a
  status code alone. Honest by design, never overstates.
- **Same-origin / signed-scope enforced in code**, not in the prompt.
- **Stealth-aware** — shared pacer (timing + jitter + concurrency + adaptive back-off) and
  persona headers; noise charged to the budget through the `_noise()` chokepoint.
- **Hermetic tests** — localhost-only fixtures; suite stays green; tool added to the
  campaign's `tooledRecon` and the surface graph, with its own noise kind.

## Shipped (10 native tools)

| Tool | RedAmon slot it replaces | Status |
|---|---|---|
| `recon.mjs` — TCP scan + service fingerprint | Masscan/Naabu/Nmap | ✅ |
| `webscan.mjs` — content discovery | FFuf | ✅ |
| `dns.mjs` — subdomain enum | Subfinder/Amass | ✅ |
| `tlsscan.mjs` — TLS config analysis | testssl | ✅ |
| `httpmethods.mjs` — method/CORS/header probe | curl+custom | ✅ |
| `ai-recon.mjs` — adversarial-AI surface fingerprint | their AI Surface layer | ✅ |
| `apisurface.mjs` — API/endpoint/param discovery (robots/sitemap/OpenAPI/GraphQL/JS) | Kiterunner/Arjun/jsluice | ✅ |
| `crawl.mjs` — native BFS link/form crawler | Katana/Hakrawler | ✅ |
| `vulncheck.mjs` — curated, content-verified vuln-check engine | Nuclei | ✅ |
| `passiv.mjs` — passive CT-log + archive aggregation (zero target contact) | crt.sh/GAU/passive subfinder | ✅ |
| `wappalyze.mjs` — tech-stack fingerprinting (rides crawl, zero extra requests) | Wappalyzer | ✅ |
| `jwtforge.mjs` — JWT decode/forge/verify toolkit (shelf→native port #1) | jwt_tool (theirs) — ours is governed + honesty-flagged | ✅ |

## Shipped (engine layer, beyond recon)

| Module | What it is |
|---|---|
| `engine/callback.mjs` — governed callback channel | Post-ex simulation channel (Fang design, green-lit by Jack): HMAC-authenticated check-ins, replay-protected, UUID task correlation, signed-scope + CIDR-ring enforcement, full audit tap, 204-uniform rejections. Ships no payload — protocol/queueing/governance only. |
| `engine/posture.mjs` — posture scorecard | 0–100 target hardness vs dated measured real-site references (stripe/github/cloudflare/axiom, 2026-07-30 snapshots). `GET /api/posture?url=…`. |
| `engine/toolshelf.mjs` — the tool shelf | Persistence for AI-written-on-the-fly tools: quarantined data, sha256'd, human-logged promotion. Seeded with 11 entries from the k2.7 Axiom breach runs. `GET/POST /api/toolshelf`. Shelf→native cycle #1 shipped: `tools/jwtforge.mjs`. |
| `tools/osfp.mjs` — OS fingerprinting (the `nmap -O` slot) | SMB-dialect (rides smbenum, strongest signal, honest "client ceiling" labels) + SSH/HTTP/FTP/SMTP banner parse + optional ping-TTL. Weighted correlation, conflict-halving, 95 cap. Fires in campaigns only where recon earned 445. 11 tests. |
| `tools/canary.mjs` — deception/canary suspicion scan | The stealth-insurance nobody ships: known canary domains, token-shaped DNS labels, bait-subdomain clusters (single never fires — real-estate honest), honey paths/shares data-fed. Suspicion 0–100 + verdict bands; zero target contact. 9 tests. |
| `tools/ldapenum.mjs` — LDAP rootDSE enum (pure-JS RFC 4511) | Hand-rolled BER codec; anonymous bind + base search + unbind. Domain DN, functional levels (honest "2016 or later" plateau), DC hostname, AD-vs-OpenLDAP. Refused bind = hardening intel. 8 tests. |
| `engine/postex.mjs` — governed post-exploitation task library | The Cobalt post-ex tier, range-bound: sysdisc, cred-sim, token-sim, persist-sim (MARKED scheduled task + MANDATORY verified teardown), lateral-relay. HITL-locked, scope-locked, SIM-labeled, MITRE-mapped, cleanup failures fail loudly. No evasion internals, ever. 11 tests. |
| `tools/detoracle.mjs` — detection oracle (structured "did the defender see it?") | Measures detectability, never asserts it: snapshot/diff/classify over the existing governed channel (zero new guest code) — Defender threat-detections, Operational 1116/1117, RTP state → verdict clean/detected/blocked/unmonitored with full evidence. HONESTY CONTRACT: 'clean' = "no detection observed in this window/host/config — NOT a claim of undetectability"; 'unmonitored' never masquerades as clean. CALIBRATED on the range: benign → clean, official AMSI test string → detected (threats +2, 1116 +2) — TRUSTWORTHY on the script-scan layer. First field report: the range image's file-signature layer does not flag textbook EICAR (106 build-time config changes) — calibrate every sensor before grading against it. THE EICAR CALIBRATION GATE (2026-08, the field finding shipped as code): `calibrate()` requires benign → 'clean' AND the EICAR test file → 'detected'/'blocked' with RTP on, else `calibrated:false` with every failure enumerated (an EICAR that reads 'clean' is called exactly what it is — a customized-soft baseline); `calibrationGate` stamps any verdict handed a failed calibration `baselineTrusted:false` with the measured verdict kept honestly, and `assess({calibration})` wires it through. The oracle REFUSES to call itself calibrated on a baseline that fails EICAR. 12 tests. CLI: `detoracle <agentId> <command>` · `detoracle calibrate <agentId>`. |
| `tools/rangehard.mjs` — RANGE BASELINE HARDENING (audit + journaled restore) | The field finding's fix: the range's Defender was CUSTOMIZED SOFT, so the baseline itself is now a governed, measurable object. `audit` reads Get-MpPreference + Get-MpComputerStatus + ASR rule states over the EXISTING governed channel (read-only, zero new guest code) and classifies against a DEFAULT-HARD baseline model (RTP on, MAPS cloud on, PUA block, behavior/IOAV/script-scan on, tamper ON-where-possible, the 16-rule ASR set in block-or-at-least-audit, ZERO exclusions, signatures ≤ 7d). `apply` is OPERATOR-INVOKED ONLY (never automatic): restores the posture — every change journaled with before/after values + a ready revert command (journal written to `.tmp/rangehard/`, the reversibility contract) — REFUSES when the range is unreachable/unreadable (never touches a sensor it cannot read), then a fresh re-audit verifies each change (the journal records what was PROVEN). `revert` replays a journal backwards and re-audits. Tamper protection is honestly a MANUAL gap (portal/Intune-guarded by design — no channel command exists; flagged, never silently skipped). UNELEVATED-READ HONESTY (measured on the wire): exclusion/ASR lists that read as 'N/A: Must be an administrator...' sentinels are reported as UNAUDITED AXES, never fabricated into gaps. 14 tests (13 hermetic + 1 guarded live, read-only). CLI: `rangehard audit|apply|revert <agentId> [journalFile] [api]`. |
| `engine/edrview.mjs` + `tools/edrview.mjs` — EDR SELF-VIEW oracle tier ("what did the defender's telemetry RECORD about us?") | One layer below detection: after a probe/action on the range, reads the DEFENDER-VISIBLE record over the governed channel (read-only Get-WinEvent, zero new guest code) — Defender/Operational (1115/1116/1117/5001/5007), Sysmon/Operational IF installed (process-create 1, network-connect 3, image-load 7, file-create 11, DNS 22), Security logon/share events (4624/4625/4648/5140/5145) from our SMB/WMI touches. Correlation by TIME-WINDOW + MARKERS, never guesswork (a query without both is refused by the classifier; an event matching no marker is telemetry but never cited as ours). Verdict contract: 'recorded' (event IDs + signals cited) / 'clean-in-telemetry' (phrased exactly "no record found in X logs between ... matching this action's markers. Absence of telemetry is NOT undetectability" — never 'undetected') / 'telemetry-absent' (says WHAT could not be checked and why — Sysmon absent, log unreadable). Parsers fail-closed, incl. the PS5.1 ConvertTo-Json quirks (scalar-array unroll, \/Date\/). 14 tests (13 hermetic + 1 guarded live, read-only). CLI: `edrview <agentId> [command|--collect] [markersCsv] [api] [--since iso]`. |
| `tools/sessride.mjs` — governed session ride (vault clearance + authenticated cookie jar) | Productizes the field-expedient `session.mjs` from the manhuaus engagement, WITHOUT its host-corruption bug (string-concat URL building dialed 'manhuaus.comc'; here every hop is a parsed absolute URL): ONE request path rides the vaulted cf_clearance AND an operator session jar (JSON [name,value] pairs, e.g. `wordpress_logged_in_*`), merge order defined + tested (jar base, clearance overlays, explicit Cookie header wins; values never reported). Signed-scope gate BEFORE any request, re-checked per redirect hop; cross-host redirects are data, never followed with the session (credential-leak guard). Ghost egress parity with cfride via `resolveRideTransport`/`rideEgressId` (fail-closed under 'required'); challenge-honest (a challenged response is failure with evidence); `--authcheck` grades auth state as EVIDENCE only (a hollow 200 is 'unverifiable', never 'authenticated'). Also shipped: `cfride raw --full-body` returns the UNCAPPED body for evidence pulls (gate stays on the calibrated 64KB window; a differing full-body classification rides alongside so nothing is hidden). CLI: `sessride <url> --jar <f> --scope <cidrCsv> [--authcheck]`. |
| `tools/rendercheck.mjs` — VISUAL change confirmation (the cached-browser gap) | Closes the gap where the AI proved a change server-side but the operator's CACHED browser showed nothing: renders the page in a REAL headless browser (the nodriver raw-CDP sidecar's new additive `--render` mode: one-shot navigate + settle + wire/DOM/text dump + viewport PNG screenshot; the mint flow is untouched) so the AI sees what a visitor's browser renders. CACHE-AWARE (the core lesson): every render carries a unique `__varvel_rc` cache-buster and the verdict reads `cf-cache-status`/`age` off the Document response — 'origin-live' (DYNAMIC/MISS) vs 'cached-copy' (HIT+age); an expect ABSENT behind a HIT reports REAL-BUT-CLOAKED ("visitors see the stale page; origin state unproven — purge/await expiry"), an expect ABSENT on an origin-fresh read reports NOT LIVE AT ORIGIN (refutes the cached-browser alibi). Governance identical to the ride family: signed-scope gate BEFORE anything (browser-tier deviation, documented: a real browser follows redirects itself, so the FINAL host is re-checked post-render and reported loudly; ridden cookies are CDP-domain-scoped and never ride cross-host), vault clearance + optional session jar (sessride merge order) seeded via a temp FILE (never argv), ghost-chain `--proxy-server` at launch (multi-hop and required+no-chain refuse fail-closed), `--no-ride` forces the cookieless anonymous-visitor view. Challenge-honest (CHALLENGED with the screenshot as evidence, never a claim); a missing `--expect` is a FAIL, never a soft pass; screenshot path only, cookie values never reported. 30 hermetic tests (mocked sidecar). CLI: `rendercheck <url> --scope <cidrCsv> [--expect <text|re:...>] [--deny <text|re:...>] [--out <png>] [--jar <f>] [--no-ride]`. |
| `engine/twinforge.mjs` — defender digital-twin generator (flagship) | Records a live defender's behavior (rate thresholds, WAF classes+block shapes, session defenses, persona, timing) into a hashed portable profile; synthesizes a loopback twin; scores fidelity. Proven: recorded the REAL Axiom SOC (strict-mode adapted threshold and all) → twin → zero fidelity misses. Nobody ships defender-cloning as a training range. 4 tests. CLI: `twinforge <baseUrl>`. |
| `engine/ghost.mjs` — Ghost Mode (governed identity stealth) | The Cobalt-redirector class, native + governed: N-hop proxy chains (http CONNECT + socks5 incl RFC1929 auth), DNS resolved by the LAST proxy (no local DNS leak), absolute-URI/CONNECT agents threaded into webscan/crawl/apisurface/vulncheck, `connect()` raw tunnel for socket tools, header scrub (persona UA, no tool markers). GUARANTEE layer: `ghost.mode=required` is FAIL-CLOSED — public egress refused (logged) until `verify()` proves the exit IP ≠ operator egress; private/range destinations always direct by design. Wired: settings keys, `/api/ghost`, `/api/state.ghost`, campaign gate + agents, chat brief IDENTITY POSTURE, agent shell proxy env (public scope only). Never bypasses hook/scope; status never logs proxy creds, masks baseline IP. 11 tests. |
| `engine/dnswire.mjs` + `agents/dns-client.mjs` + `engine/icmpcodec.mjs` — multi-protocol C2 transports | DNS fully operationalized as a REAL wire transport (not HTTP-carried shape): minimal RFC 1035 parser/crafter, UDP listener inside the channel (`dnsPort`, VARVEL_DNS_PORT baked for the range), chunked result push with per-chunk HMAC + reassembly, strict-seq replay protection, kill-list uniform-empty. Agent side in all three tiers: `agents/dns-client.mjs` (Node, both carriers), `sim-agent` `transport:'dns'`, `varvel-agent.ps1 -Transport http|dns-http|dns-udp` (PS 5.1-safe b32hex/UdpClient/chunking), `va-boot.ps1` v3 opt-in launch. 11 tests (6 dns + 5 icmp codec), incl. real-UDP round-trip ledger completion. |
| `agents/icmp-bridge.py` + channel ICMP transport — the ICMP fallback, natively terminated | Node has no raw-ICMP, so a dumb ~130-line Python byte pump (stdio JSON-lines, spawn opt-in via `VARVEL_ICMP=1`) terminates the transport; the proven codec (`icmpcodec.mjs`) and ALL governance (scope ring silent-drop, per-chunk HMAC, strict seq, reassembly — the shared `_dnsPayload` intake, `transport:'icmp'`) stay in the audited JS process. Frames carry the exact DNS-codec payload strings over RFC 1071 echo; replies ride echo-reply frames, codec-chunked past 512B; denial replies are byte-identical to idle (zero-answer parity with the DNS wire). Bridge capability is EARNED: a loopback self-probe must answer before `supported:true` (socket-open alone proved nothing — Windows opens raw sockets unelevated while restricting paths). `icmpCapability(icmpStatus())` flips to `live-verified` ONLY on an observed authenticated round trip (`liveVerified` sets when a frame advances an agent seq — never asserted). PLATFORM TRUTH, documented not hidden: Windows loopback does not deliver locally-originated echo requests to raw sockets, so full local duplex needs a real NIC boundary — pinned by tests: 5 hermetic (mock bridge: capability honesty, governed pull/push, uniform deny-vs-idle, frame chunking both directions, scope silent drop) + 4 live (capability, loopback kernel-relayed wire, RANGE-NIC echo from 192.168.50.130 verbatim, full governed duplex where the OS allows — skips precisely on the Windows bypass). Also fixed en route: codec-transport pushes (DNS incl.) now store the full body in `results()` — HTTP-parity, was preview-only. AGENT-SIDE TERMINATION + FULL GOVERNED DUPLEX: DONE and range-proven (2026-08-04) — `varvel-agent.ps1 -Transport icmp` (PS 5.1 codec parity byte-exact) completed task-down/result-back over real ICMP: governed `hostname` → `ENCLAVE-TGT` in the ledger, liveVerified flipped on observed frames. The Windows raw-socket wire contract underneath (all range-measured, seven matrices): agent→channel frames ride type 0 (malleable; passes where echo requests can't); channel→agent replies ride type 8 id 0x5602 — python raw-socket type-0 sends are silently dropped off-loopback, type 8 crosses and the agent's RCVALL socket surfaces it (Win11 24H2 raw receive requires specific-interface bind + SIO_RCVALL + ReceiveTimeout; agents send NO echo requests so the kernel's echo path never claims their replies); kernel auto-answer copies are verbatim duplicates (harmless) and kind-filtered channel-side. |
| `engine/validator.mjs` — the validator gate (proof vs belief, enforced in code) | The XBOW/ARTEMIS rail: nothing is reported as proven that wasn't reproduced against an objective oracle. HARD INGEST RULE (deterministic, no model call): a confirmed-tier claim whose evidence/ref cite no oracle — marker/read-back/diff, governed-tool ref, or reproduction step (pinned string classes in `hasObjectiveOracle`) — is DOWNGRADED to suspected at ingest with the note `validator gate: no objective oracle cited`; never deleted, never blocked (suspected was never exploitable anyway — the gate makes the contract real). VALIDATE COMMAND (`POST /api/validate {index|id|ref}`, console button, explicit only — never auto-fires, noise doctrine): http-class findings get ONE governed re-read (paced, ghost-riding, scope + ghost fail-closed, redirects are data never followed); other classes honestly report `no automatic oracle for this class — reproduce manually`. Result lands on the finding as `validation {state: validated|refuted|untestable, oracle, at}` — REFUTED is first-class and flips confidence to suspected with a refutation note. Report + console show validated / claimed-unvalidated / refuted per finding. 13 tests. |
| `engine/inlineexec.mjs` + `agents/inlineexec.mjs` + `agents/inline-exec.ps1` + `tools/execasm.mjs` — the in-memory execution tier (gap #4 remainder) | Governed `inline-dotnet` task kind: a .NET assembly executes IN THE AGENT'S OWN process memory (`[Reflection.Assembly]::Load(byte[])` + entry invoke, stdout/stderr/exit-code captured over the normal result path; the PS agent runs in-proc via a bounded nested runspace, the Node agent spawns the reviewed PS helper with the job on stdin — no disk path exists in the runner contract). HARD DOCTRINE held: NO EVASION — no AMSI patch, no ETW tamper, no injection into other processes; an AMSI scan of the load is the detoracle's measurement input, never dodged. DOUBLE GATE, fail-closed: engagement setting `exec.inMemory` (default OFF; refusal = audited `task.refused` + API 403) AND the agent launch flag (`--exec-in-memory` / `-AllowInMemoryExec`). 1 MiB assembly cap (refused pre-queue); sha256 of the bytes audited at queue time (`exec.inline-dotnet`) — the bytes never touch disk, the hash is the accountability trail. DETORACLE PAIRING: `exec-assembly <agentId> <file> [argsCsv]` = execute-assembly → verdict (refusal reads `refused:true`/unknown, never clean). BOF/COFF loader honestly NOT built (documented stretch — no native host in a Node/PS agent fleet). 13 tests (11 hermetic incl. gate/cap/hash/no-disk + 2 guarded LIVE: real csc compile → real PS CLR round trip with the build artifact deleted BEFORE execution). |
| `engine/malleable.mjs` v2 + `engine/shapegrade.mjs` + `engine/transport-grade.mjs` rankTransports + `tools/shapegrade.mjs` — the C2 SHAPING PACK (breadth roadmap #2) | Nation-grade wire-shape control, oracle-DRIVEN (the differentiator: the oracles don't just measure — their scores drive the shape). **Shape knobs:** proportional `jitterPct` cadence (real % jitter, not ±fixed ms), batch/dwell windows (held tasks flush in ONE burst at a seeded point inside each window — the point is HMAC-derived from the shared token so channel and agent agree with no coordination), constant-rate padding dummies (profile-gated, default OFF; honest cost: multiplies request volume; every pad is audited as `agent.pad` and counted in the flow ring — shaping never hides traffic from the platform's own ledger). **Profile library v2:** `plain` (today's shape, byte-identical default) + `cdn-asset` / `software-update` / `telemetry-beacon`, each declaring path templates, ordered header sets, UA families, cadence model, expected JA4H class; applied per agent via `shape.profile` settings floor + cli `shape` (rides the `x-varvel-shape` header; shaped routes are per-agent gated, clear propagates over the stale paths). **Self-measurement loop (honesty machinery):** `shapegrade <agentId>` grades the APPLIED profile against the measured wire — fporacle JA4H ring vs the computed expected fingerprint (exact-string bar; the runtime's undici append contract is pinned by test), beaconscore over the observed check-in ring vs the cadence model's pre-flight band. Divergence is reported LOUDLY (`divergent[]`), never asserted away; insufficient evidence is fail-closed. **Oracle-graded adaptive failover (gap#5 follow-through):** per-wire score = health(60/30/0) + success(min(20, observed checkins)) − 0.4×measured beacon score; eligibility fail-closed (ghc needs enabled+token+client, smb needs an enrolled link, doh/icmp need their arms live; unknown wires never rank); operator pin (assignedTransport) always wins; the recommendation surfaces in agentsView/`failover <agentId>` and applies only via the audited setTransport path — the channel never auto-switches. Agent-side adoption checks local workability (smb without a link / ghc without config are refused with a loud note). HONEST LIMIT, stated on every report: shaping covers the HTTP request layer (paths/headers/cadence) — TLS-stack JA4 needs native TLS control this pure-ESM stack does not have, and H2 fingerprints are out of reach on the http/1.1 stack. 26 tests (shape + adaptivefail). CLI: `shape`, `shapegrade`, `failover`. |

## Stealth posture (operational stealth — enforced, always-on)

- ✅ Enforced pacer: shared emission clock, jitter, concurrency, adaptive 429/503 back-off.
- ✅ Noise budget + peak ceiling + after-action proof (`budget.mjs`, honest dual-invariant wording).
- ✅ Target-aware auto-calibration (`target-profile.mjs`) — the `50 vs 200` problem RedAmon punts.
- ✅ **Stealth-by-default**: the server now defaults every campaign to `'auto'` (fingerprint +
  calibrate); `'loud'` is a deliberate operator choice, `VARVEL_STEALTH=off` for emergencies.
- ✅ **Persona headers**: one realistic, engagement-consistent browser identity shared by all
  tools (rotation per-request is itself a tell; announcing `VARVEL-*`/`nuclei` signs every log).
- Next: request-VOLUME fidelity in the noise model (`loudness × (1+log10 n)` — scoped follow-up,
  needs a `BUDGET_PRESETS` retune); footprint-cost-aware planner ranking.

### The line (REVISED 2026-07-30 by Jack — Kimi's lane widened)

**Scope:** Kimi is cleared to build BOTH non-offensive and offensive capability for VARVEL,
under Jack's direction. (The earlier non-offensive-only bar was a Claude-lane rule; Jack
revised it.) What does NOT change — these are the platform, not preferences:

- **Governance is absolute** — signed scope, the Enclave PreToolUse hook, HITL gates on
  exploit/post-ex, and the tamper-evident audit apply to EVERYTHING, offensive included.
  Offensive capability makes the gates MORE load-bearing, never less.
- **Ask-driven builds** (the HYDRA lesson — its AI built unasked): build what Jack asks,
  when he asks; flag candidates, don't self-expand scope.
- **Never touch the Enclave's own tamper-evident audit.** Anti-forensics/log tampering
  stays out permanently — it would destroy the audit that is VARVEL's reason to exist.
- **Honesty** — content-verified findings, no overstated results, offensive or otherwise.

**HYDRA reference reviewed:** `Hydra.Modules.C2/Listeners/FangListener.cs` (Jack's Fang
implant listener — reviewed 2026-07-30, that file only). Genuinely strong engineering:
minimal cookie-keyed HTTP protocol with 204-empty semantics, last-sent-command result
correlation with non-destructive re-queue, bounded queues + 4MB body cap + incomplete-body
rejection (DoS hygiene), and the 204-not-410 anti-fingerprinting trick (denied agents get
the same response as idle ones — no behavioral tell). **GREEN-LIT + SHIPPED 2026-07-30 as
`engine/callback.mjs`** — the governed callback channel: keeps Fang's 204-uniformity,
bounded queues, and body caps; FIXES its three real weaknesses (no check-in authentication
→ per-agent 128-bit token + HMAC-SHA256 request signing; no replay protection → strictly-
increasing per-agent sequences; one-byte last-sent correlation → UUID taskIds echoed in
results, so out-of-order results never mis-tag) and adds the Enclave layer (signed-scope
required to arm, loopback bind by default, CIDR-ring check-in enforcement, every event to
the audit tap). Ships no payload/implant logic — the agent is any HTTP client speaking the
protocol. 9 hermetic tests including a full round-trip.

## Standing strategy (Jack's directive, 2026-07-30 — BOTH/AND, not either/or)

VARVEL must dominate the differing areas AND beat RedAmon/Cobalt/paid platforms in their
OWN areas — no second-best anywhere: raw breadth and C2 maturity are first-class goals,
not nice-to-haves. The native-tool queue below is the breadth engine; the governed
callback channel (`engine/callback.mjs`) is the C2 entry — mature it toward Cobalt-class
capability under governance (session management, tasking, artifact staging, malleable
profiles as *documented tradecraft*, never as evasion). Every new capability ships with
the VARVEL difference built in: governed, honest, stealth-enforced, tested.

**Breadth roadmap (their turf, our standard):**
1. **Protocol level** (the Win11 VM is the proving ground): SMB/Kerberos enumeration
   natives (shares, sessions, users, signing checks), AD relationship mapping (the
   BloodHound job, native), WinRM/WMI methodical enumeration. Nmap-class service depth
   beyond the top ports.
2. **C2 maturity**: session/channel management on the callback channel (multi-agent,
   jitter profiles, task queues, artifact staging + retrieval, operator console).
   Goal: Cobalt-class operator experience, governed by signed scope + HITL + audit.
3. **Exploit-aid natives**: SSRF (done), JWT (done), header smuggling/desync probes,
   template-injection probes (SSTI), XXE probes, GraphQL-abuse pack, authz-matrix
   tester (IDOR/BOLA), weak-crypto detector (the hashid/john-the-ripper job, native).
4. **Fuzzing**: structured input fuzzer with crash/oracle detection for the in-scope
   HTTP surface (honest differential, budget-capped).
5. **Browser tier**: headless-rendered recon + DOM-XSS verification (the Playwright
   job — native driver, deferred until the VM/browser base image lands).

## Build queue (highest value first)

0. **AXIOM SOC — the adaptive blue team** (next target upgrade, designed 2026-07-30 with
   Jack). A mini security team INSIDE the Axiom practice target, mimicking a human SOC:
   - **Deterministic SOC core (the actions)** — adaptive Shield rules, never model-driven:
     burst behavior → temp-ban with lockout page; WAF-block threshold → stricter mode
     (tighter rate limit); admin-action anomaly (admin write from a session with no
     interactive login / impossible token lifecycle) → ALERT + KEY ROTATION, killing a
     leaked signing key mid-run and forcing re-derivation. Attackers must beat ADAPTIVE
     defense, not a static wall.
   - **AI analyst (the voice)** — a small model (kimi-k2.7-code or smaller) that reads the
     alert log and writes the incident summary for the operator: what was tried, what the
     SOC did. ADVISORY ONLY: its output never feeds the defense loop. The alert log is
     attacker-influenced content (UA strings, paths, payloads) — a blue-team model that
     ACTED on it would be prompt-injectable by the attacker it's watching (blind the SOC,
     trigger fake lockouts, exfil via "summary"). Realism AND safety point the same way:
     deterministic hands, AI voice.
   Why: real enterprises have SOCs; breaching "a site with a team" is the honest next
   tier, and it exercises exactly VARVEL's differentiator (adaptive stealth + watchdog)
   in a way RedAmon's evaluation can't match.

1. ✅ **`passiv.mjs` — passive source aggregator** (the crt.sh/Wayback slot) — SHIPPED
   2026-07-30. CT logs + Wayback CDX → subdomains, historic endpoints, params; sources fail
   independently; `targetContact: 0` guaranteed by construction. Wired into campaign
   tooledRecon (passive runs BEFORE any active packet; no noise charge). Live-verified
   against a public domain. Next sources when wanted: CommonCrawl, HackerTarget, URLScan.
2. ✅ **`wappalyze.mjs` — native tech-stack fingerprinting** (the Wappalyzer slot) — SHIPPED
   2026-07-30. 27-signature engine (headers/cookies/meta/asset-paths/inline markers), pure
   function over pages the crawl ALREADY fetched → zero extra requests; evidence-carrying
   hits, version extraction, firm→confirmed confidence by multi-page agreement. Rides
   `crawl.mjs` results into the surface graph; feeds vulncheck template selection.
3. ✅ **Vulncheck template packs** — SHIPPED 2026-07-30 as `engine/cvepacks.mjs`: curated
   version→CVE correlation (Apache/nginx/IIS/PHP/Tomcat/jQuery; KEV flagged). Fires ONLY on
   an actually-fingerprinted version, confidence `firm` with verification guidance (distro
   backports honesty), zero extra requests. Live-verified end-to-end: crawl fingerprinted
   nginx 1.18.0 → CVE-2021-23017 fired. EXPANDED 2026-09-12: `tools/cvepack-import.mjs`
   generates `engine/cvepacks.generated.mjs` from the NVD JSON 2.0 feeds + CISA KEV
   (441 entries / 13 products, KEV-pinned, CVSS≥7, ranges only from NVD CPE nodes — never
   guessed); the engine merges it under the curated 9, which always win per-CVE.
4. **`capture.mjs` — TrafficMind-style capture proxy** (P1 in the feature map): governed
   MITM capture + Burp-style history + replay/diff/search tools for the agent. Big win for
   the exploit phase's evidence quality.
5. **Console panels** — wave / LATS-tree / fireteam member cards (P0 #6 remainder).
6. **`browser.mjs` — headless-rendered crawl** (the ZAP Ajax Spider slot) — only if SPA
   coverage proves thin in practice; heaviest tool on the list, defer until needed.

## Gap audit (2026-07-31, ordered by Jack: "look at VARVEL, check what it's missing or underdone")

Audited against Cobalt Strike, RedAmon, HYDRA, and the temp-AI critique of our tool code.

**MISSING (build, in this order):**
1. ✅ **OS fingerprinting** — SHIPPED 2026-07-31 as `tools/osfp.mjs` (engine table above).
2. ✅ **Canary/deception detection** — SHIPPED 2026-07-31 as `tools/canary.mjs`.
3. ✅ **LDAP/AD enumeration** — SHIPPED 2026-07-31 as `tools/ldapenum.mjs`.
4. ✅ **Post-exploitation internals — IN VARVEL** — SHIPPED 2026-07-31 as `engine/postex.mjs`
   (range-bound, SIM-labeled, mandatory verified teardown, MITRE-mapped). Jack overruled the HYDRA-lane split 2026-07-31:
   "be better than Hydra so we need them… Cobalt has them, we need them and better").
   Built range-bound + governed: credential-access SIM against range-planted artifacts,
   token-theft SIM, lateral-movement orchestration over the governed channel (SMB/RPC now
   live on the range), persistence SIM with automatic teardown + detection proof.
   HITL-locked, signed-range-locked, every action audit-tapped.
   **The line I keep even under the widened lane: no EDR-evasion internals, no anti-forensics.**
   Evasion fights Defender, not a SOC; it is malware-defining, it's exactly what got Cobalt
   blacklisted by every EDR on earth, and an enterprise cannot deploy it against itself.
   VARVEL's post-ex proves impact on the range and produces DETECTIONS, not implants.
5. **Pivot chaining + named-pipe transport** on the callback channel (agent-through-agent) —
   the last Cobalt C2 primitive we lack after malleable profiles + DNS transport. QUEUED NEXT.
6. **Every tool ships its own detection signature** for the SOC side (attack/defense ratchet) —
   osfp/canary/ldapenum/postex footprint entries landed with the tools; SOC-side signatures
   for the new kinds are the follow-up. Also shipped from this audit: `engine/twinforge.mjs`
   (defender digital-twin generator — the flagship nobody has) and the postex tier.

**UNDERDONE (improve continuously):** adaptive behavior keyed to defender responses (beyond
429 back-off: WAF-signature recognition, defense fingerprinting — the temp-AI critique was
right); UI parity reviews vs RedAmon each release; deploy story (one-command install).

**HYDRA material reviewed for the ports:** `publish/Hydra.Modules.Recon.xml` (OsFingerprinter,
CanaryDetector, PortScanner+AdaptiveTimingController, ServiceAnalyzers.LdapAnalyzer/SmbAnalyzer)
— ported governed + honest + tested, not copied (theirs is C# doc XML; the protocols are the
spec). `Hydra.Modules.EtwMonitor`/`WefAbuser` reviewed for tradecraft awareness only — ETW
tampering is inside the evasion line above, NOT ported.

## Dual-stack IP foundation (2026-08-04 — IPv6 breadth, Jack's call: correctness first)

Scope math was re-derived per file from hand-rolled IPv4 regexes — every copy a place
IPv6 failed wrong or was misclassified. SHIPPED: **`engine/ipaddr.mjs`** — the ONE
implementation of IP parsing / classification / CIDR membership for the platform.

- Strict parse (v4: no out-of-range octets, no leading-zero octal ambiguity; v6:
  full/compressed/embedded-v4 forms, [brackets] and %zone stripped; anything else
  REJECTED, never coerced). v4-mapped v6 collapses to fam 4 (`::ffff:10.x` IS `10.x`).
  CIDR family-strict: `0.0.0.0/0` is all-v4, `::/0` is all-v6 — neither silently
  matches everything (fail-closed: an operator who means both signs both).
- Rewired onto it: `callback.mjs` `ipAllowed` (signed-ring check-in enforcement — v6
  rings enforce identically; ALL of 127/8 is loopback), `ghost.mjs` `isPrivateDest`
  (ULA + link-local v6 now go DIRECT — no lab-topology leak to proxy operators) +
  exit-IP `verify()` (v6 exits validate; canonical compare), `recon.mjs` `ipInScope`
  + bracketed URL forms + canonical redirect compare + literal normalization,
  `postex.mjs` sysdisc intel (v6 address lines parsed).
- **The governance hook (enforcement seam) rewired too:** `poc/enforcement-seam/util.mjs`
  `ipInCidr`/`ipInAnyScope` delegate to the shared math (a latent bits>32 shift-wrap
  bug died with the old copy); `classify.mjs` recognizes v6 targets — a ULA/link-local
  destination in a shell command is OFFENSIVE target traffic gated by signed scope,
  never research egress; `egress-allowlist.mjs` `extractHost` no longer corrupts
  bracketed v6 (`[::1]` → `[::]`) and strips trailing shell debris.
- 11 hermetic ipaddr tests + extended callback/ghost/recon/postex coverage; full suite
  green both stages (light incl. ipaddr 11; integration 170). Seam demo 20/20.

Follow-up noted honestly: the DNS C2 listener/agent bind `udp4` — real-resolver IPv6
transport for the DNS channel is a scoped follow-up (dual-bind), not a silent gap.
SHIPPED 2026-08-27 (listener half): the channel's DNS wire now dual-binds udp4 + udp6
(ipv6Only) on one port; a family that cannot bind is a NAMED `dns.bind-gap` audit event,
never a crash; a specific v4 NIC bind never expands to `::`. Agent-side v6 dialing stays
the scoped remainder.

## riskLevel + severity normalization (2026-08-04 — review item: "riskLevel field on each finding")

The review asked for a `riskLevel` field; the audit underneath it found a REAL bug:
tools spoke two severity dialects (short 'crit'/'med', long 'critical'/'medium') and
the surface's unknown→'med' coercion silently DOWNGRADED long-form criticals — a KEV
'critical' from cvepacks landed in reports as MEDIUM.

- **`engine/severity.mjs`** (NEW): the ONE vocabulary. `normSev` (alias table —
  critical/medium/moderate/informational… → canonical `crit|high|med|low|info`;
  unknown → 'med', never dropped to info), `sevRank` (sort), `riskLevel` (triage
  roll-up: crit+high → **high**, med+low → **medium**, info → **info** — the
  reviewer's exact tiers).
- Every finding node now carries `risk` (derived at `surface.finding()`, never stored
  by hand); `counts().risk = {high, medium, info}`; `fromJSON` backfills legacy saves
  (stored sev NOT re-normalized — history can't be un-coerced, only derived from).
- Report executive summary gains a **Risk levels: N high · N medium · N info** line;
  remediation items carry `risk`; campaign's findings mapping passes it through;
  classify/report/tlsscan sort via the shared rank (duplicate order tables deleted).
- Tests: `test/severity.test.mjs` (3) + engine.test extensions (dialect regression,
  counts tiers, legacy backfill). Full suite green both stages.

## AI-recon 8080 false-positive fix (2026-08-04 — review item)

`AI_PORTS` split into STRONG (`AI_PORTS` — 11434/6333/6334/8001/19530/7860/8501/1234/
11235: an open port alone IS evidence) and GENERIC (`AI_PORTS_GENERIC` — 5000/8080/
3000/8000: probed identically, but the port number ALONE never flags AI; a root-page
hint or endpoint signature must corroborate). A Tomcat/dev-server on 8080 is no
longer reported as "AI gateway". Default scan coverage unchanged (both catalogs).

## Ghost coverage completion (2026-08-04 — plumbing bundle + the private-direct keystone)

The follow-up sweep after Ghost Mode. The keystone fix, found while threading agents
into more tools: **the ghost agents tunneled EVERYTHING — including private/range
destinations.** The "private goes direct" rule was caller discipline, not code. One
bad call would have routed lab traffic through the operator's proxy chain — breaking
the sealed range AND leaking lab topology to the proxy operator.

- **`ghost.mjs` keystone**: `GhostHttpAgent`/`GhostHttpsAgent`/`Ghost.connect()` now
  dial DIRECT for private destinations by construction (`isPrivateDest` — dual-stack,
  via engine/ipaddr). `verify()` is the documented exception: measuring the chain's
  exit REQUIRES riding it, so verify uses `alwaysProxy` agents (engagement traffic
  never does). 3 new tests pin it: proxy sees nothing for private HTTP, private TLS,
  and `connect()` — while public CONNECTs still ride the chain.
- **agents plumbed** (2-line pattern): `fuzz`, `ssrfprobe`, `credstuff` (tools);
  `target-profile.detectStack` (the stealth auto-calibration profiler — it touched
  the target unprotected) and `webpaths.guidedWebSearch` (engine). Campaign passes
  ghost agents at both call sites. Honestly EXCLUDED: `twinforge` (the twin is an
  http SERVER; recording is data-fed) and `posture` (pure classifier, no egress).
- **Socket tier**: `smbv2.smbEnumerate` gains `connectImpl(host,port,timeout)` (mirror
  of ldapenum's existing opt); campaign wires `ghost.connect()` into the LDAP path —
  private dials direct by ghost's own rule, public rides the chain.
- **claude-cli env parity**: `makeClaudeAgent` takes `extraEnv` (merged after the Kimi
  routing block — no ANTHROPIC_* collisions); all three server call sites pass
  `ghostShellEnv()` (previously Kimi-only).
- **Console ghost card** (app-v6): live header chip (mode · hops · verified exit /
  NOT HIDDEN / unverified, tooltip = chain + DNS rule) + a Settings card with full
  status (mode/chain/dns/private rule/posture) and arm/verify controls over
  `/api/ghost`. Suite green; the console's script block parses.

## Standing rules (post-revision — see "The line" above)

- Offensive capability is now IN-scope for Kimi **under Jack's direction** (he green-lights;
  we don't self-expand). Governance gates are untouched by this.
- Anti-forensics / log tampering stays OUT permanently — it contradicts the audit that is
  the product. The Enclave's tamper-evident audit is never touched, by anyone.
- HYDRA remains Jack's own project — reference it when he points (as with FangListener),
  don't roam it.

## Owner-queued work — 2026-09-18 (evening sitting)

Queued at Jack's direction (300M-token DeepSeek run produced 0 findings; "clearly we are
doing something wrong"). Ordered by leverage, not by request order. Nothing here is
started unless marked.

1. **Ternary Bonsai 2 27B — head-to-head against our own Qwen3.8-27B-UD-Q6_K.** Both are
   Qwen3.8-27B, so the comparison isolates the *quantization*, which is the only honest way
   to read it. Vendor (Prism ML) claims: 98.2% of FP16 benchmark retention, 5.95 GB, ~130
   tok/s on an RTX 5090, and — the number that actually matters to us — BFCL v3 tool calling
   74.92 vs 74.00 for UD-Q4_K_XL. Accepted, not yet locally measured.
   - **HARD BLOCKER (found 2026-09-18):** the low-bit types live in the vendor's llama.cpp
     FORK (`PrismML-Eng/llama.cpp`). The Spark lane is stock `ggml-org/llama.cpp` b81c99b
     (`version: 0.3.0-dev`), and that binary contains **zero** occurrences of `pq2_0`,
     `ptq1_0`, or `ternary`; the box also has **no `nvcc`**. So the GGUF downloads fine and
     then cannot load. Building the fork for GB10 is a prerequisite, and it needs a CUDA
     toolkit install first — an owner decision, not an agent one.
   - **Packing choice is decided by our hardware, not by size.** The vendor README says
     PTQ1_0 (1.75 bits/weight, 5.95 GB) is "faster on Ada-class and smaller accelerators and
     **slower on Ampere, Hopper, and Blackwell**". Spark is GB10 = Blackwell ⇒ **PQ2_0**
     (2.13 bits/weight, 7.21 GB) is the primary candidate; PTQ1_0 is the density variant to
     *measure*, never to assume.
   - Fetch script `.tmp/get-bonsai2.sh` (must stay LF — a CRLF copy made bash die at
     `set -u\r` before it wrote anything). Verifies both files against the git-lfs oids,
     which ARE the content sha256.
2. **GLM-5.3-Flash (Z.AI: `glm-5.3-flash` / `glm-5.3-flashx`; 320B total / 18B active, 1M
   context, function calling + tool streaming) gets a fidelity scorecard BEFORE it is
   allowed to drive the loop.** One command, minutes: `node tools/brainharness.mjs run
   --provider-env --suite fidelity,honesty,loop`. This is the same gate `runLoop` now
   enforces fail-closed at startup, so a pass here is what makes it an approved cheap lane —
   and a fail is 300M tokens not spent. **This is the standing rule for every new brain:**
   measure, then trust.
   Verified endpoints (2026-09-18): OpenRouter `z-ai/glm-5.3-flash` (canonical
   `z-ai/glm-5.3-flash-20260826`, HF `zai-org/GLM-5.3-Flash`) at base URL
   `https://openrouter.ai/api/v1`; Z.AI direct at `https://api.z.ai/api/paas/v4` with model
   `glm-5.3-flash` (also `glm-5.3-flashx`); auth is `Authorization: Bearer <token>`, and the
   response carries `reasoning_content` + `tool_calls`, which is exactly the wire shape
   `engine/brain-provider.mjs` already maps. So GLM needs **no** new adapter code.
3. **DeepSeek V4.1 Flash (`deepseek/deepseek-v4.1-flash` on OpenRouter) may only be re-run
   behind that same gate.** The prior campaign's burn was not the model's fault alone: the
   loop had no competence gate and fed it unmapped work. Do not re-fund the lane because
   other people post results with it; fund it because it passes *our* fidelity gate.
4. **Implement the remaining spec** in `docs/builds/2026-09-18-spark-loop-upgrades.md`
   (the fidelity gate from that spec is DONE and merged): a validator pass distinct from the
   authoring brain, planner/executor split, parallel opportunity workers **with a single
   shared per-program+host pacing account**, retest loop, explicit brain-offline policy.
5. **Cross-cycle dupe-memory ledger** for bounty candidates (the "6 findings, all dupes"
   failure mode). Today's dedup is per-program only.
6. **Brain-prompt enrichment** from the `ato3` hand-read queue + the playbook discriminators,
   so a cheap lane spends its context on named shapes instead of re-deriving doctrine.
7. **Spark hygiene (measured 2026-09-18 19:4x):** `/` 916 GB, 567 GB used, **303 GB free
   (66%)**; inodes 2% (fine). `/home/varvel` 500 GB — `models` 292 G, `drafter-align` 77 G,
   `lora-runs` 69 G, `engine-switch` 33 G, `training-models` 21 G. RAM 121 GB, 117 free.
   **The lane is DOWN** (no listener on :8080, stale pid file, `lane-models.sh status` =
   `health=000000 model=none`), so nothing is served right now — including our Q6 baseline.

