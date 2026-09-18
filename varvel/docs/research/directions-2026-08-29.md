# VARVEL Research Directions — 2026-08-29

**Purpose:** Where new vulnerability *classes* (or significantly novel technique variants) are most likely to emerge in 2025–2026, and which of those an AI-operated platform can research autonomously, at research-lab grade.

**Method:** Web-grounded scan (August 2026) of what researchers are actually publishing — PortSwigger Research, academic venues, vendor research (Unit 42, Wiz, Imperva, Sonatype), OWASP GenAI/Agentic projects, and CVE/incident records. Every external claim below carries a URL retrieved this session. Directions where search returned nothing solid are marked **UNVERIFIED**.

**Scoring:** Rank = (VARVEL edge × feasibility × payout proximity). Each direction is labeled honestly as a **grindable seam** (systematic work, predictable output) or a **lottery ticket** (low hit rate, high payoff).

---

## The anchor fact for VARVEL's whole research lane

In August 2026, James Kettle (PortSwigger Director of Research) published the **HTTP Terminator**: an autonomous system that read 138 technical specifications, fragmented them into ~15,000 "inspiration" units, generated ~30,000 unique attack-vector hypotheses, and confirmed roughly **700 vulnerable live targets** (via authorized bug-bounty programs), pushing the HTTP desync frontier forward. Source + source code + reusable blueprint: [Can AI invent new attack techniques? — PortSwigger Research, Black Hat USA 2026](https://portswigger.net/blog/can-ai-invent-new-attack-techniques-new-research-from-james-kettle-and-portswigger-research).

Two implications for VARVEL:

1. **The "AI invents a technique" question is answered: yes, at scale, with a human at the discovery cascade.** Kettle's strongest results came when a human stepped back in to pick which anomalies deserved the next hypothesis. VARVEL's governed/HITL design (sigil gates in the campaign pipeline, see `docs/PIPELINE.md`) matches this architecture exactly.
2. **The blueprint is published.** The meta-method — spec corpus → fragmentation → hypothesis generation → cheap automated evaluation → human-curated cascade — is now a documented, repeatable procedure. VARVEL's job is to point that procedure at the *right* seams, faster than the crowd. That is what this document ranks.

---

## Ranked directions

| # | Direction | Type | Edge | Feasibility | Payout proximity |
|---|-----------|------|------|-------------|------------------|
| 1 | MCP / agentic tool-use attack surface | Grindable seam, still early | ★★★★★ | ★★★★★ | ★★★★☆ |
| 2 | HTTP desync frontier — HTTP/3/QUIC parser divergence | Grindable seam | ★★★★★ | ★★★★☆ | ★★★★★ |
| 3 | Passkey/WebAuthn ceremony manipulation | Grindable seam, young | ★★★★☆ | ★★★★☆ | ★★★★★ |
| 4 | Browser API mishaps: XS-Leaks & connection-pool classes | Grindable seam | ★★★★☆ | ★★★★☆ | ★★★☆☆ |
| 5 | AI supply chain: model files, scanner bypasses, slopsquatting 2.0 | Grindable seam, crowded | ★★★☆☆ | ★★★★★ | ★★★☆☆ |
| 6 | Inter-agent identity & delegation (A2A auth) | Lottery ticket | ★★★★☆ | ★★★☆☆ | ★★★☆☆ |
| 7 | CI/CD OIDC trust & pipeline provenance | Grindable seam, crowded | ★★★☆☆ | ★★★★☆ | ★★★★☆ |
| 8 | PQC hybrid-migration implementation bugs | Lottery ticket | ★★★☆☆ | ★★☆☆☆ | ★★☆☆☆ |
| 9 | VS Code / non-CWS extension store confusions | Grindable seam, modest payout | ★★★☆☆ | ★★★★☆ | ★★☆☆☆ |
| 10 | Wasm/V8 sandbox internals (JSPI, streaming races) | Lottery ticket, avoid for now | ★★☆☆☆ | ★★☆☆☆ | ★★★☆☆ |

---

### 1. MCP / agentic tool-use attack surface — **top pick**

**(a) Emerging class.** MCP (Model Context Protocol) went from spec (late 2024) to "backbone infrastructure" within a year, and the vulnerability literature is still catching up. Confirmed 2025–2026 classes: Tool Poisoning Attacks (hidden instructions in tool metadata — [Systematic Analysis of MCP Security, arXiv, Aug 2025](https://arxiv.org/html/2508.12538v1)), and IDE auto-execution flaws: CurXecute and **MCPoison (CVE-2025-54136)** in Cursor, both disclosed mid-2025 and cataloged by CSA: [MCP Attack Surface: Tool Poisoning and IDE Auto-Execution — CSA Labs, Jul 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/). Peer-reviewed threat modeling is only now appearing: [MDPI: MCP Threat Modeling and Prompt Injection with Tool Poisoning, May 2026](https://www.mdpi.com/2624-800X/6/3/84). Under-explored seams: cross-server injection (one malicious/low-trust MCP server poisoning a host's view of another server), tool-schema shadowing, sampling-channel abuse, and OAuth/delegation edges in remote MCP servers. Agent-infrastructure CVEs are already dropping (e.g. Flowise CVE-2025-59528 RCE — [Claw Street Journal writeup, Apr 2026](https://clawstreetjournal.github.io/cyber-defense/2026/04/10/flowise-rce-agent-infrastructure-attack-surface.html)).

**(b) VARVEL edge.** VARVEL *is* an agentic system with an MCP surface (`tools/mcpserve.mjs`) — it can self-host a fully instrumented attacker/server/victim triad. Perfect failure memory matters enormously here: poisoning exploits are stateful and multi-turn, and humans lose track of which of 500 tool-description permutations were tried. Code-reading throughput matters because most MCP servers are open-source and small — an AI can audit the *entire* server corpus for patterns (schema shadowing, unvalidated sampling responses) rather than sampling.

**(c) First lab experiment.** Stand up two MCP servers in `deploy/range-iso/` (one honest, one hostile-instrumented) plus VARVEL's own `mcpserve.mjs` as victim host against `targets/demo-corp.mjs`. Hypothesis battery: (i) hostile server's tool descriptions inject instructions that cause the host to exfiltrate the honest server's tool outputs; (ii) a tool whose *schema* (not description) carries payload; (iii) a tool that renames/shadows another server's tool between listing and invocation. Log every permutation and outcome into the hypothesis log (format below). All inside the lab VLAN; nothing touches live targets.

**(d) Difficulty & timeline.** Low–moderate. First publishable/filable result in **2–6 weeks**: either a novel cross-server poisoning variant (writeup + disclosure to MCP maintainers) or a systematic CVE sweep of popular MCP servers (filable immediately via vendor VDPs).

---

### 2. HTTP desync frontier — HTTP/3/QUIC parser divergence

**(a) Emerging class.** HTTP request smuggling is not dead — it is migrating down-stack. 2025–2026 evidence of an active, productive seam: CVE-2025-55315 (ASP.NET Core request smuggling — [Microsoft MSRC, Oct 2025](https://www.microsoft.com/en-us/msrc/blog/2025/10/understanding-cve-2025-55315)); CVE-2026-33555 (**HAProxy HTTP/3 request smuggling** causing backend desync — [SentinelOne, May 2026](https://www.sentinelone.com/vulnerability-database/cve-2026-33555/)); CVE-2025-64702 (quic-go HTTP/3 QPACK decompression asymmetry DoS — [SentinelOne, Dec 2025](https://www.sentinelone.com/vulnerability-database/cve-2025-64702/)); CVE-2025-32094 (OPTIONS + obsolete line folding smuggling, found via bug bounty — [Akamai, Aug 2025](https://www.akamai.com/blog/security-advisory/cve-2025-32094-http-request-smuggling)); QUIC-LEAK CVE-2025-54939 pre-handshake DoS in LSQUIC ([Imperva, Aug 2025](https://www.imperva.com/blog/quic-leak-cve-2025-54939-new-high-risk-pre-handshake-remote-denial-of-service-in-lsquic-quic-implementation/)). Academic work has built a taxonomy + tool for HTTP/3 smuggling from RFC 9114 violations ([NCA paper slides + HTTP3-Smuggling-Tool](https://www.nca-ieee.org/assets/slides/paper14.pdf)), and NDSS continues to publish QUIC attack papers ([NDSS 2026 paper referencing QUIC attack review](https://www.ndss-symposium.org/wp-content/uploads/2026-s1777-paper.pdf)). And this is the exact domain where the HTTP Terminator proved AI-driven technique invention works ([PortSwigger](https://portswigger.net/blog/can-ai-invent-new-attack-techniques-new-research-from-james-kettle-and-portswigger-research)).

**(b) VARVEL edge.** This is the Kettle playbook on the newest protocol layer. Desync hunting is *combinatorial* — header normalizations × parser pairs × protocol versions — which is precisely where perfect failure memory and tireless variant generation beat humans. VARVEL already has adjacent tooling (`tools/wafbypass.mjs`, `tools/fuzz.mjs`, `tools/tracetap.mjs`, `tools/variantsweep.mjs`) to adapt. Human experts are scarce here; the crowd is small; bounty programs pay top-tier for smuggling (Akamai's report proves the payout path).

**(c) First lab experiment.** Build a two-tier lab: HAProxy/nginx HTTP/3 front end → deliberately-mismatched Node/Go backend, all in `range-iso/` or as a docker pair under `deploy/`. Port the RFC 9114 violation taxonomy (content-length handling, header case/duplicate normalization, QPACK dynamic-table edge cases) into a hypothesis battery run by `fuzz.mjs`, with a differential oracle: flag any request the front end and backend parse differently. Extend `targets/demo-corp.mjs` with an HTTP/3 endpoint as the permanent regression target.

**(d) Difficulty & timeline.** Moderate (protocol plumbing is the cost; the search itself suits VARVEL). **4–8 weeks** to first differential-parser finding; smuggling-class result within a quarter is realistic. Highest payout proximity of anything on this list — CDN/proxy/vendor bounties pay 4–5 figures for desync.

---

### 3. Passkey / WebAuthn ceremony manipulation

**(a) Emerging class.** Passkeys were marketed as unphishable; 2025 broke that story. SquareX researchers demonstrated **WebAuthn API hijacking** — a compromised browser context (malicious extension/script) faking passkey registration and login ceremonies — shown at DEF CON 33: [Passkeys Pwned: Turning WebAuthn Against Itself — SquareX labs, Aug 2025](https://labs.sqrx.com/passkeys-pwned-turning-webauth-against-itself-0dbddb7ade1a), coverage: [The Hacker News, Oct 2025](https://thehackernews.com/2025/10/how-attackers-bypass-synced-passkeys.html), [SecurityWeek, Aug 2025](https://www.securityweek.com/passkey-login-bypassed-via-webauthn-process-manipulation/). Meanwhile the spec itself is moving: **WebAuthn Level 3** hit Working Draft in January 2025 with new surface (cross-device/syncing, new client APIs) — [ecosystem overview, Dec 2025](https://jeffbruchado.com.br/en/blog/webauthn-passwordless-authentication-security-2025) — and NIST SP 800-63-4 (finalized July 2025) now blesses *synced* passkeys at AAL2, which expands the trust assumptions RP implementers must get right. Under-explored: RP-side ceremony validation bugs (challenge reuse, attestation confusion, cross-device/hybrid transport downgrade, related-origin edge cases) — most research so far attacks the *client*, few systematically fuzz the *relying party*.

**(b) VARVEL edge.** Ceremony logic bugs are state-machine differential bugs — exactly what an agent with perfect memory and high code-reading throughput hunts well. RP implementations are mostly open-source libraries; VARVEL can read *all* of them and diff their validation logic against the spec, a corpus-scale job no human team does.

**(c) First lab experiment.** Stand up a local RP: extend `targets/demo-corp.mjs` with a WebAuthn registration+login flow using a popular open-source library, exercised by a browser automation harness in the lab. Battery: challenge-replay across sessions, attestation-object substitution between ceremonies, origin/RP-ID confusion with subdomain setups, and (Level 3) cross-device flow downgrade attempts. Everything local; the "victim" is a scripted browser profile.

**(d) Difficulty & timeline.** Moderate. **3–6 weeks** to first RP-side validation bug in an open-source library (filable via vendor VDP/GitHub Security); a systematic cross-library comparison is a strong writeup candidate within a quarter. Auth-bypass bugs pay well on programs that use passkeys.

---

### 4. Browser API mishaps: XS-Leaks and connection-pool classes

**(a) Emerging class.** The PortSwigger Top 10 Web Hacking Techniques of 2025 list included a new XS-Leak family abusing **Chrome's connection pool mechanics** (256 global / 6-per-origin caps, priority ordering by scheme/host) to detect cross-origin redirects — proof that browser resource-management internals are still minting new leak classes: [HackerNotes Ep. 163 — PortSwigger Top 10 of 2025](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-163-portswigger-top-10-web-hacking-techniques-of-2025). The academic XS-Leak lineage ([Van Goethem et al., KU Leuven](https://lirias.kuleuven.be/retrieve/c1091d6f-e366-4dd7-bda4-9658fc186622)) keeps extending as browsers ship new APIs faster than leak audits.

**(b) VARVEL edge.** XS-Leak discovery = enumerate browser-observable side channels × target page states. Combinatorial, timing-sensitive, documentation-heavy — an AI can maintain the full cross-reference matrix of new web platform APIs (each Chrome release notes diff) against known leak primitives, which is pure grind no human sustains.

**(c) First lab experiment.** Two lab origins (localhost ports via `vm-lab.mjs` networking): "victim" app (`demo-corp.mjs` with state-dependent redirects) and attacker page. Reproduce the connection-pool leak to validate the harness, then sweep newer primitives (fetch priority, speculation rules, new headers) for differential observability.

**(d) Difficulty & timeline.** Moderate; reproduction **2–4 weeks**, novel leak **1–2 quarters** (lottery-ish within a grindable process). Payout: XS-Leaks are accepted but usually mid-severity — this direction's real payoff is *reputation/writeups* and technique inventory for chains.

---

### 5. AI supply chain: model files, scanner bypasses, slopsquatting 2.0

**(a) Emerging class.** Three live seams: (i) **malicious model files** — ReversingLabs found pickle-based malicious models on Hugging Face (Feb 2025); ~95% of discovered malicious models use pickle ([AI Secured by Design threat landscape](https://aisecuredbydesign.io/building/model-selection/threat-landscape/), [Safeguard, Sep 2025](https://safeguard.sh/resources/blog/supply-chain-attacks-targeting-ai-ml-pipelines)); (ii) **scanner bypasses** — Sonatype disclosed four PickleScan CVEs in 2025, plus a 2026 "ShadowPickle" preprint; "a clean scan means no known-bad signature matched, not that the model is benign" ([Stingrai, Aug 2026](https://www.stingrai.io/blog/clean-model-scan-not-safe-picklescan-safetensors)); GGUF Jinja2 template poisoning executes at inference ([Pillar Security, via roadmap compilation](https://github.com/evilsquid888/ai-security-roadmap/blob/main/README.md)); (iii) **slopsquatting** — LLMs hallucinate nonexistent packages at 5–20% rates; a USENIX Security 2025 study of 576k code samples across 16 models measured ~5.2% average hallucination ([SafeDep threat model](https://safedep.io/ai-native-sdlc-supply-chain-threat-model), [arXiv Bayesian detection paper, May 2026](https://arxiv.org/html/2606.13918v1), [Nesbitt: slopsquatting meets dependency confusion, Dec 2025](https://github.com/andrew/nesbitt.io/blob/master/_posts/2025-12-10-slopsquatting-meets-dependency-confusion.md)); a fake "huggingface-cli"-style test package drew 30k+ downloads ([AI Runtime Security review](https://airuntimesecurity.io/maso/threat-intelligence/threat-intelligence-review/)). Still under-explored: hallucination patterns in *non-npm/PyPI* registries (Docker Hub images, model-hub repos, VS Code extensions) and scanner-evasion as a systematic class.

**(b) VARVEL edge.** Massive, mechanical, corpus-scale: scan registries, diff scanner capabilities against new obfuscation techniques, measure hallucination rates across models/registries. Humans do point findings; an AI platform can do the *systematic map*.

**(c) First lab experiment.** Never register anything on a live registry. In-lab: stand up a private npm/PyPI mirror + local model registry in `range-iso/`; measure hallucination rates of local models by prompting for code and checking which suggested packages are unregistered; craft pickle/GGUF payloads and test local copies of ModelScan/PickleScan for bypasses (scanner evasion findings are filable to Sonatype/ProtectAI directly).

**(d) Difficulty & timeline.** Low difficulty, **1–4 weeks** to first scanner-bypass or measurement result. Crowded field — payout modest, but it is the fastest on-ramp and builds VARVEL's supply-chain muscle for directions 7 and 9.

---

### 6. Inter-agent identity & delegation (A2A auth) — lottery ticket

**(a) Emerging class.** OWASP's Top 10 for Agentic Applications (Dec 2025) defines classes with essentially no mature detection tooling: **ASI07 Insecure Inter-Agent Communication** (message spoofing/tampering), ASI08 Cascading Failures, ASI10 Rogue Agents ([OWASP GenAI, Dec 2025](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/), [HUMAN Security explainer](https://www.humansecurity.com/learn/blog/owasp-top-10-agentic-applications/), [promptfoo docs](https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/)). Unit 42 flags agent credential theft and agent impersonation as live threats ([Unit 42, May 2025](https://unit42.paloaltonetworks.com/agentic-ai-threats/)); NIST/CAISI now treats prompt injection as an architectural control problem ([CSA note on NIST AI agent standards initiative, Mar 2026](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_NIST_AI_agent_standards_initiative_20260324-csa-styled.pdf)); comprehensive survey: [arXiv: Attack and Defense Landscape of Agentic AI, Mar 2026](https://arxiv.org/html/2603.11088v1). Under-explored: there is no "SSTI moment" yet for A2A protocols — no one has published the canonical, named technique for agent-delegation abuse.

**(b) VARVEL edge.** Greenfield — whoever maps agent-identity delegation first names the class. VARVEL runs multi-agent patterns natively, so it can attack its own architecture as the lab. But exploitation requires building realistic multi-agent topologies, which is engineering-heavy.

**(c) First lab experiment.** Two-agent lab in `range-iso/`: orchestrator agent + tool-worker agent communicating over a simple A2A-style channel. Battery: unsigned-message spoofing, delegation-token scope confusion (worker accepting orchestrator privileges), transitive trust (A trusts B, B trusts C → does A implicitly trust attacker-controlled C?). Goal: a named, reproducible delegation-confusion pattern.

**(d) Difficulty & timeline.** Moderate–high; **1–2 quarters** to a defensible novel class. Honest assessment: **lottery ticket** — huge reputational payoff if VARVEL names the class, but the probability mass is diffuse. Run as a background thread, not the main lane.

---

### 7. CI/CD OIDC trust & pipeline provenance — grindable but crowded

**(a) Emerging class.** The tj-actions/changed-files compromise (CVE-2025-30066, March 2025, 23,000+ repos affected, tags retroactively moved) is the canonical incident: [GitHub advisory](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3), [Unit 42 analysis](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/), [Wiz](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066), [StepSecurity](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised). Follow-on waves (Nx "s1ngularity", Shai-Hulud) kept the seam hot through 2025–2026 ([compiled in OpenAIRT-300 curriculum](https://github.com/pax-k/OpenAIRT-300/blob/main/OpenAIRT-300.md)). Under-explored seams: OIDC trust misconfigurations (over-broad `sub` claims in cloud federation), reusable-workflow confusion, ephemeral runner environment takeover. **Caveat:** this is the most crowded field on the list (Wiz, StepSecurity, Cycode, Unit 42 all farm it continuously).

**(b) VARVEL edge.** Modest — incumbents have live telemetry VARVEL lacks. VARVEL's honest edge is *systematic OIDC-claim auditing of public repos* (readable at scale) rather than incident response.

**(c) First lab experiment.** Local Gitea/Forgejo + runner in `range-iso/` (or a mocked GitHub Actions environment), then intentionally misconfigure OIDC trust policies and have VARVEL rediscover them — a capability benchmark, not a discovery engine. Discovery work: static audit of public workflow files (read-only, no interaction).

**(d) Difficulty & timeline.** Low–moderate, **2–4 weeks** to first public-repo misconfiguration disclosure. Payout decent (cloud takeover chains pay) but expect duplication with the big shops.

---

### 8. PQC hybrid-migration implementation bugs — lottery ticket

**(a) Emerging class.** Migration is now real and messy: [Meta's PQC migration retrospective, Apr 2026](https://engineering.fb.com/2026/04/16/security/post-quantum-cryptography-migration-at-meta-framework-lessons-and-takeaways/) ("most crypto vulnerabilities are in implementations, not algorithms"); hybrid-mode risk analysis ([postquantum.com, Jun 2026](https://postquantum.com/post-quantum/pqc-migration-risk-hybrid/) — ML-DSA bugs already cited); migration-challenge surveys ([MDPI, Dec 2025](https://www.mdpi.com/2073-431X/15/1/9), [ePrint 2025/2052](https://eprint.iacr.org/2025/2052.pdf)). Under-explored: hybrid key-exchange downgrade paths, PQC/classical negotiation confusion, and implementation mismatches between libraries — a replay of the TLS 1.3 downgrade-bug era.

**(b) VARVEL edge.** Weak-to-moderate. Deep crypto review rewards mathematical expertise more than throughput; VARVEL's angle is *protocol-state-machine fuzzing* of hybrid handshakes, not primitive cryptanalysis.

**(c) First lab experiment.** Local TLS endpoints with hybrid key exchange (openssl/boringssl builds) in `range-iso/`; differential handshake fuzzing — does either peer accept a classical-only fallback where policy says hybrid-required?

**(d) Difficulty & timeline.** High; **2+ quarters**, low hit probability. Lottery ticket. Parking lot for now; revisit when VARVEL's differential-fuzzing harness from direction 2 exists and can be pointed at TLS.

---

### 9. VS Code / non-Chrome extension store confusions — grindable, modest payout

**(a) Emerging class.** Active and under-policed: Wiz found **500+ leaked secrets in VSCode/Open VSX extensions exposing 150K installs** ([Wiz, Oct 2025](https://www.wiz.io/blog/supply-chain-risk-in-vscode-extension-marketplaces)); recurring malicious-extension incidents incl. fake Prettier ([The Hacker News, Dec 2025](https://thehackernews.com/2025/12/researchers-find-malicious-vs-code-go.html), [Visual Studio Magazine](https://visualstudiomagazine.com/articles/2025/12/08/threat-actors-keep-weaponizing-vs-code-extensions.aspx), [mazinahmed.net PoC writeup](https://mazinahmed.net/blog/publishing-malicious-vscode-extensions/)); Microsoft's own trust initiatives lag the threat ([Microsoft Developer blog, Jun 2025](https://developer.microsoft.com/blog/security-and-trust-in-visual-studio-marketplace/)). Academic gap confirmed: research concentrates on Chrome Web Store; Edge/Firefox/IDE stores are "comparatively under explored" ([MadWeb 2026 paper](https://madweb.work/papers/2026/madweb26-paper27.pdf)).

**(b) VARVEL edge.** Extension manifests + source are public and static — a pure code-reading-at-scale problem. Ideal AI-platform work.

**(c) First lab experiment.** Download-only static analysis (no execution, no publishing): build a manifest-permission-vs-code-behavior auditor; run against public extension corpuses. Any *dynamic* testing happens against locally installed extensions inside `range-iso/` VMs only.

**(d) Difficulty & timeline.** Low; **1–3 weeks** to first responsible disclosure. Payout modest (most stores are VDP, not bounty). Treat as reputation/training-wheels work.

---

### 10. Wasm/V8 sandbox internals — avoid for now

**(a) State of the art.** Real bugs exist — e.g. CVE-2025-8880, a TOCTOU race where a ReadableStream backed by a mutable SharedArrayBuffer bait-and-switches Wasm bytecode between validation and compilation ([writeup, Aug 2025](https://cvereports.hashnode.dev/cve-2025-8880-race-against-time-cracking-v8s-readablestream-with-sharedarraybuffers)); JSPI (JavaScript Promise Integration) bugs used for V8 sandbox escape ([RITSEC n-day analysis of CVE-2025-5959](https://blog.ritsec.club/posts/cve-2025-5959/)); a steady drumbeat of V8 type confusions exploited in the wild (CVE-2025-10585, CVE-2025-5419 — [Qualys](https://threatprotect.qualys.com/2025/06/03/google-fixes-third-zero-day-vulnerability-in-chrome-cve-2025-5419/), [mallory.ai](https://www.mallory.ai/vulnerabilities/CVE-2025-10585)).

**(b) Honest assessment.** This is elite memory-corruption work where VARVEL has **no demonstrated edge**: success needs fuzzing infrastructure, exploit primitives, and deep JIT internals knowledge. Google pays big ([Project Zero](https://projectzero.google/) and Big Sleep work this exact seam — [Google, Jul 2025](https://blog.google/innovation-and-ai/technology/safety-security/cybersecurity-updates-summer-2025/)), which tells you both the payout and the competition. **Recommendation: defer.** Revisit only after directions 1–3 produce publishable results and the fuzzing harness matures.

---

## Unverified / thin-evidence items (searched, not confirmed)

- **Ephemeral / preview environment takeover** (Vercel/Netlify-style preview URL hijacking, stale environment secrets): search returned no specific 2025–2026 research — only generic threat-landscape material. Marked **UNVERIFIED**; potentially genuinely under-explored, or potentially a dead seam. Worth one cheap reconnaissance week before committing.
- **HackerOne hacktivity trend data for 2025–2026**: current-year platform statistics were not retrievable this session; older reports ([HackerOne top-ten page](https://www.hackerone.com/lp/top-ten-vulnerabilities), [7th annual Hacker-Powered Security Report](https://cxo-institute.com/storage/2023/11/7th-annual-hacker-powered-security-report.pdf)) were used only as background, not as trend claims.
- **HTTP/3 adoption-driven bug density on bug-bounty targets**: individual CVEs are cited above, but no systematic "programs now accept HTTP/3 findings" dataset was found. **UNVERIFIED** at the program-policy level.

---

## How VARVEL's research lane should work

### Principles

1. **Lab-only for novel work.** All hypothesis testing runs against `targets/demo-corp.mjs`, `targets/northwind.mjs`, `deploy/range-iso/` VMs, or purpose-built local fixtures. Novel research **never** touches live bounty targets. Live targets are only ever touched by the existing governed pipeline with sigil gates, after a technique is proven in-lab and the target's scope permits it.
2. **Anomaly → hypothesis, human at the cascade.** Follow the Kettle blueprint: VARVEL generates and cheaply evaluates hypotheses autonomously; the operator reviews the anomaly queue and picks which deserve the next hypothesis. This is where the sigil/HITL machinery already built into the campaign pipeline pays off.
3. **Everything is logged, nothing is lost.** VARVEL's structural advantage is perfect failure memory — a negative result is an asset (it prunes the search space permanently). Never discard failed experiments.

### Hypothesis log format

One append-only JSONL file per direction, e.g. `varvel/data/research/d1-mcp/hypotheses.jsonl`:

```json
{
  "id": "D1-2026-0142",
  "date": "2026-09-03",
  "direction": "D1-mcp-cross-server-poisoning",
  "hypothesis": "Host applies hostile server's tool description as instruction context when calling honest server's tool with overlapping name prefix",
  "inspired_by": ["https://arxiv.org/html/2508.12538v1", "spec-fragment:mcp-spec#tools/list"],
  "lab_fixture": "range-iso: host=mcpserve.mjs, honest=srv-a, hostile=srv-b@commit abc123",
  "battery": ["desc-injection", "schema-shadow", "rename-between-list-and-call"],
  "runs": 47,
  "result": "negative|anomaly|confirmed",
  "anomaly_signature": "host called honest tool with extra param 'debug_dump' present only in hostile description",
  "next_hypothesis": "D1-2026-0143 (or null)",
  "reviewed_by_operator": false
}
```

Rules: every run appends, never edits; `result: anomaly` entries are the *only* queue the operator reviews weekly; a hypothesis graduates only from `confirmed` + operator review.

### Experiment protocol (lab)

1. **Fixture first.** Build/extend a deterministic lab fixture that reproduces the protocol or feature under study (new fixture code goes under `targets/` or `deploy/range-iso/`).
2. **Calibrate on known-knowns.** Reproduce one published technique in-lab (e.g. the SquareX passkey PoC pattern, an RFC-9114-violation smuggling probe) to prove the harness detects what it should.
3. **Sweep the battery.** Enumerate the hypothesis space; log every outcome. Detection oracles must be *differential* (front-end vs backend, expected vs observed ceremony state) — not "did it crash."
4. **Triage anomalies.** Operator reviews `anomaly` entries; each accepted anomaly spawns a weaponization sub-experiment in-lab (minimal, deterministic PoC).
5. **Record cleanup.** Any lab VM/container state is disposable; fixtures are committed code, results are committed logs.

### Graduation gates

A result leaves the research lane through exactly two doors:

- **→ Bounty pipeline.** Only when: (i) the technique is confirmed in-lab with a deterministic PoC; (ii) operator countersigns; (iii) the specific finding on the specific target passes `node tools/submit-drive.mjs scopecheck <slug> <authlevel> <vulntype>` and comes back `FILE` (not `PARK`, not `NO-FILE`) — including the June-2026 auth-level and vuln-type acceptance rules encoded in `tools/submit-drive.mjs`. If scopecheck says the auth level or type is out of scope, the finding goes to direct vendor disclosure or a writeup, never forced through a bounty form. Then the normal governed pipeline (recon → validate → sigil-gated exploit) applies.
- **→ Writeup.** When the result is a *technique* (a class/variant), not a target-specific instance: publish methodology + lab PoC + responsible disclosure timeline. Technique writeups are VARVEL's reputation engine and are how direction-level bets (1, 3, 6) pay off even when no single bounty is huge.

### Cadence proposal

- **Main lane (60% effort):** Direction 1 (MCP/agentic) — fastest route from VARVEL's existing self-hosting capability to a novel, filable result.
- **Second lane (25%):** Direction 2 (HTTP/3 desync) — highest payout proximity; builds the differential-fuzzing harness that later serves directions 4 and 8.
- **Background thread (15%):** Direction 3 (passkey ceremonies) + one cheap verification week on the UNVERIFIED preview-environment seam.
- **Explicitly deferred:** Directions 8 (PQC) and 10 (V8/Wasm) — revisit at the next quarterly review.
