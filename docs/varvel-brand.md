# VARVEL — Brand, Design Law & Feature Superset

> The feature formerly codenamed OVERWATCH. **Named VARVEL by an Opus 5 agent** (it beat my *Sigilant* and Fable's *Sigilon*). Design system distilled from an Opus 5 design critique + the de-AI playbook. See [overwatch-design.md](overwatch-design.md) for the engineering plan.

## 1. Name

**VARVEL** *(VAR-vel)* — falconry: the small engraved silver ring fixed to a hawk's jess (leash), which doubles as the owner's identifying seal. **The leash and the owner's mark are one object — and the bird still hunts alone.** That *is* the product: an autonomous offensive agent that acts unattended but is provably bound to a signed scope.

- Tagline: **"The hawk hunts alone — it wears your ring."**
- Native noun/verb: *"a varvel is minted per engagement; every action is checked against it."*
- Runner-up / possible sub-brand: **MARQUE** (a letter of marque = the signed, scoped commission that separates a privateer from a pirate — i.e. a pentest from a crime).
- Brand discipline: **falconry metaphor in the chrome and controls; plain rigor in the data.** Security buyers respect rigor and smell twee instantly — that boundary is itself a trust signal.

## 2. Color — four languages, NEVER mixed (this rule alone beats a generic dashboard)

| Language | Meaning | Texture | Hex |
|---|---|---|---|
| **BRASS** | authority / binding / governance | **metallic** (specular + engraved bevel) | `#C9A24B` primary · `#E4C67E` highlight · `#8A6D2E` deep |
| **HEAT** | target risk / severity | **flat matte** | crimson `#D34F5E` (critical) · ember `#E0803C` (high) · ochre `#B9923F` (med) · steel `#5E86A6` (low) · slate `#6C7684` (info) |
| **COOL** | the agent's hunt | desaturated | steel cyan `#6FA8B8` |
| **GREEN** | cryptographic integrity ONLY | — | sage `#4FB07A` ("signature valid / chain intact"; never "allow") |
| Neutrals | | | bg `#0A0D13` · panel `#10141C` · raised `#151A24` · hairline `#202634` · text `#E6EAF0 / #9AA3B2 / #5C6675` |

**Brass is metallic, risk is matte** — that texture difference is what stops ochre-risk from ever reading as brass-authority. Red is reserved for **critical severity only**; a **denial is brass** (the ring closing), never red.

## 3. Type, layout, motion

- **Type:** UI in a tight grotesque (Söhne / Neue Haas; Inter at −1.5% tracking as fallback). Machine content (actions, hashes, scope clauses, ledger) in a **mono with character** (Berkeley / Commit / JetBrains Mono). Wordmark **VARVEL** = engraved small-caps brass, wide tracking. All numbers tabular. **Typography encodes governance:** *italic sans* = agent thought (free, ephemeral, off-record); *mono* = act/observe (bound, hash-chained). The ReAct loop reads with zero labels.
- **Layout (1440–1920):** header 56px · footer ledger 80px (expandable) · middle band = phase rail 220px / **center feed fluid, dominant ~55%** / surface map 400px. The center gets the most pixels because governance-in-motion *is* the product.
- **Motion:** event-driven + meaningful only. **One** ambient motion: a ~4s heartbeat on the LIVE pill + tether (liveness telemetry — if it stops, you *know* the system froze). Directional grammar: data flows **left→right** (intent → gate → record); **authority pulses vertically** (up the jess to the seal and back). Nothing moves any other way.

## 4. The hero moment — "The Ring"

Every action in the center feed physically crosses **one thin vertical BRASS SEAM** down the middle of the feed — that seam is the varvel. **Nothing reaches "observe" without passing through it.** Coverage is self-evident, which answers a CISO's first fear ("are *all* actions checked, or just the flashy ones?") without a word.

The 5-second sell is a **denial** (catching + adapting shows capability and restraint in one breath):

`action chip resolves from a thought` → `slides right, jess brightens` → `hits the seam and STOPS DEAD (0 easing)` → `header scope-seal pulses (it was consulted)` → `seam blooms brass; a counterfactual GHOST of the prevented blast-radius flares + fades on the map` → `chip restyles to HELD with the matched clause inline` → `links into the footer ledger (chain click)` → `thought resumes; agent re-plans in scope; tether slack; calm returns.`

Autonomous action → caught against a *signed* rule → disaster averted → permanent record → adapts. No human, no panic. **That loop is the landing-page capture.**

## 5. Signature UX (the moves that beat a normal agent dashboard)

- **Denials are BRASS, not red.** A block = governance *succeeding*. Instant hard-stop, then a slow brass exhale (~500ms) — caught instantly, resolved calmly. Add the **counterfactual ghost** (show the harm prevented). Microcopy: **"HELD"** + the clause that held it; never the word "error" or "blocked." Reads like a seatbelt catching, not a crash.
- **Budget → "Leash"** (multi-dimensional: `62% · 1,240 actions · £340/£500 · window 4h12m`). The tether visibly **shortens** as freedom shrinks.
- **Exploit gate = an engraved brass HASP** with visible **strain** — queued intent presses against it until a human turns the key. You *feel* the leash pull. (No emoji locks.)
- **Surface map proves restraint by NEGATIVE SPACE:** out-of-scope hosts are shown but greyed **behind an engraved brass scope-ring** (the varvel writ large). The AI is visibly surrounded by things it's forbidden to touch — and doesn't. The dog that didn't bark.
- **Audit ledger = a literal linked CHAIN** (each entry's prev-hash = the last link's hash), with **"Ledger intact · N links · verified"** in sage. Allows *and* denials write to it. A broken chain would be *visible*.
- **HITL = press-and-hold BRASS RING** (fills ~1.2s), not a rubber-stamp button; **never full-screen** (dim the feed, don't blind the operator); shows what / where / blast-radius + the justifying finding + the permitting clause + **who signs** ("Authorizing as J. Naughton · Engagement Lead"). On release: `Authorized · signed · <ts>` mints into the chain.
- **RECALL** — an always-visible brass falconry kill switch: *"Recall agent to glove — halts all activity, preserves state."* Its mere visible existence is disproportionately reassuring.
- **CREANCE** — dry-run mode (the falconer's long training line): the agent flies but can **never strike**.
- **3-state status ribbon**, readable across a room: `GOVERNED · LIVE` / `HELD FOR APPROVAL` (brass) / `RECALLED · HALTED` (grey).
- **The board metric:** `Authorized N · Held N · ` **`Out-of-scope executed: 0`** — the sentence that closes the sale.
- **Flight record:** at engagement end the chain collapses into an exportable, seal-bearing, QR-verifiable **warrant-grade PDF** — a deliverable in its own right.
- **Provenance replay:** because every step is hash-chained, add a scrubber that replays the whole engagement as a *provably faithful film* — rewindable to any decision (thought → action → clause matched → ruling). Priceless for disputes and training.
- **Governance audio** (default-on, instantly mutable): allow = a soft hawk's **bell**; held/deny = a brass **clasp** (a ring closing, never a buzzer); ledger link = a faint **chain click**. A falconer bells the bird *because they can't watch it* — you hear the **rhythm of governance** from across the room, and a brass clasp cutting through means the leash just caught something.

## 6. Anti-slop law — nothing may read as AI-generated

| AI-slop tell | VARVEL rule |
|---|---|
| Purple/indigo→blue gradients; gradient hero text (**the #1 tell**) | **No decorative gradients, anywhere.** Color = meaning (the 4 languages). Brass is metallic *specular*, not a CSS gradient. |
| Glassmorphism / frosted-blur panels | Flat panels, **hairline borders** (`#202634`). Instrument, not iOS. |
| Inter/Roboto everywhere with no character | Tight grotesque + **mono-with-character**; engraved wordmark. |
| Emoji as icons (🔒 🛡️ ⚡) | **Zero emoji in the UI.** Drawn marks only (the brass hasp, the ring, the seal). |
| Neon glow, cyberpunk, matrix rain, **pew-pew attack globe** | Calm command-center. One heartbeat. Delete the globe on sight. |
| Rounded-everything + drop-shadows + uniform card grid | Deliberate asymmetric hierarchy (feed ~55%); **hairlines, not shadows**; architectural corners. |
| Rainbow charts, donut/radial gauges | Semantic limited palette; **linear** tether; tabular numbers. |
| Chatbot avatar / "AI is typing…" / anthropomorphism | The agent is a **raptor, not a chat buddy.** No personality bubbles. |
| Decorative motion everywhere | Motion is **event-driven + meaningful** (the Ring, the denial exhale). One ambient heartbeat only. |
| Symmetric, focal-point-less, evenly spaced | Strong hierarchy; the feed dominates. |
| Generic "AI/tech" imagery (glowing brains, circuit boards, hex grids) | The **falconry system** (ring, jess, seal, hasp) — specific and ownable. |
| Digital-perfect flatness (too clean *also* reads AI) | A **subtle film grain** (SVG feTurbulence, ~3–5% opacity) over the dark ground + metallic specular on brass → tactility. |
| Accent-color overuse | **Restraint.** Most of the screen is neutral; brass and heat are earned, not sprayed. |

## 7. Logo prompt (for image generation)

Paste into your image generator of choice. Primary is a **mark** (favicon/nav/seal); a wordmark variant follows.

```
A minimal, premium EMBLEM/SEAL logo for a cybersecurity-governance product called "VARVEL".
Core motif: a "varvel" — the small engraved silver ring a falconer fixes to a hawk's jess,
which doubles as the owner's identifying seal. Render it as a CIRCULAR SIGNET SEAL viewed
head-on: a fine engraved metal ring, and inside it a single spare mark that FUSES FALCONRY
WITH CRYPTOGRAPHY — a stylized falcon's head (or a single hooded-falcon silhouette) whose
form resolves into interlocking chain-links around the band, evoking a hash chain / a bound
seal. Style: engraved intaglio, heraldic wax-seal, mint-struck-coin precision line-work —
austere, confident, expensive; a bank sigil, NOT a "tech" logo. Material: antique brass and
aged silver with subtle metallic specular and an engraved bevel on a dark charcoal ground;
must also read as a single flat color. Constraints: vector-clean, geometric, perfectly legible
at 24px (favicon) AND at hero size; deliver monochrome-capable (one brass-on-dark and one
white-on-dark variant); transparent background; centered; NO text (the glyph only). Mood:
falconry heraldry meets cryptographic seal — bound, authoritative, calm. STRICTLY AVOID:
gradients, glow, neon, glassmorphism, 3D plastic bevels, generic shields / padlocks / circuit
boards / hex grids / globes, stock "AI" or "cyber" clichés, and any emoji.
```

**Wordmark variant:** `An engraved small-caps wordmark "VARVEL" in antique brass, wide letter-spacing, intaglio/mint-struck lettering with a fine engraved bevel on dark charcoal; a small circular varvel-seal glyph as the counter of the "V" or set as a separator dot; austere heraldic-cryptographic feel; flat, vector-clean, monochrome-capable; transparent background; no gradients or glow.`

**One-line micro-prompt (favicon):** `Tiny engraved brass falconry ring forming a seal, a hooded-falcon glyph and hash-chain links inside, intaglio heraldic mark, flat, monochrome, legible at 24px, transparent bg, no gradients or emoji.`

## 8. Feature superset — VARVEL must be MORE than RedAmon, and better

Capability **parity** with RedAmon is *table stakes* (roadmap in the design doc). The added rows are the moat.

| Capability | RedAmon | VARVEL |
|---|:---:|:---:|
| Autonomous recon → exploit → post-ex loop | ✓ | ✓ |
| 40+ security tools, chained | ✓ | ✓ (existing red-team image, **governed**) |
| Attack-surface graph | ✓ (Neo4j) | ✓ (roadmap: `surface.json` → graph) |
| Cross-session memory | ✓ (EvoGraph) | ✓ (roadmap) |
| Parallel sub-agents | ✓ (Fireteam) | ✓ **governed** (scope-inheriting) |
| Auto-remediation PRs | ✓ (CypherFix) | ✓ (via **governed** egress) |
| AI/LLM red-teaming | ✓ (garak/PyRIT) | ✓ (roadmap) |
| RoE / approval gates | app-level | app-level **+ signed & platform-enforced** |
| Hard target block (gov/mil) | ✓ | ✓ **cryptographically enforced** |
| **Cryptographic governance** (signed scope · unbypassable hook · Cedar PDP) | ✗ | **✓ — the moat** |
| **Tamper-evident hash-chained audit → warrant-grade flight-record PDF** | partial | **✓** |
| **RECALL + CREANCE (dry-run) operating modes** | ✗ | **✓** |
| **Press-and-hold HITL with human attribution** | ✗ | **✓** |
| **Provenance replay** (rewind the engagement as proof) | ✗ | **✓** |
| **Governance audio** | ✗ | **✓** |
| **Compliance mapping** (SOC 2 CC6/CC7) | ✗ | **✓** |

**Net:** VARVEL matches RedAmon's capability surface *and* adds an entire governance / trust / compliance layer plus new safe-operating modes. Strictly more, and better.

## 9. Build-boundary (unchanged, restated for this feature)

VARVEL is **governed autonomy over EXISTING authorized tools** — the campaign engine, the governed adapters that *drive* nmap/metasploit/nuclei/etc. (already in the red-team image), the pipeline, the console, the audit. That is the whole platform, and I build it (delegating big parts to Fable/Opus 5 first, doing them myself if they false-flag a *legitimate* task). It does **not** require developing new offensive capability — exploits, evasion, anti-detection — and that is deliberately **not** in scope for me: the tools already provide offense; improving offense is a separate lane (Kimi). A model refusing to *write an exploit* is a correct refusal, not a false flag — and VARVEL doesn't need it to.
