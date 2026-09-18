# Lab wiring build — 2026-09-01

Born from a file:line-verified audit of the LAB + AGENT-TOOLMAKING gaps: the operating
brief told agents to BUILD scratch tools but nothing anywhere told them the tool shelf
or attackbench existed; scratch tools vanished with the disposable workspace (only
their names were logged); and attackbench / the fingerprint observer had engine +
routes but zero console exposure. This build closes those three gaps — additively,
without softening any governance. Tests: `test/labwiring.test.mjs` (6), registered in
the pinned `npm test` list.

## Layout

- **`engine/live.mjs`** — `operatingBrief()` gains a compact **LAB & TOOLMAKING**
  block: scratch tools named in `scratchTools` are AUTO-SHELVED as quarantined data
  (one tool per file in the workspace root, declared by file name / relative `path` /
  inline `content`); the shelf API (`GET`/`POST /api/toolshelf`) is advertised; and
  `data/attackbench/techniques.json` is named as the invention ledger — a genuinely
  new technique goes in the closing summary as a candidate for the OPERATOR to add;
  the agent never edits the catalog. The chat brief needs no separate change: it is
  assembled from `operatingBrief()` (server.mjs `/api/message`).
- **`engine/campaign.mjs`** — the auto-shelve. `_ingest` still logs declared
  `scratchTools` names as before; it now ALSO calls `_shelveScratchTools`, which
  persists the script bytes via `engine/toolshelf.mjs shelveTool` as **quarantined**
  entries (status lifecycle untouched — promotion stays a logged human decision).
  Bytes come from the declaration itself (inline `content` / `files[]`) or are read
  back out of the agent's sealed workspace via the new `wsDir` campaign option
  (server.mjs passes the same `wsDir` the runAgent backend uses). Read-back is
  confined to the workspace (traversal refused), capped at the shelf's own 256 KiB,
  deduped per tool per campaign, and every outcome rides the activity feed
  (`scratch-tools.shelved` / `scratch-tools.shelve-error`). Best-effort by contract:
  nothing here can throw into the campaign.
- **`engine/toolshelf.mjs`** — `SHELF_KINDS` exported (the existing `KINDS` list) so
  the campaign coerces agent-declared kinds to the shelf's own vocabulary instead of
  guessing it.
- **`server.mjs`** — `GET /api/attackbench`, the route that never existed: returns
  `tools/attackbench.mjs report()` (the honest mapped / planned-only / gap coverage +
  per-tactic rollup, doctrine + non-claim carried). 200 on a valid benchmark, 500 with
  the NAMED error JSON on an unreadable/invalid catalog or map — never guessed data.
- **`app-v6.html`** — two read-only Settings cards next to the tool shelf:
  **Attackbench — ATT&CK emulation coverage** (mapped/planned/gap tiles + per-tactic
  table, "capability, never detection" pill + the non-claim verbatim) and
  **Fingerprint observer** (`GET /api/fp` — the channel's passive JA4H ring, with the
  honest unarmed state). Both load on every Settings visit via the existing
  `loadShelf`/`loadMissions` hook.
- **`docs/AGENT-GUIDE.md`** — a short "The lab — the tool shelf + attackbench" section
  mirroring the brief block.

## Rules

1. **Shelf entries are DATA, never executed** — auto-shelving changes persistence,
   not governance: quarantined → promoted stays human-only, logged with who/when.
2. **Agents never self-modify the attackbench catalog** — they NAME candidate
   techniques in their output; the operator verifies and adds them.
3. **Best-effort persistence** — a shelf/IO failure is logged and the campaign
   proceeds; auto-shelve can never fail an ingest.
4. **Honesty carried on every surface** — the attackbench card and route quote the
   capability-not-detection doctrine and the MITRE non-claim, exactly as the engine
   emits them.

## Decisions (read first, then chosen)

- **Demo-mode campaigns get NO brief** — deliberate. The mock agent
  (`mock-agent.mjs`) switches only on `messages[0].content` and never reads `system`,
  so appending `operatingBrief()` in demo mode (server.mjs startCampaign) would be
  dead text: unread by anything, and dishonest to claim as "agents told". Live
  campaigns and chat both get the block through `operatingBrief()`.
- **`/api/posture` is NOT surfaced in the console** — it is an ACTIVE probe
  (`detectStack` against a supplied `?url=`), not a read-only report; exposing it
  needs a target-input form, which is a console change beyond this build's scope.
  The two genuinely read-only backends (attackbench, fp) got cards instead.

## Verification

- `test/labwiring.test.mjs` — failing-then-passing: auto-shelve persists bytes
  (workspace + inline), refuses traversal, logs-not-throws on shelf errors, dedupes
  per campaign; the brief advertises the shelf + ledger; `GET /api/attackbench`
  serves the exact computed coverage over a spawned real server (house boot pattern).
- Suites of every touched file + the toolshelf suite (`test/posture.test.mjs`) and
  the full pinned `npm test` — 0 fail.
