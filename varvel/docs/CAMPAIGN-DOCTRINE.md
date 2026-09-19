# CAMPAIGN DOCTRINE — how a VARVEL campaign is actually run

Status: binding (referenced from `AGENTS.md` §"CAMPAIGNS — the only sanctioned path").
Written 2026-09-19 after a night in which a hand-rolled `.tmp` loop produced **zero
fileable findings** while looking busy. Every failure mode below is **measured**, not
theoretical — the numbers come from that run.

## 0. The one rule

Run campaigns through **VARVEL'S pipeline** (`tools/huntloop.mjs` stages + `tools/cli.mjs`
sub-commands + the engine modules) with the **reader lane inside it**. A `.tmp` script may
only ever be a *thin driver* that calls those tools — never a replacement for them, and
never a second implementation of recon, gating, or verification.

## 1. The sanctioned path

```
RECON       privemap <dir> --json          sinks (ranked candidates)
            reachprove <dir> --json        entry points + PROVEN reachability
            [variantsweep --sig ...]       only with a real vuln signature
            [commitwatch scan]             wp.org SVN diffs -> pre-fix shapes
              |
BAND FILTER keep ONLY reachability in {unauth, subscriber, contributor}
            drop admin-gated / server / unknown BEFORE spending anything
              |
READER      opencode + deepseek-flash, GIVEN the reachable entry points + sink hints,
            told to trace each entry point to every sink and quote every gate.
            Structured JSON per finding (file, line, sink, taint, gate evidence, poc,
            confidence, unverified=true).
              |
VALIDATOR   tools/refuter.mjs (a DIFFERENT model) with the citation gate enforced.
            hold -> continue | refute -> park with the citation | unavailable -> unverified
              |
GATES       engine/lanes.mjs classifyLane + tools/submit-drive.mjs scopecheck
              |
CONFIRM     the local lab (.tmp/wp-demo-lab: WordPress + SQLite + bundled PHP) for plugin
            proof; the VM range (vm-lab.mjs: Win11+Defender, Kali) for host/AD proof.
            A finding is UNVERIFIED until a state change is observed.
              |
LEDGER      .tmp/SUBMISSIONS.md (every outcome, incl. kills). The operator's hand does
            any submission — the driver NEVER submits.
```

## 2. Measured failure modes (do not repeat)

1. **Ad-hoc `.tmp` loops instead of the pipeline.** One night of it: 18 plugins, ~80
   validator verdicts, **4 holds — all admin-gated, all UNFILEABLE**. No recon stage, no
   band filter, no scope gate, no sandbox, no lab, no ledger. The reading stage itself
   worked (46 KB–624 KB of code analysis per plugin); everything around it was improvised.
2. **The miner's band labels are the weak link.** On read, **100% of its "unauth" claims**
   were actually nonce- or admin-gated (`check_ajax_nonce`, `check_admin_referer`,
   `wp_verify_nonce`, `manage_options`). Two refutations worth remembering: an `unlink()`
   sink whose `$src` was never traced from `$_REQUEST`; and a bare
   `{"success":true}` response that actually came from the **no-op** branch at
   `class-files.php:292` — nothing was deleted, the response was a trap. **Read the gate
   before believing the label.**
3. **A narrow judge bundle kills true candidates.** With a ±30-line window the refuter
   refuted a *live* candidate ("no link to `$_REQUEST`") because the handler sat outside the
   window. Feeding `reachprove`'s resolved handler→registration→gate chain plus a
   **verbatim, unnumbered** source block flipped one run from `{UNAVAILABLE:6, refute:2}`
   to `{refute:8}`. **Bundle width is the lever; line-number prefixes inside the quoted
   region break every multi-line citation.**
5. **`h1watch` timing was hardcoded** (`PAGE_SIZE: 100`, `timeoutMs = 20000`). A live walk
   died at page 6 with `h1-timeout` — the body stalled past the whole-operation deadline
   (the tool refused to fabricate, which was right). Now overridable via
   `VARVEL_H1_PAGE_SIZE` and `VARVEL_H1_TIMEOUT_MS` (page-25/90 s walks work through the
   SOCKS chain). `test/h1watch.test.mjs` must stay 18/18 after any change there.
6. **Targets below the install bar are unfileable.** `survey-maker` (5,000 installs) hosted
   the best technical chain of the night — a Subscriber SQLi via `esc_sql()` concatenated
   **unquoted into a numeric context**, reachable because `survey_maker_capabilities()`
   hard-returns `'read'` — and it **could not be filed anywhere**: under Wordfence's 50k bar,
   not in Patchstack mVDP. Check installs (`api.wordpress.org/plugins/info/1.2`) **before**
   spending reader time.
7. **Tooling gotchas that cost hours** (PowerShell 5.1):
   - Variables are **case-INsensitive** — `$T`/`$t` and `$R`/`$r` are the SAME variable.
     This silently corrupted two scripts; rename aggressively.
   - `"$t: ..."` parses `$t:` as a drive qualifier — use `"${t}: ..."`.
   - Scripts must be **ASCII-only** (PS 5.1 reads UTF-8-without-BOM as ANSI: an em-dash
     became a curly quote that terminated a string).
   - Never merge stderr into a JSON artifact: `> out.json 2>&1` corrupts it with Node
     warnings — always `> out.json 2> err.txt`.
   - `tools/<name>.mjs` are **modules**; the CLI entry is always `tools/cli.mjs <name> …`.
8. **What actually found something was READING.** The only survivable candidate of the night
   came from a reader following an auth path across five files. That is the N-Day-Bench
   shape: the solver gets **sink hints plus a step budget** and traces the bug through real
   code while a **blinded** judge scores it. Give the brain file access and steps — not one
   40-line bundle.
9. **Never trust "Connected".** Mullvad reported Connected while the tunnel adapter was
   missing and traffic was leaking out the operator's real IP (`86.180.122.17` vs the
   claimed exit `135.x`). Verify every time: `curl https://api.ipify.org` must NOT be the
   real IP **and** `10.64.0.1:1080` must dial. A wedged data path was cleared by
   `mullvad reset-settings` (after `mullvad export-settings <file>` as a backup) —
   `reconnect`, `disconnect/connect`, DAITA off, userspace WireGuard and MTU 1280 all
   failed first.

## 3. Model + secret rules

- **Author and validator must differ.** Author = `deepseek-flash` (**this IS
  DeepSeek-V4.1-Flash** — verified on DeepSeek's pricing page; the legacy names
  `deepseek-v4-flash`/`-vision-exp` are retired and served by V4.1-Flash).
  Validator = `deepseek-v4-pro` (DeepSeek-V4-Pro-0813, ~4x price, 500 vs 2500 concurrency)
  or the **local Qwen lane on Spark** (`VARVEL_REFUTER_BASE_URL=http://127.0.0.1:8080/v1`,
  lane health 200) — free, and it keeps plugin code off the API.
- Keys live in **environment variables only** — never in a file, log, ledger, or commit.
  `brain.apiKeyEnv` names the variable; the value never lands anywhere. Rotate any key that
  has been pasted into a chat.
- Every campaign log states: model ids, target set, ghost-chained vs offline, and the
  install counts used for the lane call.

## 4. Done means

A campaign is **done** when it has a run log with per-target results, every candidate either
refuted-with-citation / held-and-lab-tested / parked-with-reason, a lane classification per
survivor, and an honest summary that states **how many were fileable** (usually zero).
"It ran for an hour" is not a result. Log the outcome in `.tmp/SUBMISSIONS.md` the same day
and fold any new lesson back into this file.

