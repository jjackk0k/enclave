# VARVEL — WordPress plugin hunt playbook

**Purpose:** aim the hunt at the classes that actually pay, and — more importantly — kill the
candidate *before* it becomes a draft. Written 2026-09-17, after four consecutive "High!" leads
from our own miner turned out to be fabrications in our own tooling (defects E–K; see
`.tmp/SESSION-STATE-2026-09-17.md` §6–§7). The doctrine in `docs/AGENT-GUIDE.md`
§"Bounty hunting — the scope doctrine" says **what may be filed**. This doc says **where to look
and how to tell a real bug from a ranked shape**, with the market measured rather than assumed.

**The one rule, if you read nothing else:** a finding is only as good as its **discriminator**.
Our miner finds *shapes* (an `update_option`, an `update_user_meta`, a `permission_callback`).
A shape is not a bug. §4 lists the seven discriminators that separate them — each one was learned
by shipping the fabrication first.

**How to use it, in order:** §2 filter (before you read any code) → §3 entry points (where a real
one can live) → §4 discriminators (kill the candidate) → §6 signatures (the sweep) →
§7 calibration (prove the signature) → §9 filing bar (what evidence must exist).

---

## 1. The market, measured

Source: the repo's **pinned NVD snapshot** (`data/cvepack-cache/nvdcve-2.0-*.json.gz`, fetched
2026-09-12) — the same bytes `engine/cvepacks.mjs` reasons over, so these numbers are reproducible
offline and review as ordinary diffs. Reproduce with:

```
node .tmp/nvd-wp-stats.mjs 2024 2025 2026        # writes .tmp/nvd-wp-stats.log + .json
node .tmp/nvd-probe.mjs data/cvepack-cache/nvdcve-2.0-2026.json.gz   # raw record shape
```

**Sample:** 271,449 NVD entries scanned → 3,428 rejected → 12,339 WordPress-mentioning →
**11,664 WordPress-plugin CVEs** (2024: 5,032 · 2025: 3,157 · 2026: 3,475).

**Honest limitations — state these whenever quoting the numbers:**
1. **64% of these records are `vulnStatus: Deferred`** — CNA-published, never NVD-enriched.
   Consequence: **there is no `weaknesses` block, so there is no CWE data in this feed.** Any CWE
   distribution quoted from NVD for WP plugins is invented. (v1 of the miner did exactly that
   before a raw-record probe caught it — do not repeat it.)
2. Descriptions are **CNA-authored**, and 79% of them are Wordfence's. This measures *what
   Wordfence deems CVE-worthy* — useful, because Wordfence is our primary payer — **not**
   what Patchstack accepts. Where the two differ, `AGENT-GUIDE.md` wins.
3. The auth band is read from the CNA's **CVSS vector** (`privilegesRequired`), which is
   machine-readable and reliable; WP role names come from prose, which is free-form, so the
   reach-surface table below **under-matches** (absence means "not named", never "not used").

### 1.1 Who writes the CVEs (this is the whole ecosystem in one table)

| CNA | CVEs | share |
|---|---|---|
| `security@wordfence.com` | 9,263 | **79.4%** |
| `contact@wpscan.com` | 2,258 | 19.4% |
| `audit@patchstack.com` | 81 | **0.7%** |
| everyone else (MITRE, GitHub, JP-CERT, Cloudflare, Tenable, VulnCheck, VulDB, Mandiant) | 62 | 0.5% |

**Read this twice.** The WordPress-plugin CVE record *is* Wordfence's record. Patchstack — the
program with the rejection rules that have actually bitten us (GiveWP #3) — files almost no CVEs,
because their model is mVDP coordination rather than CVE issuance. So: **Wordfence's bar is the
observable market; Patchstack's bar is the binding constraint we get judged by.** Hunt for
Wordfence-shaped evidence, then sanity-check impact against Patchstack §4.2 before drafting.

### 1.2 Auth bands — where the payable space is

| `privilegesRequired` (vector) | CVEs | share |
|---|---|---|
| NONE — unauthenticated | 4,909 | **42.1%** |
| LOW — subscriber/contributor | 5,341 | 45.8% |
| HIGH — admin | 1,378 | 11.8% |

Named WP roles in prose: **contributor 22.9%**, **subscriber 10.7%**, administrator 3.6%,
author 3.0%, editor 0.5%.

Our hunting band (Wordfence standard: unauthenticated or Subscriber/Customer; Patchstack standard
the same; mVDP adds Contributor) therefore covers **the unauthenticated + subscriber rows ≈ 53% of
all WP-plugin CVEs**, plus a slice of the LOW row that is contributor-only (mVDP only). About
**2 in 5** WP-plugin CVEs are unauthenticated. The seam is not scarce; the *impact* is.
### 1.3 Impact — the table that kills most candidates before you read a line of code

CIA triplet (max CVSS across the record's metrics), all 11,664:

| triplet | share | meaning |
|---|---|---|
| `C:L I:L A:N` | **44.5%** | the low/low band — XSS-shaped, the Patchstack §4.2 minor-impact kill zone |
| `C:H I:H A:H` | **15.6%** | the full-tier band (RCE, option overwrite, file write) — the gold shapes |
| `C:N I:L A:N` | 14.3% | integrity-only — content tamper |
| `C:H I:N A:N` | 8.1% | read-only sensitive disclosure — in-band per §3.9 when the object is significant |
| `C:L I:N A:N` | 7.8% | read-only, minor |

**CVE-issued ≠ submittable.** The most common recorded shape in the whole ecosystem is the
*low-impact* XSS that Patchstack explicitly rejects and Wordfence merely records. Chasing the
count means chasing rejections.

### 1.4 Unauthenticated specifically (n = 3,612 with a vector) — the money table

| triplet | share | n |
|---|---|---|
| `C:L I:L A:N` | 30.3% | 1,095 |
| `C:N I:L A:N` | 23.1% | 833 |
| **`C:H I:H A:H`** | **19.1%** | **691** |
| `C:L I:N A:N` | 11.0% | 398 |
| **`C:H I:N A:N`** | **8.9%** | **323** |
| everything else | 7.6% | 274 |

Read it as: **~1 in 2 unauthenticated CVEs is below our bar; ~1 in 4 is one of the two shapes we
file (full-tier write/execute, or a significant read).** 691 full-tier unauth CVEs over three years
≈ 230/year across the entire plugin ecosystem — that is the size of the real prize pool, and the
reason a scanner-shaped "candidate count" must never be confused with it.

Impact classes named in unauthenticated records (labels overlap — per-mention):

| impact | share of unauth | n |
|---|---|---|
| **CSRF** | **18.9%** | **682** |
| info disclosure | 15.6% | 565 |
| XSS | 9.1% | 328 |
| RCE | 7.6% | 273 |
| SQLi | 6.8% | 244 |
| arbitrary file deletion | 5.2% | 189 |
| privilege escalation | 5.0% | 180 |
| arbitrary file upload | 3.7% | 134 |
| registration/role setting | 2.4% | 85 |
| PHP object injection | 1.6% | 56 |
| path traversal | 1.3% | 46 |
| password reset | 1.3% | 46 |
| SSRF | 1.1% | 40 |
| LFI/RFI | 1.1% | 38 |
| admin account creation | 0.2% | 8 |

### 1.5 The two findings in this data that should change how we hunt

**(a) CSRF is the single most common shape of an unauthenticated WP-plugin CVE — and our miner
cannot see it.** 18.9% of unauth records, ahead of info disclosure and more than RCE + SQLi
combined. It is also structurally invisible to `privemap`: a CSRF bug lives in a handler that is
*correctly* admin-only by registration (`admin_post_` without `_nopriv`, `admin_init`, a settings
save), where the defect is a **missing `check_admin_referer`/nonce** — there is no missing
capability check for the miner to find. `tools/submit-drive.mjs scopecheck` already accepts the
class (`case 'csrf'`: "accepted when chained to an accepted write action"), and one of the
verbatim samples in the snapshot is exactly that shape: *"...vulnerable to Cross-Site Request
Forgery ... due to missing nonce validation in the `digits_save_settings` function. This makes it
possible for unauthenticated attackers to modify the default role of registered users to
administrator"* (CVE-2024-0203) — the `default_role` write AGENT-GUIDE names as a gold shape.
Caveat: this is a UI:R chain (the victim is an admin who must load a page), it is Wordfence-primary
(Patchstack treats bare CSRF as out), and it pays **only when chained to a write with real impact**.
See §6 signature S1.

**(b) 24% of unauthenticated CVEs have prose that mentions a nonce** — 867 of 3,612. A nonce is
CSRF protection, not authorization, and it stops protecting anything once the page printing it is
reachable logged-out. This is the discriminator that left our everest-forms palette/template writes
unproven (§4 D5), and it is the class the miner most often mislabels in *both* directions —
"nonce present → protected → NO-FILE", or "no capability check → unauth!". Treat a nonce as a
*question*, never as an answer.

---

## 2. The acceptance filter — apply BEFORE reading code

Filing cost is rate, not time. Spend the filter first; it is 10 seconds and kills most leads.
Machine-encoded in `tools/submit-drive.mjs scopecheck`; run it as you go:

```
node tools/submit-drive.mjs scopecheck <slug> <unauth|subscriber|contributor|customer> "<class>"
```

1. **Auth band.** unauthenticated / Subscriber / Customer only (≥50k installs for Wordfence;
   Patchstack standard ≥1,000). Contributor/Author → mVDP software only. Editor+ → never a form.
2. **Impact must clear the bar** — one of the gold shapes (`AGENT-GUIDE.md` §impact bars):
   arbitrary option/settings write with significant effect (`siteurl`, `admin_email`, `default_role`,
   `users_can_register`, `active_plugins`), SQLi, site-wide stored XSS, file upload/deletion/download
   with full path+extension control, RCE, PHP object injection, privesc to contributor+,
   broken access control reaching significant/sensitive objects (keys, hashes, backups).
3. **Minor impact is dead.** `C:L I:L A:N` — the majority of the ecosystem's CVEs (§1.3) — is
   explicitly out for subscriber/customer, and a *single* low CIA impact is out for unauthenticated
   too (Patchstack §4.2; this is the clause that killed the real, live-verified GiveWP report).
4. **§4.x auto-dead list** — no drafting, no reframing, no exception: cron/scheduled-task
   manipulation, cache clearing, data re-ordering, admin-notice dismissal; open redirect; FPD;
   enumeration; rate-limit absence; CAPTCHA bypass; IP spoofing; 2FA; blind SSRF; CSV/CSS injection;
   clickjacking; draft-post disclosure; AI token exhaustion; AC:H chains; PII-only IDOR outside
   mVDP; contributor+ stored XSS; HTML-only injection; registration below contributor.
5. **Default-config test.** If the bug needs a non-default setting, it is a *different finding* —
   state the precondition up front or re-rank it (§4 D6).

**The two-question kill test** (both must be yes, and both must be *proven*, not assumed):
**Q1 — can an attacker who is not logged in (or is only a subscriber) reach the sink?**
**Q2 — does the sink produce a significant CIA effect on something that matters?**

---

## 3. Where unauthenticated reach actually comes from

Ranked by our measured hit rate and by how badly our tooling currently handles it. For each: the
code shape, the signature (§6), and the discriminator that makes it real.

**3.1 Handlers with no capability check at all** — the miner's home turf, and where our four
fabrications came from. Shapes: `wp_ajax_nopriv_<action>` → callback; `admin_post_nopriv_<action>`;
`register_rest_route(..., ['permission_callback' => '__return_true' | missing])`;
`add_action('init'|'wp_loaded'|'template_redirect'|'wp')` reading `$_REQUEST`/`$_POST`.
Real: §4 D1–D4. Fake: the gate exists in a form the miner cannot read (object-form
`user_can($requester, 'cap')`, a capability map, a loop-registered `permission_callback`), or the
arguments are constants, or the written row is unresolvable.

**3.2 The CSRF/missing-nonce write (§6 S1)** — the ecosystem's #1 unauth class (§1.5a) and our
blind spot. Shape: a settings/option/role write registered `admin_post_<action>` (no `_nopriv`),
`admin_init`, or a settings-save that reads `$_POST` and calls `update_option`/`update_user_meta`/
role functions — **with no `check_admin_referer` / `check_ajax_referer` / `wp_verify_nonce`** on
that path. The attacker is unauthenticated; the *victim* is the admin whose browser is made to send
the request. Discriminator: the nonce check must be genuinely absent on the write path (not merely
on a sibling branch), and the write must clear §2.2. Proof: the forged request with no cookies
+ the resulting state change (or, still convincing: static proof the path is nonce-free + the write
demonstrated with a Subscriber cookie where no capability gate exists either).

**3.3 Direct file requests — structurally unauthenticated.** A PHP file under
`wp-content/plugins/<slug>/` with **no `ABSPATH` guard** (no
`if (!defined('ABSPATH')) exit;`) that bootstraps `wp-load.php` or reads `$_POST` directly is
reachable at its own URL with no WordPress auth at all. Signature S5. Discriminator: it must reach a
sink with attacker-controlled arguments — a bare `echo` file is an info-leak non-event; a file that
`include`s a `$_GET` path is the LFI gold shape.

**3.4 Abilities API / MCP (`mcp.public`, `show_in_rest`, `wp_register_ability`).** New surface,
thin install base, and where two of our four fabrications lived (defects I/K). Shape:
`wp_register_ability()` / `register_rest_route` with a `permission_callback` of `__return_true`, or
**registered from a data-driven array whose args the parser cannot read**. Discriminator §4 D3 —
unreadable ≠ absent. A `permission_callback` inside a `$def['args']` loop **is a gate**; if you
cannot read it, the verdict is UNKNOWN, never "unauth".

**3.5 Handlers behind a *nonce the attacker can obtain*.** Shape: `wp_ajax_nopriv_<action>` +
`check_ajax_referer(<action>, 'nonce')` — which looks protected until you locate where `<action>`'s
nonce is printed. If it is localised onto a **public** page (`wp_localize_script`,
`wp_add_inline_script`, a shortcode/block rendering logged-out, an `wp_enqueue_scripts` on a
front-end page), any visitor can read it and the protection is void. Discriminator §4 D5: **find
the emission, or the finding is PARK.** This is the most common reason a real-looking candidate dies
in our corpus — and the 24% nonce number says the bugs are real, so the emission really is findable.
Search the whole plugin for the handle string, not just the handler's file.

**3.6 Public form / import / upload endpoints.** Shapes: a `template_redirect`/`init` handler for a
front-end form, `?wc-api=`-style webhooks, import-from-URL, PDF/render features. Discriminator:
does the attacker control the **path** and the **extension**, or only the bytes? (Path-only or
bytes-only → §2.2 PARK; full control → accepted class.)

**3.7 REST routes whose `permission_callback` is a name the miner cannot resolve.** Common real bug:
`'permission_callback' => [$this, 'some_check']` where `some_check` is
`current_user_can('edit_posts')` — contributor-band, not unauth. Discriminator: read the method.
`engine/privemap.mjs` resolves `[$this,'m']`, class constants and ≤2-hop gate chains; when it says
UNKNOWN, the answer is UNKNOWN.

---

## 4. The seven discriminators

Every one of these was learned by first *shipping* the wrong answer. They are the difference between
a ranked candidate and a filing. Where a discriminator is code-enforced, the identifier is named so
you can check the engine agrees with you.

### D1 — Argument control, not sink presence (defect E)

`update_option(...)` proves a write exists, nothing more. The question is whether the **name and the
value** are attacker-controlled. `update_option('mwai_db_version_discussions', MWAI_VERSION, true)`
is a constant cache-buster; it ranked #1 as "unauth arbitrary option overwrite" until the
3-argument form was parsed correctly. **Read the whole argument list, never the last one.**
Code: `engine/privemap.mjs` `callArgs()` → `hit.fixedValue` → degrade; the 3-arg literal is now
test-pinned.

### D2 — Gate semantics: a gate is a gate in any syntactic form (defect H)

SureTriggers' `Restcontroller.php` is a `__return_true` route whose handler authenticates with an
**administrator application password** and then calls `user_can($user, 'administrator')`. The miner
read the *object-form* gate as "not a gate" and emitted **CONFIRMED / UNAUTH / high** — in a
100k-install plugin. That is a filing-grade fabrication. **Resolution: a capability call whose first
argument is the resolved requester is a real gate.** `engine/privemap.mjs` now resolves it and
degrades the reach to ADMIN. Teeth: `.tmp/teeth-usercan.mjs`.

### D3 — Unreadable is not absent (defects I, K)

Everest Forms registers abilities in a loop from `$def['args']`, and each definition carries its own
`permission_callback`. The parser could not read the args, concluded "no `permission_callback`", and
fabricated an unauth ability. **Resolution: an argument list must be an inline `array(` / `[` literal
to be read; anything else is UNKNOWN (`nThArgExpr()` + `argsInline()` → `pcUnparseable`), never
`absent`.** This is the single most dangerous error direction in the whole miner: ignorance rendered
as a confident absence.

### D4 — Object/row provenance (defect J)

SureForms' nopriv endpoint reaches `update_user_meta($user->ID, …)` where the row is a caller-fed
parameter and the write sits behind a login check. **Resolution: only the caller's own row
(`selfOnly`) or a traced attacker-chosen id (`anyUser`) is a defensible claim; an unresolvable row
must be *named* (`rowUnresolved`) and never assumed.** Teeth: `.tmp/teeth-meta.mjs`.

### D5 — A nonce is not authorization, and it cuts both ways

`check_ajax_referer()` / `check_admin_referer()` / `wp_verify_nonce()` prove intent, not privilege.
The engine already treats them as **weak mitigations**: presence in the handler body downgrades
reach `unauth → subscriber` (`engine/privemap.mjs` `MITIGATIONS`, comment at line 175) — it never
claims the handler is *protected*. The human question is whether even "subscriber" is optimistic.
Three outcomes, and you must pick one **with evidence**:
- **Nonce absent on an unauth-reachable write** → the admin_init / CSRF class (§3.2), in-band *if*
  the write clears §2.2. Note this is already a modelled class, not a gap: our own Wordfence ticket
  `f26140c9` and the goldenbench positive fixture are exactly it (`admin_init` fires on
  unauthenticated `admin-ajax.php`/`admin-post.php` requests — `hookReach()` line 398).
- **Nonce present, emitted only to privileged pages** → genuinely protected → drop it.
- **Nonce present, emission NOT LOCATED** → **UNKNOWN → PARK.** Never "protected" (that is how we
  talk ourselves out of a real bug) and never "unauth" (that is how we fabricate one).
Our everest-forms palette/template candidates died here for the honest reason: subscriber-reachable,
nonce-only, emission not located in-tree. 24% of unauth CVEs involve a nonce — so the emission is
usually findable; look for `wp_create_nonce`, `wp_localize_script`, `wp_add_inline_script`, and any
shortcode/block/template that renders logged-out.

### D6 — Default-config reachability

Ask: does this fire on a stock install? Settings-gated features, disabled-by-default modules,
form/widget existence, and "requires the admin to have enabled X" all change the finding's severity
and its honesty. State the precondition in the draft — an unstated precondition is how a finding
gets downgraded for "overstated severity", which burns rate even when the bug is real.
### D7 — Reversibility and significance (§4.2, the GiveWP lesson)

The GiveWP report was real code, live-verified, video-attached — and rejected, because a subscriber
could pause/restart a migration and the effect was **recoverable, reversible and timing-only**.
Apply the same test to every write: *is the resulting state a security effect, or a cosmetic one?*
The settings that matter are the ones AGENT-GUIDE names (`siteurl`, `admin_email`, `default_role`,
`users_can_register`, `active_plugins`, role/capability rows, secrets). A style-template list or a
colour palette — our two surviving everest-forms candidates — is cosmetic. Patchstack also killed
those as "manually triggering cronjobs" and below the impact bar in the same rejection. **A
reversible cosmetic write is not a filing, however clean the reach.**


## 5. The freshness lane — hunt diffs, not code

The same 11,664-CVE surface has been read by everyone for years. The edge is **time**: a fix
announces itself in a diff, and the diff names the class.

```
node tools/cli.mjs commitwatch scan --live          # GATED: wordpress.org hosts, read-only GETs
node tools/cli.mjs commitwatch report [--all]       # ranked review-only leads + sibling-hunt seed
node tools/cli.mjs commitwatch show <slug>
```

`commitwatch` watches tracked plugins' SVN trunk, classifies fresh changesets for security
relevance, and turns **"a check was added"** into a class + affected versions + a seed for a
sibling hunt (`variantsweep`). It never hunts and never submits. Companion tells:

- **`readme.txt` changelog lines** are the author's own severity signal. Grep tags for
  `Security`, `Fix`, `sanitiz`, `escap`, `nonce`, `capability`, `permission`, `auth` — and for
  `= 1.2.3 =` bumps that coincide with a new `current_user_can`/`check_ajax_referer` in the diff.
- **"One flag flip" watch items.** Target notes already record the highest-value ones:
  `gosmtp` and `siteseo` ship `mcp.public=true` + `show_in_rest=true` abilities — one
  `permission_callback` loosening away from unauth mail relay / content tamper. `ai-engine`'s MCP
  endpoint (`meta.mcp.public` + bearer token) is the same shape. These are *watch* items, not
  findings; the flag being set today is not a bug today.
- **Sibling hunts.** A fixed bug in one plugin usually exists unfixed in N others (the same
  copy-pasted handler). `commitwatch report` prints a `--sig` line for each lead; sweep the local
  corpus with it:
  `node tools/cli.mjs variantsweep <source-dir> --sig '{"kind":"class","class":"option-overwrite"}'`
  (or `--sig <sig.json>`; a pattern signature is `{"kind":"pattern","match":…,"anchors":[…]}`). Hits
  carry a blank status field by design — the sweep never claims novelty or CVE status. This is where
  one CVE becomes several leads, without ever copying a claim from the advisory.

---

## 6. The signature sweep

Run these over a local tree (`<corpus>` = unpacked plugin/theme sources). Each signature is
deliberately *narrow*: a signature that fires on everything has no signal. Every one must be
calibrated first (§7) — **a signature that has never caught a known instance of its class is a
hypothesis, not a tool.**

| id | signature (grep -REn over PHP) | class | verification required |
|---|---|---|---|
| **S1** | `admin_post_(?!nopriv)` handler OR `admin_init`/settings-save reading `$_POST`/`$_REQUEST`, in a file with **no** `check_admin_referer\|check_ajax_referer\|wp_verify_nonce` | CSRF → write (§3.2; 18.9% of unauth CVEs) | the write path is genuinely nonce-free; the target option is significant (§2.2) |
| **S2** | `wp_ajax_nopriv_\|admin_post_nopriv_` + a sink in the callback | unauth handler | §4 D1 argument control · D2 any-form gate · D3 readable registration |
| **S3** | `register_rest_route` … `permission_callback` absent, or `__return_true` | unauth REST route | is the callback reachable with no second gate inside the handler? |
| **S4** | `wp_register_ability\|mcp\.public\|show_in_rest` near `permission_callback` | Abilities/MCP | §4 D3 — unreadable args are UNKNOWN, never absent |
| **S5** | a `.php` file with **no** `defined('ABSPATH'` and no `WPINC` guard, under the plugin root | direct-file reach (§3.3) | does it bootstrap `wp-load.php` / read `$_POST` and reach a sink? |
| **S6** | `update_option\|update_site_option\|update_user_meta\|set_role\|add_role\|add_cap` with a non-constant first arg | significant write | §4 D1 attacker control of name+value · D7 significance |
| **S7** | `$wpdb->query\|get_results\|get_var` where the SQL concatenates `$_GET\|$_POST\|$_REQUEST`, **or** `->query(` with no `prepare` and an interpolated var | SQLi (unauth 6.8%) | real dataflow into the query. `dataflowUnproven` on a hop>0 sink with `taint:'none'` means the miner found the sink and **not** the flow — never file that |
| **S8** | `include\|require\|file_get_contents\|unlink\|file_put_contents\|copy\|rename` with a request-derived path | LFI/RFI · file read/del (unauth 1.1% / 5.2%) | full path+extension control, not bytes-only |
| **S9** | `move_uploaded_file\|wp_handle_upload` where the extension, `$_FILES['x']['name']` or `type` is attacker-influenced | arbitrary file upload (unauth 3.7%) | extension control proven, destination path control proven |
| **S10** | `unserialize\s*\(` on request data | PHP object injection (unauth 1.6%) | a reachable POP chain, or a class that justifies "significant" |
| **S11** | `echo\s+\$_(GET\|POST\|REQUEST)` / `printf\(\s*\$_` with no `esc_`/`sanitize_` nearby | XSS / reflection | only site-wide stored, or reflected with proven JS execution (§2.4) |
| **S12** | `set_transient\|wp_schedule_single_event\|wp_clear_scheduled_hook\|delete_…` on other users' rows | various | **§4.x auto-dead**: cron/cache/reorder/dismiss are NO-FILE regardless of reach |

**How to use the sweep without generating a fiction:** every hit is a *question*, and the answer must
name a `file:line` and quote the code. If you cannot quote the line that proves the discriminator,
you do not have a finding — you have a grep match.

The ranked view, if you want the miner's opinion first:

```
node tools/cli.mjs privemap <corpus> --top 20 [--json]        # RANKS (pre-adjudication)
node tools/cli.mjs privemap <corpus> --json | node tools/cli.mjs reachprove <corpus> --rescore -
                                                              # ADJUDICATES (only CONFIRMED actionable)
node tools/submit-drive.mjs scopecheck <slug> <auth> "<class>"    # the mandatory gate
```

(`reachprove --rescore -` reads the privemap report from **stdin** — always pipe it, never run it
bare, or it will sit waiting on stdin.)

**Where the S1 gap actually is — stated precisely, because over-claiming a gap is its own
dishonesty.** privemap *does* model the `admin_init` option-write without a nonce: that is the
golden-sink positive, the Madara ticket shape, and `hookReach()` returns `unauth` for it. What it
does **not** model is the `admin_post_<action>` settings-save form (CVE-2024-0203's
`digits_save_settings`): `hookReach()` classifies `admin_post_*` as `base: subscriber` (line 401),
so a missing-nonce write there lands in the subscriber band and can never surface as the
unauthenticated CSRF class the CVE data says is the ecosystem's largest (18.9% of unauth records).
Narrow, verifiable, and worth closing — see §10.

---

## 7. Calibration — prove the signature on a known-known before trusting it

From `docs/RESEARCH.md` (rule 2), applied to hunting: **a detector that has never caught a known
instance of its class is a hypothesis, not a tool.** What we actually have on disk, stated exactly
(checked, not assumed):

| tree | what it really is | how to use it |
|---|---|---|
| `test/fixtures/goldenbench/golden-sink/golden-sink.php` | **the corpus-independent positive**: `add_action('admin_init', …)` → `isset($_POST['golden_settings'])` → `update_option('golden_settings', $_POST[…])`, no nonce, no capability check (pinned `golden-sink.php:11`, `class: option-overwrite`, `minReachability: unauth`) | the must-hit every signature set must reproduce — it is the minimal Madara `wp_manga_settings` shape |
| `data/goldenbench/manifest.json` → `madara-core` | must-hit pins at `inc/settings.php:126`, `wp-manga.php:789`, `inc/upload/imgur-upload.php:39` (all `option-overwrite`, minReachability `unauth`). Root is `C:/Users/Jack/Downloads/varvel-kimi/research/madara-site/…` — **outside this repo**; the entry SKIPs with a named reason when absent, and a SKIP is not a pass | run `node tools/cli.mjs goldenbench` (or equivalent) and read the skips aloud before claiming recall |
| `.tmp/wp-demo-lab/wordpress/wp-content/themes/madara/` | **NOT vulnerable — version 2.2.7.1**, patched well past CVE-2025-4524 (≤ 2.2.2). The `madara_load_more` handler still exists (`core.php:275-277`) | a **negative control** for the LFI surface: the entry point is present and the traversal is fixed, so a correct S8 signature must not claim unauth inclusion here |
| the four fabrication fixtures (SureTriggers `user_can` object-form, Everest Forms loop-registered `permission_callback`, SureForms caller-fed meta row, ai-engine 3-arg constant `update_option`) | **not-a-bug controls** built during defects E–K | the signature must either stay silent or emit UNKNOWN/DEGRADED — never UNAUTH/`absent` |

Madara theme 2.2.7.1 on disk is worth internalising: the temptation was to write "we have the
known-vulnerable CVE-2025-4524 tree for calibration" — it is the *patched* version, and asserting
otherwise would have been a fabrication about our own lab.

Procedure (and the reason our fixes hold):

1. Build the signature; run it on the positive fixture → it must fire on the pinned `file:line`.
2. Run it on a **negative control** (present surface, real gate / fixed bug) → silent or UNKNOWN.
3. Only then run it over the hunt corpus. A signature never shown to fail correctly is not evidence.
4. Pin the pair as a test where practical: `test/privemap.test.mjs`, `test/reachprove.test.mjs`
   (`npm test` is the pinned list; **never** `node --test test/`).

The teeth technique that makes this real (used four times in defects E–K, scripts kept in `.tmp/`):
mutate the *engine* to the pre-fix behaviour, show the new test **fails** on the mutant and passes on
the fixed engine, then delete the mutant. A regression test that has never been seen to fail proves
nothing. `make-mutants.mjs` **must leave `engine/` clean** — a mutant engine file in `engine/` is a
fabrication factory with a friendly name (§8).

---

## 8. Traps that have already cost us real time

1. **Capture the NAME, not the `$`.** A regex that captured `$` inside a group and then prepended
   `\$` turned `$` into an **end-anchor**: it silently matched nothing **while every test passed**.
   Only re-running the real plugin exposed it. Corollary: run the tool on real code, not just on
   fixtures.
1b. **Scope your alternation — its sibling.** The S1 sweep's first matcher put its `|` at the **top
   level**, so the callback branch `[ $x, 'name' ]` matched *any* array literal — including every
   REST `'callback' => [ $this, 'rest_update_option' ]` line — and reported 63 "hits" labelled
   `admin_post` with `hook=undefined`. Both traps are the same family: **the matcher looked plausible
   and matched the wrong thing.** The cure is the same too — print the matched text next to the
   label (`grep -n` equivalent) and make a hook-less match impossible (`if (!hook || !fn) continue;`).
2. **`.tmp/*.json` written by PowerShell redirects is UTF-16.** `JSON.parse` on it yields garbage or
   throws. Build reports in-process, or write with Node (`writeFileSync(..., 'utf8')`). Our NVD
   miner writes its JSON with Node for exactly this reason.
3. **A mutant engine left in `engine/`.** `make-mutants.mjs` writes `engine/privemap-mutant-*.mjs`
   because relative imports (`./severity.mjs`) only resolve from there. A race between a parallel
   cleanup and a fresh mutant run left two of them in place — and a 75KB *deliberately-buggy* engine
   copy is exactly the thing a later agent runs by accident. **Always verify `Get-ChildItem engine
   -Filter '*mutant*'` is empty after teeth work.**
4. **Docker phantoms.** Four "failures" in `huntloop` were a half-started daemon, not code. With
   Docker genuinely up, the same tests pass (slowly: ~24s each on the kernel tier). Check the daemon
   before believing a red suite.
5. **The miner's `verified` ≠ exploitable.** `verified` means *the check reproduced in a fresh
   sandbox*. 59 of 61 ledger `verified` entries were the version→CVE correlation oracle. Filing still
   needs the human repro every draft leaves as `TODO(validate)`.
6. **NVD has no CWE for WP plugins** (§1 limitation 1). Do not synthesise one.
7. **Feed-shape guessing.** v1 of the NVD miner confidently produced "CVSS: 100% unknown" and "1
   subscriber+ CVE" because it guessed at key names and prose patterns. The fix was a 25-second raw
   probe (`.tmp/nvd-probe.mjs`). **Probe the bytes before trusting the aggregate.**
8. **An accessor is not a sink.** `UM()->query()->post_data($id)` matched the raw-query regex on the
   `->query(` inside the *getter* and produced an `unauth high` SQL-injection claim in a 200k-install
   plugin (ultimate-member). Structural cure: a sink call whose result is **immediately
   dereferenced** (`->query()->x`) is an accessor chain — unless the receiver is a real db handle.
   Corollary: the same trap catches *gates* (`UM()->admin()->check_ajax_nonce()` is a nonce check on
   a method chain the gate vocabulary doesn't resolve).
9. **An exclusion that misses a leading `\` is not an exclusion.** The core-query-class guard tested
   `new WP_User_Query` while the real code says `new \WP_User_Query`. Test exclusions against real
   third-party code, never only against the shape you imagined.
10. **A fix that removes true positives is worse than the false positive it removes — and only
    calibration can tell you.** The first defect-M fix passed the new regression test and broke a
    hand-verified madara sink; the **golden-bench soak caught it by name**. Run the calibration gate
    after *every* engine change, before believing the fix. (See §7.)

---

## 9. The filing bar — what must exist before a draft

A report is only as strong as its weakest unproven sentence. Every draft must carry, explicitly:

1. **Version range**, with the exact version tested and the boundary (e.g. "≤ 3.2.5, verified on
   3.2.5; changelog shows the fix in 3.2.6"). From `readme.txt`/`stable tag`, not from memory.
2. **Auth level, proven** — "unauthenticated" means *no cookies sent* and the request shown raw.
   If a Subscriber cookie was needed, say Subscriber (§2.1 band, §4 D2/D5).
3. **The exact request/response pair**, with the control case: the same request that does nothing
   when the sink is guarded. A claim without a control is an assertion.
4. **The discriminator sentence** — one line naming why the reach and the impact are real (§4),
   including the argument control (D1), the gate form (D2), the row provenance (D4).
5. **Preconditions** — non-default settings, required form/widget/module, multisite-only (§4 D6).
6. **Recoverability, stated honestly.** If a triager can say "reversible, timing-only", it is already
   rejected (§2.3 / §4 D7). Lead with the non-reversible effect or drop the finding.
7. **No fabricated detail.** The honesty contract is absolute: nothing invented, unverified claims
   marked unverified, clean days reported clean. Hallucinated code is the one unforgivable sin on
   every platform, and it is the one that ends an account (Wordfence: **4 AI-hallucinated reports =
   permanent ban**).
8. **Drafting order (mandatory):** `classifyLane` → `scopecheck` → draft → `payload` → `fill` →
   **the operator's hand clicks Submit — never the driver's, never yours.**

---

## 10. Open questions and the concrete next build

**What this playbook does not yet know:**
- The reach-surface table under-matches (§1 limitation 3) because the CNA prose is free-form. A
  better surface measurement would join the CVE's `affected` product to the plugin's actual code —
  a corpus we do not yet have at scale.
- We have no measured denominator for **what fraction of our corpus hits are false positives** —
  only per-defect spot checks. Without it, "the miner is precise now" is a claim, not a measurement.
- Patchstack's acceptance landscape is nearly invisible in NVD (81 CVEs, 0.7%). Our knowledge of
  their bar is one rejection (GiveWP) and the §4.x list. **Do not generalise Wordfence-shaped
  findings to a Patchstack filing without re-checking §4.2.**

**The build this data justifies (do this next): the `admin_post_<action>` missing-nonce write.**
The `admin_init` variant is already modelled (golden-sink positive = our Madara ticket). The
unmodelled variant is the **settings-save handler registered `admin_post_<action>` (non-nopriv) with
no nonce check on the write path** — CVE-2024-0203's `digits_save_settings` shape, reaching
`default_role`. Today `hookReach()` puts it in the subscriber band, so a genuinely unauthenticated
CSRF chain is scored below where the ecosystem says it belongs (18.9% of unauth CVEs, §1.5a). It
would need: argument control on the target option/role (§4 D1), a nonce-presence test on the *write
path* rather than the file, and a §2.2 significance filter (a nonce-less write to a cosmetic option
is still NO-FILE — §4 D7). Ranking must stay honest: **UNKNOWN** when the nonce check cannot be
located on that path, never "vulnerable". Calibrate against the golden-sink fixture (must-hit) and
against the four fabrication fixtures (must not fire) before it is allowed to rank anything (§7).

**Where our next real bug most likely is**, honestly ranked by the evidence above:
1. S1/CSRF-to-significant-write in a ≥50k plugin (largest class, invisible to our current tooling).
2. A nonce whose emission we can locate on a public page, turning one of our parked
   subscriber-reachable writes into a proven unauth write (§4 D5).
3. An unauth read of a significant object (§1.4: 8.9% of unauth CVEs, in-band under §3.9) — the
   cheapest class to prove with a single request and no state change.

---

*Provenance of this document: market numbers from `.tmp/nvd-wp-stats.mjs` over the pinned NVD
snapshot (`data/cvepack-cache/`, 2026-09-12); discriminator sections from the defect ledger in
`.tmp/SESSION-STATE-2026-09-17.md` §6–§7; acceptance rules from `docs/AGENT-GUIDE.md` and
`tools/submit-drive.mjs scopecheck`. Where a claim here contradicts an engine, **the engine is
wrong and must be fixed — or this document is.** Never carry a disagreement silently.*

