# Human-in-the-loop captcha handoff build — 2026-08-31

Signup automation (semrush first, every recipe-driven program after) hits image
challenges we will **never auto-solve and never bypass**. This build adds the
clean handoff rail: the browser flow **detects** a challenge, **pauses**, leaves
the headed Firefox window visible for the operator (Jack), **verifies** the
solve from page signals, then **resumes** and harvests the resulting session
into the session broker. Tests: `test/captchaassist.test.mjs` (13), neighbors
`test/acctfactory.test.mjs` (8) and `test/sessionbroker.test.mjs` (15) still
green.

## Layout

- **`tools/captchaassist.mjs`** — the rail. Signature classification
  (`challengePageProbe` / `classifyProbe`), the handoff state machine
  (`handoffOnce` / `captchaHandoff`), the pausable step-runner
  (`runHandoffFlow` + `sanitizeFlowRecipe`), the operator status board
  (`listHandoffs`), and the CLI (`run` / `status`).
- **`tools/acctfactory.mjs`** — the recipe primitive. `sanitizeRecipe` accepts
  `captcha: 'handoff'` (or `{mode:'handoff', timeoutMs, pollMs, after}`), and
  `provisionAccount` pauses after the signup submit (and optionally after
  activation) through an injectable `handoff`; the real default is lazily
  `captchaassist.captchaHandoff`. `playwrightDriverFactory` gains
  `detectChallenge()` (in-page probe, node-side classify) and `bodyText()`.
- **`recipes/semrush-signup.json`** — the semrush flow migrated off
  `.tmp/semrush-signup.mjs` (which hard-died on the reCAPTCHA wall) onto the
  primitive: goto → consent → fill → submit → **`captcha: handoff`** →
  waitMail (activation link) → verify oracle at `/accounts/profile/`.

## Usage

```bash
export PATH="/c/Program Files/nodejs:$PATH"
cd /c/Users/Jack/Downloads/enclave/varvel

# fire the semrush signup — it PAUSES at the captcha; solve it in the
# Firefox window that opens; the flow resumes and brokers the session.
# --inbox/--inbox-pass rides a PRE-PROVISIONED mail.tm inbox and skips the
# fingerprint-throttled account-creation leg entirely (only a token call runs).
node tools/captchaassist.mjs run --program semrush --label a --recipe recipes/semrush-signup.json \
  --inbox varvel-probe-q9x@emalupe.com --inbox-pass 'VarvelProbe!9'

# the operator board: pending / resolved / timed-out handoffs
node tools/captchaassist.mjs status
```

The run exits `0` on a verified+brokered session, `3` on a flow failure, `4`
on OPERATOR-TIMEOUT. Evidence lands at `.tmp/semrush-signup-<label>-result.json`;
the managed session lands at `.tmp/sessions/semrush-<label>.json` with the
harvested `/accounts/profile/` canary and a relogin recipe pointing back at the
same command.

## The handoff contract

1. **Detection is by signature, honestly heuristic.** reCAPTCHA (iframe
   `google.com/recaptcha*`, text `i'm not a robot` / `select all images`),
   hCaptcha (iframe `hcaptcha.com`), Cloudflare (iframe
   `challenges.cloudflare.com` / `cf-chl`, text `verify you are human` /
   `checking your browser`). An exotic challenge that slips the signatures is
   not silently bypassed — the next recipe step simply fails by name, which is
   the generic operator-intervention pause.
2. **On detection:** the headed window stays up (headless is never used on
   this rail), `.tmp/captcha-needed-<program>.json` is written
   `{program, label, step, state:NEEDED, since, url, vendor, signals}`, and one
   loud `[CAPTCHA-HANDOFF] OPERATOR NEEDED …` console line prints.
3. **Solve verification — the pin.** `RESOLVED` requires the challenge
   signature gone **and** one corroborating signal: `url-change` (page moved
   since the handoff began), `success-marker` (configurable `successRe`; default
   matches check-your-email / welcome / dashboard), or `submit-re-enabled` (a
   control disabled at handoff time re-enabled). A challenge that merely stops
   rendering — crash, error page, redirect back — is **never** claimed as
   solved; the runner keeps waiting and dies OPERATOR-TIMEOUT (default 10 min,
   `--timeout` / per-step `timeoutMs`, hard cap 30 min).
4. **Post-solve:** the recipe resumes automatically, the `verify` step (when
   declared) re-proves authentication (deny-URL regex + body-must-contain,
   `$email` interpolates the provisioned address), and only then are
   cookies/storage harvested and `registerSession` called with the canary.
   No verified flow → no broker entry. No session material → honest
   `capture` failure even if every step landed.

## acctfactory primitive

```js
const recipe = { signupUrl: 'https://…', captcha: 'handoff', /* … */ };
await provisionAccount(recipe, { mailtm, driver, program: 'semrush' });
// after the signup submit the flow pauses for the operator; OPERATOR-TIMEOUT
// fails step 'captcha' with 'nothing claimed' in the error.
```

`after: ['signup','activate']` adds a second gate behind the activation step.
Tests inject the handoff; production lazily loads the real rail.

## Limitations

- **We solve nothing automatically.** The operator's hands are the rail.
- **Detection heuristics can miss exotic challenges** (custom in-house
  puzzles, challenges rendered inside cross-origin shadow frames with no
  signature iframe). The failure mode is safe: the flow stalls at the next
  step with a named error, and the headed window is still on screen for a
  manual look. The `success-marker` signal needs per-program tuning via
  `successRe` when the post-solve page text is unusual.
- **One browser, one operator.** Concurrent runs against the same program +
  label share the persistent profile; run labels `a`/`b` sequentially.
- The semrush recipe's fill step uses selector-driven `fill()`; if the SPA
  demands keystroke-level events (the 2026-08-26 script typed with
  `page.keyboard`), the fill step fails honestly by name and the recipe needs
  a driver-level tweak — not silent retries.
- Status files are advisory state for the operator board, not locks; a
  crashed run can leave a stale `NEEDED` — re-running overwrites it.
- **mail.tm rate-limits account creation per IP** (observed 2026-08-31:
  `POST /accounts` answering 429, occasionally 504, after a few attempts in a
  day while `GET /domains` stays 200). The flow fails honestly at step
  `inbox` in that case — wait for the window to reset or move egress IP, then
  re-fire. This is upstream throttling, not a rail failure.
- **mail.tm's edge throttles Node's TLS fingerprint** on `POST /accounts`
  (same-minute evidence: curl → 201, undici AND `https.request` → 429/504).
  The CLI therefore rides `curlJsonTransport` (curl subprocess) for mail.tm;
  the library default stays zero-dep node. Failures name the HTTP status
  (`lastError`) — a bare "creation failed" is a bug.
- **Pre-provisioned inboxes** (`--inbox`/`--inbox-pass`, or the `inbox`
  injection point in `runHandoffFlow`) skip account creation entirely; only
  the token call and mail polling touch mail.tm.
- **Firefox profile hygiene is self-healing**: stale `parent.lock` /
  `.startup-incomplete` removed pre-launch, exact-profile-holder firefox
  processes reaped (the operator's own browser is never matched), and a
  wedged profile (hard kills wedge it — launch hangs to timeout) is
  QUARANTINED aside (`<profile>.quarantine-<ts>` — renamed, never deleted)
  with one fresh-profile retry.
- **ESM top-level-await deadlock (fixed 2026-08-31)**: when
  `captchaassist.mjs` is the CLI entry, the driver's default
  `detectChallenge` dynamically importing this module can never resolve (the
  module is awaiting the flow that awaits the import). The runner rebinds
  detection against `driver._page` with its own probe/classifier. Pinned in
  the test suite.
