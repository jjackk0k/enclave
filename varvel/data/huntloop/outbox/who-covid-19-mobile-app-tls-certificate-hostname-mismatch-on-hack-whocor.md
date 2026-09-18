<!-- VARVEL huntloop draft — HUMAN REVIEW ONLY. The loop NEVER submits: this file waits in the outbox for the operator's hand. Verdict: VERIFIED (replay-verification PASSED). Evidence bundle: C:\Users\Jack\Downloads\enclave\varvel\data\huntloop\evidence\who-covid-19-mobile-app_new-program_in_27bbfa6051e5\tls-certificate-hostname-mismatch-on-hack-whocor -->
> **[REGRADED 2026-09-18] This draft predates the evidence-grade fix — its readiness banner is VOID.**
> It was rendered while the loop reported an *offline* replay as a validated oracle. The replay
> runs inside the isolated sandbox (`--network none`): the check re-executes against the recorded
> evidence bundle and the live target is NEVER re-probed, so the pass re-derives the record — a
> reproduced CORRELATION, not a reproduced vulnerability. Under the current gate the finding grades
> **FIRM (not confirmed)** and is **NOT submittable** until the auto-forge (or an equivalent live
> re-probe) captures a real impact marker. Tooling: `tools/huntloop.mjs` (findingGrade/isSubmittable),
> `tools/pocforge.mjs`. Run the console's per-row VERIFY, or let the loop's auto-forge stage do it.


# TLS certificate hostname mismatch on hack.whocoronavirus.org

> **DISPOSITION (operator record, 2026-09-16): NO-FILE.** This draft is retained as the
> record of the finding, not as a filing candidate. Reasons, each verified:
> (1) the new `intakeGate` kills the class — *"TLS/certificate config observations are
> informational (no demonstrated crypto break)"*; (2) the H1 program is a VDP —
> `offers_bounties: false` and **every** structured scope is `eligible_for_bounty: false`,
> so a valid report pays £0; (3) the "replay-verification PASSED" verdict proves the *check*
> re-ran in a fresh sandbox (`--network none`), not that anything was exploited — the oracle
> string-matches its own pre-supplied EVIDENCE blob. The underlying TLS observation was real
> and honestly gathered. Full reasoning: `.tmp/OUTBOX-TRIAGE-2026-09-16.md`,
> `.tmp/SUBMISSIONS.md`.

> Submission readiness: **READY** — validator-gate validated and fresh.

**Severity:** Low  
**Severity (internal scale):** low · **confidence:** suspected  
**Reported to:** hackerone

## Summary

TLS certificate hostname mismatch on hack.whocoronavirus.org. Severity Low, confidence suspected, validation state validated.

## Steps to Reproduce

1. TODO(validate) — affected host/URL (the input carried no host binding for this finding; name the exact asset from your validated session)
2. TODO(validate) — exact endpoint/parameter (the finding carries no ref; write the precise request from your validated session)
3. Reproduce the proof exactly as the validator gate did: huntloop replay-verification.
4. TODO(validate) — full impact demonstration (state-changing proof is operator sign-off territory; attach only the verified exchange)

## Evidence

stored evidence:

```
The evidence for the in-scope host hack.whocoronavirus.org shows ERR_TLS_CERT_ALTNAME_INVALID: the hostname is not in the presented certificate's altnames, which include DNS:internal.joinforma.com. This is a concrete TLS endpoint misconfiguration on an in-scope asset.
```

validator oracle:

```
huntloop replay-verification
```


## Impact

TODO(validate) — concrete impact statement (derive from the VERIFIED repro at suspected confidence: what does a successful exploit READ, CHANGE, or REACH? The static record does not state impact, so this report does not either)

## Remediation

- Enforce TLS with modern ciphers; encrypt sensitive data at rest and in transit.
- Maps to: A02:2021 Cryptographic Failures · MITRE TA0009 Collection

## Scope Attestation

TODO(validate) — scope attestation (the input carried no signed scope; attach the program scope + authorization before submission — a report without an attestation reads as unscoped testing)

## Honesty — unverified gaps

- confidence is 'suspected' — the platform did not confirm this finding end-to-end
- no signed scope in the input — the attestation line could not be rendered from evidence
- no researcher handle supplied (--researcher) — the platform credit line is a TODO, never a fabricated name

---
_Evidence is verbatim-minus-redactions; gaps are listed, never hidden; readiness is computed from the validator gate, never asserted._