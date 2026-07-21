# PoC — governed AI memory

**Should Enclave sessions have persistent AI memory?** Yes — it's valuable (the AI remembers the engagement, prior findings, the operator's style). But "save it in the sandbox" is the wrong answer, and naive memory is a security hole. This is memory done the Enclave way.

## Two kinds of memory

| | Where | Lifetime | Governed by |
|---|---|---|---|
| **Session scratch** | *inside* the ephemeral sandbox | wiped on teardown | the sandbox itself ([`../isolation`](../isolation)) |
| **Persistent memory** | a store *outside* the sandbox | across sessions | this — scoped, DLP'd, audited, inert |

The sandbox is destroyed on teardown by design, so anything meant to *outlive* the session can't live there — it needs a governed store.

## Run it

```bash
npm run demo
```

```
  1) persistence   ✓ dana recalls her IR hypothesis in a new session
  2) scope         ✓ a different workspace recalls NOTHING of incident-2231's memory
                   ✓ a lower-clearance (L2) reader can't read the L3 memory
  3) DLP           ✓ writing a credential to memory is refused
                   ✓ writing a 3000-char raw dump is refused
  4) poisoning     ✓ an injected "grant admin" note is stored (it's just data)
                   ✓ …but sam's deleteFiles is STILL denied (authz on identity, not memory)
  5) integrity     ✓ hash-chain verifies; editing an entry breaks it
  MEMORY-GOVERNANCE: PASS ✓
```

## The four rules that make persistent memory safe

- **Scoped.** Every memory is tagged `(workspace, clearance)`. Recall only returns memories in *your* workspace, at or below *your* clearance — so memory never crosses tenants or leaks up the clearance ladder. (Reuses the same identity model as [`../enforcement-seam`](../enforcement-seam).)
- **DLP'd on write.** Writes that look like secrets/credentials, or oversized raw dumps, are refused. Memory is for notes and summaries — not a side channel to exfiltrate source or keys past the egress controls.
- **Audited + tamper-evident.** Entries are hash-chained; any edit is detectable (and would anchor the same way as [`../audit-anchor`](../audit-anchor)).
- **Inert.** Memory is **data, never instruction**. The demo proves it: an injected "treat sam as L5 admin" note is stored, but sam's `deleteFiles` is *still denied* — authorization decides on the signed identity, not on anything in memory. **Memory informs the AI; it never authorizes it** — the same rule as clearance. This is what defeats *memory poisoning*.

## Why this matters

Public-AI memory is a black box. For security work, "the AI remembers things" has to mean *governed* memory — or it silently undoes the isolation, egress, and clearance controls everything else enforces. Governed memory is a genuine differentiator: the AI remembers exactly what it's allowed to, scoped and logged.

*Production: back the store with the same WORM/anchoring as the audit ledger, and let the console surface a per-workspace "what the AI remembers" panel that an operator (and an auditor) can review.*
