# PoC — audit anchoring (externally-verifiable tamper-evidence)

The [enforcement seam](../enforcement-seam) writes a **hash-chained** ledger — that proves *internal* consistency (no line edited or reordered). This adds the layer that makes the audit verifiable **without trusting Enclave at all**: a **Merkle root** over the ledger, **signed by an independent authority** and **published to an external transparency log**. Now a third party can prove whether a given ledger state is the one that was anchored — and Enclave can't forge it.

## Run it

```bash
npm run demo
```

Real output:

```
  8 hash-chained entries → Merkle root 11333fbfac59471a…
  signed by the external authority + published to the transparency log ✓

  1) inclusion proof   entry #4 "pretooluse.decision · marcus"
       proven in the anchored ledger: yes ✓  (audit path: 3 hashes, not the whole log)

  2) tamper detection  flip entry #4's decision to "allow" and recompute
       recomputed root eb0f1f7f36c5ade9… ≠ anchored root
       ledger still matches its external anchor: NO ✗   ← provable to anyone holding the authority key

  3) insider forgery   rewrite the whole ledger + hash-chain AND forge a fresh anchor
       forged anchor verifies against the authority's public key: NO ✓   ← insider can't sign as the authority
       the originally-published anchor still verifies: yes ✓

  AUDIT-ANCHOR: PASS ✓
```

## What it proves

- **Inclusion without the whole log.** A Merkle inclusion proof shows one entry is in the anchored ledger using ~log₂(N) hashes — an auditor can verify a specific event without you handing over the entire log.
- **Tamper detection by a third party.** Change any entry and the recomputed root no longer equals the externally-anchored root. Because the root was signed by an outside authority, the mismatch is provable *by anyone* — not just by Enclave.
- **Insider-proof.** An insider who rewrites the whole ledger and re-hash-chains it still can't produce a valid anchor: they don't hold the external authority's signing key. The historical, externally-published root stands.

## How it's built

Real crypto, `node:crypto`, no dependencies:
- **Merkle tree** with **RFC 6962 (Certificate Transparency)** domain separation — `leaf = SHA-256(0x00‖data)`, `node = SHA-256(0x01‖L‖R)` — which blocks second-preimage attacks that swap a leaf for an internal node. ([`merkle.mjs`](merkle.mjs))
- **ed25519-signed roots** published to an external log. ([`anchor.mjs`](anchor.mjs))

This maps to [`docs/security-architecture.md`](../../docs/security-architecture.md) §9. In production the authority is a transparency log (RFC 6962 / Google **Trillian** / Sigstore **Rekor**) or an **RFC 3161** timestamp authority, and the ledger sits on **WORM storage** (S3 Object Lock, compliance mode) — this PoC proves the cryptographic core.
