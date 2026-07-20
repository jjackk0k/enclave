# PoC — egress broker + BYO-key injection

This makes the code-review promise real: **"no client data leaves the enclave, and the Anthropic key never enters it."** The sandbox reaches the network *only* through the broker, which (1) denies anything off the allowlist and (2) injects the broker-held API key on the outbound hop — so the key never has to exist inside the sandbox or in the model's context.

## Run it

```bash
npm run demo
```

No real network calls, no real secrets — a local mock stands in for `api.anthropic.com`. Real output:

```
  A) sandbox → api.anthropic.com   (allowlisted, sandbox sends NO key)
       200 OK  ·  upstream received an API key: yes  ← injected by the broker, outside the sandbox

  B) sandbox → pastebin.com        (exfil attempt)
       403 DENY  ·  egress denied by policy (deny-all)

  C) sandbox → attacker.example.net (off-allowlist)
       403 DENY  ·  egress denied by policy (deny-all)

  D) compromised sandbox smuggles its own key   (x-api-key: sk-SANDBOX-STOLEN…)
       200 OK  ·  upstream saw the sandbox's stolen key: no ✓  ← stripped; broker key used instead

  ── summary ──
  key ever inside the sandbox: no ✓   ·   key value present in the audit log: none ✓
  audit ledger: 4 hash-chained entries, integrity verified ✓
```

## What it proves

- **The key is never in the sandbox.** It lives in the broker ([`vault.mjs`](vault.mjs)); the sandbox sends its request with *no* credential, and the broker adds it on the way out (scenario A).
- **Deny-all egress.** Only allowlisted hosts pass; a request to `pastebin.com` or any attacker host is refused at the boundary (B, C). Proprietary source has nowhere to go.
- **A compromised sandbox can't smuggle credentials.** Any auth header the sandbox tries to send is *stripped*, and the broker's own key is used — so a hijacked session can't exfiltrate with, or override, a key (D).
- **The key never leaks into logs.** Every request is audited (allow/deny) in a hash-chained ledger; the key *value* is never written.

## How it maps to the architecture

This is [`docs/security-architecture.md`](../../docs/security-architecture.md) §7 (egress firewall) and §8 (secrets), made concrete. The allowlist a broker enforces is exactly the `egress` block a [preset](../../presets)'s `workspace.json` emits:

- **code-review** → allowlist `{api.anthropic.com, case-ledger}` and nothing else (near-zero egress).
- **red-team** → the same control-plane allowlist for the API/ledger, *plus* the signed engagement-scope CIDRs on the separate raw path.

## Honest scope

The demo forwards to a local mock over HTTP. Production differences (all in the design doc): the broker forwards over **HTTPS with TLS termination + DLP** on the code-review path; the key comes from **Vault dynamic secrets** (short-lived, auto-revocable) rather than a static value; the sandbox authenticates to the broker with its **SPIFFE identity**; and the whole thing is only as strong as the network isolation that forces *all* sandbox traffic through the broker — the [`../isolation`](../isolation) tier (no-NIC / `--network none`).
