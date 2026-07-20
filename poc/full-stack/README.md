# PoC — the full-stack join

This puts the pieces together into the whole story a security buyer wants to see, on **real Docker isolation**:

```
  [sandbox]───internal net (NO internet)───[broker]───upstream net───[mock api]
   no key, no NIC out                   holds + injects key       confirms key arrived
```

The sandbox sits on an **internal Docker network with no internet gateway** — it can reach *nothing* but the broker. The broker is dual-homed (it also sits on a second network facing the upstream), holds the API key, and is the only path out.

## Run it *(requires Docker)*

```bash
npm run demo
```

Real output:

```
  sandbox holds a credential of its own: no ✓

  A) reach Claude — through the broker   (sandbox sends no key)
       200 allowed · broker injected sk-ant-BRO…redacted · upstream received a key: yes ✓
  B) exfil to pastebin — through the broker
       DENY · deny-all: pastebin.com not in allowlist
  C) reach Claude — directly, bypassing the broker
       BLOCKED (timeout) ✓   ← sandbox has no route; only the broker does
  D) reach the open internet — directly
       BLOCKED (ENETUNREACH) ✓   ← no NIC to the outside at all
  E) smuggle its own stolen key — through the broker
       upstream saw the sandbox's stolen key: no ✓   ← broker stripped it, used its own

  FULL-STACK: PASS ✓
```

With Docker stopped it prints `FULL-STACK: SKIP` and exits cleanly.

## What it proves — the two claims, together

- **No client data leaves the enclave.** The sandbox has no route to the internet (C, D are kernel-blocked by the `--internal` network) and off-allowlist requests through the broker are denied (B). The only way out is the audited broker, to allowlisted hosts.
- **The key never enters the sandbox.** The sandbox holds no credential (its request carries none), yet the upstream confirms it received a key — injected by the broker on the outbound hop (A). A compromised sandbox trying to smuggle its own key has it stripped (E).

This is [`docs/security-architecture.md`](../../docs/security-architecture.md) §6–§8 as one runnable system: the isolation tier ([`../isolation`](../isolation)) and the egress broker ([`../egress-broker`](../egress-broker)) composed. The Docker `--internal` network stands in for the production **no-NIC + vsock** boundary; the topology and guarantees are the same.
