# PoC — the isolation layer (Phase 1 spine)

The identity/authorization brain is proven in [`../enforcement-seam`](../enforcement-seam). This is the other half a buyer scrutinizes: **where the AI actually runs**. It's the Phase-1 spine, runnable today —

```
provision an isolated sandbox → gate every tool call at the real PEP →
run allowed work INSIDE the sandbox → block disallowed work before it runs →
tear down (wipe) → everything audited.
```

## Honest note on Firecracker

Real Firecracker isolation needs a **KVM host** (bare-metal / nested-virt Linux) — it can't run on Windows or macOS. So the sandbox manager is **provider-abstracted** and auto-selects the strongest tier available:

| Tier | Isolation | Egress denied (kernel) | Runs where |
|---|---|---|---|
| `firecracker` | hardware microVM (KVM) + jailer | ✅ (no NIC, vsock only) | **production** Linux/KVM hosts |
| `docker` | namespaces + seccomp (`--network none`, read-only, cap-drop) | ✅ | anywhere Docker runs |
| `local-process` | ephemeral dir + scrubbed env | ❌ (dev only) | **anywhere, incl. Windows** |

The Firecracker provider ships its real config (jailer args, microVM config, vsock egress) in [`providers/firecracker.mjs`](providers/firecracker.mjs); it's guarded to KVM hosts and the manager falls back automatically.

## Run it

```bash
# once: the demo reuses the enforcement seam's real Cedar PEP
cd ../enforcement-seam && npm install && cd -
npm run demo
```

Real output on this (Windows, Docker off) machine — the process tier:

```
  what each tier enforces          (★ = the tier running now)
  property                ★ local-process   docker   firecracker
  ephemeral filesystem      true            true     true
  secrets scrubbed          true            true     true
  egress denied (kernel)    false           true     true
  isolation                 none            namespaces+seccomp   hardware VM (KVM)

  1) provisioned  session sess-1003 · <ephemeral dir> · local-process

  2a) allowed work    dana (L3) · "ls -la ./evidence"   → ALLOW → ran in sandbox
       wrote a file in the ephemeral dir: yes   sandbox can see the ANTHROPIC key: no (scrubbed ✓)

  2b) disallowed work dana (L3) · "nmap -sS 10.10.5.20" → DENY
       executed in sandbox: no (gate precedes execution ✓)
       blocked: network scan requires clearance ≥ L4. …decided against the bound identity.

  3) teardown  sandbox destroyed, state wiped: yes
  audit ledger: 4 hash-chained entries, integrity verified ✓
```

Start Docker Desktop and re-run: the manager auto-upgrades to the **container tier** with real kernel-enforced `--network none` egress deny — no code change.

## What it proves

- **The spine is real, not a diagram** — provision → PEP gate → isolated exec → teardown → audit, all wired.
- **The gate lives outside the sandbox** — `exec()` spawns the *actual* enforcement-seam PreToolUse hook (real Cedar) and only runs the tool if it's allowed; a denied call **never reaches the provider**.
- **Secrets don't enter the sandbox** — a credential planted in the parent environment is invisible to the in-sandbox process (scrubbed at the process tier; never passed in at the container tier).
- **Sandboxes are ephemeral** — teardown wipes; nothing persists across sessions.
- **One abstraction, three tiers** — the same spine gets stronger isolation by swapping providers, no caller changes.

## How it connects

- Uses the real PEP from [`../enforcement-seam`](../enforcement-seam) — identity + Cedar policy + qualification gates, unchanged.
- A [preset](../../presets)'s `workspace.json` (workload class + egress allowlist + scope) is exactly what drives provider config in production: code-review → no-NIC + proxy; red-team → scoped-CIDR egress.
- Matches [`docs/security-architecture.md`](../../docs/security-architecture.md) §6 (isolation) and §7 (egress).

## Honest scope

The **process tier is dev-only** — it scopes the filesystem and scrubs secrets but does **not** provide kernel network/FS isolation. Real containment is the **Docker** tier (runnable when the daemon is up) and the **Firecracker** tier (production). Snapshot restore, dm-crypt scratch, and the vsock egress proxy from the architecture doc are the next build on top of this spine.
