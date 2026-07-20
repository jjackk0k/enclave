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
| `hyperv` | hardware VM (Hyper-V), per session | ✅ | Windows **Pro/Enterprise** hosts |
| `docker` | namespaces + seccomp (`--network none`, read-only, cap-drop) | ✅ | anywhere Docker runs (incl. Windows, via its Linux VM) |
| `local-process` | ephemeral dir + scrubbed env | ❌ (dev only) | **anywhere, incl. Windows Home** |

Each provider ships its real config and is guarded to hosts that support it; the manager falls back automatically (VM → container → process).

### "Can Firecracker run on Windows?"

No — Firecracker is built on **KVM**, a Linux-kernel feature, so it's Linux-only by design and there's no Windows port. The Windows-native equivalent is **Hyper-V** (see [`providers/hyperv.mjs`](providers/hyperv.mjs)), which needs Windows **Pro/Enterprise**. The practical point on a Windows dev box: the **`docker` tier already runs containers inside a real Linux VM** (Docker Desktop's WSL2 backend), so you get genuine Linux-kernel isolation — `--network none`, namespaces, seccomp — on Windows today. **Production hosts are Linux + Firecracker regardless.**

## Run it

```bash
# once: the demo reuses the enforcement seam's real Cedar PEP
cd ../enforcement-seam && npm install && cd -
npm run demo
```

Real output on the **container tier** (Docker running — auto-selected, no code change):

```
  what each tier enforces          (★ = the tier running now)
  property                  local-process   ★ docker   firecracker
  ephemeral filesystem      true            true       true
  secrets scrubbed          true            true       true
  egress denied (kernel)    false           true       true
  isolation                 none            namespaces+seccomp   hardware VM (KVM)

  1) provisioned  session sess-1003 · enclave-sess-1003 · docker

  2a) allowed work    dana (L3) · "ls -la ./evidence"   → ALLOW → ran in sandbox
       in-sandbox cwd: /work
       wrote a file in the ephemeral dir: yes   sandbox can see the ANTHROPIC key: no (scrubbed ✓)

  2b) disallowed work dana (L3) · "nmap -sS 10.10.5.20" → DENY
       executed in sandbox: no (gate precedes execution ✓)

  2c) egress from inside the sandbox   connect 1.1.1.1:443 → BLOCKED (ENETUNREACH) ✓  ← kernel-enforced --network none

  3) teardown  sandbox destroyed, state wiped: yes
  audit ledger: 4 hash-chained entries, integrity verified ✓
```

With Docker stopped, the same command falls back to the **process tier** (dev-only: ephemeral dir + scrubbed env, but no kernel-enforced egress) — no code change either way.

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
