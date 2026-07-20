# PoC — tool-forge (build tools for Linux + Windows, isolated)

Answers a real question: *is Enclave good for people building new / red-team tooling, on both Windows and Linux?* This builds a security tool for **both** targets **inside a sealed, no-network container** — the tool-dev workload made concrete.

## Run it *(requires Docker)*

```bash
npm run demo
```

Real output:

```
  built inside a sealed --network none container (offline, GOPROXY=off, read-only root):
     Linux target    → portcheck-linux          2995964 bytes · magic 7f454c46 (ELF ✓)
     Windows target  → portcheck-windows.exe    3161088 bytes · magic 4d5a (PE / MZ ✓)
  TOOL-FORGE: PASS ✓
```

The magic bytes prove it: `7f454c46` is a Linux **ELF**, `4d5a` (`MZ`) is a Windows **PE** — two real binaries for two operating systems, from one source tree.

## What it shows about the platform

- **Yes for tool development.** An operator can write, compile, and cross-compile tooling entirely inside the enclave.
- **Windows *and* Linux, honestly.** The enclave is Linux-based, so it builds Linux tools natively and **cross-compiles Windows targets** (here via Go `GOOS=windows`; mingw-w64 / .NET cross-build cover C/C++/.NET). *Running/testing* the Windows binary uses the Windows isolation tier ([`../isolation/providers/hyperv.mjs`](../isolation/providers/hyperv.mjs)).
- **Built in isolation.** `--network none` + `--read-only` root + `--cap-drop ALL` + `GOPROXY=off` — the build needs no egress and can't touch the host. Real dependencies would come from the **allowlisted package registries** in the `tool-dev` preset ([`../../presets/templates/tool-dev.mjs`](../../presets/templates/tool-dev.mjs)).
- **The guardrails still apply.** Building is gated to L4 + an offensive/exploit-dev cert; *using* the finished tool against a target stays gated at runtime (offensive cert + signed, in-scope target). A tool built here can't be pointed off-scope.

Scaffold a tool-dev workspace with `node ../../presets/scaffold.mjs --preset tool-dev --name <tool> --tool <name> --purpose "…" --lead "…"`.
