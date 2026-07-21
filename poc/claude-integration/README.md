# PoC — real Claude Code, governed by Enclave

This is the whole product thesis, running: a **live headless Claude Code session** whose **every tool call is intercepted by the Enclave hook and decided by Cedar** against a cryptographically-bound identity. Not the hook fed synthetic payloads (that's [`../enforcement-seam`](../enforcement-seam)) — the *actual CLI*, gated.

## Run it *(requires the `claude` CLI + node)*

```bash
bash run.sh          # skips cleanly if `claude` isn't installed
```

Real output:

```
── ALLOW · Sam (L1 SOC-Analyst) reads his own workspace ──
  The current directory contains two files: - notes.txt (11 bytes) - settings.json (200 bytes)

── DENY · Sam (L1) tries to edit a file (needs L2) ──
  The write was blocked by an access control system. The error indicates that editing files
  in the `triage-queue` directory requires clearance level L2 or higher, but the current
  identity (sam, L1 SOC-Analyst) only has L1 clearance.

── Enclave hook decisions (audit ledger) ──
  sam (L1) · Bash  → readCode  → ALLOW
  sam (L1) · Write → editCode  → DENY

CLAUDE-INTEG: PASS ✓ — real Claude Code, clearance-gated by Enclave
```

The denial text is **Claude reporting the Enclave hook's own Cedar decision** back to the user — the operator's `ls` runs, but their `Write` is blocked because the bound identity is L1 and editing needs L2.

## What it proves

- **"Auto-attaches to Claude CLI" is real.** A `PreToolUse` hook (via `--settings`) routes every tool call to the enforcement seam before it executes.
- **Enforcement is against the bound identity, not the prompt.** `ENCLAVE_SESSION` names the signed session; the hook decides via Cedar on *that* identity. Sam can't talk his way to L2.
- **Allowed work still flows.** `ls` (readCode, own workspace) runs normally — the gate permits, it doesn't just block everything.
- **Everything is logged.** Each decision lands in the tamper-evident audit ledger (see [`../audit-anchor`](../audit-anchor)).

## How it works

`run.sh` writes a `settings.json` that wires the real hook:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "*",
  "hooks": [ { "type": "command", "command": "node --no-warnings <…>/pretooluse-hook.mjs" } ] } ] } }
```

then launches `claude -p "<task>" --settings settings.json` with `ENCLAVE_SESSION` set to the operator's signed session, in a workspace-named directory. The hook classifies each call, asks Cedar (in-process, or the networked PDP via `ENCLAVE_PDP_URL`), and returns `permissionDecision: allow | deny` — which Claude Code honours.

## Not in `npm test`

This spends a little Claude usage and needs the `claude` CLI, so it's a run-on-demand demo (it self-skips if `claude` is absent) rather than a CI proof. The *mechanism* it exercises is CI-verified in [`../enforcement-seam`](../enforcement-seam) (the same hook, 20 scenarios).
