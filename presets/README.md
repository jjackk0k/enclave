# Presets — start work in seconds, not hours

Configuring egress, clearance/qualification gates, and writing scope / RoE / checklist docs by hand is exactly the friction that stops a security team adopting a tool. **Presets** turn a few facts about the project into a **ready, correctly-configured, correctly-documented** enclave.

## Use it

```bash
node scaffold.mjs --list         # see presets

node scaffold.mjs --preset red-team --name northwind-q3 \
    --client "Northwind Traders" --scope "10.10.0.0/16,10.20.0.0/24" --lead "M. Vale"
```

That writes a workspace with:
- **`workspace.json`** — the environment config the platform *enforces*: workload class, the clearance + certification the operator must hold, the deny-all egress allowlist (and, for red team, the authorized target scope). This is what the [enforcement seam](../poc/enforcement-seam/) reads.
- **Pre-filled starter docs** — e.g. red team gets a `RULES-OF-ENGAGEMENT.md`, a signed-scope stub `ENGAGEMENT-SCOPE.json`, and a `FINDINGS-REGISTER.md`, all populated with the client, scope, lead, and dates you passed. The operator edits sign-off lines, not blank pages.

## The presets

| Preset | Workload | Gate (clearance + qualification) | Starter docs |
|---|---|---|---|
| `code-review` | Secure code review | L2 | Review scope, threat model, checklist, findings |
| `incident-response` | IR / forensics | L3 + IR cert (GCIH/GCFA/…) | Timeline, case notes, chain of custody |
| `red-team` | Red team ops | L4 + offensive cert (OSCP/OSEP/…) | Rules of engagement, signed scope, findings register |
| `grc-audit` | GRC / compliance | L2 + audit cert (CISA/CISSP/…) | Evidence register, control mapping |

The `requires` and `egress` a preset emits line up with the policy model in the enforcement seam — so a scaffolded workspace is not just documented, it's *governed*: the same clearance/qualification/scope gates the PoC demonstrates apply to it.

## Add your own

Drop a `templates/<id>.mjs` exporting `{ id, title, workload, requires, egress, tools, params, docs }`. `docs` maps a filename to a template string; `{{param}}` tokens are filled from `--param` flags (plus `{{name}}`, `{{date}}`, and `{{scopeJsonArray}}`). No build step, no dependencies.
