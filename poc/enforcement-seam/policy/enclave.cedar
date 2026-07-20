// ─────────────────────────────────────────────────────────────────────────────
//  Enclave — authorization policies (Cedar)
//
//  Cedar is DEFAULT-DENY. A tool call is permitted ONLY if a `permit` below
//  matches. The `principal` is ALWAYS the cryptographically-bound session
//  identity resolved by the PreToolUse hook — never anything the model wrote,
//  never anything inside the tool input. That is the whole point: clearance
//  INFORMS the model, but only these policies AUTHORIZE an action.
// ─────────────────────────────────────────────────────────────────────────────

// P1 — Read source / evidence: any authenticated operator, own workspace only.
permit (
  principal,
  action == Action::"readCode",
  resource
)
when { resource.name == principal.workspace };

// P2 — Edit source: clearance L2+ (analyst tier), own workspace only.
permit (
  principal,
  action == Action::"editCode",
  resource
)
when { principal.clearance >= 2 && resource.name == principal.workspace };

// P3 — Destructive filesystem ops (rm -rf, format, force-push, DROP TABLE):
//      clearance L3+ (senior / IR), own workspace only.
permit (
  principal,
  action == Action::"deleteFiles",
  resource
)
when { principal.clearance >= 3 && resource.name == principal.workspace };

// P4 — Credential rotation: clearance L3+ AND an incident-response role,
//      own workspace only.
permit (
  principal,
  action == Action::"rotateCredentials",
  resource
)
when {
  principal.clearance >= 3 &&
  principal.role == "IR-Analyst" &&
  resource.name == principal.workspace
};

// P5 — Offensive network scan: clearance L4+ AND the target address is inside
//      the signed engagement scope (the hook computes `context.inScope` from the
//      session's Rules-of-Engagement CIDRs; the model cannot set it).
permit (
  principal,
  action == Action::"networkScan",
  resource
)
when { principal.clearance >= 4 && context.inScope == true };

// P6 — Exploit / high-risk offensive action: everything P5 requires, PLUS an
//      explicit human approval. With no approval the request falls through to
//      the default DENY and the PEP raises an approval request (human-in-the-loop).
permit (
  principal,
  action == Action::"exploit",
  resource
)
when {
  principal.clearance >= 4 &&
  context.inScope == true &&
  context.approved == true
};
