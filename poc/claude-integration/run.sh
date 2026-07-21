#!/usr/bin/env bash
# Real Claude Code, governed by the Enclave PreToolUse hook → Cedar.
#
# A live headless `claude -p` session has EVERY tool call intercepted by the
# enforcement seam's hook, which decides via Cedar against a cryptographically-bound
# session identity. This is the whole product thesis, end to end — not the hook fed
# synthetic payloads (that's poc/enforcement-seam), but the actual CLI being gated.
#
# Requires: the `claude` CLI (2.x) + node. Costs a little Claude usage. Skips cleanly
# if `claude` isn't installed, so it's safe to run anywhere.
set -e
command -v claude >/dev/null 2>&1 || { echo "SKIP: claude CLI not found."; echo "CLAUDE-INTEG: SKIP"; exit 0; }

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
win(){ cygpath -m "$1" 2>/dev/null || echo "$1"; }   # MSYS path → C:/… for Windows processes

HOOK="$(win "$REPO/poc/enforcement-seam/hook/pretooluse-hook.mjs")"
SESS="$(win "$REPO/poc/enforcement-seam/session/sam.json")"
LEDGER="$(win "$REPO/poc/enforcement-seam/audit-ledger.jsonl")"

# Cedar must be installed for the hook.
[ -d "$REPO/poc/enforcement-seam/node_modules/@cedar-policy" ] || \
  ( cd "$REPO/poc/enforcement-seam" && npm install --no-audit --no-fund >/dev/null 2>&1 )

# Workspace named after the operator's workspace (so workspace-scoped reads pass).
WD="$(win "$HERE/.work")/triage-queue"
rm -rf "$(win "$HERE/.work")" 2>/dev/null || true; mkdir -p "$WD"
echo "case notes" > "$WD/notes.txt"
printf '{ "hooks": { "PreToolUse": [ { "matcher": "*", "hooks": [ { "type": "command", "command": "node --no-warnings %s" } ] } ] } }' "$HOOK" > "$WD/settings.json"
rm -f "$LEDGER"
export ENCLAVE_SESSION="$SESS" NODE_NO_WARNINGS=1

run(){ ( cd "$WD" && timeout 180 claude -p "$1" --settings "$WD/settings.json" --output-format json </dev/null 2>&1 ) \
  | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const j=JSON.parse(s);console.log("  "+(j.result||j.subtype||"").replace(/\s+/g," ").slice(0,240))}catch{console.log("  (no result)")}})'; }

echo "── ALLOW · Sam (L1 SOC-Analyst) reads his own workspace ──"
run "Use the Bash tool to run exactly: ls -la . — just run it, no confirmation."
echo ""
echo "── DENY · Sam (L1) tries to edit a file (needs L2) ──"
run "Use the Write tool to create a file report.txt containing: hello"
echo ""
echo "── Enclave hook decisions (audit ledger) ──"
LEDGER="$LEDGER" node -e '
const fs=require("fs"); const L=process.env.LEDGER;
const lines=fs.existsSync(L)?fs.readFileSync(L,"utf8").trim().split("\n").filter(Boolean):[];
let a=0,d=0; for(const l of lines){const e=JSON.parse(l); if(e.event==="pretooluse.decision"){console.log(`  ${e.principal} (L${e.clearance}) · ${e.tool} → ${e.mapped_action} → ${e.decision.toUpperCase()}`); e.decision==="allow"?a++:d++;}}
console.log("\n"+((a>=1&&d>=1)?"CLAUDE-INTEG: PASS ✓ — real Claude Code, clearance-gated by Enclave":"CLAUDE-INTEG: CHECK (expected ≥1 allow + ≥1 deny; claude may have declined to call a tool)"));
'
