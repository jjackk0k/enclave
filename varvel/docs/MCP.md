# VARVEL × MCP — Model Context Protocol adoption, with the governance bridge

VARVEL now speaks MCP (Model Context Protocol — JSON-RPC 2.0, newline-delimited over
stdio) in **both directions**, and both directions ride the **same governance bridge**.
That bridge — not the protocol — is the point of this build: MCP is how the wider
agent ecosystem talks, and VARVEL's answer is to adopt the wire *without* adopting the
trust. Every MCP call, inbound or outbound, is classified against the signed scope and
the egress allowlist, checked against ghost posture, and written to the audit ledger
**before** anything executes.

```
 inbound  (A): MCP client ──► tools/mcpserve.mjs ──► BRIDGE ──► VARVEL's governed tools
 outbound (B): VARVEL ──────► engine/mcpclient.mjs ─► BRIDGE ──► external MCP server (child)
                                   │
                    engine/mcpgov.mjs — one choke-point:
                    classify(call) -> allow | hold | deny
```

## What each direction gives

**Direction A — VARVEL as an MCP server** (`tools/mcpserve.mjs`). Any MCP-speaking
client (Claude, an IDE, another agent) can call a curated set of VARVEL tools. This is
the *same governed tool surface the AI itself gets* — not a raw CLI passthrough. Each
exposed tool declares a governance policy, and the bridge enforces it: an MCP client
that asks `varvel_webscan` to hit an out-of-scope host gets a `DENIED` tool result,
the tool never runs, and the refusal is in the ledger.

**Direction B — VARVEL as an MCP client** (`engine/mcpclient.mjs`). VARVEL's AI can
consume the community MCP ecosystem (the 40+ tool advantage). External servers are
**powerful and UNTRUSTED**, so the seam is the price:

- They are **never auto-discovered**. The only source is an operator-written JSON
  registry naming each server by **absolute path**.
- `mcp.allowExternal=false` (the default) refuses to even **spawn** one — spawning a
  community server *is* executing untrusted code, so the setting gates the spawn.
- Every call's target arguments are extracted and classified **before dispatch**: a
  call naming an out-of-scope host is denied before the child sees it — with lazy
  spawn, before the child process exists at all.
- Timeouts reap the child (a wedged external server is distrusted, not waited on),
  and every client method returns `{ ok:false }` instead of throwing — a crashed
  community server can never take the platform down with it.

## The bridge doctrine (`engine/mcpgov.mjs`)

`judgeCall(ctx) -> { verdict, reason, targets }` — pure, total, never throws:

| verdict | meaning | resolution |
|---|---|---|
| `allow` | run/dispatch now | — (audited) |
| `hold`  | not forbidden, but needs an operator — the platform's existing hold pattern | operator surfaces the target into scope and re-issues; audited either way |
| `deny`  | final | none — do not rephrase to get past it (audited) |

Classification reuses the Enclave enforcement seam's logic directly:

- **IP-literal targets** are checked against the **signed CIDR ring** with the same
  strict `engine/ipaddr.mjs` parser the seam imports (`inAnyCidr`, v4 **and** v6,
  family-strict, fail-closed). Out-of-scope IP ⇒ `deny`.
- **Hostname targets** must have been **surfaced by the engagement** (the state
  store's known hosts — the campaign validate gate's exact rule). An unsurfaced
  hostname is not forbidden outright: inbound calls `hold` for the operator.
- **Public egress** (direction B) honors the seam's research allowlist
  (`poc/enforcement-seam/egress-allowlist.mjs` — `hostAllowed`): allowlisted research
  hosts are governed egress; any other public host ⇒ `deny`.
- **Ghost posture**: with `ghost.mode=required` and the identity chain unverified,
  target-touching calls `deny` (fail-closed) while read-only tools still answer.
- **Tool-level policy**: every exposed tool declares `read-only` or
  `target-touching` (plus which argument fields name targets). A target-touching
  call with no legible target fails closed (inbound `deny`; outbound `hold` — an
  unclassifiable external call is never dispatched blind).
- Target extraction is debris-proof the same way the seam is: URLs go through the
  seam's `extractHost` (userinfo/port/bracket/shell-debris stripping); bare
  `host:port` and `[v6]:port` are normalized before any scope math.

**The audit ledger** (`data/mcp-audit.jsonl`, append-only JSONL,
`VARVEL_MCP_AUDIT_FILE` to relocate): every call lands as
`{ at, kind:'mcp.call', direction, server, tool, argsDigest:'sha256:…', argsPreview,
verdict, reason, targets }`. The args ride as a **digest + a redacted, capped
preview** — secret-class values (`token`, `secret`, `password`, `api_key`, …) are
`[REDACTED]` before the preview is even built. The ledger proves governance happened;
it never becomes a credential store.

## Exposed tools (direction A) and their policies

| MCP tool | wraps | policy | targets |
|---|---|---|---|
| `varvel_ghost_status` | settings ghost posture | read-only | — |
| `varvel_state_query` | `engine/statestore` counts + redacted listing | read-only | — |
| `varvel_recon` | `tools/recon.mjs scanHost` | target-touching | `host` |
| `varvel_webscan` | `tools/webscan.mjs webScan` | target-touching | `url` |
| `varvel_apisurface` | `tools/apisurface.mjs apiSurface` | target-touching | `url` |
| `varvel_crawl` | `tools/crawl.mjs crawl` | target-touching | `url` |
| `varvel_tlsscan` | `tools/tlsscan.mjs analyzeTls` | target-touching | `host` |

## Configuration

Settings (`POST /api/settings` or the console):

```
mcp.serverEnabled   (bool, default false)  — direction A: serve governed tools over stdio
mcp.allowExternal   (bool, default false)  — direction B: permit operator-configured external servers
```

Run the server (a direct operator launch is itself the enable, or set
`mcp.serverEnabled=true` for programmatic spawns):

```sh
node tools/mcpserve.mjs                     # stdio, newline-delimited JSON-RPC
VARVEL_MCP_SCOPE=192.168.50.0/24 node tools/mcpserve.mjs
```

Scope resolution is fail-closed: `VARVEL_MCP_SCOPE` (explicit) → the signed Enclave
session's engagement scope → **standalone fallback `127.0.0.0/8` only** (loopback —
the demo's ring, mirroring the console). Ghost verification is handed in as
`VARVEL_GHOST_VERIFIED=1` by whatever verified the chain.

External server registry (`data/mcp.servers.json`, `VARVEL_MCP_SERVERS` to relocate):

```json
{
  "servers": [
    {
      "name": "community-fs",
      "command": "C:\\abs\\path\\to\\server.mjs",
      "args": ["--readonly"],
      "env": {},
      "timeoutMs": 20000
    }
  ]
}
```

`command` **must** be an absolute path or the entry is skipped with a named error.
The child receives a minimal environment allowlist (PATH/SystemRoot/HOME/… + the
entry's own `env`), never the operator's whole credential-laden environment.

Protocol pin: `2025-06-18` native; `2025-03-26` and `2024-11-05` accepted (the older
tool-result shape is a subset of what VARVEL emits — plain `content` blocks ride every
response regardless). Unknown client versions get VARVEL's pinned version back, per
the spec's negotiation rule.

## Honest limits (this wave)

- **stdio transport only.** No SSE / HTTP transport yet — MCP clients that speak
  only streamable-HTTP cannot reach direction A this wave.
- **Tools only.** No MCP resources, prompts, or roots; `capabilities` advertises
  exactly `tools` and nothing more.
- **Top-level target fields.** The bridge reads targets from top-level string
  arguments (`url`, `uri`, `endpoint`, `target`, `host`, `hostname`, `domain`, `ip`,
  `baseUrl` for external calls; each VARVEL tool's declared fields inbound). A server
  that hides its target in nested structures defeats extraction — which is why
  *unclassifiable* outbound calls `hold` instead of dispatching.
- **Hostname scope needs the engagement's memory.** Inbound hostname targets are
  judged against what the engagement state store has surfaced; a fresh standalone
  server holds every bare hostname for the operator (use IP targets or surface the
  host first).
- **The bridge classifies; it does not sandbox.** Direction B executes an
  operator-configured local binary with a minimal env — the OS user account is the
  containment boundary, exactly as for any tool the operator installs.
- Governance refusals are returned as MCP tool results (`isError: true`) — the
  protocol exchange succeeded; the *action* was refused. Clients that retry forever
  against a `deny` are wasting their own turns: a denial is final for the session.
