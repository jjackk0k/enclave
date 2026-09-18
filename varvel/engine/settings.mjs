// VARVEL — per-engagement settings engine v1 (the RedAmon 500+ engine's honest seed).
//
// A validated settings store: a SCHEMA (types, ranges, enums, labels), a per-engagement
// registry, and campaign consumption as DEFAULTS (explicit options always win — settings
// are the floor, never an override the operator didn't see). Every set is validated or
// rejected; unknown keys are refused outright. This is how VARVEL grows per-engagement
// knobs without turning into an ungoverned grab-bag.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SETTINGS_SCHEMA = {
  'stealth.profile':     { type: 'enum', values: ['auto', 'loud', 'normal', 'quiet', 'paranoid', 'off'], default: 'auto', label: 'Default operational-stealth profile' },
  'stealth.autoThrottle':{ type: 'bool', default: true, label: 'OPSEC watchdog auto-throttles at critical noise' },
  'recon.maxPages':      { type: 'int', min: 1, max: 200, default: 25, label: 'Crawler page budget per host' },
  'recon.maxProbes':     { type: 'int', min: 3, max: 60, default: 20, label: 'Vulncheck request budget per host' },
  'agent.maxTurns':      { type: 'int', min: 4, max: 80, default: 40, label: 'Max governed tool turns per chat message' },
  'agent.effort':        { type: 'enum', values: ['low', 'medium', 'high'], default: 'high', label: 'Default Kimi reasoning effort' },
  'notify.onComplete':   { type: 'bool', default: false, label: 'Notify when a campaign completes' },
  'ghost.mode':          { type: 'enum', values: ['off', 'on', 'required'], default: 'off', label: 'Ghost Mode: identity-stealth transport (required = fail-closed until verified)' },
  'ghost.chain':         { type: 'string', default: '', label: 'Proxy chain (comma-separated http(s):// or socks5:// URLs, in order)' },
  'ghost.checkUrl':      { type: 'string', default: 'https://api.ipify.org?format=json', label: 'Echo endpoint used to verify the chain exit IP' },
  'ghost.expectExit':    { type: 'string', default: '', label: 'Expected ghost exit IP — pin ONE Mullvad server for clearance-class ops (empty = unpinned; env VARVEL_GHOST_EXPECT_EXIT also honored)' },
  'ghost.pinStrict':     { type: 'bool', default: false, label: 'Exit-pin enforcement: expected-exit mismatch makes the egress check FAIL-CLOSED (default off = loud warning)' },
  'validator.staleDays': { type: 'int', min: 0, max: 3650, default: 30, label: 'Validated findings older than this many days render as STALE (0 = never stale)' },
  'exec.inMemory':       { type: 'bool', default: false, label: 'In-memory execution tier (inline-dotnet task kind) — default OFF; the engagement must explicitly enable governed in-memory .NET execution' },
  // EVASION INTERNALS TIER (stage 1, doctrine 2026-08-12): governed, own-process-only
  // AMSI/ETW neutralization for the PS range agent — default OFF, double-gated (this
  // setting AND the agent's launch flag), patch-verified, restorable, detoracle-measured.
  'exec.evasion':        { type: 'bool', default: false, label: 'Evasion internals tier stage 1 (evasion-enable/-restore/-status task kinds) — default OFF; the engagement must explicitly enable governed own-process AMSI/ETW patching' },
  // GOVERNED PERSISTENCE TIER (roadmap #8): standard user-land persistence for the
  // Windows range agent (HKCU Run-key / user-context on-logon scheduled task / startup-
  // folder shortcut) — default OFF, double-gated (this setting AND the agent's launch
  // flag -AllowPersist / --persist 1), with MANDATORY CLEANUP-PROOF: install snapshots
  // pre-install state and verifies by re-read, remove verifies ABSENCE by re-read (a
  // removal that cannot verify is a loud escalated failure), and the engagement sweep
  // refuses to call the engagement clean while unverified persistence exists.
  'persist.enabled':     { type: 'bool', default: false, label: 'Governed persistence tier (persist-install/-status/-remove/-audit task kinds) — default OFF; the engagement must explicitly enable cleanup-proof user-land persistence' },
  // SIGNED-PROXY EXECUTION TIER (engine/execproxy.mjs — the governed answer to
  // application allowlisting): run the agent's DLL form through Microsoft-signed
  // hosts (rundll32-class direct load, regsvr32-class load-only, sideload-class
  // search-order plant — copies into the governed sandbox ONLY, never in place).
  // default OFF, double-gated (this setting AND the agent's -AllowProxyExec /
  // --proxy 1 flag), sha256-audited for every file planted/executed, with the
  // persist-tier cleanup-proof discipline (no silent clobber, removal verified by
  // re-read, assessExecProxyClean refuses 'clean' while unverified plants exist).
  'exec.proxy':          { type: 'bool', default: false, label: 'Signed-proxy execution tier (execproxy-run/-remove/-status task kinds) — default OFF; the engagement must explicitly enable governed execution through Microsoft-signed host binaries' },
  // GOVERNED AD TIER (roadmap lose-point #3 — a company-PC breach is an AD
  // engagement). Three rungs, each default OFF, each double-gated (the setting
  // AND the agent's own launch flag), fully audited, cleanup-proof, and
  // edrview-paired (the capability is MEASURED against the hardened range,
  // never claimed). See docs/AGENT-GUIDE.md "The governed AD tier".
  'ad.roast':            { type: 'bool', default: false, label: 'AD roast collectors (adroast-enum/-kerberoast/-asrep task kinds) — default OFF; SPN/DONT_REQ_PREAUTH collection + hashcat-ready formatting (cracking stays OFFLINE operator-side); DC must sit inside the signed CIDR ring' },
  'ad.lateral':          { type: 'bool', default: false, label: 'Lateral exec adapters (lateral-exec/-remove/-status: wmi, winrm, psexec-class) — default OFF; scope-checked IP-literal targets only, artifact manifest with cleanup-proof verified removal' },
  'cred.access':         { type: 'bool', default: false, label: 'Credential access — LSASS via comsvcs MiniDump (cred-dump/-remove/-status) — default OFF; dump stays in the governed sandbox, sha256+marker audited, edrview pairing MANDATORY' },
  // PER-HOP ENVELOPE ENCRYPTION (engine/envelope.mjs — AEAD-sealed wire envelope
  // CONTENT, end-to-end agent↔listener, opaque to relay parents on the pivot mesh).
  // off = layer disabled (sealed content refused loudly); preferred = backward-compat
  // migration mode: plaintext-only agents keep working, capability-flagged agents
  // (ec:1) ratchet to sealed and plaintext from them is then refused as a downgrade;
  // required = plaintext is refused loudly (the fleet-enforcement end state — flip
  // once every fielded agent is enc-capable). The wire denial stays 204-uniform.
  'enc.mode':            { type: 'enum', values: ['off', 'preferred', 'required'], default: 'preferred', label: 'Envelope encryption mode (engine/envelope AEAD layer) — preferred = mixed fleets degrade honestly; required = plaintext refused loudly' },
  // Cloud/SaaS API C2 (engine/ghc2.mjs — the GitHub gist dead-drop transport 'ghc').
  // TOKEN DOCTRINE: ghc2.token is a BURNER account's fine-grained PAT (gist scope only),
  // operator-supplied at engagement time — NEVER the operator's real account, NEVER
  // committed, NEVER logged. secret:true = the API/console render presence only.
  'ghc2.enabled':        { type: 'bool', default: false, label: 'Cloud/SaaS C2 via GitHub gist dead-drop (transport ghc) — default OFF; the engagement must explicitly opt in' },
  'ghc2.token':          { type: 'string', default: '', secret: true, label: 'GitHub BURNER-account fine-grained PAT (gist scope) — secret-class: rendered presence-only, never the value' },
  'ghc2.repo':           { type: 'string', default: '', label: 'ghc dead-drop mailbox: the SECRET (unlisted) gist id owned by the burner account' },
  'ghc2.intervalSec':    { type: 'int', min: 30, max: 3600, default: 60, label: 'ghc mailbox poll cadence (seconds) — SLOW by default: low-and-slow tasking, never interactive shells (GitHub ≈5k req/hr/token)' },
  // STEGANOGRAPHY CHANNEL (engine/stegocodec.mjs — the image-carried fallback wire 'stg').
  // Task/result envelopes ride LSB-embedded INSIDE innocuous PNG images served from the
  // channel listener. LOW bandwidth, HIGH latency — the last-resort 443-image-blend
  // fallback, never a primary wire. Content cover only; size/timing side-channels are
  // documented in docs/AGENT-GUIDE.md (no traffic-analysis immunity is claimed).
  'stg.enabled':         { type: 'bool', default: false, label: 'Steganography image channel (transport stg) — default OFF; the engagement must explicitly opt in' },
  'stg.profile':         { type: 'enum', values: ['gradient', 'flat', 'noise'], default: 'gradient', label: 'stg cover-image scene class (seeded per serve; identical envelopes never byte-repeat)' },
  // LISTENER UPSTREAM PROXY (engine/callback.mjs — operator directive): ONE proxy that the
  // listener's OWN upstream legs (today: the ghc SaaS mailbox poll) ride. http:// or
  // socks5h:// ONLY (the 'h' = the PROXY resolves names — a stealth listener never resolves
  // a SaaS name locally). Empty = direct (the byte-identical default). FAIL-CLOSED: a
  // configured-but-malformed value refuses channel construction with a named
  // UpstreamProxyError, and a configured-but-unreachable proxy fails the leg with the same
  // named error — NEVER a silent direct fallback (a stealth configuration must not leak).
  // Precedence: constructor option > env VARVEL_UPSTREAM_PROXY > this setting.
  'channel.upstreamProxy':{ type: 'string', default: '', label: 'Listener upstream proxy (http:// or socks5h:// URL; empty = direct) for the channel\'s own upstream legs — fail-CLOSED when configured but unreachable' },
  // C2 SHAPING PACK (engine/malleable v2 + engine/shapegrade): per-engagement wire-shape
  // application. ALL defaults are off/'plain' — with defaults, the wire is byte-identical
  // to before the pack. Applied per agent via the cli `shape` command (which reads these
  // as the engagement floor when no explicit profile is passed).
  'shape.profile':       { type: 'enum', values: ['plain', 'cdn-asset', 'software-update', 'telemetry-beacon'], default: 'plain', label: 'Wire-shape profile applied per agent (plain = today\'s unshaped wire, byte-identical)' },
  'shape.batchWindowMin':{ type: 'int', min: 0, max: 720, default: 0, label: 'Batch/dwell window in minutes (0 = off): held tasks flush in ONE burst at a seeded point inside each window (minutes→hours)' },
  'shape.padding':       { type: 'bool', default: false, label: 'Constant-rate dummy envelopes (default OFF) — busy and idle windows emit the same request count; multiplies request volume (honest cost)' },
  'shape.padRate':       { type: 'int', min: 2, max: 8, default: 2, label: 'Envelopes per check-in cycle when shape.padding is on (1 real + N-1 dummies, audited as agent.pad)' },
  // TLS-INSPECTION DETECTION + POLICY (engine/tlsinspect + tools/tlsinspect — lose-point
  // #5: enterprise egress does SSL-bump; VARVEL DETECTS it against a reference set and
  // DECIDES deliberately). policy: 'fail-closed' (default — direct TLS wires http/doh/ws
  // refuse under inspection; nothing leaks), 'adapt' (failover ranking deprioritizes
  // direct wires and elevates inspection-tolerant ones — ghc/stg/dns/icmp), 'ignore'
  // (operator override — warns loudly). Adaptation changes which WIRE we ride, never
  // claims the inspection away: ghc/stg are inspection-COMPATIBLE, not inspection-proof.
  'tlsinspect.policy':   { type: 'enum', values: ['fail-closed', 'adapt', 'ignore'], default: 'fail-closed', label: 'TLS-inspection posture policy — fail-closed: direct wires refuse under SSL-bump; adapt: failover ranking elevates inspection-tolerant wires; ignore: operator override (loud)' },
  'tlsinspect.refs':     { type: 'string', default: 'api.github.com,www.microsoft.com', label: 'TLS-inspection reference set (comma-separated host[:port]) — well-known SaaS domains probed for SSL-bump; our own listener is added by the operator when wanted' },
  // MCP ADOPTION (roadmap #6 — engine/mcprpc + engine/mcpgov + tools/mcpserve +
  // engine/mcpclient; docs/MCP.md). Both directions default OFF; every call crosses
  // the governance bridge and lands in the audit ledger (data/mcp-audit.jsonl).
  // MCP ADOPTION (roadmap #6 — engine/mcprpc + engine/mcpgov + tools/mcpserve +
  // engine/mcpclient; docs/MCP.md). Both directions default OFF; every call crosses
  // the governance bridge and lands in the audit ledger (data/mcp-audit.jsonl).
  'mcp.serverEnabled':   { type: 'bool', default: false, label: 'MCP server (direction A): expose governed VARVEL tools over stdio JSON-RPC — every call rides the governance bridge' },
  'mcp.allowExternal':   { type: 'bool', default: false, label: 'MCP client (direction B): allow operator-configured EXTERNAL MCP servers (absolute path, never auto-discovered; calls classified vs scope + egress allowlist pre-dispatch)' },
  // AUTO-REMEDIATION PR LOOP (roadmap #7 — engine/remediate.mjs record lifecycle +
  // tools/rempr.mjs remote leg; docs/REMEDIATE.md). Double-gated, both default OFF.
  // A PR is NEVER opened autonomously: the loop produces a local patch + PR DRAFT;
  // the operator's explicit `remediate open-pr <id>` is the ONLY push/open path.
  // TOKEN DOCTRINE mirrors ghc2: remediate.ghToken is a BURNER account's PAT (repo
  // scope), operator-supplied at engagement time — NEVER the operator's real
  // account, NEVER committed, NEVER logged (secret:true renders presence-only).
  'remediate.prEnabled':  { type: 'bool', default: false, label: 'Auto-remediation PR loop: draft/patch/verify legs for VALIDATED findings only — default OFF; the engagement must explicitly opt in' },
  'remediate.remoteAllow':{ type: 'bool', default: false, label: 'Remediation REMOTE leg (git push + PR open against the client repo) — a SECOND, separate gate beyond remediate.prEnabled; default OFF' },
  'remediate.ghToken':    { type: 'string', default: '', secret: true, label: 'GitHub BURNER-account PAT for remediation PRs (repo scope) — secret-class: rendered presence-only, never the value; NEVER the operator\'s real account' },
  // BRAIN PROVIDER (engine/brain-provider.mjs — the LOCAL-MODEL seam, e.g. a DGX Spark
  // serving Qwen3-class / gpt-oss-120b over an OpenAI-compatible endpoint). ADDITIVE:
  // every default is the Kimi status quo — with defaults, the brain path is byte-identical
  // to before. TOKEN DOCTRINE: brain.apiKeyEnv names the ENV VAR holding the endpoint key
  // (local servers usually need none), NEVER the key itself — the value is resolved from
  // the environment at call time and is never logged or rendered.
  'brain.provider':       { type: 'enum', values: ['kimi', 'openai-compatible'], default: 'kimi', label: 'Agent-brain provider — kimi (default, unchanged) or an OpenAI-compatible local endpoint (vLLM / llama.cpp server)' },
  'brain.baseUrl':        { type: 'string', default: '', label: 'OpenAI-compatible base URL (e.g. http://spark:8000/v1) — required when brain.provider is openai-compatible' },
  'brain.model':          { type: 'string', default: '', label: 'Model id the local endpoint serves (e.g. qwen3-32b, gpt-oss-120b) — required when brain.provider is openai-compatible' },
  'brain.apiKeyEnv':      { type: 'string', default: '', label: 'NAME of the env var holding the endpoint key (empty = no auth header — the common local case); the key VALUE never enters config' },
  'brain.timeoutMs':      { type: 'int', min: 0, max: 600000, default: 0, label: 'Per-call inactivity ceiling for the local brain in ms (0 = off, same semantics as VARVEL_KIMI_CALL_TIMEOUT_MS)' },
};

// Persistence (2026-08-05 — root-caused by Jack's "it says off but I think it's on"): the
// registry used to be memory-only, so EVERY restart silently wiped ghost.mode/chain,
// stealth.profile, budgets. Settings now write through to varvel/data/settings.json and
// lazy-load back (validated on load; corrupt files and unknown/invalid keys are dropped
// honestly, never thrown on the boot path).
const FILE = () => process.env.VARVEL_SETTINGS_FILE || join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'settings.json');
function loadAll() { try { return JSON.parse(readFileSync(FILE(), 'utf8')); } catch { return {}; } }
function saveAll(obj) { try { mkdirSync(dirname(FILE()), { recursive: true }); writeFileSync(FILE(), JSON.stringify(obj, null, 2)); } catch {} }

const registry = new Map(); // engagement -> Settings

function validate(key, value) {
  const spec = SETTINGS_SCHEMA[key];
  if (!spec) throw new TypeError('unknown setting: ' + key);
  switch (spec.type) {
    case 'bool': return value === true || value === 'true' || value === 1 || value === '1';
    case 'int': {
      const n = Math.floor(Number(value));
      if (!Number.isFinite(n)) throw new TypeError(key + ' must be a number');
      if (spec.min != null && n < spec.min) throw new RangeError(key + ' must be ≥ ' + spec.min);
      if (spec.max != null && n > spec.max) throw new RangeError(key + ' must be ≤ ' + spec.max);
      return n;
    }
    case 'enum':
      if (!spec.values.includes(String(value))) throw new TypeError(key + ' must be one of ' + spec.values.join(', '));
      return String(value);
    default: return value;
  }
}

export class Settings {
  constructor(engagement) {
    this.engagement = engagement || 'default';
    this.values = {};
  }
  get(key) {
    const spec = SETTINGS_SCHEMA[key];
    if (!spec) throw new TypeError('unknown setting: ' + key);
    return key in this.values ? this.values[key] : spec.default;
  }
  set(key, value) {
    this.values[key] = validate(key, value);
    const all = loadAll();
    all[this.engagement] = { ...(all[this.engagement] || {}), [key]: this.values[key] };
    saveAll(all);
    return this.values[key];
  }
  toJSON() {
    const out = {};
    for (const k of Object.keys(SETTINGS_SCHEMA)) {
      const v = this.get(k);
      // Secret-class keys (ghc2.token): presence only, NEVER the value — the API/console
      // layer renders this verbatim, so the redaction happens here, once.
      out[k] = SETTINGS_SCHEMA[k].secret ? (v ? '<redacted:set>' : '') : v;
    }
    return { engagement: this.engagement, values: out, overrides: Object.keys(this.values) };
  }
  static for(engagement) {
    const k = engagement || 'default';
    if (!registry.has(k)) {
      const s = new Settings(k);
      const stored = loadAll()[k] || {}; // write-through persistence: restore on first touch
      for (const [key, value] of Object.entries(stored)) { try { s.values[key] = validate(key, value); } catch { /* invalid stored value: dropped honestly */ } }
      registry.set(k, s);
    }
    return registry.get(k);
  }
  static schema() {
    return Object.entries(SETTINGS_SCHEMA).map(([key, s]) => ({ key, ...s }));
  }
}
