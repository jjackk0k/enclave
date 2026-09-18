// VARVEL — live-mode engine config (real agent, real governance).
//
// Demo mode uses the mock agent. LIVE mode drives the Enclave's `runGovernedAgent`,
// which needs two things VARVEL must assemble: a MODEL BACKEND (Kimi K3 / an API key)
// and the GOVERNANCE seam (the policy hook + the signed session + the sealed
// workspace). This module gathers both from the same places the Enclave console does
// — the k3/KimiCode login and the ENCLAVE_* environment handoff — and reports, plainly,
// whether a live run is ready and what is missing if not.
//
// It authorizes nothing. It only wires the backend + points the agent at the SAME hook
// the Enclave enforces with; the hook is still the sole authority.

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { claudeAvailable } from './claude-cli.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const SEAM = join(__dir, '..', '..', 'poc', 'enforcement-seam');
export const HOOK_PATH = join(SEAM, 'hook', 'pretooluse-hook.mjs');
// A dedicated, loopback-scoped signed session so the bundled demo can be breached
// live out of the box (scope 127.0.0.0/8 ONLY — it can touch nothing but the demo).
export const DEMO_SESSION = join(SEAM, 'session', 'demo.json');

// Wire-safe model id. The k3 CLI config stores DISPLAY ids like `kimi-k3[1m]`; Kimi's raw
// coding API (Anthropic shape) accepts only base ids (`k3`, `kimi-k2.7-code`) and 401s on the
// display id. Strip the [1m] tag for every backend; map kimi-k3 → k3 only on the Anthropic path.
export function wireModelId(m, apiType) {
  let s = String(m || '').replace(/\s*\[1m\]\s*$/i, '').trim();
  if (apiType === 'anthropic' && /^kimi-k3$/i.test(s)) s = 'k3';
  return s;
}

// Resolve the model backend the SAME way the Enclave console does (k3 / KimiCode login
// + env overrides). Returns { apiBase, apiType, model, apiKey, source }. apiKey === ''
// means no backend is attached yet.
export function readBackend(env = process.env) {
  const dir = env.KIMICODE_HOME || join(homedir(), '.kimicode');
  let cfg = {};
  try { cfg = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')) || {}; } catch { /* no k3 config */ }
  let base = cfg.baseUrl || 'https://api.moonshot.ai/v1';
  let type = (cfg.apiType && cfg.apiType !== 'auto') ? cfg.apiType : (/\/anthropic|kimi\.com\/coding/i.test(base) ? 'anthropic' : 'openai');
  let model = (cfg.models && cfg.models.main) || 'kimi-k3';
  if (cfg.subscription) { base = 'https://api.kimi.com/coding'; type = 'anthropic'; model = (cfg.models && cfg.models.main) || 'k3'; }
  else if (cfg.freeTier) { base = 'https://openrouter.ai/api/v1'; type = 'openai'; model = (cfg.models && cfg.models.main) || 'qwen/qwen3-coder:free'; }
  const k3key = env.KIMI_API_KEY || env.MOONSHOT_API_KEY || env.OPENROUTER_API_KEY || env.ENCLAVE_KIMI_KEY || env.ANTHROPIC_AUTH_TOKEN || cfg.apiKey || '';
  // kimiKey = the KIMI-SCOPED credential only (explicit VARVEL/Kimi keys), NEVER a bare
  // ambient ANTHROPIC_API_KEY — so Kimi routing can never ship the operator's real Anthropic
  // key to Moonshot's servers. apiKey keeps ANTHROPIC_API_KEY only as a LAST resort (a
  // configured Kimi key wins), for the documented case where it IS the intended backend.
  const kimiKey = env.VARVEL_API_KEY || k3key;
  const apiKey = env.VARVEL_API_KEY || k3key || env.ANTHROPIC_API_KEY || '';
  const source = cfg.subscription ? 'kimi-subscription' : (cfg.freeTier ? 'k3-free-tier' : (apiKey ? 'config/env' : 'none'));
  const effType = env.KIMI_APITYPE || type;
  return { apiBase: env.KIMI_BASE_URL || base, apiType: effType, model: wireModelId(env.VARVEL_MODEL || env.KIMI_MODEL || model, effType), apiKey, kimiKey, source };
}

// Should a Kimi-compatible backend route the Anthropic `claude` CLI? True ONLY with a
// Kimi-scoped key (never a bare ambient ANTHROPIC_API_KEY) AND a Kimi/Moonshot host with an
// Anthropic-style endpoint. Single source of truth for both kimiBackend() and readiness.
export function kimiRoutable(b) {
  let host = ''; try { host = new URL(b.apiBase).host.toLowerCase(); } catch { host = ''; }
  const kimiHost = /(^|\.)kimi\.(com|ai)$/.test(host) || /(^|\.)moonshot\.ai$/.test(host);
  // Require an Anthropic-style PATH (/anthropic or /coding), not just apiType — a Kimi host
  // on the OpenAI /v1 path is NOT Anthropic-compatible and would break `claude -p`.
  const anthropicEndpoint = /\/anthropic\b|\/coding\b/i.test(b.apiBase || '');
  return !!b.kimiKey && kimiHost && anthropicEndpoint;
}

// The governance seam, from the ENCLAVE_* handoff. `sessionFile` may be overridden
// (the demo run uses its own loopback-scoped session).
export function governance(env = process.env, { sessionFile } = {}) {
  return {
    hookPath: HOOK_PATH,
    sessionFile: sessionFile || env.ENCLAVE_SESSION || null,
    wsDir: env.ENCLAVE_WORKSPACE_DIR || process.cwd(),
    container: env.ENCLAVE_CONTAINER || '',
  };
}

// The engine object runGovernedAgent expects for a live campaign.
export function liveEngine(env = process.env, { sessionFile, maxSteps = 14, effort } = {}) {
  const b = readBackend(env);
  const g = governance(env, { sessionFile });
  return { model: b.model, apiBase: b.apiBase, apiKey: b.apiKey, apiType: b.apiType, hookPath: g.hookPath, sessionFile: g.sessionFile, wsDir: g.wsDir, container: g.container, maxSteps, effort };
}

// The concise operating brief handed to the live agent as system context (the full
// version is docs/AGENT-GUIDE.md). Covers the cross-cutting rules the per-phase prompts
// assume: the output contract, the toolset, governance, OPSEC, and the boundary.
export function operatingBrief() {
  return [
    '# VARVEL operating brief (read once — the per-phase objective follows).',
    'You are the autonomous operator of VARVEL, a governed red-team platform. Map the',
    'attack surface, prove real weaknesses with minimum force, demonstrate impact only',
    'when countersigned, and leave the target clean. Be thorough, honest, and precise.',
    '',
    'OUTPUT CONTRACT: end your turn with ONE fenced ```json block — it is the only thing',
    'ingested. recon→{hosts:[{ip,label,services:[{port,proto,name}],endpoints:[{url,method}],tech:[{name,version}]}]}.',
    'validate→{findings:[{host,title,sev,ref,confidence:"confirmed"|"suspected",evidence}]} (sev=crit|high|med|low|info).',
    'exploit→{exploits:[{finding,title,result:"proved"|"failed",ref,host}]}. post-ex→{artifacts:[{host,kind,path,cleanup}]}.',
    'Confidence is load-bearing: only CONFIRMED findings may be exploited; never inflate it.',
    'Record EVERY artifact you drop with a cleanup command. Be honest — claiming progress',
    'with no real result is detected and downgraded.',
    '',
    'TOOLS: Bash runs your shell + toolchain (curl always; nmap/nuclei/ffuf where available);',
    'Read/Write/Edit/Grep/Glob work on files. Your CURRENT DIRECTORY is your sealed workspace —',
    'keep all files there and use relative paths; do NOT read/write outside it or the platform',
    'denies it. Targets are REMOTE HTTP services — reach them with curl, never local file reads.',
    'Check a tool exists (which <tool>) before relying on it.',
    '',
    'TOOL AUTHORING: if NO pinned tool covers the job, BUILD ONE — write a scratch script',
    '(node/python) in your workspace and run it via Bash. NEVER skip an area because the',
    'arsenal lacks a tool: a tooling gap is a task, not a wall. Scratch tools live in your',
    'workspace (never edit the pinned arsenal), cross the same governance hook as everything',
    'else, and must be named in your output JSON (field "scratchTools") so the operator can',
    'audit them and promote the good ones into the pinned set.',
    '',
    'LAB & TOOLMAKING: scratch tools no longer die with the workspace — every script you',
    'name in "scratchTools" is AUTO-SHELVED: the platform copies its bytes out of your',
    'workspace as QUARANTINED data on the tool shelf (never executed; a human promotes',
    'the good ones into the pinned set). So keep one tool per file in your workspace root',
    'and declare each by its file name (or a relative "path", or inline "content") so the',
    'bytes can be found. The shelf is also an API: GET http://127.0.0.1:8971/api/toolshelf',
    'lists it; POST /api/toolshelf with {name, kind, description, files:[{name, content}]}',
    'shelves a tool yourself (lands quarantined — promotion is the operator\'s, never',
    'yours). The attackbench catalog (data/attackbench/techniques.json) is the invention',
    'ledger: the priority ATT&CK techniques the lab measures emulation coverage against.',
    'If you discover a GENUINELY new technique, name it in your closing summary as a',
    'catalog candidate with its evidence — the operator verifies and adds it; you never',
    'edit the catalog yourself.',
    '',
    'CHAINS: after validate, the engine composes candidate exploit chains from the lows/',
    'meds you validated (typed primitives — two lows can compose into one high). In the',
    'exploit phase, execute composed chains with chainrun (node tools/cli.mjs chainrun',
    '<chainFile>). A chain is only "proved" when its IMPACT assertion passes — steps',
    'green with impact absent is a hollow success; report it failed, never proved.',
    '',
    'PLATFORM ARSENAL (native + governed — prefer these over ad-hoc tooling; reach them via',
    'Bash: `node <platform>/tools/cli.mjs <tool> ...` or http://127.0.0.1:8971/api/*):',
    '· C2 channel: register + task agents over http/dns/icmp/doh/ws (ws = instant push, no poll',
    '  cadence). Agents fail over off dead wires and honor setTransport assignments — check the',
    '  transport grade before relying on a wire, and pick the transport the target\'s egress allows.',
    '· Oracles — MEASURE, never assert: detoracle <agentId> <cmd> (did the endpoint Defender log,',
    '  alert, or block that); fporacle ja4s|http (exact JA4/JA4S/JA4H wire fingerprints);',
    '  floworacle <agentId> | floworacle profile <name> (beacon-timing score — pre-flight a cadence',
    '  BEFORE deploying it); tradecraft <agentId> | tradecraft check <jsonArray> (AI-agent',
    '  command-shape score — pre-flight your own shell streams before sending them);',
    '  preflight [host] [ports] (your OWN infrastructure as Censys/Shodan see it — run before',
    '  exposing anything). Their output is evidence, never a guarantee: quote it exactly,',
    '  including insufficient-data and unmonitored states, and never upgrade it to a claim.',
    '· Challenge tier (Cloudflare-class defenses — detect/measure, never "bypass"): cfcheck <url>',
    '  (classify ONE response: managed-js/turnstile/captcha/block-1020/rate-limit/labyrinth/none',
    '  + evidence); cfmap <baseUrl> (paced per-path posture map — unchallenged paths are findings;',
    '  a labyrinth-suspect STOPS the map, never follow those links); originintel <domain> (PASSIVE',
    '  origin candidates — NO contact until scope-signed); egressbench <url> (MEASURED challenge',
    '  rate per egress — a measurement, never a claim); clearance mint <url> (stealth-browser',
    '  cf_clearance — VISIBLE window, proven before vaulted; cookies bind to exit IP + UA).',
    '  Strongest permitted statement: "passed challenge on zone X, config Y, date Z" — observed.',
    '· Rides + render (act + SEE as the vaulted identity): cfride <url> [crawl|apisurface|',
    '  vulncheck|raw] (ride the vault — exact UA+cookie, challenge-honest, --full-body for',
    '  uncapped evidence pulls); sessride <url> --jar <f> (vault clearance + an authenticated',
    '  session jar in ONE governed transport; --authcheck grades login state from observable',
    '  evidence only); cfbrowser (visible-window interaction as the vaulted identity);',
    '  rendercheck <url> --expect <text> [--deny <t>] [--out png] (headless-browser render as',
    '  a REAL VISITOR sees it: screenshot + DOM assertions + cache-aware verdict — it tells',
    '  CONFIRMED VISIBLE TO VISITORS apart from REAL-BUT-CLOAKED-by-cache and NOT-LIVE).',
    '',
    'GOVERNANCE: every tool call crosses the Enclave hook, which authorizes against your',
    'SIGNED clearance + scope. Clearance INFORMS, never authorizes. A denial is FINAL —',
    'do not rephrase or re-encode to get past it; note it and adjust. Stay in scope.',
    '',
    'OPSEC: everything leaves a trace; be professional, not invisible. Scan only what the',
    'objective needs; prefer quiet signals; make minimum, reversible proof. Revert changes',
    'by DEFAULT — BUT if the operator EXPLICITLY asks you to LEAVE a change in place (e.g.',
    'so they can verify it in a browser), honor that: leave it as instructed and note it',
    'for later cleanup. The operator\'s explicit instruction wins over the default.',
    '',
    'PROOF STANDARD (the validator doctrine — proof vs belief, the frontier discipline):',
    '· A success claim needs an OBJECTIVE oracle: a state change read back, executed JS, a',
    '  content diff — never a status code or string pattern alone. "Logged in" means post-auth',
    '  content observed; "written" means an independent read returned it.',
    '· FALSIFY YOURSELF before reporting: run the control that SHOULD fail (garbage nonce,',
    '  wrong endpoint, pre-change state) and show it failing — a hollow 200 that also matches',
    '  garbage input proves nothing. Markers are unique random strings, never usernames or',
    '  URL-echoable content (collision-proof).',
    '· A change you call VISIBLE is confirmed with rendercheck as a visitor sees it — a cache',
    '  HIT can cloak a live change from the world; quote the cache state, never assume it.',
    '· A "closed"/"unexploitable" verdict needs ≥3 DISTINCT evidenced failed hypotheses',
    '  (different classes/shapes, not retries). Absence of evidence is reported as UNTESTED,',
    '  never as absent — name the untested families explicitly.',
    '· Difficulty discipline: keep a per-branch attempt count; after 3 failures on one branch',
    '  with NO new information, pivot or report the wall — never hammer a dead technique. And',
    '  never end on recon alone: every recon phase answers "what did this make exploitable,',
    '  or what did it rule out?"',
    '· The validator gate enforces this at ingest: a "confirmed" claim citing no objective',
    '  oracle lands as SUSPECTED (never deleted — the note says why). Earn it back with',
    '  validate <findingIndex> (POST /api/validate): ONE governed re-read, never auto-fired;',
    '  REFUTED is a first-class outcome — report it, do not hide it.',
    'BOUNDARY: authorized + in-scope only; minimum reversible impact; never touch real',
    'user data or cause an outage; orchestrate legitimate tools (no malware/implants).',
  ].join('\n');
}

// Plain-language readiness for a live run — what's present, what's missing, and whether
// it's enough to start. `sessionFile` lets callers check the demo session specifically.
export function liveReadiness(env = process.env, { sessionFile } = {}) {
  const b = readBackend(env);
  const g = governance(env, { sessionFile });
  const cli = claudeAvailable(env);
  const notes = [];
  // Is the Claude CLI routed at Kimi? Single source of truth (kimiRoutable) — requires a
  // Kimi-scoped key, so this can't report "routed" while the child would ship the wrong key.
  const cliOnKimi = cli && kimiRoutable(b);
  // Prefer the Claude CLI backend when present — it runs host-side (reaches host-local
  // targets like the demo) and needs no container. When a Kimi key is configured it runs
  // the CLI ON Kimi K3 (still host-side, still governed by the same hook).
  const backendKind = cli ? (cliOnKimi ? 'claude-cli-kimi' : 'claude-cli') : (b.apiKey ? 'kimi' : 'none');
  const backend = cli || !!b.apiKey;
  if (cliOnKimi) notes.push(`Claude CLI routed at Kimi (${b.model} · ${b.apiBase}) — host-side + governed.`);
  if (!backend) notes.push('No model backend — install/login the Claude CLI, or subscribe to Kimi K3 / set VARVEL_API_KEY.');
  const hook = existsSync(g.hookPath);
  if (!hook) notes.push('Enclave policy hook not found at ' + g.hookPath + ' — governance unavailable.');
  const session = !!g.sessionFile && existsSync(g.sessionFile);
  if (!session) notes.push('No signed session — open VARVEL from the Enclave console (or use the bundled demo session).');
  const container = !!g.container;
  // Only the Kimi container backend needs the container tier; the Claude CLI reaches the
  // host-local demo directly.
  if (backendKind === 'kimi' && !container) notes.push('The Kimi backend runs tools in a sealed container — start the container tier, or use the Claude CLI (host-side) which reaches the demo directly.');
  return { backend, backendKind, backendSource: cliOnKimi ? b.source : (cli ? 'claude-cli' : b.source), model: cliOnKimi ? b.model : (cli ? (env.VARVEL_MODEL || 'sonnet') : b.model), cliOnKimi, hook, session, container, ready: backend && hook && session, notes };
}
