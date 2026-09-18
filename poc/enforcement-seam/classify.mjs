// classify.mjs — part of the Policy Enforcement Point (PEP).
// Maps a raw Claude Code tool call (tool_name + input) to a SEMANTIC capability
// that the Cedar policies reason about. This mapping is deliberately in the
// enforcement layer, not the model: the model just emits "run this command",
// the PEP decides what class of action that actually is.

import { extractHost, isEgressCommand } from './egress-allowlist.mjs';
import { extractIp, isPrivate, parseIp } from '../../varvel/engine/ipaddr.mjs';

const OFFENSIVE_SCAN  = /\b(nmap|masscan|zmap|rustscan|unicornscan)\b/;
const OFFENSIVE_EXPL  = /\b(msfconsole|metasploit|sqlmap|hydra|responder|mimikatz|crackmapexec|impacket)\b/;
const CRED_OPS        = /\b(vault\s|passwd|secretsmanager|az\s+keyvault|aws\s+iam|rotate-?(key|cred|secret))\b/;
const PROVISION       = /\b(terraform\s+(apply|destroy|plan)|kubectl\s+(apply|create|delete|scale|rollout)|helm\s+(install|upgrade|uninstall)|pulumi\s+up|cloudformation\s+(deploy|create-stack|update-stack)|docker\s+(compose\s+up|stack\s+deploy)|ansible-playbook|serverless\s+deploy|provision|deploy)\b/;
const DESTRUCTIVE     = /(\brm\s+-|\brmdir\b|\bdel\s+\/|\bformat\b|\bmkfs\b|\bdd\s+if=|drop\s+table|--force\b|-f\b.*\bpush\b|:\s*>\s*\/)/;
const READONLY_SHELL  = /^\s*(git\s+(status|log|diff|show|blame)|ls|ll|cat|less|head|tail|grep|rg|find|pwd|whoami|id|ps|env)\b/;

// IP extraction + address classification come from engine/ipaddr (shared, strict):
// v4 AND v6 targets are recognized — an IPv6 target can no longer slip past the
// classifier into the wrong capability class.

/**
 * @param {string} toolName
 * @param {object} toolInput   e.g. { command } | { file_path } | { url }
 * @returns {{action:string, kind:'workspace'|'target', label:string, targetIp?:string}}
 */
// Tools that have no business inside a sealed enclave: egress/exfil (web, publish),
// orchestration (subagents, skills, tool discovery), persistence/automation,
// external comms, and filesystem/process escape. These map to an action that NO
// Cedar policy permits, so — because Cedar is default-deny — they are refused for
// EVERY operator regardless of clearance. (The console also strips them from the
// CLI surface via --disallowedTools; this is the enforcement-layer backstop.)
const SEALED_TOOLS = new Set([
  'Artifact', 'Task', 'Agent', 'Workflow', 'Skill', 'ToolSearch',
  'CronCreate', 'CronList', 'CronDelete', 'ScheduleWakeup', 'RemoteTrigger', 'PushNotification',
  'SendMessage', 'DesignSync', 'EnterWorktree', 'ExitWorktree', 'Monitor',
  'ListMcpResourcesTool', 'ReadMcpResourceTool', 'ReadMcpResourceDirTool',
]);

export function classify(toolName, toolInput = {}) {
  if (SEALED_TOOLS.has(toolName) || /^mcp__/.test(toolName))
    return { action: 'sealedToolBlocked', kind: 'workspace', label: 'tool not permitted in a sealed enclave' };

  // Web research is a GOVERNED egress channel, not a blocked one: the PEP gates it
  // against the allowlist + DLP (see egress-allowlist.mjs), so the model can pull
  // current CVEs / advisories / docs / PoC code but cannot exfiltrate.
  if (toolName === 'WebSearch')
    return { action: 'webResearch', kind: 'egress', host: 'search', url: (toolInput.query || '').toString(), label: 'web search' };
  if (toolName === 'WebFetch')
    return { action: 'webResearch', kind: 'egress', host: extractHost(toolInput.url), url: (toolInput.url || '').toString(), label: 'web fetch' };

  // FILE tools are classified by the OPERATION (read vs write), NEVER by the file's name.
  // A file called "Hydra.Modules.Credentials.xml" or "nmap-notes.txt" is inert data —
  // opening it is a read, editing it is an edit. The offensive/destructive classifiers
  // below apply only to COMMANDS you execute, not to paths you open. (Confinement of the
  // path to the workspace is enforced separately in the hook.)
  if (toolName === 'Read' || toolName === 'Glob' || toolName === 'Grep')
    return { action: 'readCode', kind: 'workspace', label: 'read source' };
  if (toolName === 'Edit' || toolName === 'Write' || toolName === 'NotebookEdit')
    return { action: 'editCode', kind: 'workspace', label: 'edit source' };

  // SHELL commands: classify by what actually RUNS (the command text only — not a file path).
  const cmd = (toolInput.command ?? '').toString();
  const c = cmd.toLowerCase();
  const cc = cmd.replace(/^\s*enclave-shell\s+/i, '');  // unwrap so we see the real tool invocation

  // Capability checks are benign READS, not offensive ops: `which nmap`, `nmap --version`,
  // `hydra -h`, `type msfconsole` don't scan or exploit any target, so they must NOT require
  // an engagement scope. Only an actual invocation (a real target/args) is gated below.
  if (/^\s*(which|type|command\s+-v)\b/i.test(cc)) return { action: 'readCode', kind: 'workspace', label: 'capability check' };
  const versionOnly = /(^|\s)(--version|-V|--help|-h|version)(\s|$)/.test(cc) && !extractIp(cc);

  if (isEgressCommand(cmd)) {
    // Proxy specs are EGRESS INFRASTRUCTURE, never the destination: strip
    // `--proxy/-x/--socks*/-U <arg>` and inline `http_proxy=` env assignments
    // BEFORE any host/IP extraction. The old code let `extractIp(cmd)` grab the
    // proxy's own IP (e.g. Mullvad's in-tunnel 10.64.0.1) and misclassified a
    // proxied request as traffic TO the proxy — an out-of-scope "target" that
    // never was (the 2026-08-05 manhuaus ghost-verify denial).
    const PROXY_ARGS = /(?:--proxy(?:-user)?|--socks[45](?:-hostname)?|-x|-U)(?:\s+|=)\S+|-x[a-z0-9+.-]+:\/\/\S+|(?:^|[\s;])(?:https?_proxy|all_proxy|no_proxy)=\S+/gim;
    const noProxy = cmd.replace(PROXY_ARGS, ' ');
    const host = extractHost(noProxy);
    // tool traffic to a PRIVATE-range host (an engagement/lab target — v4 RFC1918/
    // loopback/link-local, v6 ULA/link-local/::1) is an offensive action gated by the
    // engagement scope — NOT web research to be allowlist-checked. Classification runs
    // on a CLEAN canonical address, never parser debris: a command like
    // `curl http://127.0.0.1:8973$p/...` (a stray shell var hard against the port)
    // leaves '$p' hugging the host — extract the address FIRST, then classify it,
    // or scope parsing downstream produces a contradictory "outside scope" denial.
    const targetIp = (parseIp(host) || {}).text || extractIp(host) || extractIp(noProxy);
    if (targetIp && isPrivate(targetIp)) {
      return { action: 'networkScan', kind: 'target', label: 'tool traffic to an in-scope target', targetIp };
    }
    return { action: 'webResearch', kind: 'egress', host, url: cmd, label: 'shell egress' };
  }
  if (OFFENSIVE_EXPL.test(c)) return versionOnly ? { action: 'readCode', kind: 'workspace', label: 'tool version check' } : { action: 'exploit',     kind: 'target', label: 'exploit / offensive tooling', targetIp: extractIp(cmd) || undefined };
  if (OFFENSIVE_SCAN.test(c)) return versionOnly ? { action: 'readCode', kind: 'workspace', label: 'tool version check' } : { action: 'networkScan', kind: 'target', label: 'network scan',                targetIp: extractIp(cmd) || undefined };
  if (PROVISION.test(c))      return { action: 'provisionInfra',    kind: 'workspace', label: 'provision / deploy infrastructure' };
  if (CRED_OPS.test(c))       return { action: 'rotateCredentials', kind: 'workspace', label: 'credential rotation' };
  if (DESTRUCTIVE.test(c))    return { action: 'deleteFiles', kind: 'workspace', label: 'destructive filesystem op' };
  if (READONLY_SHELL.test(c)) return { action: 'readCode', kind: 'workspace', label: 'read (shell)' };
  return { action: 'editCode', kind: 'workspace', label: 'run command' }; // default: moderate
}
