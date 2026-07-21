// classify.mjs — part of the Policy Enforcement Point (PEP).
// Maps a raw Claude Code tool call (tool_name + input) to a SEMANTIC capability
// that the Cedar policies reason about. This mapping is deliberately in the
// enforcement layer, not the model: the model just emits "run this command",
// the PEP decides what class of action that actually is.

import { extractHost, isEgressCommand } from './egress-allowlist.mjs';

const OFFENSIVE_SCAN  = /\b(nmap|masscan|zmap|rustscan|unicornscan)\b/;
const OFFENSIVE_EXPL  = /\b(msfconsole|metasploit|sqlmap|hydra|responder|mimikatz|crackmapexec|impacket)\b/;
const CRED_OPS        = /\b(vault\s|passwd|secretsmanager|az\s+keyvault|aws\s+iam|rotate-?(key|cred|secret))\b/;
const PROVISION       = /\b(terraform\s+(apply|destroy|plan)|kubectl\s+(apply|create|delete|scale|rollout)|helm\s+(install|upgrade|uninstall)|pulumi\s+up|cloudformation\s+(deploy|create-stack|update-stack)|docker\s+(compose\s+up|stack\s+deploy)|ansible-playbook|serverless\s+deploy|provision|deploy)\b/;
const DESTRUCTIVE     = /(\brm\s+-|\brmdir\b|\bdel\s+\/|\bformat\b|\bmkfs\b|\bdd\s+if=|drop\s+table|--force\b|-f\b.*\bpush\b|:\s*>\s*\/)/;
const READONLY_SHELL  = /^\s*(git\s+(status|log|diff|show|blame)|ls|ll|cat|less|head|tail|grep|rg|find|pwd|whoami|id|ps|env)\b/;

const IPV4 = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

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

  if (isEgressCommand(cmd))   return { action: 'webResearch', kind: 'egress', host: extractHost(cmd), url: cmd, label: 'shell egress' };
  if (OFFENSIVE_EXPL.test(c)) return { action: 'exploit',     kind: 'target', label: 'exploit / offensive tooling', targetIp: (cmd.match(IPV4) || [])[1] };
  if (OFFENSIVE_SCAN.test(c)) return { action: 'networkScan', kind: 'target', label: 'network scan',                targetIp: (cmd.match(IPV4) || [])[1] };
  if (PROVISION.test(c))      return { action: 'provisionInfra',    kind: 'workspace', label: 'provision / deploy infrastructure' };
  if (CRED_OPS.test(c))       return { action: 'rotateCredentials', kind: 'workspace', label: 'credential rotation' };
  if (DESTRUCTIVE.test(c))    return { action: 'deleteFiles', kind: 'workspace', label: 'destructive filesystem op' };
  if (READONLY_SHELL.test(c)) return { action: 'readCode', kind: 'workspace', label: 'read (shell)' };
  return { action: 'editCode', kind: 'workspace', label: 'run command' }; // default: moderate
}
