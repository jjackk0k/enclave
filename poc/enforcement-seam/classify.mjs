// classify.mjs — part of the Policy Enforcement Point (PEP).
// Maps a raw Claude Code tool call (tool_name + input) to a SEMANTIC capability
// that the Cedar policies reason about. This mapping is deliberately in the
// enforcement layer, not the model: the model just emits "run this command",
// the PEP decides what class of action that actually is.

const OFFENSIVE_SCAN  = /\b(nmap|masscan|zmap|rustscan|unicornscan)\b/;
const OFFENSIVE_EXPL  = /\b(msfconsole|metasploit|sqlmap|hydra|responder|mimikatz|crackmapexec|impacket)\b/;
const CRED_OPS        = /\b(vault\s|passwd|secretsmanager|az\s+keyvault|aws\s+iam|rotate-?(key|cred|secret))\b/;
const DESTRUCTIVE     = /(\brm\s+-|\brmdir\b|\bdel\s+\/|\bformat\b|\bmkfs\b|\bdd\s+if=|drop\s+table|--force\b|-f\b.*\bpush\b|:\s*>\s*\/)/;
const READONLY_SHELL  = /^\s*(git\s+(status|log|diff|show|blame)|ls|ll|cat|less|head|tail|grep|rg|find|pwd|whoami|id|ps|env)\b/;

const IPV4 = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

/**
 * @param {string} toolName
 * @param {object} toolInput   e.g. { command } | { file_path } | { url }
 * @returns {{action:string, kind:'workspace'|'target', label:string, targetIp?:string}}
 */
export function classify(toolName, toolInput = {}) {
  const raw = (toolInput.command ?? toolInput.file_path ?? toolInput.url ?? '').toString();
  const c = raw.toLowerCase();

  if (OFFENSIVE_EXPL.test(c)) return { action: 'exploit',     kind: 'target', label: 'exploit / offensive tooling', targetIp: (raw.match(IPV4) || [])[1] };
  if (OFFENSIVE_SCAN.test(c)) return { action: 'networkScan', kind: 'target', label: 'network scan',                targetIp: (raw.match(IPV4) || [])[1] };
  if (CRED_OPS.test(c))       return { action: 'rotateCredentials', kind: 'workspace', label: 'credential rotation' };
  if (DESTRUCTIVE.test(c))    return { action: 'deleteFiles', kind: 'workspace', label: 'destructive filesystem op' };

  if (toolName === 'Edit' || toolName === 'Write' || toolName === 'NotebookEdit')
    return { action: 'editCode', kind: 'workspace', label: 'edit source' };
  if (toolName === 'Read' || toolName === 'Glob' || toolName === 'Grep')
    return { action: 'readCode', kind: 'workspace', label: 'read source' };

  if (toolName === 'Bash') {
    if (READONLY_SHELL.test(c)) return { action: 'readCode', kind: 'workspace', label: 'read (shell)' };
    return { action: 'editCode', kind: 'workspace', label: 'run command' }; // default: moderate
  }
  return { action: 'editCode', kind: 'workspace', label: 'other' };
}
