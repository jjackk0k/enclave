// tool-shelf.mjs — the curated, gating-aware tool shelf per workload (2025-2026).
// Each workload's isolated sandbox is provisioned with its shelf. Every tool carries
// a GATE TIER that maps to the "clearance informs, server authorizes" rule:
//
//   T0  analysis / defensive / read-only    — no special gate (safe-by-default shelf)
//   T1  sensitive / dual-use                — workload context + full audit logging
//   T2  restricted / offensive              — REQUIRES: offensive/exploit cert (attested)
//                                             + a signed, in-scope target bound to an
//                                             engagement/authorization id + audit.
//                                             Server enforces; clearance only informs.
//
// Sourced from current-practice research; deprecated tools are excluded on purpose
// (see `deprecations`). Pull exact SPDX + latest tag from each project at build time.

export const GATE_TIERS = {
  T0: 'analysis / defensive / read-only — no special gate',
  T1: 'sensitive / dual-use — workload context + full audit',
  T2: 'restricted / offensive — offensive cert + signed in-scope target + audit (server-enforced)',
};

const t = (name, purpose, license, gate) => ({ name, purpose, license, gate });

export const TOOL_SHELF = {
  'code-review': {
    title: 'Secure code review / AppSec', windows: 'n/a — scans source/artifacts, not OSes',
    tools: [
      t('Semgrep', 'fast pattern/dataflow SAST, 30+ langs', 'open-core', 'T0'),
      t('CodeQL', 'deep semantic query-based SAST', 'commercial (free for OSS)', 'T0'),
      t('Trivy', 'SCA + image + IaC/misconfig + secrets + SBOM', 'OSS', 'T0'),
      t('Grype + Syft', 'CVE scanner + SBOM (SPDX/CycloneDX)', 'OSS', 'T0'),
      t('OSV-Scanner v2', 'OSV.dev dep scanning + guided remediation', 'OSS', 'T0'),
      t('Gitleaks', 'secrets in git history / pre-commit', 'OSS', 'T0'),
      t('TruffleHog', 'secrets with live credential verification', 'OSS', 'T1'),
      t('Checkov', 'IaC policy-as-code (TF/CFN/K8s/Helm)', 'OSS', 'T0'),
      t('Kubescape', 'K8s posture vs NSA/CIS + admission', 'OSS', 'T0'),
    ],
  },
  'red-team': {
    title: 'Red team ops', windows: 'central — implants cross-compiled from Linux; .NET post-ex runs on target',
    tools: [
      t('ProjectDiscovery (subfinder/httpx/naabu/dnsx/katana)', 'recon pipeline', 'OSS', 'T1'),
      t('Nmap (+NSE)', 'port/service/version + scripted checks', 'OSS', 'T1'),
      t('masscan', 'internet-scale SYN scan', 'OSS', 'T2'),
      t('Burp Suite / OWASP ZAP', 'web proxy + active scanning', 'open-core / OSS', 'T1'),
      t('Nuclei', 'templated vuln scanning (active templates)', 'OSS', 'T2'),
      t('sqlmap', 'SQL injection automation', 'OSS', 'T2'),
      t('Metasploit + msfvenom', 'exploitation + payload gen', 'open-core', 'T2'),
      t('Sliver', 'modern Go C2, cross-platform implants (mTLS/DNS/WG)', 'OSS', 'T2'),
      t('Mythic / Havoc', 'modular C2 frameworks', 'OSS', 'T2'),
      t('NetExec (nxc)', 'AD swiss-army (SMB/WinRM/LDAP/MSSQL) — CME successor', 'OSS', 'T2'),
      t('Impacket', 'AD/protocol toolkit (secretsdump, ntlmrelayx)', 'OSS', 'T2'),
      t('BloodHound CE (+SharpHound/AzureHound)', 'AD/Azure attack-path graphing', 'OSS', 'T1'),
      t('Responder', 'LLMNR/NBT-NS/mDNS poisoning', 'OSS', 'T2'),
      t('Certipy / Kerbrute', 'AD CS abuse / Kerberos spray', 'OSS', 'T2'),
      t('Hashcat + John', 'offline hash cracking (GPU)', 'OSS', 'T1'),
      t('GhostPack (Rubeus/Certify/Seatbelt)', 'Windows .NET post-ex (compile on Linux)', 'OSS', 'T2'),
    ],
  },
  'incident-response': {
    title: 'Incident response / forensics', windows: 'Windows-artifact analysis is Linux-native (no Windows tier)',
    tools: [
      t('Velociraptor', 'endpoint hunting + artifact collection (VQL)', 'OSS', 'T0'),
      t('osquery', 'SQL over endpoint state', 'OSS', 'T0'),
      t('Volatility 3', 'memory forensics (Win/Linux/macOS)', 'OSS', 'T0'),
      t('The Sleuth Kit + Autopsy', 'disk/file/timeline analysis', 'OSS', 'T0'),
      t('Plaso (log2timeline) + Timesketch', 'super-timeline + collaborative review', 'OSS', 'T0'),
      t('Hayabusa / Chainsaw', 'fast EVTX timeline + Sigma hunting', 'OSS', 'T0'),
      t('Sigma / pySigma', 'vendor-neutral detection rules', 'OSS', 'T0'),
      t('YARA-X + capa + FLOSS', 'malware classification / capability ID', 'OSS', 'T0'),
      t('Ghidra', 'reverse engineering / decompiler', 'OSS', 'T0'),
      t('CyberChef', 'offline decode/decrypt/deobfuscate', 'OSS', 'T0'),
      t('Wireshark / Zeek / Suricata', 'network forensics / IDS', 'OSS', 'T0'),
      t('CAPE / Cuckoo3', 'dynamic malware detonation', 'OSS', 'T1'),
    ],
  },
  'grc-audit': {
    title: 'GRC / compliance audit', windows: 'SCAP/CIS-CAT cover Windows baselines; agent or Windows tier for host scans',
    tools: [
      t('Prowler', 'multi-cloud security + compliance (40+ frameworks)', 'open-core', 'T1'),
      t('Steampipe + Powerpipe', 'SQL over cloud/SaaS + CIS/NIST dashboards', 'OSS', 'T1'),
      t('OpenSCAP + SSG', 'SCAP CIS/STIG baseline scanning + reports', 'OSS', 'T0'),
      t('Lynis', 'Unix/Linux host hardening audit', 'OSS', 'T0'),
      t('Chef InSpec', 'compliance-as-code (Linux/Win/cloud)', 'OSS', 'T0'),
      t('Wazuh', 'SIEM/XDR + SCA config assessment + regulatory maps', 'OSS', 'T0'),
      t('CIS-CAT (Lite/Pro)', 'official CIS Benchmark assessor', 'commercial (Lite free)', 'T0'),
      t('OpenVAS / Greenbone', 'network vuln scanning for evidence', 'open-core', 'T1'),
    ],
  },
  'tool-dev': {
    title: 'Security tool development', windows: 'cross-compile PE from Linux; Windows debug tier for WinDbg/x64dbg',
    tools: [
      t('LLVM/Clang + GCC (+ASan/UBSan/MSan)', 'compilers + sanitizers', 'OSS', 'T0'),
      t('MinGW-w64', 'build native Windows PE from Linux', 'OSS', 'T0'),
      t('Zig (zig cc)', 'drop-in cross-compiler across arch/libc', 'OSS', 'T0'),
      t('Rust + cross · Go (GOOS) · .NET SDK', 'multi-target build toolchains', 'OSS', 'T0'),
      t('QEMU (user + system)', 'run/emulate other-arch binaries', 'OSS', 'T0'),
      t('GDB + pwndbg/GEF · LLDB · rr', 'exploit-dev debugging / time-travel', 'OSS', 'T0'),
      t('Ghidra · rizin+Cutter · radare2', 'reverse engineering', 'OSS', 'T0'),
      t('AFL++ · libFuzzer · honggfuzz · LibAFL', 'coverage-guided fuzzing', 'OSS', 'T0'),
      t('pwntools · ROPgadget/ropper · checksec', 'exploit-dev helpers', 'OSS', 'T0'),
      t('frida', 'dynamic instrumentation / runtime hooking', 'OSS', 'T1'),
    ],
  },
};

// Excluded on purpose — do NOT ship as "maintained":
export const deprecations = {
  tfsec: 'merged into Trivy (use Trivy misconfig)',
  Terrascan: 'archived Nov 2025 (read-only)',
  CrackMapExec: 'stalled — use NetExec (nxc)',
  ScoutSuite: 'no update since ~May 2024 — prefer Prowler',
  'Volatility 2': 'legacy — ship Volatility 3',
  YARA: 'adopt YARA-X (maintained Rust rewrite)',
};

/** Does an operator's tier permit a tool's gate? (server-side check; clearance informs.) */
export function toolAllowed({ gate, hasOffensiveCert, targetInScope }) {
  if (gate === 'T2') return !!(hasOffensiveCert && targetInScope);
  return true; // T0/T1 available (T1 still fully audited)
}
