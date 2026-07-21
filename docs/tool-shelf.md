# Tool shelf — curated, gating-aware (2025–2026)

Each workload's sandbox is provisioned with a **curated shelf** of best-in-class tools. The machine-readable manifest is [`tool-shelf.mjs`](../tool-shelf.mjs); this is the human view. Selections favour actively-maintained OSS (with the notable commercial options noted), and **deprecated tools are deliberately excluded**.

## Gate tiers

Every tool carries a tier that plugs into "clearance informs, server authorizes":

| Tier | Meaning | Gate |
|---|---|---|
| **T0** | analysis / defensive / read-only | none (safe-by-default shelf) |
| **T1** | sensitive / dual-use | workload context + full audit |
| **T2** | restricted / offensive | **offensive/exploit cert (attested) + a signed, in-scope target bound to an engagement id + audit** — server-enforced |

`toolAllowed()` in the manifest makes T2 require both an offensive cert *and* an in-scope target — the same axes the [enforcement seam](../poc/enforcement-seam/) already gates on.

## By workload (highlights)

- **Secure code review / AppSec** *(all T0/T1)* — **Semgrep**, **CodeQL**, **Trivy** (SCA+image+IaC+secrets+SBOM), **Grype+Syft**, **OSV-Scanner**, **Gitleaks**, **Checkov**, **Kubescape**.
- **Red team ops** *(T1/T2)* — **ProjectDiscovery** suite, **Nmap**, **Nuclei**, **Burp/ZAP**, **Metasploit**, **Sliver / Mythic / Havoc** (C2), **NetExec**, **Impacket**, **BloodHound CE**, **Responder**, **Certipy/Kerbrute**, **Hashcat/John**, **GhostPack**.
- **Incident response / forensics** *(mostly T0)* — **Velociraptor**, **osquery**, **Volatility 3**, **Sleuth Kit/Autopsy**, **Plaso+Timesketch**, **Hayabusa/Chainsaw**, **Sigma**, **YARA-X + capa**, **Ghidra**, **CyberChef**, **Wireshark/Zeek/Suricata**.
- **GRC / compliance** *(T0/T1)* — **Prowler**, **Steampipe+Powerpipe**, **OpenSCAP+SSG**, **Lynis**, **Chef InSpec**, **Wazuh**, **CIS-CAT**, **OpenVAS**.
- **Security tool development** *(T0/T1)* — **Clang/GCC + sanitizers**, **MinGW-w64**, **Zig**, **Rust/Go/.NET** cross-compilers, **QEMU**, **GDB+pwndbg / rr**, **Ghidra/rizin**, **AFL++/libFuzzer/honggfuzz/LibAFL**, **pwntools**.

## Excluded (do not ship as "maintained")

- `tfsec` → **merged into Trivy** · `Terrascan` → **archived Nov 2025** · `CrackMapExec` → **use NetExec** · `ScoutSuite` → stale, prefer **Prowler** · `Volatility 2` → ship **3** · `YARA` → adopt **YARA-X**.

## Linux sandbox vs Windows targets

- **Linux-native (no Windows tier):** all Windows-*artifact* forensics (Volatility 3, Hayabusa, Chainsaw, EZ-Tools via `dotnet`); cross-compiled Windows *payloads/implants* (Sliver, `msfvenom`, MinGW, Go/Rust/.NET → SharpHound/Rubeus).
- **Needs the Windows tier:** WinDbg/TTD, x64dbg, native execution of .NET post-ex + Mimikatz (run *on the target*), Windows-only commercial forensics, CIS-CAT Windows baselines, live Cobalt Strike Beacon.

*Pin exact SPDX license + latest version from each project's repo at build time rather than hardcoding.*
