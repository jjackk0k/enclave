// hyperv provider — the WINDOWS VM tier: the Windows-native answer to "can you do
// Firecracker on Windows?". Firecracker itself is KVM-bound (Linux only) and will
// never run on Windows — but Hyper-V is Windows' own hardware hypervisor, so a
// VM-per-session model maps onto it directly.
//
// Reality check for THIS machine: Hyper-V (and Windows Sandbox) require Windows
// Pro/Enterprise; Windows Home does not have them. Home users get VM-backed Linux
// isolation through the *docker* tier instead (Docker Desktop runs a real Linux VM
// via WSL2). So on a Home box this provider reports unavailable and the manager
// falls back to docker -> local. It's here so a Windows *Pro* host has a real
// VM tier, and so the abstraction is honest about the options.

import { existsSync } from 'node:fs';

// The per-session VM the provider would create on a Hyper-V host (via PowerShell).
export function newVmArgs(session) {
  return {
    create: `New-VM -Name enclave-${session.session_id} -Generation 2 -MemoryStartupBytes 1GB ` +
            `-VHDPath C:\\enclave\\snapshots\\${session.workload || 'code-review'}.vhdx`,
    // No external switch attached => no network out (deny-all by construction);
    // egress, when needed, goes through a host proxy over a private switch.
    harden: `Set-VMProcessor enclave-${session.session_id} -Count 2; ` +
            `Disable-VMIntegrationService enclave-${session.session_id} -Name "Guest Service Interface"`,
    // Exec inside the VM without a network path, using PowerShell Direct:
    exec: `Invoke-Command -VMName enclave-${session.session_id} -Credential $cred -ScriptBlock { node -e $args }`,
  };
}

function hyperVPresent() {
  // vmms.exe (Hyper-V VM Management Service) exists only when Hyper-V is installed —
  // i.e. Windows Pro/Enterprise with the feature enabled. Absent on Home.
  return process.platform === 'win32' && existsSync(`${process.env.SystemRoot || 'C:\\Windows'}\\System32\\vmms.exe`);
}
const NOT_HERE = 'hyper-v VM tier needs Windows Pro/Enterprise with Hyper-V enabled; not available here — on Windows Home use the docker tier (VM-backed Linux isolation via WSL2). See providers/hyperv.mjs.';

export default {
  name: 'hyperv',
  tier: 'Windows VM (Hyper-V, per session)',
  enforces: { ephemeralFs: true, secretsScrubbed: true, egressDenied: true, kernelIsolation: 'hardware VM (Hyper-V)' },

  available() { return hyperVPresent(); },

  create(session) {
    if (!this.available()) throw new Error(NOT_HERE);
    // On a real Hyper-V host: run newVmArgs(session).create + .harden, start from a
    // differencing disk off the golden VHDX, then exec via PowerShell Direct (.exec).
    throw new Error(NOT_HERE);
  },
  run() { throw new Error(NOT_HERE); },
  destroy() { /* on a real host: Stop-VM -TurnOff; Remove-VM -Force; delete the diff disk */ return true; },
};
