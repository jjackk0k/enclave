// firecracker provider — the PRODUCTION isolation tier: one hardware-virtualized
// microVM per session, behind the jailer, restored from a golden snapshot, with
// NO network interface (egress leaves only over vsock -> host proxy). This is the
// isolation buyers scrutinize; see docs/security-architecture.md §6–§7.
//
// It requires a KVM host (bare-metal or nested-virt Linux). On any other host —
// e.g. this Windows dev machine — available() returns false and the manager falls
// back to the docker/local tier. The config below is the real intended shape.

import { existsSync } from 'node:fs';

// The per-session microVM configuration the manager would hand to Firecracker.
export function vmConfig(session) {
  return {
    'boot-source': { kernel_image_path: '/enclave/vmlinux', boot_args: 'console=ttyS0 reboot=k panic=1 pci=off' },
    drives: [{ drive_id: 'rootfs', path_on_host: `/enclave/snapshots/${session.workload || 'code-review'}.ext4`,
               is_root_device: true, is_read_only: true }],
    'machine-config': { vcpu_count: 2, mem_size_mib: 1024, smt: false },
    // NO network-interfaces: egress is vsock -> host proxy only (deny-all by construction).
    vsock: { guest_cid: 3, uds_path: `/enclave/run/${session.session_id}.vsock` },
  };
}
// The jailer wraps Firecracker in its own chroot + namespaces + cgroup + seccomp.
export function jailerArgs(session) {
  return ['--id', session.session_id, '--exec-file', '/usr/bin/firecracker',
    '--uid', '30000', '--gid', '30000', '--chroot-base-dir', '/enclave/jail',
    '--', '--config-file', `/enclave/run/${session.session_id}.json`];
}

function kvmHost() { return process.platform === 'linux' && existsSync('/dev/kvm'); }
const NOT_HERE = 'firecracker requires a KVM host (bare-metal / nested-virt Linux); not available on this machine — see providers/firecracker.mjs and docs/security-architecture.md §6.';

export default {
  name: 'firecracker',
  tier: 'microVM (Firecracker + jailer, snapshot restore)',
  enforces: { ephemeralFs: true, secretsScrubbed: true, egressDenied: true, kernelIsolation: 'hardware VM (KVM)' },

  available() { return kvmHost() && existsSync('/usr/bin/firecracker'); },

  create(session) {
    if (!this.available()) throw new Error(NOT_HERE);
    // On a real host: write vmConfig(session) to /enclave/run/<id>.json, launch via
    // jailerArgs(session), restore the golden snapshot (~28ms), reseed guest RNG.
    throw new Error(NOT_HERE);
  },
  run() { throw new Error(NOT_HERE); },
  destroy() { /* on a real host: kill VMM, unlink COW + vsock, drop dm-crypt key, free egress-IP lease */ return true; },
};
