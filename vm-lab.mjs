// vm-lab.mjs — Enclave's VMware cyber-range manager (the high-fidelity tier).
//
// Governs an EPHEMERAL VM lab driven entirely via `vmrun`:
//   * TARGET   — a real Windows 11 box with live Defender (the thing a Linux
//                container target can never be); attacked over the network.
//   * ATTACKER — a Kali VM the governed agent drives (its Bash runs here).
//
// Lifecycle contract (this is the important part):
//   labUp()   -> revert each VM to its clean baseline snapshot, boot headless,
//                return the target's IP once it's up.
//   labDown() -> revert to baseline (wipe) THEN hard power-off. Clean AND off.
//   cleanupOrphans() -> startup/exit backstop: any lab VM left RUNNING (e.g. by
//                a crash or a browser that closed suddenly) is reverted + killed.
// So a session can never leave a dirty or running VM behind: teardown is called
// on graceful close, and even if that never fires, the next server start sweeps.

import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const VMRUN = process.env.ENCLAVE_VMRUN ||
  ['C:/Program Files (x86)/VMware/VMware Workstation/vmrun.exe',
   'C:/Program Files/VMware/VMware Workstation/vmrun.exe'].find(p => existsSync(p)) || 'vmrun';

// The lab VMs. `baseline` is the clean snapshot each is reset to every cycle.
const LAB = {
  target: {
    role: 'target',
    vmx: process.env.ENCLAVE_TARGET_VMX || 'C:/Users/Jack/Documents/Virtual Machines/enclave-target/enclave-target.vmx',
    baseline: process.env.ENCLAVE_TARGET_SNAP || 'clean-install',
    mac: (process.env.ENCLAVE_TARGET_MAC || '00:0c:29:33:a4:15').toLowerCase(), // target has no Tools -> IP via DHCP lease
    hasTools: false,
  },
  attacker: {
    role: 'attacker',
    vmx: process.env.ENCLAVE_KALI_VMX || 'C:/Users/Jack/Downloads/kali-linux-2025.4-vmware-amd64/kali-linux-2025.4-vmware-amd64.vmwarevm/kali-linux-2025.4-vmware-amd64.vmx',
    baseline: process.env.ENCLAVE_KALI_SNAP || 'enclave-base',
    user: process.env.ENCLAVE_KALI_USER || 'kali',
    pass: process.env.ENCLAVE_KALI_PASS || 'kali',
    hasTools: true,
  },
};
const LEASES = process.env.ENCLAVE_VMNET_LEASES || 'C:/ProgramData/VMware/vmnetdhcp.leases';
const VMS = [LAB.target, LAB.attacker];
const norm = p => String(p).replace(/\\/g, '/').toLowerCase();
const sleep = ms => new Promise(r => setTimeout(r, ms));

export const vmLabAvailable = () => existsSync(VMRUN) && existsSync(LAB.target.vmx) && existsSync(LAB.attacker.vmx);

// env handed to the child so enclave-shell (Claude-CLI path) can run a command inside the
// Kali attacker VM via vmrun guest-ops and capture its output to a host-readable file.
export function kaliShellEnv() {
  return {
    ENCLAVE_KALI_VMX: LAB.attacker.vmx, ENCLAVE_KALI_USER: LAB.attacker.user, ENCLAVE_KALI_PASS: LAB.attacker.pass,
    ENCLAVE_VMRUN: VMRUN, ENCLAVE_KALI_OUT: join(tmpdir(), 'enclave_eshell_out').replace(/\\/g, '/'),
  };
}
export const vmLabTargetIp = () => targetIpFromLeases(LAB.target.mac) || '192.168.50.130';

function vmrun(args, timeout = 180000) {
  return new Promise(resolve => {
    const p = spawn(VMRUN, ['-T', 'ws', ...args]);
    let out = '', err = '';
    p.stdout.on('data', d => (out += d));
    p.stderr.on('data', d => (err += d));
    const t = setTimeout(() => { try { p.kill(); } catch {} resolve({ status: 124, stdout: out, stderr: 'timeout' }); }, timeout);
    p.on('close', code => { clearTimeout(t); resolve({ status: code, stdout: out, stderr: err }); });
    p.on('error', e => { clearTimeout(t); resolve({ status: 1, stdout: out, stderr: e.message }); });
  });
}

async function runningVmxs() {
  const r = await vmrun(['list']);
  return (r.stdout || '').split(/\r?\n/).map(l => l.trim()).filter(l => /\.vmx$/i.test(l)).map(norm);
}
async function isRunning(vmx) { return (await runningVmxs()).includes(norm(vmx)); }

function targetIpFromLeases(mac) {
  try {
    const txt = readFileSync(LEASES, 'utf8');
    const re = new RegExp('lease\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s*\\{[^}]*?' + mac.replace(/[:.]/g, m => '\\' + m), 'gi');
    let m, last = null; while ((m = re.exec(txt))) last = m[1];
    return last;
  } catch { return null; }
}

// Run a command INSIDE the Kali attacker via Tools guest-ops; return combined output.
export async function runInKali(command, timeout = 150000) {
  const a = LAB.attacker;
  const guestOut = '/tmp/.enclave_out';
  const script = `{ ${command} ; } > ${guestOut} 2>&1`;
  const r = await vmrun(['-gu', a.user, '-gp', a.pass, 'runScriptInGuest', a.vmx, '/bin/bash', script], timeout);
  const host = join(tmpdir(), 'enclave_kali_' + process.pid + '_' + Date.now());
  await vmrun(['-gu', a.user, '-gp', a.pass, 'copyFileFromGuestToHost', a.vmx, guestOut, host]);
  let out = '';
  try { out = readFileSync(host, 'utf8'); } catch {}
  try { unlinkSync(host); } catch {}
  if (!out && r.status !== 0) out = 'ERROR (Kali guest-op): ' + (r.stderr || r.stdout || 'unknown');
  return (out || '(no output)').slice(0, 8000);
}

async function toolsReady() {
  const r = await runInKali('echo enclave-ready', 20000);
  return /enclave-ready/.test(r);
}

// Bring the lab up: reset both VMs to clean, boot headless, wait for readiness.
export async function labUp({ waitMs = 95000 } = {}) {
  if (!vmLabAvailable()) return { ok: false, error: 'VM lab unavailable (vmrun or a lab VM is missing)' };
  for (const vm of VMS) {
    await vmrun(['revertToSnapshot', vm.vmx, vm.baseline]);   // -> clean, powered off
    if (!(await isRunning(vm.vmx))) await vmrun(['start', vm.vmx, 'nogui']); // boot headless
  }
  // wait for the target to boot (has no Tools; give it time) and Kali's Tools to answer
  const end = Date.now() + waitMs;
  let kaliOk = false;
  while (Date.now() < end) {
    await sleep(5000);
    if (!kaliOk) kaliOk = await toolsReady();
    if (kaliOk && targetIpFromLeases(LAB.target.mac)) break;
  }
  const targetIp = targetIpFromLeases(LAB.target.mac);
  return {
    ok: true, targetIp, targetUser: 'target', targetOs: 'Windows 11 Pro (Defender on)',
    attackerReady: kaliOk,
    note: `Attacker = Kali (your Bash runs there). Target = ${targetIp || 'booting'} on the sealed lab net. Fire tools from Kali AT the target.`,
  };
}

// Tear the lab down: wipe to baseline, then guarantee powered-off. Never throws.
export async function labDown() {
  if (!existsSync(VMRUN)) return;
  for (const vm of VMS) {
    try { await vmrun(['revertToSnapshot', vm.vmx, vm.baseline]); } catch {}
    try { await vmrun(['stop', vm.vmx, 'hard']); } catch {}
  }
}

// Startup / exit backstop: only touch VMs that are actually RUNNING (crash orphans).
export async function cleanupOrphans() {
  if (!existsSync(VMRUN)) return { swept: 0 };
  let swept = 0;
  for (const vm of VMS) {
    if (await isRunning(vm.vmx)) {
      try { await vmrun(['revertToSnapshot', vm.vmx, vm.baseline]); } catch {}
      try { await vmrun(['stop', vm.vmx, 'hard']); } catch {}
      swept++;
    }
  }
  return { swept };
}

export async function labStatus() {
  if (!existsSync(VMRUN)) return { available: false };
  const running = await runningVmxs();
  return {
    available: vmLabAvailable(),
    targetRunning: running.includes(norm(LAB.target.vmx)),
    attackerRunning: running.includes(norm(LAB.attacker.vmx)),
    targetIp: targetIpFromLeases(LAB.target.mac),
  };
}

// Install process-level teardown once, so a server kill (SIGINT/SIGTERM) also
// powers the lab off. Idempotent; call from server bootstrap.
let hooked = false;
export function installLabTeardown() {
  if (hooked) return; hooked = true;
  const bye = () => { labDown().finally(() => process.exit(0)); };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
  process.on('beforeExit', () => { /* best-effort async */ labDown(); });
}
