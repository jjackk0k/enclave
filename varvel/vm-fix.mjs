// Unmount the stale read-only mount, then mount rw and inject.
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync, unlinkSync } from 'node:fs';
import { kaliShellEnv } from '../vm-lab.mjs';

const env = kaliShellEnv();
function run(script, timeout = 90000) {
  const outFile = '/tmp/.es' + Math.random().toString(36).slice(2, 8);
  spawnSync(env.ENCLAVE_VMRUN, ['-T', 'ws', '-gu', env.ENCLAVE_KALI_USER, '-gp', env.ENCLAVE_KALI_PASS, 'runScriptInGuest', env.ENCLAVE_KALI_VMX, '/bin/bash', `{ ${script}; } >${outFile} 2>&1`], { encoding: 'utf8', timeout });
  try { unlinkSync(env.ENCLAVE_KALI_OUT); } catch {}
  spawnSync(env.ENCLAVE_VMRUN, ['-T', 'ws', '-gu', env.ENCLAVE_KALI_USER, '-gp', env.ENCLAVE_KALI_PASS, 'copyFileFromGuestToHost', env.ENCLAVE_KALI_VMX, outFile, env.ENCLAVE_KALI_OUT], { encoding: 'utf8', timeout: 40000 });
  return existsSync(env.ENCLAVE_KALI_OUT) ? readFileSync(env.ENCLAVE_KALI_OUT, 'utf8') : '(no output)';
}

const TASK = String.raw`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled></Settings>
  <Actions><Exec><Command>powershell.exe</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -Command "Set-NetConnectionProfile -NetworkCategory Private; Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'; Get-NetConnectionProfile | Out-File C:\enclave-fwfix.log"</Arguments></Exec></Actions>
</Task>`;

const py = `import subprocess, codecs, os
subprocess.run(['umount', '/mnt/w'], check=False)
subprocess.run(['umount', '/dev/sdb3'], check=False)
subprocess.run(['mount', '-t', 'ntfs-3g', '-o', 'rw', '/dev/sdb3', '/mnt/w'], check=True)
print('MOUNTED-RW')
xml = ${JSON.stringify(TASK)}
path = '/mnt/w/Windows/System32/Tasks/EnclaveFwFix'
with open(path, 'wb') as f:
    f.write(codecs.BOM_UTF16_LE + xml.encode('utf-16-le'))
print('TASK WRITTEN', os.path.getsize(path), 'bytes')
subprocess.run(['sync'], check=True)
subprocess.run(['umount', '/mnt/w'], check=True)
print('UNMOUNTED')
`;

const b64 = Buffer.from(py).toString('base64');
run(`echo ${b64} | base64 -d > /tmp/enclave-fix.py`);
console.log(run(`echo kali | sudo -S python3 /tmp/enclave-fix.py`));
