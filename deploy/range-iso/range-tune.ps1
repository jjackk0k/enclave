# range-tune.ps1 — in-band range provisioning (runs during specialize as SYSTEM).
# Replaces ALL the offline hive surgery from the Jul 31 / Aug 02 sessions.
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\range-tune.log'
function L($m) { "$(Get-Date -Format s) $m" | Out-File -Append -Encoding utf8 $log }
L 'range-tune start'

# --- persistent autologon (NO LogonCount — that self-destructs; set directly, no limit) ---
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $wl AutoAdminLogon '1'
Set-ItemProperty $wl DefaultUserName 'target'
Set-ItemProperty $wl DefaultPassword 'TargetLab1!'
Set-ItemProperty $wl DefaultDomainName 'ENCLAVE-TGT'
Remove-ItemProperty $wl 'AutoLogonCount' -ErrorAction SilentlyContinue
Set-LocalUser -Name target -PasswordNeverExpires $true
L 'autologon + account set'

# --- remote admin token policy (future SMB tooling paths) ---
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
New-Item $sys -Force | Out-Null
Set-ItemProperty $sys LocalAccountTokenFilterPolicy 1
L 'LATFP set'

# --- network: unidentified networks -> Private; firewall posture per prior image ---
$sig = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24'
New-Item $sig -Force | Out-Null
Set-ItemProperty $sig Category 1
Set-ItemProperty $sig CategoryReadOnly 0
netsh advfirewall set publicprofile state off | Out-Null
netsh advfirewall set privateprofile state on | Out-Null
Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Set-NetFirewallRule -Enabled True
L 'network + firewall set'

# --- RDP (operator console path; also the in-band management fallback) ---
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService' Start 2
netsh advfirewall firewall add rule name="VARVEL RDP In" dir=in action=allow protocol=TCP localport=3389 | Out-Null
L 'rdp set'

# --- VarvelBoot service: pre-logon SYSTEM launcher for the channel agent ---
sc.exe create VarvelBoot binPath= "C:\Windows\System32\cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Temp\va-boot.ps1" start= auto obj= LocalSystem | Out-Null
L 'VarvelBoot service created'

L 'range-tune done'
