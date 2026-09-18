#!/bin/bash
# install-service.sh — create VarvelBoot service (pre-logon SYSTEM launcher for va-boot.ps1),
# plus forensics from the previous boot. Verifies the new key actually landed.
echo kali | sudo -S true 2>/dev/null
PART=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}')
sudo -n ntfsfix -d /dev/$PART >/dev/null 2>&1
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o rw,recover /dev/$PART /mnt/tgt && echo MOUNTED
echo "=====forensics: va-boot.log====="
sudo -n cat /mnt/tgt/Windows/Temp/va-boot.log 2>&1
echo "=====forensics: AutoAdminLogon====="
printf 'cd Microsoft\\Windows NT\\CurrentVersion\\Winlogon\ncat AutoAdminLogon\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SOFTWARE 2>&1 | grep -A2 -i AutoAdminLogon | head -3
cat > /tmp/svc.reg <<'REGEOF'
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
echo "=====import service====="
echo y | sudo -n reged -I /mnt/tgt/Windows/System32/config/SYSTEM 'HKEY_LOCAL_MACHINE\SYSTEM' /tmp/svc.reg
echo "=====verify service key====="
printf 'cd ControlSet001\\Services\\VarvelBoot\nls\ncat ImagePath\ncat Start\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SYSTEM 2>&1 | grep -iE 'VarvelBoot|ImagePath|Start|Type|Node has' | head -12
sudo -n umount /mnt/tgt && echo UNMOUNTED
