#!/bin/bash
# fix-autologon4.sh — AutoAdminLogon=1 + DefaultDomainName=ENCLAVE-TGT + verify + unmount.
echo kali | sudo -S true 2>/dev/null
sudo -n umount /mnt/tgt 2>/dev/null
PART=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}')
sudo -n mount -t ntfs-3g -o rw,recover /dev/$PART /mnt/tgt && echo MOUNTED
cat > /tmp/winlogon5.reg <<'REGEOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"AutoAdminLogon"="1"
"DefaultUserName"="target"
"DefaultPassword"="TargetLab1!"
"DefaultDomainName"="ENCLAVE-TGT"
REGEOF
echo y | sudo -n reged -I /mnt/tgt/Windows/System32/config/SOFTWARE 'HKEY_LOCAL_MACHINE\SOFTWARE' /tmp/winlogon5.reg
echo "=====VERIFY====="
printf 'cd Microsoft\\Windows NT\\CurrentVersion\\Winlogon\ncat AutoAdminLogon\ncat DefaultDomainName\ncat DefaultPassword\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SOFTWARE 2>&1 | grep -A2 -iE 'AutoAdminLogon|DefaultDomainName|DefaultPassword' | head -12
sudo -n umount /mnt/tgt && echo UNMOUNTED
