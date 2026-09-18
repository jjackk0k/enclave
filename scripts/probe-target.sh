#!/bin/bash
# probe2.sh — read va-boot.log, post-boot Winlogon state, logon evidence; stage evtx for host parse.
echo kali | sudo -S true 2>/dev/null
PART=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}')
echo "target partition: $PART"
sudo -n ntfsfix -d /dev/$PART >/dev/null 2>&1
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o ro /dev/$PART /mnt/tgt && echo MOUNTED
echo "=====va-boot.log====="
sudo -n cat /mnt/tgt/Windows/Temp/va-boot.log 2>&1
echo "=====AutoAdminLogon now====="
printf 'cd Microsoft\\Windows NT\\CurrentVersion\\Winlogon\ncat AutoAdminLogon\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SOFTWARE 2>&1 | grep -A2 -i AutoAdminLogon | head -3
echo "=====profile touched since 16:00 local====="
sudo -n find /mnt/tgt/Users/target -maxdepth 1 -newermt '2026-08-02 16:00' 2>/dev/null | head -5
echo "=====stage evtx====="
sudo -n cp /mnt/tgt/Windows/System32/winevt/Logs/Security.evtx /mnt/tgt/Windows/System32/winevt/Logs/System.evtx /tmp/ && sudo -n chmod 644 /tmp/Security.evtx /tmp/System.evtx && echo STAGED
