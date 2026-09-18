#!/bin/bash
# restore-system.sh — put RegBack's pristine SYSTEM hive in place (undo expansion), keep
# SOFTWARE(Winlogon)+SAM(password) edits. Logs already deleted.
echo kali | sudo -S true 2>/dev/null
PART=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}')
sudo -n ntfsfix -d /dev/$PART >/dev/null 2>&1
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o rw,recover /dev/$PART /mnt/tgt && echo MOUNTED
C=/mnt/tgt/Windows/System32/config
sudo -n ls -la --time-style=full-iso $C/RegBack/ | head -8
sudo -n cp $C/RegBack/SYSTEM $C/SYSTEM && echo SYSTEM-RESTORED
sudo -n rm -f $C/SYSTEM.LOG1 $C/SYSTEM.LOG2 $C/SOFTWARE.LOG1 $C/SOFTWARE.LOG2 $C/SAM.LOG1 $C/SAM.LOG2 $C/SECURITY.LOG1 $C/SECURITY.LOG2
sudo -n ls $C | grep -cE 'SYSTEM|SOFTWARE|SAM|SECURITY'
printf 'cd Microsoft\\Windows NT\\CurrentVersion\\Winlogon\ncat AutoAdminLogon\nq\n' | sudo -n chntpw -e $C/SOFTWARE 2>&1 | grep -A2 AutoAdminLogon | head -3
sudo -n umount /mnt/tgt && echo UNMOUNTED
