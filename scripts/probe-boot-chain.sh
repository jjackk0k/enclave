#!/bin/bash
# probe-boot-chain.sh — why didn't the agent relaunch? ControlSet flip? service gone? va-boot.log?
echo kali | sudo -S true 2>/dev/null
WIN=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$3=="ntfs" && $2 ~ /^59/ {print $1}' | head -1)
sudo -n ntfsfix -d /dev/$WIN >/dev/null 2>&1
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o rw,recover /dev/$WIN /mnt/tgt && echo MOUNTED
C=/mnt/tgt/Windows/System32/config
echo "=====va-boot.log (did it run this boot?)====="
sudo -n ls -la --time-style=full-iso /mnt/tgt/Windows/Temp/va-boot.log 2>/dev/null && sudo -n cat /mnt/tgt/Windows/Temp/va-boot.log
echo "=====Select====="
printf 'cd Select\nls\nq\n' | sudo -n chntpw -e $C/SYSTEM 2>&1 | grep -iE 'Current|LastKnownGood' | head -5
echo "=====ControlSets present====="
printf 'ls\nq\n' | sudo -n chntpw -e $C/SYSTEM 2>&1 | grep -iE 'ControlSet' | head -5
echo "=====VarvelBoot in CS001?====="
printf 'cd ControlSet001\\Services\\VarvelBoot\ncat Start\nq\n' | sudo -n chntpw -e $C/SYSTEM 2>&1 | grep -A2 -E 'Start|not found' | head -4
echo "=====VarvelBoot in CS002?====="
printf 'cd ControlSet002\\Services\\VarvelBoot\ncat Start\nq\n' | sudo -n chntpw -e $C/SYSTEM 2>&1 | grep -A2 -E 'Start|not found' | head -4
echo "=====Winlogon autologon intact?====="
printf 'cd Microsoft\\Windows NT\\CurrentVersion\\Winlogon\ncat AutoAdminLogon\ncat DefaultPassword\nq\n' | sudo -n chntpw -e $C/SOFTWARE 2>&1 | grep -A2 -iE 'AutoAdminLogon|DefaultPassword' | head -8
sudo -n umount /mnt/tgt && echo UNMOUNTED
