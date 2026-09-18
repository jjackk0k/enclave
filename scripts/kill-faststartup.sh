#!/bin/bash
# kill-faststartup.sh — force a real cold boot now + forever: delete hiberfil.sys,
# HiberbootEnabled=0. (Hybrid boot skips service init → VarvelBoot never re-runs.)
echo kali | sudo -S true 2>/dev/null
WIN=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$3=="ntfs" && $2 ~ /^59/ {print $1}' | head -1)
sudo -n ntfsfix -d /dev/$WIN >/dev/null 2>&1
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o rw,recover /dev/$WIN /mnt/tgt && echo MOUNTED
C=/mnt/tgt/Windows/System32/config
sudo -n ls -la --time-style=full-iso /mnt/tgt/hiberfil.sys 2>/dev/null | head -2
sudo -n rm -f /mnt/tgt/hiberfil.sys && echo HIBERFIL-DELETED
cat > /tmp/hib.reg <<'REGEOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Power]
"HiberbootEnabled"=dword:00000000
REGEOF
echo y | sudo -n reged -I $C/SYSTEM 'HKEY_LOCAL_MACHINE\SYSTEM' /tmp/hib.reg | grep -E 'END|OK'
printf 'cd ControlSet001\\Control\\Session Manager\\Power\ncat HiberbootEnabled\nq\n' | sudo -n chntpw -e $C/SYSTEM 2>&1 | grep -A2 Hiberboot | head -3
sudo -n umount /mnt/tgt && echo UNMOUNTED
