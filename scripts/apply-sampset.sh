#!/bin/bash
# apply-sampset.sh — run sampset.py, import patched V into SAM, restore Winlogon autologon
# (AutoAdminLogon=1 + DefaultPassword=TargetLab1!), verify everything, unmount.
echo kali | sudo -S true 2>/dev/null
python3 /tmp/sampset.py || exit 1
echo "=====import SAM V====="
echo y | sudo -n reged -I /mnt/tgt/Windows/System32/config/SAM 'HKEY_LOCAL_MACHINE\SAM' /tmp/sam-v.reg
echo "=====verify hash====="
sudo -n samdump2 /mnt/tgt/Windows/System32/config/SYSTEM /mnt/tgt/Windows/System32/config/SAM 2>&1 | grep '^target'
cat > /tmp/winlogon4.reg <<'REGEOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"AutoAdminLogon"="1"
"DefaultUserName"="target"
"DefaultPassword"="TargetLab1!"
REGEOF
echo "=====import Winlogon====="
echo y | sudo -n reged -I /mnt/tgt/Windows/System32/config/SOFTWARE 'HKEY_LOCAL_MACHINE\SOFTWARE' /tmp/winlogon4.reg
echo "=====verify Winlogon====="
printf 'cd Microsoft\\Windows NT\\CurrentVersion\\Winlogon\ncat AutoAdminLogon\ncat DefaultPassword\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SOFTWARE 2>&1 | grep -A2 -iE 'AutoAdminLogon|DefaultPassword' | head -8
sudo -n umount /mnt/tgt && echo UNMOUNTED
