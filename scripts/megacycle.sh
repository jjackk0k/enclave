#!/bin/bash
# megacycle.sh — forensics (service/evtx) + enable RDP + stage logs, one pass.
echo kali | sudo -S true 2>/dev/null
PART=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}')
echo "partition: $PART"
sudo -n ntfsfix -d /dev/$PART >/dev/null 2>&1
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o rw,recover /dev/$PART /mnt/tgt && echo MOUNTED
echo "=====va-boot.log====="
sudo -n cat /mnt/tgt/Windows/Temp/va-boot.log 2>&1
echo "=====Select====="
printf 'cd Select\nls\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SYSTEM 2>&1 | grep -iE 'Current|LastKnownGood' | head -6
echo "=====VarvelBoot key====="
printf 'cd ControlSet001\\Services\\VarvelBoot\nls\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SYSTEM 2>&1 | grep -iE 'VarvelBoot|Start|Type|ImagePath|Node has' | head -8
echo "=====RDP import====="
cat > /tmp/rdp.reg <<'REGEOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server]
"fDenyTSConnections"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\TermService]
"Start"=dword:00000002

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules]
"VARVEL-RDP-In"="v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=VARVEL RDP In|"
REGEOF
echo y | sudo -n reged -I /mnt/tgt/Windows/System32/config/SYSTEM 'HKEY_LOCAL_MACHINE\SYSTEM' /tmp/rdp.reg
echo "=====verify RDP====="
printf 'cd ControlSet001\\Control\\Terminal Server\ncat fDenyTSConnections\nq\n' | sudo -n chntpw -e /mnt/tgt/Windows/System32/config/SYSTEM 2>&1 | grep -A2 fDeny | head -3
echo "=====stage evtx====="
sudo -n cp /mnt/tgt/Windows/System32/winevt/Logs/System.evtx /mnt/tgt/Windows/System32/winevt/Logs/Security.evtx /tmp/ 2>&1 && sudo -n chmod 644 /tmp/System.evtx /tmp/Security.evtx && echo STAGED
sudo -n umount /mnt/tgt && echo UNMOUNTED
pkill -f "http.server 8899" 2>/dev/null; nohup python3 -m http.server 8899 -d /tmp >/dev/null 2>&1 & sleep 1; echo SERVED
