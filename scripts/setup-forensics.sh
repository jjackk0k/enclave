#!/bin/bash
# setup-forensics.sh — why did phase 1 die? Panther logs + Windows census.
echo kali | sudo -S true 2>/dev/null
WIN=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$3=="ntfs" && $2 ~ /^59/ {print $1}' | head -1)
echo "WIN=$WIN"
sudo -n mkdir -p /mnt/tgt
sudo -n ntfsfix -d /dev/$WIN >/dev/null 2>&1
sudo -n mount -t ntfs-3g -o ro /dev/$WIN /mnt/tgt && echo WIN-MOUNTED
echo "=====root====="
sudo -n ls /mnt/tgt/ | head -15
echo "=====windows census====="
sudo -n ls /mnt/tgt/Windows/ 2>/dev/null | wc -l
echo "=====panther====="
sudo -n ls '/mnt/tgt/$Windows.~BT/Sources/Panther/' 2>/dev/null | head -15
echo "=====setuperr====="
sudo -n cat '/mnt/tgt/$Windows.~BT/Sources/Panther/setuperr.log' 2>/dev/null | tail -30
echo "=====setupact tail====="
sudo -n cat '/mnt/tgt/$Windows.~BT/Sources/Panther/setupact.log' 2>/dev/null | tail -25
sudo -n umount /mnt/tgt 2>/dev/null; echo DONE
