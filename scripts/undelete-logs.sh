#!/bin/bash
# undelete-logs.sh — recover the deleted hive transaction logs via ntfsundelete.
echo kali | sudo -S true 2>/dev/null
PART=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}')
echo "partition: $PART"
mkdir -p /tmp/undel && cd /tmp/undel
sudo -n ntfsundelete /dev/$PART -s 2>/dev/null | grep -iE 'SYSTEM.LOG|SOFTWARE.LOG|SAM.LOG|SECURITY.LOG' | head -10
echo "=====scan done (inodes above)====="
