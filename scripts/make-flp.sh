#!/bin/bash
# make-flp.sh — build a 1.44MB FAT12 floppy image carrying autounattend.xml + serve it.
echo kali | sudo -S true 2>/dev/null
dd if=/dev/zero of=/tmp/range.flp bs=1k count=1440 status=none
sudo -n mkfs.vfat /tmp/range.flp >/dev/null 2>&1
sudo -n mkdir -p /mnt/flp
sudo -n mount -o loop /tmp/range.flp /mnt/flp && echo FLP-MOUNTED
echo "$1" | base64 -d | sudo -n tee /mnt/flp/autounattend.xml > /dev/null && echo XML-WRITTEN
sudo -n ls -la /mnt/flp
sudo -n umount /mnt/flp && echo FLP-DONE
pkill -f "http.server 8899" 2>/dev/null; nohup python3 -m http.server 8899 -d /tmp >/dev/null 2>&1 & sleep 1; echo SERVED
