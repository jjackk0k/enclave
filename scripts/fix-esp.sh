#!/bin/bash
# fix-esp.sh — inspect the new install's ESP; install the EFI fallback loader so the
# disk boots without any NVRAM entry (the stale July entry is what fails).
echo kali | sudo -S true 2>/dev/null
lsblk -ln -o NAME,SIZE,FSTYPE | grep -E 'sd|G |M '
ESP=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="300M" && $3=="vfat" {print $1}' | head -1)
WIN=$(lsblk -ln -o NAME,SIZE,FSTYPE | awk '$2=="59G" && $3=="ntfs" {print $1}' | head -1)
echo "ESP=$ESP WIN=$WIN"
sudo -n mkdir -p /mnt/esp
sudo -n mount -o ro /dev/$ESP /mnt/esp && echo ESP-MOUNTED
echo "=====ESP tree====="
sudo -n find /mnt/esp -type f | head -20
if sudo -n test -f /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi; then
  echo "bootmgfw.efi PRESENT"
  sudo -n umount /mnt/esp
  sudo -n mount /dev/$ESP /mnt/esp && echo ESP-RW
  sudo -n mkdir -p /mnt/esp/EFI/BOOT
  sudo -n cp /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi /mnt/esp/EFI/BOOT/BOOTX64.EFI && echo FALLBACK-INSTALLED
  sudo -n ls -la /mnt/esp/EFI/BOOT/
  sudo -n ls -la /mnt/esp/EFI/Microsoft/Boot/ | head -8
else
  echo "bootmgfw.efi MISSING — phase 1 did not finish the bootloader"
fi
sudo -n umount /mnt/esp 2>/dev/null; echo ESP-UNMOUNTED
sudo -n mkdir -p /mnt/tgt
sudo -n mount -t ntfs-3g -o ro /dev/$WIN /mnt/tgt 2>/dev/null && echo WIN-MOUNTED
sudo -n ls /mnt/tgt/ 2>/dev/null | head -12
sudo -n ls /mnt/tgt/Windows/ 2>/dev/null | wc -l
sudo -n umount /mnt/tgt 2>/dev/null; echo DONE
