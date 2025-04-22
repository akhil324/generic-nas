#!/bin/bash

# Make sure usb_share.img contains your LATEST scripts before running!'
CORE_FILE_DIR="/Users/akhil/Documents/Development/PiCode"

qemu-system-aarch64 \
    -M raspi4b \
    -m 2G \
    -cpu cortex-a72 \
    -smp 4 \
    -kernel "$CORE_FILE_DIR/kernel8.img" \
    -dtb "$CORE_FILE_DIR/bcm2711-rpi-4-b.dtb" \
    -append "root=/dev/mmcblk1p2 rw rootwait loglevel=8 systemd.run=/usr/local/bin/qemu-firstrun-wrapper.sh" \
    -drive file="$CORE_FILE_DIR/2024-11-19-raspios-bookworm-arm64-lite.img,format=raw,if=sd" \
    -drive file="$CORE_FILE_DIR/usb_share.img,format=raw,if=none,id=usbstick" \
    -device usb-storage,drive=usbstick \
    -serial file:rpi_boot.log \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 \
    -device usb-net,netdev=net0 \
    -nographic