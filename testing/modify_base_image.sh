#!/bin/bash

# Script to perform the ONE-TIME modification of the base Raspberry Pi OS image.
# Adds the QEMU wrapper script and modifies cmdline.txt to trigger it.
# Reads the base image path from the .env file in the repository root.
#
# !!! WARNING !!! Modifying ext4 partitions directly on macOS is complex and potentially risky.
# !!! RECOMMENDED: Run this script inside a Linux VM or Docker container on your Mac !!!
#

set -e
# set -u
set -o pipefail

# --- Configuration ---
SCRIPT_DIR=$(dirname "$(realpath "$0")")
REPO_ROOT=$(realpath "${SCRIPT_DIR}/..")

# Path to the .env file (expected at repo root)
ENV_FILE="${REPO_ROOT}/.env"

# Path to the wrapper script source (in testing/ dir)
WRAPPER_SCRIPT_SRC="${SCRIPT_DIR}/qemu-firstrun-wrapper.sh"

# Target path for the wrapper script inside the image's rootfs
WRAPPER_SCRIPT_TARGET_PATH="/usr/local/bin/qemu-firstrun-wrapper.sh"

# Systemd run parameter to add to cmdline.txt
SYSTEMD_RUN_PARAM="systemd.run=${WRAPPER_SCRIPT_TARGET_PATH}"

# Mount points (temporary)
BOOT_MNT="${SCRIPT_DIR}/mnt_boot"
ROOT_MNT="${SCRIPT_DIR}/mnt_root"

# --- Helper Functions ---
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (modify_base): $1"
}
warn() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN (modify_base): $1" >&2
}
error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR (modify_base): $1" >&2
  cleanup # Attempt cleanup on error
  exit 1
}

cleanup() {
    warn "Attempting cleanup..."
    sync || true
    # Check mount command output for safety before unmounting
    if mount | grep -q "${ROOT_MNT}"; then
        umount "$ROOT_MNT" || warn "Failed to unmount $ROOT_MNT"
    fi
    if mount | grep -q "${BOOT_MNT}"; then
        umount "$BOOT_MNT" || warn "Failed to unmount $BOOT_MNT"
    fi
    # Remove mount point dirs only if they are empty
    rmdir "$BOOT_MNT" 2>/dev/null || true
    rmdir "$ROOT_MNT" 2>/dev/null || true
    # Detach loop devices (Linux specific - macOS handled differently)
    if [[ "$(uname -s)" == "Linux" ]] && command -v losetup &> /dev/null; then
       # Attempt to find loop devices associated with the image and detach them
       mapfile -t LOOP_DEVICES < <(losetup -j "$BASE_IMAGE_PATH" -O NAME --noheadings)
       for loop_dev in "${LOOP_DEVICES[@]}"; do
           if [[ -n "$loop_dev" ]]; then
               log "Detaching loop device $loop_dev"
               losetup -d "$loop_dev" || warn "Failed to detach $loop_dev"
           fi
       done
    fi
    log "Cleanup attempt finished."
}


check_root() {
  if [[ "$(uname -s)" == "Linux" && "$EUID" -ne 0 ]]; then
    error "This script must be run as root (use sudo) on Linux."
  fi
}

# Define check_tools_linux and check_tools_macos as in the previous response
# (Including realpath/greadlink checks)
check_tools_linux() {
    local missing=0
    local tools="fdisk mount umount losetup cp chmod sed grep cut realpath awk" # Added grep, cut, awk
    for tool in $tools; do
        if ! command -v "$tool" &> /dev/null; then
             echo "ERROR: Linux tool '$tool' not found."
             missing=1
        fi
    done
     if [[ "$missing" -eq 1 ]]; then error "Please install missing Linux tools."; fi
}
check_tools_macos() {
    local missing=0
    local tools="hdiutil diskutil cp chmod sed grep cut realpath awk" # Added grep, cut, awk
     for tool in $tools; do
        if ! command -v "$tool" &> /dev/null; then
             if [[ "$tool" == "realpath" ]]; then
                if ! command -v greadlink &> /dev/null && ! realpath --version &>/dev/null; then
                    echo "ERROR: 'realpath'/'greadlink' not found. Try 'brew install coreutils'."
                    missing=1
                elif command -v greadlink &> /dev/null; then
                   realpath() { greadlink -f "$@"; }
                fi
             else echo "ERROR: macOS tool '$tool' not found."; missing=1; fi
        fi
     done
     if [[ "$missing" -eq 1 ]]; then error "Please install missing macOS tools."; fi
     warn "Attempting modification on macOS. This is less reliable for ext4. Using a Linux environment is recommended."
     # Check for FUSE/ext4 support?
     if ! command -v fuse-ext2 &> /dev/null && ! command -v mkfs.ext4 &> /dev/null; then # Heuristic
         warn "No obvious FUSE ext4 tools detected (fuse-ext2, mkfs.ext4 via e2fsprogs). Read/write for root partition may fail."
         warn "Consider installing macFUSE and ext4 fuse module or using Linux."
     fi
}


# --- Main Execution ---
log "Starting one-time modification of base image..."

# Define realpath using greadlink if needed before using SCRIPT_DIR
if [[ "$(uname -s)" == "Darwin" ]] && command -v greadlink &> /dev/null && ! command -v realpath &>/dev/null; then
    realpath() { greadlink -f "$@"; }
fi

# Check for .env file first
if [[ ! -f "$ENV_FILE" ]]; then
    error ".env file not found at expected location: $ENV_FILE"
fi
log "Reading configuration from $ENV_FILE"

# Read IMAGE_FILE from .env using grep/cut, remove potential quotes
BASE_IMAGE_PATH=$(grep '^IMAGE_FILE=' "$ENV_FILE" | head -n 1 | cut -d '=' -f2- | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')

if [[ -z "$BASE_IMAGE_PATH" ]]; then
    error "Could not read IMAGE_FILE from $ENV_FILE."
fi
log "Base image path read from .env: ${BASE_IMAGE_PATH}"


if [[ ! -f "$BASE_IMAGE_PATH" ]]; then
    error "Base image file not found: $BASE_IMAGE_PATH"
fi
if [[ ! -f "$WRAPPER_SCRIPT_SRC" ]]; then
    error "Wrapper script source not found: $WRAPPER_SCRIPT_SRC"
fi

# Basic OS check - recommend Linux
OS_TYPE=$(uname -s)
if [[ "$OS_TYPE" == "Linux" ]]; then
    log "Detected Linux. Proceeding with recommended method."
    check_root
    check_tools_linux
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    log "Detected macOS. Attempting macOS method (less reliable for ext4)."
    check_tools_macos
else
    error "Unsupported operating system: $OS_TYPE"
fi

# --- Linux Method ---
if [[ "$OS_TYPE" == "Linux" ]]; then
    log "Getting partition offsets..."
    # Use fdisk -l -o Device,Start,Sectors <image> and parse output
    # Sector size usually 512, confirm if needed: blockdev --getss "$BASE_IMAGE_PATH" (doesn't work on files)
    SECTOR_SIZE=512
    BOOT_INFO=$(fdisk -l "$BASE_IMAGE_PATH" | grep -E ' W95 FAT32 \(LBA\)| EFI System' | head -n 1)
    ROOT_INFO=$(fdisk -l "$BASE_IMAGE_PATH" | grep -E ' Linux' | head -n 1)

    BOOT_START_SEC=$(echo "$BOOT_INFO" | awk '{print $2}')
    ROOT_START_SEC=$(echo "$ROOT_INFO" | awk '{print $2}')

    if [[ -z "$BOOT_START_SEC" || ! "$BOOT_START_SEC" =~ ^[0-9]+$ ]]; then
        error "Could not determine boot partition start sector using fdisk."
    fi
     if [[ -z "$ROOT_START_SEC" || ! "$ROOT_START_SEC" =~ ^[0-9]+$ ]]; then
        error "Could not determine root partition start sector using fdisk."
    fi

    BOOT_OFFSET=$((BOOT_START_SEC * SECTOR_SIZE))
    ROOT_OFFSET=$((ROOT_START_SEC * SECTOR_SIZE))
    log "Boot partition offset: $BOOT_OFFSET"
    log "Root partition offset: $ROOT_OFFSET"

    # Create mount points
    mkdir -p "$BOOT_MNT" "$ROOT_MNT"

    # Setup loop device explicitly for cleaner cleanup
    LOOP_DEV=$(losetup -f --show -o "$BOOT_OFFSET" "$BASE_IMAGE_PATH") || error "Failed to setup loop device for boot partition."
    log "Using loop device $LOOP_DEV for boot partition."
    mount "$LOOP_DEV" "$BOOT_MNT" || { losetup -d "$LOOP_DEV"; error "Failed to mount boot partition."; }

    # Use a different loop device for the root partition
    ROOT_LOOP_DEV=$(losetup -f --show -o "$ROOT_OFFSET" "$BASE_IMAGE_PATH") || { umount "$BOOT_MNT"; losetup -d "$LOOP_DEV"; error "Failed to setup loop device for root partition."; }
    log "Using loop device $ROOT_LOOP_DEV for root partition."
    mount "$ROOT_LOOP_DEV" "$ROOT_MNT" || { umount "$BOOT_MNT"; losetup -d "$LOOP_DEV"; losetup -d "$ROOT_LOOP_DEV"; error "Failed to mount root partition."; }


    # --- Perform Modifications ---
    log "Copying wrapper script..."
    WRAPPER_DEST="${ROOT_MNT}${WRAPPER_SCRIPT_TARGET_PATH}"
    mkdir -p "$(dirname "$WRAPPER_DEST")" || error "Failed to create target dir for wrapper."
    cp -v "$WRAPPER_SCRIPT_SRC" "$WRAPPER_DEST" || error "Failed to copy wrapper script."
    chmod +x "$WRAPPER_DEST" || error "Failed to chmod wrapper script."
    log "Wrapper script copied and made executable."

    # Find and modify cmdline.txt
    CMDLINE_FILE=""
    # Check both potential locations within the mounted boot partition
    if [[ -f "${BOOT_MNT}/firmware/cmdline.txt" ]]; then
        CMDLINE_FILE="${BOOT_MNT}/firmware/cmdline.txt"
    elif [[ -f "${BOOT_MNT}/cmdline.txt" ]]; then
        CMDLINE_FILE="${BOOT_MNT}/cmdline.txt"
    else
        error "cmdline.txt not found in boot partition mount $BOOT_MNT."
    fi
    log "Modifying $CMDLINE_FILE ..."

    # Make a backup first
    cp "$CMDLINE_FILE" "${CMDLINE_FILE}.orig" || error "Failed to backup cmdline.txt"

    # Remove existing systemd.run= parameter if present, then append new one
    # Ensure parameter starts with a space if content exists, otherwise no leading space
    if grep -q 'systemd\.run=' "$CMDLINE_FILE"; then
      log "Removing existing systemd.run parameter..."
      sed -i 's/ systemd\.run=[^ ]*//g' "$CMDLINE_FILE" || error "Failed to remove existing systemd.run"
    fi
    # Append, ensuring space separation
    if [[ -s "$CMDLINE_FILE" ]]; then # Check if file has content
       if [[ $(tail -c1 "$CMDLINE_FILE" | wc -l) -eq 0 ]]; then # Check if ends with newline
          printf " %s" "$SYSTEMD_RUN_PARAM" >> "$CMDLINE_FILE" || error "Failed to append systemd.run"
       else # Add space if no trailing newline (unlikely but possible)
          printf " %s" "$SYSTEMD_RUN_PARAM" >> "$CMDLINE_FILE" || error "Failed to append systemd.run"
       fi
    else
       printf "%s" "$SYSTEMD_RUN_PARAM" > "$CMDLINE_FILE" || error "Failed to write systemd.run to empty file"
    fi

    log "cmdline.txt modified successfully."
    # Optional: Show diff
    # diff "${CMDLINE_FILE}.orig" "$CMDLINE_FILE" || true

    # --- Cleanup ---
    log "Modifications complete. Unmounting..."
    # Pass loop devices to cleanup for detachment
    cleanup # Should now detach LOOP_DEV and ROOT_LOOP_DEV

# --- macOS Method (Attempt - Use with Caution!) ---
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # (Keep macOS attempt logic from previous response here if desired, but strongly recommend Linux)
    error "macOS modification attempt is commented out due to unreliability. Please use a Linux environment."
    # ... (macOS hdiutil/diskutil/fuse-ext2 logic commented out or removed) ...
fi # End OS TYPE check

log "--- Base Image modification complete ---"
exit 0