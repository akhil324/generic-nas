#!/bin/bash

# Script to prepare the usb_share.img file for QEMU testing.
# Creates, formats (FAT32), and copies necessary configuration files
# from the repository root into the image.

set -e
# set -u # Disabled for safety with potential empty vars/paths
set -o pipefail

# --- Configuration ---
SCRIPT_DIR=$(dirname "$(realpath "$0")")
REPO_ROOT=$(realpath "${SCRIPT_DIR}/..") # Assumes testing/ is one level down

# Source files/dirs in the repository root
FIRST_RUN_SRC="${REPO_ROOT}/firstrun.sh"
ENV_SRC="${REPO_ROOT}/.env" # Assuming .env is at the root
SETUP_SCRIPTS_SRC_DIR="${REPO_ROOT}/setup_scripts"
MONITORING_APP_SRC_DIR="${REPO_ROOT}/monitoring_app"
UDEV_RULES_SRC_DIR="${REPO_ROOT}/udev_rules"

# Target image configuration (created within the testing/ directory)
USB_IMG_PATH="${SCRIPT_DIR}/usb_share.img"
IMG_SIZE_MB=100 # Size in Megabytes
VOLUME_NAME="QEMU_SHARE" # Name for the FAT32 volume

# --- Helper Functions ---
log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (prepare_usb): $1"
}
warn() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN (prepare_usb): $1" >&2
}
error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR (prepare_usb): $1" >&2
  # Attempt cleanup if mount device exists
  if [[ -n "$MOUNT_DEVICE" && -e "$MOUNT_DEVICE" ]]; then
    warn "Attempting unmount of $MOUNT_DEVICE during error cleanup..."
    diskutil unmount "$MOUNT_DEVICE" || true
  fi
  if [[ -n "$HDIUTIL_DEVICE" ]]; then
      warn "Attempting detach of $HDIUTIL_DEVICE during error cleanup..."
      hdiutil detach "$HDIUTIL_DEVICE" -force || true
  fi
  exit 1
}

check_tools() {
  local missing=0
  local tools="dd hdiutil diskutil cp rsync realpath mkfs.vfat" # mkfs.vfat might need dosfstools

  for tool in $tools; do
    if ! command -v "$tool" &> /dev/null; then
      if [[ "$tool" == "mkfs.vfat" ]]; then
        echo "ERROR: Required tool '$tool' not found. Try 'brew install dosfstools'."
      elif [[ "$tool" == "rsync" ]]; then
         warn "WARN: 'rsync' not found. Directory copy will use 'cp', potentially less efficient."
         # Don't mark as missing if cp exists
         if ! command -v cp &> /dev/null; then echo "ERROR: 'cp' also not found!"; missing=1; fi
      elif [[ "$tool" == "realpath" ]]; then
          # Handle GNU vs BSD realpath
          if ! command -v greadlink &> /dev/null && ! realpath --version &>/dev/null; then # Check for coreutils and system realpath
             echo "ERROR: Required tool 'realpath' (or 'greadlink' from coreutils) not found. Try 'brew install coreutils'."
             missing=1
          elif command -v greadlink &> /dev/null; then
             # Define realpath using greadlink if available
             realpath() { greadlink -f "$@"; }
             echo "INFO: Using 'greadlink -f' from coreutils for realpath."
          fi
      else
        echo "ERROR: Required tool '$tool' not found."
        missing=1
      fi
    fi
  done
  if [[ "$missing" -eq 1 ]]; then error "Please install missing tools."; fi
}

# --- Main Execution ---
log "Starting preparation of ${USB_IMG_PATH}..."
check_tools

# Resolve source paths after potential realpath definition
# Ensure realpath is defined correctly first if using coreutils
if command -v greadlink &> /dev/null && ! command -v realpath &>/dev/null; then
    realpath() { greadlink -f "$@"; }
fi

FIRST_RUN_SRC=$(realpath "$FIRST_RUN_SRC")
ENV_SRC=$(realpath "$ENV_SRC")
SETUP_SCRIPTS_SRC_DIR=$(realpath "$SETUP_SCRIPTS_SRC_DIR")
MONITORING_APP_SRC_DIR=$(realpath "$MONITORING_APP_SRC_DIR")
UDEV_RULES_SRC_DIR=$(realpath "$UDEV_RULES_SRC_DIR")


# Check if source files/dirs exist
[[ -f "$FIRST_RUN_SRC" ]] || error "Source file not found: $FIRST_RUN_SRC"
[[ -f "$ENV_SRC" ]] || error "Source file not found: $ENV_SRC"
[[ -d "$SETUP_SCRIPTS_SRC_DIR" ]] || error "Source directory not found: $SETUP_SCRIPTS_SRC_DIR"
[[ -d "$MONITORING_APP_SRC_DIR" ]] || error "Source directory not found: $MONITORING_APP_SRC_DIR"
[[ -d "$UDEV_RULES_SRC_DIR" ]] || error "Source directory not found: $UDEV_RULES_SRC_DIR"


# 1. Create image file if it doesn't exist
if [[ ! -f "$USB_IMG_PATH" ]]; then
    log "Image file not found. Creating ${USB_IMG_PATH} (${IMG_SIZE_MB}MB)..."
    dd if=/dev/zero of="$USB_IMG_PATH" bs=1m count=${IMG_SIZE_MB} || error "dd failed"
else
    log "Image file ${USB_IMG_PATH} already exists."
fi

# 2. Format the image as FAT32
# We use hdiutil to attach without mounting, then diskutil to format.
log "Attaching image without mounting..."
HDIUTIL_DEVICE=$(hdiutil attach -nomount "$USB_IMG_PATH" | cut -f 1) || error "hdiutil attach failed"
log "Attached as device: $HDIUTIL_DEVICE"

log "Formatting ${HDIUTIL_DEVICE} as FAT32 with name ${VOLUME_NAME}..."
# Use diskutil; mkfs.vfat on the image file directly can be tricky on macOS
# This will erase the whole "disk" presented by hdiutil
diskutil eraseVolume FAT32 "$VOLUME_NAME" "$HDIUTIL_DEVICE" || error "diskutil eraseVolume failed for $HDIUTIL_DEVICE"
log "Formatting complete."

# diskutil might automatically mount it after formatting, find the mount point
# Or it might eject it, requiring re-attach. Let's try finding mount point first.
sleep 2 # Give time for mount
MOUNT_INFO=$(diskutil info "$HDIUTIL_DEVICE" | grep "Mount Point:")
MOUNT_POINT=""
HDIUTIL_DEVICE_PART1="${HDIUTIL_DEVICE}s1" # Usually the FAT partition is s1 after formatting

if [[ -n "$MOUNT_INFO" ]]; then
    MOUNT_POINT=$(echo "$MOUNT_INFO" | cut -d ':' -f 2- | sed 's/^[[:space:]]*//')
    # Verify the mount point corresponds to the expected partition
    if df "$MOUNT_POINT" | grep -q "$HDIUTIL_DEVICE_PART1"; then
        log "Volume appears mounted at: $MOUNT_POINT"
    else
        log "Found mount point $MOUNT_POINT but it doesn't match $HDIUTIL_DEVICE_PART1. Unmounting and retrying."
        diskutil unmount "$MOUNT_POINT" || true # Unmount whatever it is
        MOUNT_POINT="" # Reset mount point
    fi
else
    log "Volume not found mounted via diskutil info."
fi

# If not mounted correctly, try manual mount
if [[ -z "$MOUNT_POINT" ]]; then
    log "Attempting manual mount..."
    # Try mounting the first partition
    # Create a temporary mount point dir if needed
    TEMP_MOUNT_DIR=$(mktemp -d)
    diskutil mount -mountPoint "$TEMP_MOUNT_DIR" "$HDIUTIL_DEVICE_PART1" || error "Failed to manually mount ${HDIUTIL_DEVICE_PART1}"
    MOUNT_POINT="$TEMP_MOUNT_DIR"
    log "Manually mounted at: $MOUNT_POINT"
fi


if [[ -z "$MOUNT_POINT" || ! -d "$MOUNT_POINT" ]]; then
    error "Could not determine mount point for the image."
fi


# 3. Delete existing .firstrun_complete flag file (if any)
FLAG_FILE="${MOUNT_POINT}/.firstrun_complete"
if [[ -f "$FLAG_FILE" ]]; then
    log "Removing existing completion flag file: $FLAG_FILE"
    rm -f "$FLAG_FILE" || warn "Could not remove flag file $FLAG_FILE"
fi

# 4. Copy files into the mounted image
log "Copying files from repository root to $MOUNT_POINT..."
cp -v "$FIRST_RUN_SRC" "$MOUNT_POINT/" || error "Failed to copy firstrun.sh"
cp -v "$ENV_SRC" "$MOUNT_POINT/" || error "Failed to copy .env"

log "Copying setup_scripts directory..."
mkdir -p "${MOUNT_POINT}/setup_scripts" || error "mkdir setup_scripts failed"
if command -v rsync &> /dev/null; then
    rsync -a --delete "${SETUP_SCRIPTS_SRC_DIR}/" "${MOUNT_POINT}/setup_scripts/" || error "rsync setup_scripts failed"
else
    cp -a "${SETUP_SCRIPTS_SRC_DIR}/"* "${MOUNT_POINT}/setup_scripts/" || error "cp setup_scripts failed"
fi

log "Copying monitoring_app directory..."
mkdir -p "${MOUNT_POINT}/monitoring_app" || error "mkdir monitoring_app failed"
if command -v rsync &> /dev/null; then
    rsync -a --delete "${MONITORING_APP_SRC_DIR}/" "${MOUNT_POINT}/monitoring_app/" || error "rsync monitoring_app failed"
else
     cp -a "${MONITORING_APP_SRC_DIR}/"* "${MOUNT_POINT}/monitoring_app/" || error "cp monitoring_app failed"
fi

log "Copying udev_rules directory..."
mkdir -p "${MOUNT_POINT}/udev_rules" || error "mkdir udev_rules failed"
if command -v rsync &> /dev/null; then
    rsync -a --delete "${UDEV_RULES_SRC_DIR}/" "${MOUNT_POINT}/udev_rules/" || error "rsync udev_rules failed"
else
     cp -a "${UDEV_RULES_SRC_DIR}/"* "${MOUNT_POINT}/udev_rules/" || error "cp udev_rules failed"
fi

log "Syncing filesystem..."
sync

# 5. Unmount and Detach
log "Unmounting volume from $MOUNT_POINT..."
diskutil unmount "$MOUNT_POINT" || warn "Unmount failed for $MOUNT_POINT"
# Make sure the underlying device is detached
log "Detaching device $HDIUTIL_DEVICE..."
hdiutil detach "$HDIUTIL_DEVICE" || warn "hdiutil detach failed for $HDIUTIL_DEVICE"

# Clean up temp mount dir if created
if [[ -n "$TEMP_MOUNT_DIR" && -d "$TEMP_MOUNT_DIR" ]]; then
    rmdir "$TEMP_MOUNT_DIR"
fi

log "--- USB Share Image preparation complete: ${USB_IMG_PATH} ---"
exit 0