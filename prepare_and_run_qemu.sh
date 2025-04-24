#!/bin/bash

# Script to prepare a Raspberry Pi OS image file with first-boot
# configurations and run it directly in QEMU for testing.

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Disabled as grep/cut might return empty strings legitimately
# Ensure pipeline failures are caught.
set -o pipefail

# --- Configuration ---
ENV_FILE=".env" # Default name, can be overridden by argument
OS_TYPE=""
TEMP_DIR="" # Global for cleanup
MOUNT_POINT="" # Global for cleanup
LOOP_DEVICE="" # Linux specific, for cleanup
HDIUTIL_DEVICE="" # macOS specific, for cleanup
BOOT_PARTITION_DEVICE="" # Device node for boot partition (e.g., /dev/mapper/loop0p1 or /dev/diskXs1)

# --- Functions ---
usage() {
  echo "Usage: $0 [-e <env_file>]"
  echo "  -e <env_file>: Path to the environment file (default: .env)"
  exit 1
}

cleanup() {
  local exit_status=$?
  echo "--- Running cleanup ---"
  # Attempt unmounts first
  if [[ -n "$MOUNT_POINT" && -d "$MOUNT_POINT" ]]; then
    sync || true
    if [[ "$OS_TYPE" == "Linux" && -n "$BOOT_PARTITION_DEVICE" ]]; then
      echo "INFO: Unmounting $MOUNT_POINT (Linux)..."
      umount "$MOUNT_POINT" || echo "WARN: Unmount $MOUNT_POINT failed (maybe already unmounted)."
    elif [[ "$OS_TYPE" == "Darwin" && -n "$BOOT_PARTITION_DEVICE" ]]; then
      echo "INFO: Unmounting $BOOT_PARTITION_DEVICE (macOS)..."
      diskutil unmount "$BOOT_PARTITION_DEVICE" || echo "WARN: Unmount $BOOT_PARTITION_DEVICE failed (maybe already unmounted)."
    fi
    sleep 1 # Give time for unmount
  fi

  # Detach loop/hdiutil device
  if [[ "$OS_TYPE" == "Linux" && -n "$LOOP_DEVICE" ]]; then
    echo "INFO: Detaching partitions from $LOOP_DEVICE (kpartx)..."
    kpartx -d "$LOOP_DEVICE" || echo "WARN: kpartx -d $LOOP_DEVICE failed."
    sleep 1
    echo "INFO: Detaching loop device $LOOP_DEVICE (losetup)..."
    losetup -d "$LOOP_DEVICE" || echo "WARN: losetup -d $LOOP_DEVICE failed."
  elif [[ "$OS_TYPE" == "Darwin" && -n "$HDIUTIL_DEVICE" ]]; then
    echo "INFO: Detaching image device $HDIUTIL_DEVICE (hdiutil)..."
    hdiutil detach "$HDIUTIL_DEVICE" -force || echo "WARN: hdiutil detach $HDIUTIL_DEVICE failed."
  fi

  # Remove temp directory
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    echo "INFO: Removing temporary directory $TEMP_DIR..."
    rm -rf "$TEMP_DIR"
  fi

  if [[ $exit_status -ne 0 ]]; then
      echo "ERROR: Script exited with status $exit_status"
  fi
  echo "--- Cleanup finished ---"
  exit $exit_status
}

# Register cleanup function to run on EXIT signal
trap cleanup EXIT

error() {
  echo "ERROR: $1" >&2
  # Cleanup function will be called automatically via trap
  exit 1
}

detect_os() {
  case "$(uname -s)" in
    Linux*)  OS_TYPE="Linux" ;;
    Darwin*) OS_TYPE="Darwin" ;; # macOS
    *)       error "Unsupported operating system: $(uname -s)" ;;
  esac
  echo "INFO: Detected OS: $OS_TYPE"
}

check_tools() {
  local missing=0
  # Tools needed by this script specifically
  local common_tools="mktemp openssl cp chmod grep cut sed xz qemu-img qemu-system-aarch64"
  local linux_tools="losetup kpartx mount umount realpath"
  local macos_tools="hdiutil diskutil realpath" # realpath might need 'brew install coreutils'

  for tool in $common_tools; do
    if ! command -v "$tool" &> /dev/null; then
      echo "ERROR: Required common tool '$tool' not found."
      missing=1
    fi
  done

  if [[ "$OS_TYPE" == "Linux" ]]; then
    for tool in $linux_tools; do
      if ! command -v "$tool" &> /dev/null; then
        echo "ERROR: Required Linux tool '$tool' not found."
        missing=1
      fi
    done
  elif [[ "$OS_TYPE" == "Darwin" ]]; then
    for tool in $macos_tools; do
      if ! command -v "$tool" &> /dev/null; then
        if [[ "$tool" == "realpath" ]]; then
             echo "ERROR: Required macOS tool '$tool' not found. Try 'brew install coreutils'."
        else
             echo "ERROR: Required macOS tool '$tool' not found."
        fi
        missing=1
      fi
    done
     if ! command -v rsync &> /dev/null; then
        echo "WARN: 'rsync' command not found. Directory copy might be less efficient."
    fi
  fi

  if [[ "$missing" -eq 1 ]]; then
    error "Please install missing tools and try again."
  fi
}

# --- Argument Parsing ---
while getopts ":e:" opt; do
  case ${opt} in
    e ) ENV_FILE=$OPTARG ;;
    \? ) usage ;;
  esac
done
shift $((OPTIND -1))

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Environment file '$ENV_FILE' not found."
  usage
fi

# --- Detect OS & Check Tools ---
detect_os
check_tools # Check tools after detecting OS

# --- Load Environment Variables (from original script, slightly adapted) ---
# Use grep/cut for safety, remove potential surrounding quotes
IMAGE_FILE_XZ=$(grep '^IMAGE_FILE=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SET_USERNAME=$(grep '^SET_USERNAME=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SET_PASSWORD=$(grep '^SET_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
ENABLE_SSH=$(grep '^ENABLE_SSH=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//' | tr '[:upper:]' '[:lower:]')
SSH_PUB_KEY_FILE=$(grep '^SSH_PUB_KEY_FILE=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
# Add other variables from .env as needed by firstrun.sh/sub-scripts

# --- Validations ---
if [[ -z "$IMAGE_FILE_XZ" || ! -f "$IMAGE_FILE_XZ" ]]; then
  error "IMAGE_FILE ('$IMAGE_FILE_XZ') is not set or not a valid file in $ENV_FILE."
fi
if [[ ! "$IMAGE_FILE_XZ" == *.xz ]]; then
    error "IMAGE_FILE ('$IMAGE_FILE_XZ') must be an .xz compressed image."
fi
if [[ -z "$SET_USERNAME" ]]; then
    error "SET_USERNAME not set in $ENV_FILE."
fi
if [[ "$ENABLE_SSH" != "true" && "$ENABLE_SSH" != "false" ]]; then
    error "ENABLE_SSH must be 'true' or 'false'."
fi
if [[ -n "$SSH_PUB_KEY_FILE" && ! -f "$SSH_PUB_KEY_FILE" ]]; then
    error "SSH_PUB_KEY_FILE ('$SSH_PUB_KEY_FILE') is set but file not found."
fi

# Check existence of source scripts/dirs relative to this script
SCRIPT_DIR=$(dirname "$(realpath "$0")")
if [[ ! -f "${SCRIPT_DIR}/firstrun.sh" || \
      ! -d "${SCRIPT_DIR}/setup_scripts" || \
      ! -d "${SCRIPT_DIR}/monitoring_app" || \
      ! -f "${SCRIPT_DIR}/udev_rules/99-share-automount.rules" ]]; then
    error "One or more required source files/directories (firstrun.sh, setup_scripts/, monitoring_app/, 99-share-automount.rules) not found in script directory: $SCRIPT_DIR"
fi

# --- Prepare Temporary Environment ---
TEMP_DIR=$(mktemp -d)
echo "INFO: Using temporary directory: $TEMP_DIR"
RAW_IMG_FILE="$TEMP_DIR/raspios_image.img"
KERNEL_FILE="$TEMP_DIR/kernel8.img"
DTB_FILE="$TEMP_DIR/bcm2711-rpi-4-b.dtb" # Assuming RPi4 DTB

# --- Decompress Image ---
echo "INFO: Decompressing '$IMAGE_FILE_XZ' to '$RAW_IMG_FILE'..."
xz -dkc "$IMAGE_FILE_XZ" > "$RAW_IMG_FILE" || error "Failed to decompress image."
echo "INFO: Decompression complete."

# --- Resize Image (Optional but requested) ---
echo "INFO: Resizing image file to 4GB..."
qemu-img resize "$RAW_IMG_FILE" 4G || error "Failed to resize image with qemu-img."
echo "INFO: Image resized."

# --- Mount Boot Partition ---
MOUNT_POINT="$TEMP_DIR/boot_mnt"
mkdir -p "$MOUNT_POINT" || error "Failed to create mount point $MOUNT_POINT"

echo "INFO: Setting up mount for boot partition..."
if [[ "$OS_TYPE" == "Linux" ]]; then
    echo "INFO: Setting up loop device (Linux)..."
    LOOP_DEVICE=$(losetup --find --show "$RAW_IMG_FILE") || error "Failed to setup loop device."
    echo "INFO: Loop device created: $LOOP_DEVICE"
    sleep 2 # Give kernel time to recognize the device
    echo "INFO: Mapping partitions using kpartx..."
    # kpartx output goes to stderr sometimes, redirect to capture it
    # Use -n to avoid read-only mapping if possible, though mount options matter more
    kpartx_output=$(kpartx -av "$LOOP_DEVICE" 2>&1) || error "kpartx failed to map partitions. Output: $kpartx_output"
    echo "INFO: kpartx output: $kpartx_output"
    # Extract the first partition device name (e.g., loop0p1)
    # Assuming boot is the first partition
    BOOT_PARTITION_DEVICE="/dev/mapper/$(basename "$LOOP_DEVICE")p1"
    if ! ls "$BOOT_PARTITION_DEVICE" > /dev/null 2>&1; then
        # Try without 'p' prefix if needed (older kpartx?)
        BOOT_PARTITION_DEVICE="/dev/mapper/$(basename "$LOOP_DEVICE")1"
        if ! ls "$BOOT_PARTITION_DEVICE" > /dev/null 2>&1; then
           error "Could not find mapped boot partition device for $LOOP_DEVICE. Check kpartx output."
        fi
    fi
    echo "INFO: Determined boot partition device: $BOOT_PARTITION_DEVICE"
    sleep 3 # Give system time for device nodes to settle
    echo "INFO: Mounting $BOOT_PARTITION_DEVICE to $MOUNT_POINT..."
    mount "$BOOT_PARTITION_DEVICE" "$MOUNT_POINT" || error "Failed to mount $BOOT_PARTITION_DEVICE"

# --- Mount Boot Partition --- (macOS part revised)
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    echo "INFO: Attaching image with hdiutil (macOS)..."
    hdiutil_output=$(hdiutil attach -nomount -plist "$RAW_IMG_FILE") || error "hdiutil attach failed."

    echo "DEBUG: hdiutil output:"
    echo "$hdiutil_output" # Add debug output

    # Revised parsing: Find the dict with 'partitions', then get its 'dev-entry'
    HDIUTIL_DEVICE=$(echo "$hdiutil_output" | plutil -convert xml1 -o - - | \
                     xmllint --xpath 'string(//dict[key="partitions"]/string[preceding-sibling::key[1]="dev-entry"])' - 2>/dev/null)

    if [[ -z "$HDIUTIL_DEVICE" ]]; then
        # Fallback or alternative parsing if the above fails?
        # Maybe try extracting all dev-entries and picking the shortest one (e.g., /dev/diskX vs /dev/diskXsY)?
        echo "WARN: Primary XPath failed to find HDIUTIL_DEVICE. Trying alternative..."
        ALL_DEVS=$(echo "$hdiutil_output" | plutil -convert xml1 -o - - | xmllint --xpath '//key[text()="dev-entry"]/following-sibling::string[1]' - 2>/dev/null | sed 's/<string>//g; s/<\/string>/\n/g' | grep '^/dev/disk[0-9]*$')
        # Select the shortest path matching /dev/diskN
        HDIUTIL_DEVICE=$(echo "$ALL_DEVS" | awk '{ print length, $0 }' | sort -n | head -1 | cut -d' ' -f2-)

        if [[ -z "$HDIUTIL_DEVICE" ]]; then
           error "Could not determine device path from hdiutil output using primary or alternative methods. Raw output was:\n$hdiutil_output"
        fi
        echo "INFO: Used alternative parsing method to find device: $HDIUTIL_DEVICE"
    fi

    # Validate the device path format
    if [[ ! "$HDIUTIL_DEVICE" =~ ^/dev/disk[0-9]+$ ]]; then
        error "Parsed HDIUTIL_DEVICE ('$HDIUTIL_DEVICE') does not look like a valid whole disk path (/dev/diskN)."
    fi

    echo "INFO: Image attached as whole disk: $HDIUTIL_DEVICE"
    # Assume boot partition is slice 1 of the whole disk
    BOOT_PARTITION_DEVICE="${HDIUTIL_DEVICE}s1"
    echo "INFO: Determined boot partition device: $BOOT_PARTITION_DEVICE"

    # Add a check to see if the partition device actually exists before mounting
    echo "INFO: Checking existence of $BOOT_PARTITION_DEVICE..."
    if ! diskutil list "$BOOT_PARTITION_DEVICE" &> /dev/null; then
        echo "ERROR: Boot partition device $BOOT_PARTITION_DEVICE does not seem to exist. Listing devices attached by hdiutil:"
        diskutil list "$HDIUTIL_DEVICE"
        # Maybe list all disks for context?
        # diskutil list
        error "Cannot proceed without a valid boot partition device."
    fi
    echo "INFO: Boot partition device $BOOT_PARTITION_DEVICE found."

    sleep 3 # Give system time
    echo "INFO: Mounting $BOOT_PARTITION_DEVICE to $MOUNT_POINT..."
    diskutil mount -mountPoint "$MOUNT_POINT" "$BOOT_PARTITION_DEVICE" || error "Failed to mount $BOOT_PARTITION_DEVICE"
fi
echo "INFO: Boot partition mounted successfully."
sleep 3 # Wait after mount as requested

# --- Extract Kernel and DTB ---
echo "INFO: Extracting Kernel and DTB..."
# Check for firmware subdir first
BOOT_PREFIX="${MOUNT_POINT}"
if [[ -d "${MOUNT_POINT}/firmware" ]]; then
    BOOT_PREFIX="${MOUNT_POINT}/firmware"
    echo "INFO: Using firmware subdirectory path: ${BOOT_PREFIX}"
fi

if [[ -f "${BOOT_PREFIX}/kernel8.img" ]]; then
    cp "${BOOT_PREFIX}/kernel8.img" "$KERNEL_FILE" || error "Failed to copy kernel8.img"
else
    error "kernel8.img not found in ${BOOT_PREFIX}/"
fi

if [[ -f "${BOOT_PREFIX}/bcm2711-rpi-4-b.dtb" ]]; then
    cp "${BOOT_PREFIX}/bcm2711-rpi-4-b.dtb" "$DTB_FILE" || error "Failed to copy bcm2711-rpi-4-b.dtb"
else
     error "bcm2711-rpi-4-b.dtb not found in ${BOOT_PREFIX}/"
fi
echo "INFO: Kernel and DTB extracted."

# --- Apply Configurations to Mounted Boot Partition ---
# (Reusing logic from flash_and_configure_crossplatform.sh, targeting MOUNT_POINT)

echo "INFO: Creating directories for setup files on boot partition..."
mkdir -p "${MOUNT_POINT}/setup_scripts" || error "Failed to create setup_scripts dir."
mkdir -p "${MOUNT_POINT}/monitoring_app/templates" || error "Failed to create monitoring_app/templates dir."
mkdir -p "${MOUNT_POINT}/udev_rules" || error "Failed to create udev_rules dir."

echo "INFO: Copying firstrun.sh orchestrator..."
cp "${SCRIPT_DIR}/firstrun.sh" "${MOUNT_POINT}/firstrun.sh" || error "Failed to copy firstrun.sh"
chmod +x "${MOUNT_POINT}/firstrun.sh" || error "Failed to chmod firstrun.sh"

echo "INFO: Copying sub-scripts..."
cp "${SCRIPT_DIR}/setup_scripts/setup_autologin.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_autologin.sh"
cp "${SCRIPT_DIR}/setup_scripts/setup_vpn.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_vpn.sh"
cp "${SCRIPT_DIR}/setup_scripts/manage_storage.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy manage_storage.sh"
cp "${SCRIPT_DIR}/setup_scripts/setup_filebrowser.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_filebrowser.sh"
cp "${SCRIPT_DIR}/setup_scripts/setup_monitoring.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_monitoring.sh"
chmod +x "${MOUNT_POINT}/setup_scripts"/* || error "Failed to chmod sub-scripts"

echo "INFO: Copying monitoring app..."
if command -v rsync &> /dev/null; then
    rsync -a --delete "${SCRIPT_DIR}/monitoring_app/" "${MOUNT_POINT}/monitoring_app/" || error "Failed to rsync monitoring_app"
else
    cp -a "${SCRIPT_DIR}/monitoring_app/"* "${MOUNT_POINT}/monitoring_app/" || error "Failed to copy monitoring_app"
fi

echo "INFO: Copying udev rule..."
cp "${SCRIPT_DIR}/udev_rules/99-share-automount.rules" "${MOUNT_POINT}/udev_rules/" || error "Failed to copy udev rule"

echo "INFO: Copying .env configuration file..."
cp "$ENV_FILE" "${MOUNT_POINT}/.env" || error "Failed to copy $ENV_FILE"

echo "INFO: Applying base OS customizations..."
if [[ "$ENABLE_SSH" == "true" ]]; then
  echo "INFO: Enabling SSH..."
  touch "${MOUNT_POINT}/ssh" || touch "${MOUNT_POINT}/ssh.txt"
fi

ENCRYPTED_PASSWORD=""
if [[ -n "$SET_PASSWORD" ]]; then
    echo "INFO: Generating encrypted password..."
    SALT=$(openssl rand -base64 8)
    ENCRYPTED_PASSWORD=$(openssl passwd -6 -salt "$SALT" "$SET_PASSWORD")
    if [[ -z "$ENCRYPTED_PASSWORD" ]]; then
        error "Failed to generate encrypted password."
    fi
    echo "INFO: Creating userconf.txt..."
    echo "${SET_USERNAME}:${ENCRYPTED_PASSWORD}" > "${MOUNT_POINT}/userconf.txt" || error "Failed to write userconf.txt"
else
    echo "INFO: No password set. Creating user without password."
    echo "${SET_USERNAME}:" > "${MOUNT_POINT}/userconf.txt" || error "Failed to write userconf.txt"
fi

if [[ -n "$SSH_PUB_KEY_FILE" ]]; then
    echo "INFO: SSH Public Key file specified. firstrun.sh will handle adding it."
    if [[ ! -r "$SSH_PUB_KEY_FILE" ]]; then
        echo "WARN: Specified SSH_PUB_KEY_FILE '$SSH_PUB_KEY_FILE' is not readable by this script."
    fi
fi

CMDLINE_FILE=""
FIRST_RUN_TRIGGER_PATH=""
# Check for Bookworm path first (relative to mount point)
if [[ -f "${MOUNT_POINT}/firmware/cmdline.txt" ]]; then
    CMDLINE_FILE="${MOUNT_POINT}/firmware/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firmware/firstrun.sh" # Path as seen by Pi's systemd
elif [[ -f "${MOUNT_POINT}/cmdline.txt" ]]; then # Older path
    CMDLINE_FILE="${MOUNT_POINT}/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firstrun.sh" # Path as seen by Pi's systemd
else
    error "Cannot find cmdline.txt in mounted boot partition ($MOUNT_POINT)."
fi

echo "INFO: Modifying $CMDLINE_FILE to trigger $FIRST_RUN_TRIGGER_PATH..."
if ! grep -q "systemd.run=" "$CMDLINE_FILE"; then
  ESCAPED_TRIGGER_PATH=$(printf '%s\n' "$FIRST_RUN_TRIGGER_PATH" | sed 's:[][\/.^$*]:\\&:g')
  # Create backup for safety during modification
  cp "$CMDLINE_FILE" "$CMDLINE_FILE.bak"
  sed 's|$| systemd.run='"$ESCAPED_TRIGGER_PATH"'|' "$CMDLINE_FILE.bak" > "$CMDLINE_FILE" || error "Failed to modify cmdline.txt"
  rm -f "${CMDLINE_FILE}.bak"
else
  echo "WARN: systemd.run trigger already found in $CMDLINE_FILE. Not adding again."
fi
echo "INFO: Configuration applied to boot partition."

# --- Unmount and Detach ---
echo "INFO: Unmounting boot partition..."
sync
if [[ "$OS_TYPE" == "Linux" ]]; then
    umount "$MOUNT_POINT" || error "Failed to unmount $MOUNT_POINT (Linux)"
    # kpartx/losetup detachment happens in cleanup trap
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # Store device path before potentially clearing it
    device_to_detach="$HDIUTIL_DEVICE"
    partition_to_unmount="$BOOT_PARTITION_DEVICE"

    diskutil unmount "$partition_to_unmount" || error "Failed to unmount $partition_to_unmount (macOS)"

    # <<< ADD EXPLICIT DETACH HERE >>>
    if [[ -n "$device_to_detach" ]]; then
        echo "INFO: Explicitly detaching image device $device_to_detach before QEMU..."
        hdiutil detach "$device_to_detach" -force || echo "WARN: Explicit hdiutil detach failed (maybe already detached?)."
        # Clear HDIUTIL_DEVICE so cleanup trap doesn't try again redundantly / error out
        HDIUTIL_DEVICE=""
    else
        echo "WARN: No HDIUTIL device was recorded, cannot explicitly detach."
    fi
fi
# Clear mount-related variables so cleanup doesn't try again on normal exit
BOOT_PARTITION_DEVICE=""
# Keep LOOP_DEVICE set for Linux cleanup trap

echo "INFO: Boot partition unmounted and image detached (if macOS)."
sleep 3 # Wait after unmount/detach for safety

# --- Construct and Run QEMU Command ---
echo "-----------------------------------------------------"
echo "INFO: Preparing to launch QEMU..."
echo "  Image: $RAW_IMG_FILE"
echo "  Kernel: $KERNEL_FILE"
echo "  DTB: $DTB_FILE"
echo "-----------------------------------------------------"

# Construct the command
QEMU_CMD=(
    qemu-system-aarch64
    -M raspi4b
    -m 2G # Adjust memory as needed
    -cpu cortex-a72
    -smp 4
    -kernel "$KERNEL_FILE"
    -dtb "$DTB_FILE"
    -append "root=/dev/mmcblk1p2 rw rootwait loglevel=8 console=ttyAMA0,115200" # Added console for serial output
    -drive "file=$RAW_IMG_FILE,format=raw,if=sd,id=hd0"
    -serial stdio # Redirect serial console to terminal
    -netdev user,id=net0,hostfwd=tcp::10022-:22 # Forward host port 10022 to guest port 22 (SSH)
    -device usb-net,netdev=net0
    # Add other devices if needed (e.g., USB storage for testing automount)
    # -drive file=my-usb-test.img,format=raw,if=none,id=usbstick
    # -device usb-storage,drive=usbstick
    # -nographic # Use if you only want serial console, remove -device usb-kbd/mouse if added
)

echo "INFO: Executing QEMU command:"
# Print command for debugging, quoting arguments appropriately
printf "%q " "${QEMU_CMD[@]}"
echo # Newline after command

# Execute QEMU
"${QEMU_CMD[@]}"

# QEMU will run until explicitly closed.
# The cleanup trap will run when QEMU exits or the script is interrupted.

echo "INFO: QEMU exited."
# Normal exit, cleanup trap will still run.
exit 0