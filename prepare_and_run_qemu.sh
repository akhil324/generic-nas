#!/bin/bash

# Script to prepare a Raspberry Pi OS image file for QEMU testing.
# It decompresses, resizes, mounts, configures (like the original flash script),
# extracts boot components, and then launches QEMU.
# Designed to be cross-platform (Linux/macOS).

# --- Strict Mode ---
# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Disabled as grep/cut/parsing might return empty strings legitimately
# Ensure pipeline failures are caught.
set -o pipefail

# --- Globals ---
ENV_FILE=".env" # Default name, can be overridden by argument
OS_TYPE=""
TEMP_DIR="" # Main temporary working directory
MOUNT_POINT="" # Mount point for the boot partition
LOOP_DEVICE="" # Linux loop device (e.g., /dev/loop0)
HDIUTIL_DEVICE="" # macOS base device from hdiutil (e.g., /dev/diskN)
BOOT_PARTITION_DEVICE="" # Specific partition device (e.g., /dev/loop0p1 or /dev/diskNs1)
KEEP_TEMP_DIR=0 # Flag to keep temp dir for debugging

# --- Functions ---
usage() {
  echo "Usage: $0 [-e <env_file>] [-k]"
  echo "  -e <env_file>: Path to the environment file (default: .env)"
  echo "  -k           : Keep temporary directory on exit for debugging."
  exit 1
}

detect_os() {
  case "$(uname -s)" in
    Linux*)  OS_TYPE="Linux" ;;
    Darwin*) OS_TYPE="Darwin" ;; # macOS
    *)       error "Unsupported operating system: $(uname -s)" ;;
  esac
  log "Detected OS: $OS_TYPE"
}

check_root() {
  # Root is needed for losetup/mount on Linux, and potentially hdiutil/mount on macOS
  if [[ "$EUID" -ne 0 ]]; then
    error "This script requires root privileges (use sudo) for mounting operations."
  fi
}

check_tools() {
  local missing=0
  # Tools needed for this script specifically
  local common_tools="mktemp openssl cp chmod grep cut sed xz qemu-img qemu-system-aarch64 sync realpath"
  local linux_tools="losetup partprobe mount umount lsblk" # partprobe/kpartx might be alternatives if losetup --partscan fails
  local macos_tools="hdiutil diskutil mount umount"

  # Add rsync if available (optional enhancement)
  if command -v rsync &> /dev/null; then common_tools+=" rsync"; fi

  for tool in $common_tools; do
    if ! command -v "$tool" &> /dev/null; then
      # Provide specific hints
      if [[ "$tool" == "qemu-img" || "$tool" == "qemu-system-aarch64" ]]; then
          echo "ERROR: Required tool '$tool' not found. Install QEMU (e.g., 'sudo apt install qemu-utils qemu-system-arm' on Debian/Ubuntu, 'brew install qemu' on macOS)."
      elif [[ "$tool" == "xz" ]]; then
           echo "ERROR: Required tool '$tool' not found. Install xz-utils (Linux) or xz (macOS brew)."
      elif [[ "$tool" == "realpath" && "$OS_TYPE" == "Darwin" ]]; then
           echo "ERROR: Required tool '$tool' not found. Try 'brew install coreutils'."
      else
           echo "ERROR: Required common tool '$tool' not found."
      fi
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
        echo "ERROR: Required macOS tool '$tool' not found."
        missing=1
      fi
    done
  fi

  if [[ "$missing" -eq 1 ]]; then
    error "Please install missing tools and try again."
  fi
}

# Logging functions
_log_msg() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') $level: $*"
}
log() { _log_msg "INFO" "$@"; }
warn() { _log_msg "WARN" "$@" >&2; }
error() { _log_msg "ERROR" "$@" >&2; cleanup; exit 1; } # Error exits script after cleanup

# Cleanup function: Ensures resources are released
cleanup() {
  # Run sync before attempting unmounts/detaches
  sync || warn "Sync failed during cleanup."

  if [[ -n "$MOUNT_POINT" && -d "$MOUNT_POINT" ]]; then
    log "Cleanup: Attempting to unmount $MOUNT_POINT..."
    if [[ "$OS_TYPE" == "Linux" ]]; then
      umount "$MOUNT_POINT" || warn "Unmount $MOUNT_POINT failed (maybe already unmounted?)."
    elif [[ "$OS_TYPE" == "Darwin" && -n "$BOOT_PARTITION_DEVICE" ]]; then
      # Use the specific partition device for unmount on macOS
      diskutil unmount "$BOOT_PARTITION_DEVICE" || warn "diskutil unmount $BOOT_PARTITION_DEVICE failed (maybe already unmounted?)."
    fi
    # Attempt to remove mount point dir only if unmount likely succeeded or wasn't mounted
    rmdir "$MOUNT_POINT" || warn "Could not remove mount point directory $MOUNT_POINT (maybe not empty?)."
  fi
  MOUNT_POINT=""
  BOOT_PARTITION_DEVICE=""

  if [[ -n "$LOOP_DEVICE" && -b "$LOOP_DEVICE" ]]; then
    log "Cleanup: Detaching loop device $LOOP_DEVICE..."
    losetup -d "$LOOP_DEVICE" || warn "losetup -d $LOOP_DEVICE failed (maybe already detached?)."
  fi
  LOOP_DEVICE=""

  if [[ -n "$HDIUTIL_DEVICE" ]]; then
      # Check if the device still exists before trying to detach
      if diskutil list "$HDIUTIL_DEVICE" &>/dev/null; then
          log "Cleanup: Detaching macOS device $HDIUTIL_DEVICE..."
          hdiutil detach "$HDIUTIL_DEVICE" -force || warn "hdiutil detach $HDIUTIL_DEVICE failed (maybe already detached?)."
      else
          log "Cleanup: macOS device $HDIUTIL_DEVICE already gone."
      fi
  fi
  HDIUTIL_DEVICE=""

  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    if [[ "$KEEP_TEMP_DIR" -eq 1 ]]; then
      log "Cleanup: Keeping temporary directory: $TEMP_DIR"
    else
      log "Cleanup: Removing temporary directory $TEMP_DIR..."
      rm -rf "$TEMP_DIR" || warn "Failed to remove temporary directory $TEMP_DIR."
    fi
  fi
  TEMP_DIR=""

  log "Cleanup finished."
}

# --- Argument Parsing ---
while getopts ":e:k" opt; do
  case ${opt} in
    e ) ENV_FILE=$OPTARG ;;
    k ) KEEP_TEMP_DIR=1 ;;
    \? ) usage ;;
  esac
done
shift $((OPTIND -1))

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: Environment file '$ENV_FILE' not found." >&2
  usage
fi

# --- Setup ---
detect_os
check_root # Needed for mount/losetup/hdiutil
check_tools

# Set trap for cleanup on exit, interrupt, or termination
trap cleanup EXIT SIGINT SIGTERM

# Create secure temporary directory
TEMP_DIR=$(mktemp -d)
log "Created temporary directory: $TEMP_DIR"

# --- Load Environment Variables (from .env) ---
# Use grep/cut/sed for safety, remove potential surrounding quotes
# Using function to avoid repetition
get_env_var() {
    grep "^$1=" "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//'
}

IMAGE_FILE_XZ=$(get_env_var "IMAGE_FILE")
SET_USERNAME=$(get_env_var "SET_USERNAME")
SET_PASSWORD=$(get_env_var "SET_PASSWORD")
ENABLE_SSH=$(get_env_var "ENABLE_SSH" | tr '[:upper:]' '[:lower:]')
SSH_PUB_KEY_FILE=$(get_env_var "SSH_PUB_KEY_FILE")
# Add any other vars needed from .env for configuration steps
# SET_HOSTNAME=$(get_env_var "SET_HOSTNAME") # Example if needed later

# --- Validations (from .env) ---
if [[ -z "$IMAGE_FILE_XZ" || ! -f "$IMAGE_FILE_XZ" ]]; then
  error "IMAGE_FILE ('$IMAGE_FILE_XZ') is not set in $ENV_FILE or not a valid file."
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
# Add other validations as needed

# --- Image Preparation ---
IMAGE_FILE_RAW="${TEMP_DIR}/raspios_image.img"
log "Decompressing '$IMAGE_FILE_XZ' to '$IMAGE_FILE_RAW'..."
xz -dc "$IMAGE_FILE_XZ" > "$IMAGE_FILE_RAW" || error "Failed to decompress image."
log "Decompression complete."

log "Resizing image '$IMAGE_FILE_RAW' to 4GB..."
qemu-img resize "$IMAGE_FILE_RAW" 4G || error "Failed to resize image with qemu-img."
log "Image resized."
sync # Ensure resize operation is flushed

# --- Mount Boot Partition ---
log "Attaching image file and finding boot partition..."
MOUNT_POINT=$(mktemp -d) # Create mount point dir first

if [[ "$OS_TYPE" == "Linux" ]]; then
    # Use losetup with partscan
    LOOP_DEVICE=$(losetup --find --show --partscan "$IMAGE_FILE_RAW") || error "losetup failed for '$IMAGE_FILE_RAW'."
    log "Attached image to loop device: $LOOP_DEVICE"
    # Assume boot partition is p1. Wait a moment for the device node to appear.
    BOOT_PARTITION_DEVICE="${LOOP_DEVICE}p1"
    log "Expecting boot partition at: $BOOT_PARTITION_DEVICE"
    # Wait up to 5 seconds for the partition device node to appear
    for i in {1..5}; do
        if [[ -b "$BOOT_PARTITION_DEVICE" ]]; then
            log "Boot partition device found."
            break
        fi
        log "Waiting for $BOOT_PARTITION_DEVICE to appear... ($i/5)"
        sleep 1
    done
    if [[ ! -b "$BOOT_PARTITION_DEVICE" ]]; then
        lsblk "$LOOP_DEVICE" # Show available partitions for debugging
        error "Boot partition device $BOOT_PARTITION_DEVICE did not appear after losetup."
    fi
    # Try mounting
    log "Mounting $BOOT_PARTITION_DEVICE to $MOUNT_POINT..."
    mount "$BOOT_PARTITION_DEVICE" "$MOUNT_POINT" || error "Failed to mount $BOOT_PARTITION_DEVICE."

elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # Use hdiutil
    log "Attaching image with hdiutil..."
    # The output format can vary slightly, this tries to capture /dev/diskN
    HDIUTIL_OUTPUT=$(hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount "$IMAGE_FILE_RAW") || error "hdiutil attach failed for '$IMAGE_FILE_RAW'."
    log "hdiutil output: $HDIUTIL_OUTPUT"
    # Try to extract the base device path (e.g., /dev/disk4)
    HDIUTIL_DEVICE=$(echo "$HDIUTIL_OUTPUT" | grep -o '/dev/disk[0-9]*' | head -n 1)

    if [[ -z "$HDIUTIL_DEVICE" ]]; then
        error "Could not parse base device path from hdiutil output. Output was: $HDIUTIL_OUTPUT"
    fi
    log "Detected macOS base device: $HDIUTIL_DEVICE"
    # Assume boot partition is slice 1 (s1)
    BOOT_PARTITION_DEVICE="${HDIUTIL_DEVICE}s1"
    log "Expecting boot partition at: $BOOT_PARTITION_DEVICE"
    # Verify the partition exists using diskutil
    if ! diskutil list "$BOOT_PARTITION_DEVICE" &> /dev/null; then
         sleep 2 # Give diskutil a moment more
         if ! diskutil list "$BOOT_PARTITION_DEVICE" &> /dev/null; then
            diskutil list "$HDIUTIL_DEVICE" # Show available partitions for debugging
            error "Could not find expected boot partition $BOOT_PARTITION_DEVICE on macOS device $HDIUTIL_DEVICE."
         fi
    fi
    # Try mounting
    log "Mounting $BOOT_PARTITION_DEVICE to $MOUNT_POINT..."
    # Ensure it's unmounted first (macOS might auto-mount elsewhere)
    diskutil unmount "$BOOT_PARTITION_DEVICE" &> /dev/null || true
    diskutil mount -mountPoint "$MOUNT_POINT" "$BOOT_PARTITION_DEVICE" || error "Failed to mount $BOOT_PARTITION_DEVICE on macOS."
fi

log "Boot partition mounted successfully at $MOUNT_POINT."
sleep 1 # Small pause after mount

# --- Apply Configuration to Mounted Partition ---
log "Applying configurations to the mounted boot partition..."
SCRIPT_DIR=$(dirname "$(realpath "$0")") # Get directory where this script resides

# Check source files/dirs exist (relative to this script)
if [[ ! -f "${SCRIPT_DIR}/firstrun.sh" || \
      ! -d "${SCRIPT_DIR}/setup_scripts" || \
      ! -d "${SCRIPT_DIR}/monitoring_app" || \
      ! -f "${SCRIPT_DIR}/udev_rules/99-share-automount.rules" ]]; then
    error "One or more required source files/directories not found in script directory: $SCRIPT_DIR"
fi

# Create directories
log "Creating target directories..."
mkdir -p "${MOUNT_POINT}/setup_scripts" || error "Failed to create setup_scripts dir."
mkdir -p "${MOUNT_POINT}/monitoring_app/templates" || error "Failed to create monitoring_app/templates dir."
mkdir -p "${MOUNT_POINT}/udev_rules" || error "Failed to create udev_rules dir."

# Copy files (reuse logic from original script)
log "Copying firstrun.sh orchestrator..."
cp "${SCRIPT_DIR}/firstrun.sh" "${MOUNT_POINT}/firstrun.sh" || error "Failed to copy firstrun.sh"
chmod +x "${MOUNT_POINT}/firstrun.sh" || error "Failed to chmod firstrun.sh"

log "Copying sub-scripts..."
cp "${SCRIPT_DIR}/setup_scripts/"*.sh "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup scripts."
chmod +x "${MOUNT_POINT}/setup_scripts"/* || error "Failed to chmod sub-scripts"

log "Copying monitoring app..."
if command -v rsync &> /dev/null; then
    rsync -a --delete "${SCRIPT_DIR}/monitoring_app/" "${MOUNT_POINT}/monitoring_app/" || error "Failed to rsync monitoring_app"
else
    cp -a "${SCRIPT_DIR}/monitoring_app/"* "${MOUNT_POINT}/monitoring_app/" || error "Failed to copy monitoring_app"
fi

log "Copying udev rule..."
cp "${SCRIPT_DIR}/udev_rules/99-share-automount.rules" "${MOUNT_POINT}/udev_rules/" || error "Failed to copy udev rule"

log "Copying .env configuration file..."
cp "$ENV_FILE" "${MOUNT_POINT}/.env" || error "Failed to copy $ENV_FILE"

# Apply Base OS Customizations
log "Applying base OS customizations (SSH, userconf)..."
if [[ "$ENABLE_SSH" == "true" ]]; then
  log "Enabling SSH..."
  touch "$MOUNT_POINT/ssh" || touch "$MOUNT_POINT/ssh.txt" || error "Failed to create ssh file."
fi

# Prepare userconf.txt
ENCRYPTED_PASSWORD=""
if [[ -n "$SET_PASSWORD" ]]; then
    log "Generating encrypted password..."
    # Use head -c for better portability than /dev/urandom if available
    SALT=$(openssl rand -base64 6) # 6 bytes = 8 base64 chars, standard for sha512crypt
    ENCRYPTED_PASSWORD=$(openssl passwd -6 -salt "$SALT" "$SET_PASSWORD") || error "openssl passwd command failed."
    if [[ -z "$ENCRYPTED_PASSWORD" ]]; then
        error "Failed to generate encrypted password (openssl output empty)."
    fi
    log "Creating userconf.txt with password..."
    echo "${SET_USERNAME}:${ENCRYPTED_PASSWORD}" > "$MOUNT_POINT/userconf.txt" || error "Failed to write userconf.txt"
else
    log "Creating userconf.txt without password (SSH key required)..."
    echo "${SET_USERNAME}:" > "$MOUNT_POINT/userconf.txt" || error "Failed to write userconf.txt"
fi

# Note: SSH Public Key is handled by firstrun.sh reading .env

# Modify cmdline.txt
CMDLINE_FILE=""
FIRST_RUN_TRIGGER_PATH=""
# Check for Bookworm path first
if [[ -f "${MOUNT_POINT}/firmware/cmdline.txt" ]]; then
    CMDLINE_FILE="${MOUNT_POINT}/firmware/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firmware/firstrun.sh" # Path as seen by Pi's systemd
elif [[ -f "${MOUNT_POINT}/cmdline.txt" ]]; then # Older path
    CMDLINE_FILE="${MOUNT_POINT}/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firstrun.sh" # Path as seen by Pi's systemd
else
    error "Cannot find cmdline.txt on boot partition ($MOUNT_POINT)."
fi

log "Modifying $CMDLINE_FILE to trigger $FIRST_RUN_TRIGGER_PATH..."
if ! grep -q "systemd.run=" "$CMDLINE_FILE"; then
  ESCAPED_TRIGGER_PATH=$(printf '%s\n' "$FIRST_RUN_TRIGGER_PATH" | sed 's:[][\/.^$*]:\\&:g')
  # Use sed -i.bak for macOS compatibility
  sed -i.bak 's|$| systemd.run='"$ESCAPED_TRIGGER_PATH"'|' "$CMDLINE_FILE" || error "Failed to modify cmdline.txt"
  rm -f "${CMDLINE_FILE}.bak" # Remove backup file on success
else
  warn "systemd.run trigger already found in $CMDLINE_FILE. Not adding again."
fi
log "Configuration applied."

# --- Extract Boot Components ---
log "Extracting kernel and DTB..."
# Define expected filenames (adjust if your image uses different names)
KERNEL_FILENAME="kernel8.img" # For 64-bit RPi 4
DTB_FILENAME="bcm2711-rpi-4-b.dtb"

# Check both root and firmware subdir
KERNEL_SRC_PATH=""
DTB_SRC_PATH=""

if [[ -f "$MOUNT_POINT/firmware/$KERNEL_FILENAME" ]]; then
    KERNEL_SRC_PATH="$MOUNT_POINT/firmware/$KERNEL_FILENAME"
elif [[ -f "$MOUNT_POINT/$KERNEL_FILENAME" ]]; then
    KERNEL_SRC_PATH="$MOUNT_POINT/$KERNEL_FILENAME"
else
    error "Kernel file '$KERNEL_FILENAME' not found in $MOUNT_POINT or $MOUNT_POINT/firmware/."
fi

if [[ -f "$MOUNT_POINT/firmware/$DTB_FILENAME" ]]; then
    DTB_SRC_PATH="$MOUNT_POINT/firmware/$DTB_FILENAME"
elif [[ -f "$MOUNT_POINT/$DTB_FILENAME" ]]; then
    DTB_SRC_PATH="$MOUNT_POINT/$DTB_FILENAME"
else
    error "DTB file '$DTB_FILENAME' not found in $MOUNT_POINT or $MOUNT_POINT/firmware/."
fi

log "Found kernel: $KERNEL_SRC_PATH"
log "Found DTB: $DTB_SRC_PATH"

cp "$KERNEL_SRC_PATH" "$TEMP_DIR/" || error "Failed to copy kernel."
cp "$DTB_SRC_PATH" "$TEMP_DIR/" || error "Failed to copy DTB."
log "Kernel and DTB extracted to $TEMP_DIR."

# --- Unmount and Detach ---
log "Unmounting boot partition and detaching image..."
sync # Ensure all writes are flushed before unmount
sleep 1

if [[ "$OS_TYPE" == "Linux" ]]; then
    umount "$MOUNT_POINT" || error "Failed to unmount $MOUNT_POINT."
    losetup -d "$LOOP_DEVICE" || error "Failed to detach loop device $LOOP_DEVICE."
    LOOP_DEVICE="" # Clear var after successful detach
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    diskutil unmount "$BOOT_PARTITION_DEVICE" || error "Failed to unmount $BOOT_PARTITION_DEVICE on macOS."
    # Detach the whole disk discovered earlier
    hdiutil detach "$HDIUTIL_DEVICE" || error "Failed to detach macOS device $HDIUTIL_DEVICE."
    HDIUTIL_DEVICE="" # Clear var after successful detach
fi

rmdir "$MOUNT_POINT" || error "Failed to remove temporary mount point $MOUNT_POINT."
MOUNT_POINT="" # Clear var after successful removal
BOOT_PARTITION_DEVICE=""
log "Unmount and detach successful."

# --- Construct and Run QEMU ---
log "Constructing QEMU command..."

# Use extracted components and modified image
QEMU_KERNEL="$TEMP_DIR/$KERNEL_FILENAME"
QEMU_DTB="$TEMP_DIR/$DTB_FILENAME"
QEMU_IMAGE="$IMAGE_FILE_RAW" # Path to the modified raw image

# Base QEMU command structure from user input - adapt memory/cpu as needed
QEMU_CMD=(
    qemu-system-aarch64
    -M raspi4b
    -m 2G # Adjust memory if needed
    -cpu cortex-a72
    -smp 4 # Adjust core count if needed
    -kernel "$QEMU_KERNEL"
    -dtb "$QEMU_DTB"
    # Root partition is usually the second one (p2 for Linux view, mmcblk1p2 for guest view)
    -append "root=/dev/mmcblk1p2 rw rootwait loglevel=8 console=ttyAMA0,115200" # Added console for serial output
    -drive "file=$QEMU_IMAGE,format=raw,if=sd"
    -serial stdio # Connect guest serial to host stdio
    -netdev user,id=net0,hostfwd=tcp::2222-:22 # Forward host 2222 to guest 22 (for SSH testing)
    -device usb-net,netdev=net0
    # -device usb-kbd # Usually not needed with -serial stdio
    # -device usb-mouse # Usually not needed with -serial stdio
)

log "QEMU command:"
# Print command array elements for clarity
printf '%q ' "${QEMU_CMD[@]}"
echo # Newline

log "Starting QEMU..."
log "--- QEMU Output Starts ---"

# Execute the command array directly
"${QEMU_CMD[@]}"

QEMU_EXIT_CODE=$?
log "--- QEMU Output Ends ---"
log "QEMU exited with code $QEMU_EXIT_CODE."

# Cleanup will be handled by the trap

log "Script finished."
exit $QEMU_EXIT_CODE # Exit with QEMU's exit code