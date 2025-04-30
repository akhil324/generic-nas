#!/bin/bash

# Script to flash a Raspberry Pi OS image and apply pre-configuration
# for a headless setup, including custom first-boot scripts.
# Designed to be cross-platform (Linux/macOS).

# Exit immediately if a command exits with a non-zero status.
# set -ex
# Treat unset variables as an error when substituting.
# set -u # Disabled as grep/cut might return empty strings legitimately
# Ensure pipeline failures are caught.
set -o pipefail

# --- Configuration ---
ENV_FILE=".env" # Default name, can be overridden by argument
OS_TYPE=""
MOUNT_POINT="" # Global variable for cleanup in error handler
BOOT_PARTITION="" # Global variable for cleanup in error handler
selected_device="" # Global variable to hold the chosen device

# --- Functions ---
usage() {
  echo "Usage: $0 [-e <env_file>]"
  echo "  -e <env_file>: Path to the environment file (default: .env)"
  exit 1
}

detect_os() {
  case "$(uname -s)" in
    Linux*)  OS_TYPE="Linux" ;;
    Darwin*) OS_TYPE="Darwin" ;; # macOS
    *)       error "Unsupported operating system: $(uname -s)"; exit 1 ;;
  esac
  echo "INFO: Detected OS: $OS_TYPE"
}

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    error "This script must be run as root (use sudo)."
  fi
}

check_tools() {
  local missing=0
  local common_tools="dd mktemp openssl cp chmod grep cut sed"
  local linux_tools="lsblk partprobe mount umount realpath"
  local macos_tools="diskutil realpath"

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
    if ! command -v xzcat &> /dev/null && [[ "$(grep '^IMAGE_FILE=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')" == *.xz ]]; then
        echo "ERROR: 'xzcat' command needed for .xz image but not found. Install 'xz-utils' or similar."
        missing=1
    fi
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
    if ! command -v pv &> /dev/null; then
        echo "WARN: 'pv' command not found. Install using 'brew install pv' for better progress display on macOS."
    fi
    if ! command -v rsync &> /dev/null; then
        echo "WARN: 'rsync' command not found. Directory copy might be less efficient."
    fi
    if ! command -v xzcat &> /dev/null && [[ "$(grep '^IMAGE_FILE=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')" == *.xz ]]; then
        echo "ERROR: 'xzcat' command needed for .xz image but not found. Install 'xz' or similar (e.g., 'brew install xz')."
        missing=1
    fi
  fi

  if ! command -v openssl &> /dev/null; then
     echo "ERROR: Need 'openssl' for password hashing."
     missing=1
  fi

  if [[ "$missing" -eq 1 ]]; then
    error "Please install missing tools and try again."
  fi
}

# Error handler function for cleanup
error() {
  echo "ERROR: $1" >&2
  # Attempt cleanup if mount point exists
  if [[ -n "$MOUNT_POINT" && -d "$MOUNT_POINT" ]]; then
      echo "INFO: Attempting cleanup unmount..."
      sync || true
      if [[ "$OS_TYPE" == "Linux" ]]; then umount "$MOUNT_POINT" || true; fi
      # On macOS, unmount the partition device if known
      if [[ "$OS_TYPE" == "Darwin" && -n "$BOOT_PARTITION" ]]; then
          diskutil unmount "$BOOT_PARTITION" || true
      fi
      rmdir "$MOUNT_POINT" || true
      echo "INFO: Cleanup attempt finished."
  fi
  exit 1
}


# --- Argument Parsing
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

# --- Detect OS
detect_os

# --- Load Environment Variables

IMAGE_FILE=$(grep '^IMAGE_FILE=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SET_USERNAME=$(grep '^SET_USERNAME=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SET_PASSWORD=$(grep '^SET_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
ENABLE_SSH=$(grep '^ENABLE_SSH=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//' | tr '[:upper:]' '[:lower:]')
SSH_PUB_KEY_FILE=$(grep '^SSH_PUB_KEY_FILE=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')

# --- Validations
check_root
check_tools # Check tools after detecting OS

if [[ -z "$IMAGE_FILE" || ! -f "$IMAGE_FILE" ]]; then
  error "IMAGE_FILE ('$IMAGE_FILE') is not set or not a valid file."
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
SCRIPT_DIR=$(dirname "$(realpath "$0")") # Keep original script dir logic
if [[ ! -f "${SCRIPT_DIR}/firstrun.sh" || \
      ! -d "${SCRIPT_DIR}/setup_scripts" || \
      ! -d "${SCRIPT_DIR}/monitoring_app" || \
      ! -f "${SCRIPT_DIR}/udev_rules/99-share-automount.rules" ]]; then
    error "One or more required source files/directories (firstrun.sh, setup_scripts/, monitoring_app/, 99-share-automount.rules) not found in script directory: $SCRIPT_DIR"
fi


# --- Interactive Disk Selection ---
echo "INFO: Detecting available block devices..."
declare -a devices
declare -a device_infos

if [[ "$OS_TYPE" == "Linux" ]]; then
    # Initialize arrays
    devices=()
    device_infos=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue # Skip empty lines
        devices+=("$(echo "$line" | awk '{print $1}')")
        device_infos+=("$line")
    done < <(lsblk -d -n -p -o NAME,SIZE,MODEL | grep -v 'loop')
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # Initialize arrays
    devices=()
    device_infos=()
    # Pipe only device paths, get info inside loop
    while IFS= read -r dev_path; do
        [[ -z "$dev_path" ]] && continue # Skip empty lines
        # Get info for this specific device path
        info=$(diskutil info "$dev_path" | grep -E 'Total Size|Device / Media Name' | cut -d ':' -f2 | xargs | paste -sd ' ' -)
        devices+=("$dev_path")
        device_infos+=("$dev_path ($info)")
    done < <(diskutil list external physical | grep '^/dev/disk' | awk '{print $1}')
else
    error "Internal error: OS detection failed or unsupported OS." # Should not happen if detect_os worked
fi

if [[ ${#devices[@]} -eq 0 ]]; then
    error "No suitable external devices found."
fi

echo "INFO: Available devices:"
for i in "${!devices[@]}"; do
    printf "  [%d]\t%s\n" "$((i+1))" "${device_infos[$i]}"
done

while true; do
    read -p "Enter the number of the device to flash: " selected_device_index
    if [[ "$selected_device_index" =~ ^[0-9]+$ ]] && \
       [[ "$selected_device_index" -ge 1 ]] && \
       [[ "$selected_device_index" -le ${#devices[@]} ]]; then
        selected_device="${devices[$((selected_device_index-1))]}" # Assign selection to global variable
        echo "INFO: You selected: ${device_infos[$((selected_device_index-1))]}"
        break
    else
        echo "Invalid selection. Please enter a number between 1 and ${#devices[@]}."
    fi
done


# --- Safety Confirmation ---
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
# --- Use selected_device ---
echo "This script will ERASE ALL DATA on the device: $selected_device"
echo "It will write the image: $IMAGE_FILE"
echo "Target Username: $SET_USERNAME"
echo "--- Device Details ---"
if [[ "$OS_TYPE" == "Linux" ]]; then
    lsblk "$selected_device"
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    diskutil list "$selected_device"
fi
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
read -p "ARE YOU ABSOLUTELY SURE? Type 'YES' in uppercase to proceed: " confirmation
if [[ "$confirmation" != "YES" ]]; then
  echo "Aborted by user."
  exit 0
fi

# --- Unmount Existing Partitions ---
echo "INFO: Unmounting any existing partitions on $selected_device..."
if [[ "$OS_TYPE" == "Linux" ]]; then
    umount "${selected_device}"* &> /dev/null || true # Ignore errors if not mounted
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    diskutil unmountDisk "$selected_device" || true # Ignore errors
fi
sync
sleep 1

# --- Write Image ---
echo "INFO: Writing image '$IMAGE_FILE' to '$selected_device'..."
echo "INFO: This may take a long time."

DD_TARGET="$selected_device"
if [[ "$OS_TYPE" == "Darwin" ]]; then
    # Use raw device on macOS for potentially better performance
    RAW_TARGET="/dev/r$(basename "$selected_device")"
    if [[ -c "$RAW_TARGET" ]]; then
        DD_TARGET="$RAW_TARGET"
        echo "INFO: Using raw device $DD_TARGET on macOS."
    else
        echo "WARN: Raw device $RAW_TARGET not found, using $DD_TARGET."
    fi
fi

# Check if image is compressed
if [[ "$IMAGE_FILE" == *.xz ]]; then
    echo "INFO: Detected .xz compression. Decompressing on the fly."
    if command -v pv &> /dev/null; then
      xzcat "$IMAGE_FILE" | pv | dd of="$DD_TARGET" bs=4M conv=fsync status=none
    else
      if [[ "$OS_TYPE" == "Linux" ]]; then
        xzcat "$IMAGE_FILE" | dd of="$DD_TARGET" bs=4M conv=fsync status=progress
      elif [[ "$OS_TYPE" == "Darwin" ]]; then
        echo "INFO: 'pv' not found. Use Ctrl+T in this terminal to check dd progress."
        xzcat "$IMAGE_FILE" | dd of="$DD_TARGET" bs=4M conv=fsync
      fi
    fi
else
    # Original logic for uncompressed images
    echo "INFO: Writing uncompressed image."
    if command -v pv &> /dev/null; then
      pv "$IMAGE_FILE" | dd of="$DD_TARGET" bs=4M conv=fsync status=none
    else
      if [[ "$OS_TYPE" == "Linux" ]]; then
        dd if="$IMAGE_FILE" of="$DD_TARGET" bs=4M conv=fsync status=progress
      elif [[ "$OS_TYPE" == "Darwin" ]]; then
        echo "INFO: 'pv' not found. Use Ctrl+T in this terminal to check dd progress."
        dd if="$IMAGE_FILE" of="$DD_TARGET" bs=4M conv=fsync
      fi
    fi
fi

echo "INFO: Image write complete. Flushing buffers..."
sync
sleep 2 # Give kernel time to settle

# --- Reread Partition Table / Ensure Partitions Visible
echo "INFO: Ensuring partitions are visible..."
if [[ "$OS_TYPE" == "Linux" ]]; then
    partprobe "$selected_device" || echo "WARN: partprobe failed, continuing..."
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # macOS usually detects changes, but unmounting/remounting can help
    diskutil unmountDisk "$selected_device" || true
    sleep 3 # Give it more time
    diskutil mountDisk "$selected_device" || echo "WARN: diskutil mountDisk failed after write, continuing..."
fi
sleep 2 # Give kernel more time

# --- Identify Boot Partition ---
BOOT_PARTITION=""
if [[ "$OS_TYPE" == "Linux" ]]; then
    if [[ -b "${selected_device}1" ]]; then
        BOOT_PARTITION="${selected_device}1"
    elif [[ -b "${selected_device}p1" ]]; then
        BOOT_PARTITION="${selected_device}p1"
    fi
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # Raspberry Pi images typically use MBR or Hybrid MBR, boot is slice 1
    BOOT_PARTITION="${selected_device}s1"
    if ! diskutil list "$BOOT_PARTITION" &> /dev/null; then
         error "Could not find expected boot partition $BOOT_PARTITION on macOS."
    fi
fi

if [[ -z "$BOOT_PARTITION" ]]; then
    error "Could not automatically determine boot partition for $selected_device."
fi
echo "INFO: Determined boot partition: $BOOT_PARTITION"

# --- Mount Boot Partition ---
MOUNT_POINT=$(mktemp -d)
echo "INFO: Mounting $BOOT_PARTITION to $MOUNT_POINT..."
if [[ "$OS_TYPE" == "Linux" ]]; then
    mount "$BOOT_PARTITION" "$MOUNT_POINT" || error "Failed to mount $BOOT_PARTITION on Linux."
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # Ensure it's unmounted first (macOS might auto-mount)
    diskutil unmount "$BOOT_PARTITION" || true
    diskutil mount -mountPoint "$MOUNT_POINT" "$BOOT_PARTITION" || error "Failed to mount $BOOT_PARTITION on macOS."
fi

# --- Prepare Directories on Boot Partition ---
echo "INFO: Creating directories for setup files on boot partition..."
mkdir -p "${MOUNT_POINT}/setup_scripts" || error "Failed to create setup_scripts dir."
mkdir -p "${MOUNT_POINT}/monitoring_app/templates" || error "Failed to create monitoring_app/templates dir."
mkdir -p "${MOUNT_POINT}/udev_rules" || error "Failed to create udev_rules dir."

# --- Copy Setup Files ---
echo "INFO: Copying firstrun.sh orchestrator..."
cp "${SCRIPT_DIR}/firstrun.sh" "${MOUNT_POINT}/firstrun.sh" || error "Failed to copy firstrun.sh"
chmod +x "${MOUNT_POINT}/firstrun.sh" || error "Failed to chmod firstrun.sh"

echo "INFO: Copying sub-scripts..."
cp "${SCRIPT_DIR}/setup_scripts/setup_autologin.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_autologin.sh"
cp "${SCRIPT_DIR}/setup_scripts/setup_vpn.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_vpn.sh"
cp "${SCRIPT_DIR}/setup_scripts/manage_storage.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy manage_storage.sh"
cp "${SCRIPT_DIR}/setup_scripts/setup_filebrowser.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_filebrowser.sh"
cp "${SCRIPT_DIR}/setup_scripts/setup_monitoring.sh" "${MOUNT_POINT}/setup_scripts/" || error "Failed to copy setup_monitoring.sh"
# Make sub-scripts executable
chmod +x "${MOUNT_POINT}/setup_scripts"/* || error "Failed to chmod sub-scripts"

echo "INFO: Copying monitoring app..."
# Use rsync for directories if available, otherwise cp -a
if command -v rsync &> /dev/null; then
    rsync -a --delete "${SCRIPT_DIR}/monitoring_app/" "${MOUNT_POINT}/monitoring_app/" || error "Failed to rsync monitoring_app"
else
    cp -a "${SCRIPT_DIR}/monitoring_app/"* "${MOUNT_POINT}/monitoring_app/" || error "Failed to copy monitoring_app"
fi

echo "INFO: Copying udev rule..."
cp "${SCRIPT_DIR}/udev_rules/99-share-automount.rules" "${MOUNT_POINT}/udev_rules/" || error "Failed to copy udev rule"

echo "INFO: Copying .env configuration file..."
cp "$ENV_FILE" "${MOUNT_POINT}/.env" || error "Failed to copy $ENV_FILE"

# --- Apply Base OS Customizations (SSH, userconf)
echo "INFO: Applying base OS customizations..."

# 1. Enable SSH
if [[ "$ENABLE_SSH" == "true" ]]; then
  echo "INFO: Enabling SSH..."
  touch "$MOUNT_POINT/ssh" || touch "$MOUNT_POINT/ssh.txt" # Some older images might use ssh.txt
fi

# 2. Prepare userconf.txt (User/Password)
ENCRYPTED_PASSWORD=""
if [[ -n "$SET_PASSWORD" ]]; then
    echo "INFO: Generating encrypted password using openssl..."
    SALT=$(openssl rand -base64 8)
    ENCRYPTED_PASSWORD=$(openssl passwd -6 -salt "$SALT" "$SET_PASSWORD")
    if [[ -z "$ENCRYPTED_PASSWORD" ]]; then
        error "Failed to generate encrypted password with openssl."
    fi
    echo "INFO: Creating userconf.txt..."
    echo "${SET_USERNAME}:${ENCRYPTED_PASSWORD}" > "$MOUNT_POINT/userconf.txt" || error "Failed to write userconf.txt"
else
    echo "INFO: No password set. Creating user without password (requires SSH key or console access)."
    echo "${SET_USERNAME}:" > "$MOUNT_POINT/userconf.txt" || error "Failed to write userconf.txt" # Create user with empty password field
fi

# 3. Add SSH Public Key to firstrun.sh (if provided)
# Note: The firstrun.sh script itself now handles reading the key file path from .env
# and embedding the content. We just need to ensure the SSH_PUB_KEY_FILE variable is set correctly in .env
if [[ -n "$SSH_PUB_KEY_FILE" ]]; then
    echo "INFO: SSH Public Key file specified in .env. firstrun.sh will attempt to add it."
    if [[ ! -r "$SSH_PUB_KEY_FILE" ]]; then
        warn "Specified SSH_PUB_KEY_FILE '$SSH_PUB_KEY_FILE' is not readable. Key may not be added."
    fi
fi


# --- Modify cmdline.txt to trigger firstrun.sh ---
CMDLINE_FILE=""
FIRST_RUN_TRIGGER_PATH=""
# Check for Bookworm path first (adjust if RPi OS changes mount structure)
if [[ -f "${MOUNT_POINT}/firmware/cmdline.txt" ]]; then
    CMDLINE_FILE="${MOUNT_POINT}/firmware/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firmware/firstrun.sh" # Path as seen by Pi's systemd
elif [[ -f "${MOUNT_POINT}/cmdline.txt" ]]; then # Older path
    CMDLINE_FILE="${MOUNT_POINT}/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firstrun.sh" # Path as seen by Pi's systemd
else
    error "Cannot find cmdline.txt on boot partition ($MOUNT_POINT)."
fi

echo "INFO: Modifying $CMDLINE_FILE to trigger $FIRST_RUN_TRIGGER_PATH..."
# Check if trigger already exists
if ! grep -q "systemd.run=" "$CMDLINE_FILE"; then
  # Append the trigger to the end of the line, ensuring a space separator
  # Use sed -i.bak for macOS compatibility
  # Escape the path for sed just in case
  ESCAPED_TRIGGER_PATH=$(printf '%s\n' "$FIRST_RUN_TRIGGER_PATH" | sed 's:[][\/.^$*]:\\&:g')
  sed -i.bak 's|$| systemd.run='"$ESCAPED_TRIGGER_PATH"'|' "$CMDLINE_FILE" || error "Failed to modify cmdline.txt"
  rm -f "${CMDLINE_FILE}.bak" # Remove backup file
else
  warn "systemd.run trigger already found in $CMDLINE_FILE. Not adding again."
fi

# --- Unmount and Cleanup ---
echo "INFO: Unmounting $BOOT_PARTITION..."
sync
if [[ "$OS_TYPE" == "Linux" ]]; then
    umount "$MOUNT_POINT" || error "Failed to unmount $MOUNT_POINT on Linux."
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    diskutil unmount "$BOOT_PARTITION" || error "Failed to unmount $BOOT_PARTITION on macOS."
fi
rmdir "$MOUNT_POINT" || error "Failed to remove temporary mount point $MOUNT_POINT."
# Clear global vars after successful unmount
MOUNT_POINT=""
BOOT_PARTITION=""

echo "-----------------------------------------------------"
echo "SUCCESS: Image written and configured."
echo "Device: $selected_device"
echo "You can now remove the USB device/SD card."
echo "On first boot, the Raspberry Pi will apply remaining settings via firstrun.sh."
echo "Monitor logs in /var/log/firstrun/ on the Pi for details."
echo "-----------------------------------------------------"

exit 0