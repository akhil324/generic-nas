#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Ensure pipeline failures are caught.
set -o pipefail

# --- Configuration ---
ENV_FILE=".env" # Default name, can be overridden by argument
OS_TYPE=""

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
    *)       echo "ERROR: Unsupported operating system: $(uname -s)"; exit 1 ;;
  esac
  echo "INFO: Detected OS: $OS_TYPE"
}

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)."
    exit 1
  fi
}

check_tools() {
  local missing=0
  local common_tools="dd mktemp openssl"
  local linux_tools="lsblk partprobe mount umount"
  local macos_tools="diskutil"

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
        echo "ERROR: Required macOS tool '$tool' not found."
        missing=1
      fi
    done
    if ! command -v pv &> /dev/null; then
        echo "WARN: 'pv' command not found. Install using 'brew install pv' for better progress display on macOS."
    fi
  fi

  if ! command -v openssl &> /dev/null; then
     echo "ERROR: Need 'openssl' for password hashing."
     missing=1
  fi

  if [[ "$missing" -eq 1 ]]; then
    exit 1
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

# --- Detect OS ---
detect_os

# --- Load Environment Variables ---
TARGET_DEVICE=$(grep '^TARGET_DEVICE=' "$ENV_FILE" | cut -d '=' -f2-)
IMAGE_FILE=$(grep '^IMAGE_FILE=' "$ENV_FILE" | cut -d '=' -f2-)
SET_HOSTNAME=$(grep '^SET_HOSTNAME=' "$ENV_FILE" | cut -d '=' -f2-)
SET_USERNAME=$(grep '^SET_USERNAME=' "$ENV_FILE" | cut -d '=' -f2-)
SET_PASSWORD=$(grep '^SET_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2-)
SET_TIMEZONE=$(grep '^SET_TIMEZONE=' "$ENV_FILE" | cut -d '=' -f2-)
SET_KEYMAP=$(grep '^SET_KEYMAP=' "$ENV_FILE" | cut -d '=' -f2-)
ENABLE_SSH=$(grep '^ENABLE_SSH=' "$ENV_FILE" | cut -d '=' -f2-)
SSH_PUB_KEY_FILE=$(grep '^SSH_PUB_KEY_FILE=' "$ENV_FILE" | cut -d '=' -f2-)

# --- Validations ---
check_root
check_tools

if [[ -z "$TARGET_DEVICE" ]]; then
    echo "ERROR: TARGET_DEVICE is not set in $ENV_FILE."
    exit 1
fi

# OS-specific device validation
if [[ "$OS_TYPE" == "Linux" ]]; then
    if [[ ! -b "$TARGET_DEVICE" ]]; then
        echo "ERROR: TARGET_DEVICE ('$TARGET_DEVICE') is not a valid block device on Linux."
        echo "Use 'lsblk' to find the correct device name (e.g., /dev/sdb)."
        exit 1
    fi
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    if [[ ! "$TARGET_DEVICE" =~ ^/dev/disk[0-9]+$ ]]; then
        echo "ERROR: TARGET_DEVICE ('$TARGET_DEVICE') on macOS should be like /dev/diskN (whole disk)."
        echo "Use 'diskutil list' to find the correct identifier."
        exit 1
    fi
    if ! diskutil list "$TARGET_DEVICE" &> /dev/null; then
        echo "ERROR: TARGET_DEVICE ('$TARGET_DEVICE') not found by diskutil."
        exit 1
    fi
fi


if [[ -z "$IMAGE_FILE" || ! -f "$IMAGE_FILE" ]]; then
  echo "ERROR: IMAGE_FILE ('$IMAGE_FILE') is not set or not a valid file."
  exit 1
fi

if [[ -z "$SET_HOSTNAME" || -z "$SET_USERNAME" || -z "$SET_TIMEZONE" || -z "$SET_KEYMAP" ]]; then
    echo "ERROR: Hostname, Username, Timezone, or Keymap not set in $ENV_FILE."
    exit 1
fi

if [[ "$ENABLE_SSH" != "true" && "$ENABLE_SSH" != "false" ]]; then
    echo "ERROR: ENABLE_SSH must be 'true' or 'false'."
    exit 1
fi

if [[ -n "$SSH_PUB_KEY_FILE" && ! -f "$SSH_PUB_KEY_FILE" ]]; then
    echo "ERROR: SSH_PUB_KEY_FILE ('$SSH_PUB_KEY_FILE') is set but file not found."
    exit 1
fi

# --- Safety Confirmation ---
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "This script will ERASE ALL DATA on the device: $TARGET_DEVICE"
echo "It will write the image: $IMAGE_FILE"
echo "Target Hostname: $SET_HOSTNAME"
echo "Target Username: $SET_USERNAME"
echo "--- Device Details ---"
if [[ "$OS_TYPE" == "Linux" ]]; then
    lsblk "$TARGET_DEVICE"
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    diskutil list "$TARGET_DEVICE"
fi
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
read -p "ARE YOU ABSOLUTELY SURE? Type 'YES' in uppercase to proceed: " confirmation
if [[ "$confirmation" != "YES" ]]; then
  echo "Aborted by user."
  exit 0
fi

# --- Unmount Existing Partitions ---
echo "INFO: Unmounting any existing partitions on $TARGET_DEVICE..."
if [[ "$OS_TYPE" == "Linux" ]]; then
    umount "${TARGET_DEVICE}"* &> /dev/null || true # Ignore errors if not mounted
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    diskutil unmountDisk "$TARGET_DEVICE" || true # Ignore errors
fi
sync
sleep 1

# --- Write Image ---
echo "INFO: Writing image '$IMAGE_FILE' to '$TARGET_DEVICE'..."
echo "INFO: This may take a long time."

DD_TARGET="$TARGET_DEVICE"
if [[ "$OS_TYPE" == "Darwin" ]]; then
    # Use raw device on macOS for potentially better performance
    RAW_TARGET="/dev/r$(basename "$TARGET_DEVICE")"
    if [[ -c "$RAW_TARGET" ]]; then
        DD_TARGET="$RAW_TARGET"
        echo "INFO: Using raw device $DD_TARGET on macOS."
    else
        echo "WARN: Raw device $RAW_TARGET not found, using $DD_TARGET."
    fi
fi

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
echo "INFO: Image write complete. Flushing buffers..."
sync
sleep 2 # Give kernel time to settle

# --- Reread Partition Table / Ensure Partitions Visible ---
echo "INFO: Ensuring partitions are visible..."
if [[ "$OS_TYPE" == "Linux" ]]; then
    partprobe "$TARGET_DEVICE" || echo "WARN: partprobe failed, continuing..."
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # macOS usually detects changes, but unmounting/remounting can help
    diskutil unmountDisk "$TARGET_DEVICE" || true
    sleep 3 # Give it more time
    diskutil mountDisk "$TARGET_DEVICE" || echo "WARN: diskutil mountDisk failed after write, continuing..."
fi
sleep 2 # Give kernel more time

# --- Identify Boot Partition ---
BOOT_PARTITION=""
if [[ "$OS_TYPE" == "Linux" ]]; then
    if [[ -b "${TARGET_DEVICE}1" ]]; then
        BOOT_PARTITION="${TARGET_DEVICE}1"
    elif [[ -b "${TARGET_DEVICE}p1" ]]; then
        BOOT_PARTITION="${TARGET_DEVICE}p1"
    fi
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # Raspberry Pi images typically use MBR or Hybrid MBR, boot is slice 1
    BOOT_PARTITION="${TARGET_DEVICE}s1"
    # Verify it exists
    if ! diskutil list "$BOOT_PARTITION" &> /dev/null; then
         echo "ERROR: Could not find expected boot partition $BOOT_PARTITION on macOS."
         exit 1
    fi
fi

if [[ -z "$BOOT_PARTITION" ]]; then
    echo "ERROR: Could not automatically determine boot partition for $TARGET_DEVICE."
    if [[ "$OS_TYPE" == "Linux" ]]; then lsblk "$TARGET_DEVICE"; fi
    if [[ "$OS_TYPE" == "Darwin" ]]; then diskutil list "$TARGET_DEVICE"; fi
    exit 1
fi
echo "INFO: Determined boot partition: $BOOT_PARTITION"

# --- Mount Boot Partition ---
MOUNT_POINT=$(mktemp -d)
echo "INFO: Mounting $BOOT_PARTITION to $MOUNT_POINT..."
if [[ "$OS_TYPE" == "Linux" ]]; then
    mount "$BOOT_PARTITION" "$MOUNT_POINT"
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    # Ensure it's unmounted first (macOS might auto-mount)
    diskutil unmount "$BOOT_PARTITION" || true
    diskutil mount -mountPoint "$MOUNT_POINT" "$BOOT_PARTITION"
fi

# --- Apply Customizations ---
echo "INFO: Applying OS customizations..."

# 1. Enable SSH
if [[ "$ENABLE_SSH" == "true" ]]; then
  echo "INFO: Enabling SSH..."
  touch "$MOUNT_POINT/ssh" || touch "$MOUNT_POINT/ssh.txt" # Some older images might use ssh.txt
fi

# 2. Prepare userconf.txt (User/Password)
ENCRYPTED_PASSWORD=""
if [[ -n "$SET_PASSWORD" ]]; then
    echo "INFO: Generating encrypted password using openssl..."
    # Generate salt for openssl passwd
    SALT=$(openssl rand -base64 8)
    ENCRYPTED_PASSWORD=$(openssl passwd -6 -salt "$SALT" "$SET_PASSWORD")
    if [[ -z "$ENCRYPTED_PASSWORD" ]]; then
        echo "ERROR: Failed to generate encrypted password with openssl."
        # Cleanup before exiting
        if [[ "$OS_TYPE" == "Linux" ]]; then umount "$MOUNT_POINT"; fi
        if [[ "$OS_TYPE" == "Darwin" ]]; then diskutil unmount "$BOOT_PARTITION" || true; fi
        rmdir "$MOUNT_POINT"
        exit 1
    fi
    echo "INFO: Creating userconf.txt..."
    echo "${SET_USERNAME}:${ENCRYPTED_PASSWORD}" > "$MOUNT_POINT/userconf.txt"
else
    echo "INFO: No password set. Creating user without password (requires SSH key or console access)."
    echo "${SET_USERNAME}:" > "$MOUNT_POINT/userconf.txt" # Create user with empty password field
fi

# 3. Prepare firstrun.sh for other settings
echo "INFO: Creating firstrun.sh for hostname, locale, keymap, timezone, and SSH key..."
# --- firstrun.sh content (runs on Pi, so uses Linux commands) ---
cat << EOF > "$MOUNT_POINT/firstrun.sh"
#!/bin/bash
# This script runs once on first boot, triggered by cmdline.txt

echo "INFO (firstrun.sh): Applying system configurations..."

# Set Hostname
echo "INFO (firstrun.sh): Setting hostname to $SET_HOSTNAME..."
hostnamectl set-hostname "$SET_HOSTNAME" || echo "WARN (firstrun.sh): Failed to set hostname."

# Set Timezone
echo "INFO (firstrun.sh): Setting timezone to $SET_TIMEZONE..."
timedatectl set-timezone "$SET_TIMEZONE" || echo "WARN (firstrun.sh): Failed to set timezone."

# Set Keymap
echo "INFO (firstrun.sh): Setting keymap to $SET_KEYMAP..."
localectl set-keymap "$SET_KEYMAP" || echo "WARN (firstrun.sh): Failed to set keymap."

# Add SSH Public Key if provided
# Note: SSH_PUB_KEY_FILE path is from the host machine where the script runs
# We need to embed the key content directly into firstrun.sh
SSH_PUB_KEY_CONTENT=""
if [[ -n "$SSH_PUB_KEY_FILE" && -f "$SSH_PUB_KEY_FILE" ]]; then
  # Read key content, handle potential special characters for embedding
  SSH_PUB_KEY_CONTENT=\$(cat "$SSH_PUB_KEY_FILE")
fi

if [[ -n "\$SSH_PUB_KEY_CONTENT" ]]; then
  echo "INFO (firstrun.sh): Adding SSH public key for user $SET_USERNAME..."
  USER_HOME="/home/${SET_USERNAME}"
  # Ensure home directory exists (might not on very first boot stage)
  if [[ ! -d "\$USER_HOME" ]]; then
      mkdir -p "\$USER_HOME"
      chown "${SET_USERNAME}:${SET_USERNAME}" "\$USER_HOME"
  fi
  mkdir -p "\$USER_HOME/.ssh"
  chmod 700 "\$USER_HOME/.ssh"
  echo "\$SSH_PUB_KEY_CONTENT" >> "\$USER_HOME/.ssh/authorized_keys"
  chmod 600 "\$USER_HOME/.ssh/authorized_keys"
  # Ensure ownership is correct, might need to run later in boot process if user isn't fully set up yet
  chown -R "${SET_USERNAME}:${SET_USERNAME}" "\$USER_HOME/.ssh" || echo "WARN (firstrun.sh): Failed to chown SSH directory. May need manual fix."
fi

# Self-destruct mechanism
echo "INFO (firstrun.sh): Configuration complete. Removing firstrun.sh trigger from cmdline.txt..."
# Determine correct cmdline.txt path within the Pi's filesystem
CMDLINE_PATH=""
if [[ -f /boot/firmware/cmdline.txt ]]; then # RPi OS >= Bookworm path
    CMDLINE_PATH="/boot/firmware/cmdline.txt"
    FIRST_RUN_PATH="/boot/firmware/firstrun.sh"
elif [[ -f /boot/cmdline.txt ]]; then # Older RPi OS path
    CMDLINE_PATH="/boot/cmdline.txt"
    FIRST_RUN_PATH="/boot/firstrun.sh"
fi

if [[ -n "\$CMDLINE_PATH" ]]; then
    # Remove the trigger using sed. Use a different delimiter for sed just in case paths contain '/'
    sed -i "s| systemd.run=\$FIRST_RUN_PATH||" "\$CMDLINE_PATH"
    # Remove the script itself
    rm -f "\$FIRST_RUN_PATH"
else
    echo "WARN (firstrun.sh): Could not find cmdline.txt to remove trigger."
fi

echo "INFO (firstrun.sh): Script finished."
# No reboot here, let the normal boot process continue

exit 0
EOF
# --- End of firstrun.sh content ---

chmod +x "$MOUNT_POINT/firstrun.sh"

# 4. Modify cmdline.txt to trigger firstrun.sh
CMDLINE_FILE=""
FIRST_RUN_TRIGGER_PATH=""
# Check for Bookworm path first
if [[ -f "$MOUNT_POINT/firmware/cmdline.txt" ]]; then
    CMDLINE_FILE="$MOUNT_POINT/firmware/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firmware/firstrun.sh" # Path as seen by Pi's systemd
elif [[ -f "$MOUNT_POINT/cmdline.txt" ]]; then # Older path
    CMDLINE_FILE="$MOUNT_POINT/cmdline.txt"
    FIRST_RUN_TRIGGER_PATH="/boot/firstrun.sh" # Path as seen by Pi's systemd
else
    echo "ERROR: Cannot find cmdline.txt on boot partition ($MOUNT_POINT)."
    # Cleanup before exiting
    if [[ "$OS_TYPE" == "Linux" ]]; then umount "$MOUNT_POINT"; fi
    if [[ "$OS_TYPE" == "Darwin" ]]; then diskutil unmount "$BOOT_PARTITION" || true; fi
    rmdir "$MOUNT_POINT"
    exit 1
fi

echo "INFO: Modifying $CMDLINE_FILE to trigger firstrun.sh..."
# Check if trigger already exists (e.g., from previous failed run)
if ! grep -q "systemd.run=" "$CMDLINE_FILE"; then
  # Append the trigger to the end of the line, ensuring a space separator
  sed -i.bak 's|$| systemd.run='"$FIRST_RUN_TRIGGER_PATH"'|' "$CMDLINE_FILE"
  rm -f "${CMDLINE_FILE}.bak" # Remove backup file created by sed -i on macOS
else
  echo "WARN: systemd.run trigger already found in $CMDLINE_FILE. Not adding again."
fi

# --- Unmount and Cleanup ---
echo "INFO: Unmounting $BOOT_PARTITION..."
sync
if [[ "$OS_TYPE" == "Linux" ]]; then
    umount "$MOUNT_POINT"
elif [[ "$OS_TYPE" == "Darwin" ]]; then
    diskutil unmount "$BOOT_PARTITION" || echo "WARN: Failed to unmount $BOOT_PARTITION cleanly."
fi
rmdir "$MOUNT_POINT"

echo "-----------------------------------------------------"
echo "SUCCESS: Image written and configured."
echo "Device: $TARGET_DEVICE"
echo "You can now remove the USB device/SD card."
echo "On first boot, the Raspberry Pi will apply remaining settings (hostname, timezone, etc.)."
echo "-----------------------------------------------------"

exit 0