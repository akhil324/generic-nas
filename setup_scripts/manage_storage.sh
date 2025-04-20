#!/bin/bash

# This script manages mounting USB storage partitions and configuring Samba shares.
# It can be run in two modes:
# 1. No arguments: Scans all non-OS disks (intended for first boot).
# 2. Argument $1: Processes a specific partition device name (intended for udev trigger).

# Exit immediately if a command exits with a non-zero status.
# set -e # Disable 'exit on error' globally, handle errors within functions
# Treat unset variables as an error when substituting.
# set -u # Disable temporarily for grep/cut
# Ensure pipeline failures are caught.
set -o pipefail

# --- Configuration & Constants ---
ENV_FILE="/boot/firmware/.env" # Path to the config file on the Pi's boot partition
FSTAB_FILE="/etc/fstab"
SAMBA_CONF_FILE="/etc/samba/smb.conf"
SAMBA_SHARES_DIR="/etc/samba/shares.d"
LOG_FILE="/var/log/manage_storage.log"
MAX_LOG_SIZE=1048576 # 1MB max log size

# --- Logging ---
# Rotate log file if it exceeds max size
if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE") -gt $MAX_LOG_SIZE ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.1" || true
fi
# Redirect stdout and stderr to log file and also to console if running interactively
exec > >(tee -a "$LOG_FILE") 2>&1
# Note: udev runs scripts detached, so console output might not be visible there.

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1"
}

warn() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN: $1" >&2
}

error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: $1" >&2
  # Don't exit globally with set -e, return error code from functions
}

# --- Helper Functions ---
# Check if a package is installed
is_pkg_installed() {
    dpkg -s "$1" &> /dev/null
    return $?
}

# Install packages if not already installed
install_packages() {
    local missing_pkgs=()
    for pkg in "$@"; do
        if ! is_pkg_installed "$pkg"; then
            missing_pkgs+=("$pkg")
        fi
    done

    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        log "Attempting to install missing packages: ${missing_pkgs[*]}"
        # Run apt update only if installing something
        apt-get update || { warn "apt-get update failed"; return 1; }
        apt-get install -y "${missing_pkgs[@]}" || { error "Failed to install packages: ${missing_pkgs[*]}"; return 1; }
    else
        log "Required packages ($*) already installed."
    fi
    return 0
}

# Check if Samba user exists
is_samba_user() {
    pdbedit -L -u "$1" &> /dev/null
    return $?
}

# --- Core Processing Function ---
process_partition() {
    local partition="$1"
    local uuid=""
    local type=""
    local uuid_suffix=""
    local mount_point=""
    local share_name=""
    local share_conf_file=""
    local mount_options=""

    log "Processing partition: $partition"

    # Get UUID and TYPE using blkid
    local partition_info
    partition_info=$(blkid -o export "$partition" 2>/dev/null) || { warn "blkid failed for $partition."; return 1; }
    if [[ -z "$partition_info" ]]; then
        warn "Could not get blkid info for $partition. Skipping."
        return 1
    fi

    uuid=$(echo "$partition_info" | grep '^UUID=' | cut -d '=' -f2-)
    type=$(echo "$partition_info" | grep '^TYPE=' | cut -d '=' -f2-)

    if [[ -z "$uuid" || -z "$type" ]]; then
        warn "Missing UUID or TYPE for $partition. Skipping."
        return 1
    fi

    log "Found Partition: $partition | UUID: $uuid | TYPE: $type"

    # Check if filesystem type is allowed
    if ! echo "$type" | grep -qE "^($ALLOWED_FS_REGEX)$"; then
        log "Filesystem type '$type' is not in ALLOWED_FILESYSTEMS. Skipping $partition."
        return 0 # Not an error, just skipping
    fi

    # --- fstab Handling (Idempotent) ---
    if grep -q "UUID=$uuid" "$FSTAB_FILE"; then
        log "Partition $partition (UUID: $uuid) already exists in $FSTAB_FILE."
    else
        log "Partition $partition (UUID: $uuid) not found in $FSTAB_FILE. Adding entry."
        uuid_suffix=$(echo "$uuid" | tail -c 9)
        mount_point="${SHARE_BASE_PATH}/disk-${uuid_suffix}"

        log "Creating mount point: $mount_point"
        mkdir -p "$mount_point" || { error "Failed to create mount point $mount_point."; return 1; }

        mount_options="defaults,nofail,auto,x-systemd.automount,uid=${USER_UID},gid=${USER_GID}"
        if [[ "$type" == "vfat" || "$type" == "ntfs" || "$type" == "exfat" ]]; then
             mount_options+=",umask=0002"
        fi

        log "Adding entry to $FSTAB_FILE for $partition (UUID: $uuid)"
        # Add comments for clarity
        {
            echo "# Entry added by manage_storage.sh for $partition ($type)"
            echo "UUID=$uuid $mount_point $type $mount_options 0 0"
        } >> "$FSTAB_FILE" || { error "Failed to write fstab entry for $partition."; return 1; }

        log "Attempting to mount new entry: $mount_point"
        mount "$mount_point" || warn "Failed to mount $mount_point immediately. Systemd automount should handle it later."
    fi

    # --- Samba Share Handling (Idempotent) ---
    # Determine mount point even if fstab entry existed
    if [[ -z "$mount_point" ]]; then
         mount_point=$(findmnt -n -o TARGET --source "UUID=$uuid")
         if [[ -z "$mount_point" ]]; then
             warn "Could not determine mount point for existing fstab entry UUID=$uuid. Cannot configure Samba share."
             return 1
         fi
         log "Found existing mount point: $mount_point"
    fi
     # Ensure mount point directory exists (might be needed if fstab entry existed but dir was deleted)
    mkdir -p "$mount_point" || { error "Failed to ensure mount point directory exists: $mount_point"; return 1; }


    if [[ -z "$uuid_suffix" ]]; then
        uuid_suffix=$(echo "$uuid" | tail -c 9)
    fi
    share_name="Share-${uuid_suffix}"
    share_conf_file="${SAMBA_SHARES_DIR}/${share_name}.conf"

    if [[ -f "$share_conf_file" ]]; then
        log "Samba share config '$share_conf_file' already exists."
    else
        log "Samba share config '$share_conf_file' not found. Creating."
        # Ensure the include directory exists
        mkdir -p "$SAMBA_SHARES_DIR" || { error "Failed to create Samba shares directory: $SAMBA_SHARES_DIR"; return 1; }

        # Create the share definition file
        cat << EOF > "$share_conf_file"
# Share definition created by manage_storage.sh for $partition
[$share_name]
   path = $mount_point
   comment = Mounted Disk $partition ($type)
   # Inherits global settings like browseable, read only, valid users, masks
   # Add specific overrides here if needed
EOF
        if [[ $? -ne 0 ]]; then
            error "Failed to write Samba share config file: $share_conf_file"
            return 1
        fi
        log "Created Samba share config: $share_conf_file"

        log "Reloading Samba configuration..."
        smbcontrol all reload-config || warn "smbcontrol reload-config failed. A full Samba restart might be needed."
    fi

    log "Successfully processed partition: $partition"
    return 0
}


# --- Main Script Execution ---
log "Starting manage_storage.sh execution..."
log "Mode: ${1:-Scan All}" # Log mode: specific partition or scan all

# --- Load Environment Variables ---
if [[ ! -f "$ENV_FILE" ]]; then
  error "Environment file '$ENV_FILE' not found."
  exit 1 # Exit here as config is essential
fi
# Use source carefully or stick to grep/cut
SHARE_BASE_PATH=$(grep '^SHARE_BASE_PATH=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
ALLOWED_FILESYSTEMS=$(grep '^ALLOWED_FILESYSTEMS=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SMB_WORKGROUP=$(grep '^SMB_WORKGROUP=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SET_USERNAME=$(grep '^SET_USERNAME=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SET_PASSWORD=$(grep '^SET_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
# Re-enable set -u if desired after reading potentially empty vars
# set -u

# --- Validate Configuration ---
if [[ -z "$SHARE_BASE_PATH" || -z "$ALLOWED_FILESYSTEMS" || -z "$SMB_WORKGROUP" || -z "$SET_USERNAME" ]]; then
    error "Required variables (SHARE_BASE_PATH, ALLOWED_FILESYSTEMS, SMB_WORKGROUP, SET_USERNAME) not set in $ENV_FILE."
    exit 1
fi
if [[ -z "$SET_PASSWORD" ]]; then
    error "SET_PASSWORD must be set in $ENV_FILE for Samba user setup."
    exit 1
fi

# --- One-Time Initial Setup Tasks (Idempotent Checks) ---
log "Performing initial setup checks..."

# 1. Install Packages
apt_packages="samba util-linux procps" # util-linux for findmnt/lsblk, procps for pgrep?
if [[ "$ALLOWED_FILESYSTEMS" == *"vfat"* ]]; then apt_packages+=" dosfstools"; fi
if [[ "$ALLOWED_FILESYSTEMS" == *"exfat"* ]]; then apt_packages+=" exfatprogs"; fi # Or exfat-utils
if [[ "$ALLOWED_FILESYSTEMS" == *"ntfs"* ]]; then apt_packages+=" ntfs-3g"; fi
install_packages $apt_packages || exit 1 # Exit if essential packages fail

# 2. Create Base Mount Directory
if [[ ! -d "$SHARE_BASE_PATH" ]]; then
    log "Creating base mount directory: $SHARE_BASE_PATH"
    mkdir -p "$SHARE_BASE_PATH" || { error "Failed to create base mount directory."; exit 1; }
fi

# 3. Configure Main Samba smb.conf (if include directive missing)
SAMBA_INCLUDE_LINE="include = ${SAMBA_SHARES_DIR}/%.conf" # Using % allows different filenames
if ! grep -q -F "$SAMBA_INCLUDE_LINE" "$SAMBA_CONF_FILE"; then
    log "Adding include directive to $SAMBA_CONF_FILE"
    # Backup existing smb.conf
    cp "$SAMBA_CONF_FILE" "${SAMBA_CONF_FILE}.bak.init.$(date +%F_%T)" || warn "Failed to backup Samba config."
    # Create minimal smb.conf with global section and include directive
    cat << EOF > "$SAMBA_CONF_FILE"
[global]
   workgroup = $SMB_WORKGROUP
   server string = %h server (Samba)
   dns proxy = no
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d
   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
   pam password change = yes
   map to guest = bad user

   # Default share settings (can be overridden per share)
   browseable = yes
   read only = no
   guest ok = no
   create mask = 0664
   directory mask = 0775
   valid users = $SET_USERNAME

# Include individual share definitions
   $SAMBA_INCLUDE_LINE

EOF
    if [[ $? -ne 0 ]]; then
        error "Failed to write initial $SAMBA_CONF_FILE"
        exit 1
    fi
    # Ensure shares dir exists after creating config that uses it
    mkdir -p "$SAMBA_SHARES_DIR" || { error "Failed to create Samba shares directory: $SAMBA_SHARES_DIR"; exit 1; }

    log "Initial Samba config written. Reloading Samba..."
    systemctl reload smbd || systemctl restart smbd || warn "Failed to reload/restart smbd after initial config."

else
    log "Samba include directive already present in $SAMBA_CONF_FILE."
fi

# 4. Add Samba User (if not already added)
if ! is_samba_user "$SET_USERNAME"; then
    log "Adding Samba user: $SET_USERNAME"
    printf "%s\n%s\n" "$SET_PASSWORD" "$SET_PASSWORD" | smbpasswd -a -s "$SET_USERNAME" || { error "Failed to add Samba user $SET_USERNAME."; exit 1; }
else
    log "Samba user $SET_USERNAME already exists."
fi

# 5. Ensure Samba services are enabled
if ! systemctl is-enabled -q smbd; then
    log "Enabling smbd service..."
    systemctl enable smbd || warn "Failed to enable smbd service."
fi
if ! systemctl is-enabled -q nmbd; then
    log "Enabling nmbd service..."
    systemctl enable nmbd || warn "Failed to enable nmbd service."
fi

log "Initial setup checks complete."

# --- Determine OS Disk ---
log "Identifying OS disk..."
ROOT_SOURCE=$(findmnt -n -o SOURCE /)
if [[ -z "$ROOT_SOURCE" ]]; then
    error "Could not determine root filesystem source device."
    exit 1
fi
OS_DISK=$(lsblk -n -o PKNAME "$ROOT_SOURCE")
if [[ -z "$OS_DISK" ]]; then
     OS_DISK=$(echo "$ROOT_SOURCE" | sed 's/[0-9]*$//' | sed 's/p[0-9]*$//')
fi
if [[ -z "$OS_DISK" ]]; then
    error "Could not reliably determine the OS base disk from $ROOT_SOURCE."
    exit 1
fi
OS_DISK_BASENAME=$(basename "$OS_DISK") # Get 'sda' or 'mmcblk0'
log "OS disk identified as: $OS_DISK (Basename: $OS_DISK_BASENAME)"

# --- Get User Info ---
log "Getting UID/GID for user: $SET_USERNAME"
USER_UID=$(id -u "$SET_USERNAME") || { error "Failed to get UID for user $SET_USERNAME."; exit 1; }
USER_GID=$(id -g "$SET_USERNAME") || { error "Failed to get GID for user $SET_USERNAME."; exit 1; }
log "UID: $USER_UID, GID: $USER_GID"

# --- Convert allowed FS list to regex ---
ALLOWED_FS_REGEX=$(echo "$ALLOWED_FILESYSTEMS" | sed 's/,/|/g')

# --- Process Target Partition(s) ---
if [[ -n "${1:-}" ]]; then
    # Mode 2: Process specific partition passed as argument (udev mode)
    log "Processing specific partition from argument: $1"
    if [[ ! -b "$1" ]]; then
        error "Argument '$1' is not a valid block device."
        exit 1
    fi
    # Check if the partition belongs to the OS disk
    PART_DISK_BASENAME=$(lsblk -n -o PKNAME "$1")
    if [[ "$PART_DISK_BASENAME" == "$OS_DISK_BASENAME" ]]; then
        log "Partition $1 belongs to the OS disk ($OS_DISK_BASENAME). Skipping."
    else
        process_partition "$1"
    fi
else
    # Mode 1: Scan all potential data partitions (first boot mode)
    log "Scanning all non-OS partitions..."
    shopt -s extglob # Enable extended globbing

    processed_something=0
    # Iterate through potential block devices
    for device in /dev/sd* /dev/nvme* ; do
        # Skip if not a block device or if it's the OS disk itself
        if [[ ! -b "$device" || "$(basename "$device")" == "$OS_DISK_BASENAME" ]]; then
            continue
        fi

        log "Scanning device: $device"
        # Check partitions on the device
        lsblk -n -o NAME,TYPE "$device" | while read -r name type; do
            # Process only partitions
            if [[ "$type" != "part" ]]; then
                continue
            fi
            partition="/dev/$name"
            process_partition "$partition"
            if [[ $? -eq 0 ]]; then processed_something=1; fi # Track if we did something
        done # End partition loop
    done # End device loop

    # Mount all just in case some weren't mounted immediately
    log "Running 'mount -a' after initial scan..."
    mount -a || warn "Some filesystems failed to mount via 'mount -a'."

    # Reload samba once after initial scan if anything was processed
    # Note: process_partition already reloads if it adds a share config
    # if [[ $processed_something -eq 1 ]]; then
    #    log "Reloading Samba config after initial scan..."
    #    smbcontrol all reload-config || warn "smbcontrol reload-config failed after initial scan."
    # fi
fi

log "manage_storage.sh finished."
exit 0