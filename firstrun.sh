#!/bin/bash

# Main orchestrator script executed once on first boot via cmdline.txt trigger.
# Modified to detect QEMU environment via argument.

# set -e # Disable global exit on error, check return codes of sub-scripts
# set -u # Disable temporarily for grep/cut
set -o pipefail

# --- Basic Logging Setup (before full config) ---
# Need a log file path that works early in both modes
EARLY_LOG_DIR="/var/log/firstrun"
mkdir -p "$EARLY_LOG_DIR" || echo "WARN (firstrun.sh): Could not create log directory $EARLY_LOG_DIR early." >&2
EARLY_MAIN_LOG_FILE="${EARLY_LOG_DIR}/firstrun_orchestrator.log"
exec > >(tee -a "$EARLY_MAIN_LOG_FILE") 2>&1

echo "--- Starting firstrun.sh ---"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Arguments received: [$*]"

# --- Environment Detection ---
RUN_MODE="REAL_HW" # Default
QEMU_MOUNT_POINT="/mnt/qemu_share" # Default mount point used by wrapper

if [[ "$1" == "QEMU" ]]; then
    RUN_MODE="QEMU"
    echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Detected QEMU run mode (via argument)."
else
    echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Assuming Real Hardware run mode."
fi

# --- Determine script's base directory ---
SCRIPT_REAL_PATH=$(realpath "$0")
SCRIPT_BASE_DIR=$(dirname "$SCRIPT_REAL_PATH")
echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Script running from base directory: $SCRIPT_BASE_DIR"

# --- Configuration ---
LOG_DIR="/var/log/firstrun" # Final log dir path
MAIN_LOG_FILE="${LOG_DIR}/firstrun_orchestrator.log"
UDEV_RULES_TARGET_DIR="/etc/udev/rules.d" # Target is always the same

# --- Conditional Paths ---
if [[ "$RUN_MODE" == "QEMU" ]]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Setting paths for QEMU mode relative to script dir."
    # Paths relative to the script's location on the USB share
    ENV_FILE="${SCRIPT_BASE_DIR}/.env"
    SETUP_SCRIPTS_DIR="${SCRIPT_BASE_DIR}/setup_scripts"
    UDEV_RULES_SOURCE_DIR="${SCRIPT_BASE_DIR}/udev_rules"
    # MONITORING_APP_SOURCE_DIR="${SCRIPT_BASE_DIR}/monitoring_app" # Add if needed
else
    # Original paths for Real Hardware mode
    echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Setting paths for Real Hardware mode."
    if [[ -d "/boot/firmware" ]]; then # RPi OS >= Bookworm path
        ENV_FILE="/boot/firmware/.env"
        SETUP_SCRIPTS_DIR="/boot/firmware/setup_scripts"
        UDEV_RULES_SOURCE_DIR="/boot/firmware/udev_rules"
        # MONITORING_APP_SOURCE_DIR="/boot/firmware/monitoring_app" # Add if needed
    else # Fallback for older structure maybe?
        ENV_FILE="/boot/.env"
        SETUP_SCRIPTS_DIR="/boot/setup_scripts"
        UDEV_RULES_SOURCE_DIR="/boot/udev_rules"
        # MONITORING_APP_SOURCE_DIR="/boot/monitoring_app" # Add if needed
    fi
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Using ENV_FILE: $ENV_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Using SETUP_SCRIPTS_DIR: $SETUP_SCRIPTS_DIR"
echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): Using UDEV_RULES_SOURCE_DIR: $UDEV_RULES_SOURCE_DIR"


# --- Logging Setup (Re-initialize with final path if needed, tee handles append) ---
mkdir -p "$LOG_DIR" || echo "WARN (firstrun.sh): Could not create final log directory $LOG_DIR" >&2
# exec redirection already done

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): $1"
}
warn() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN (firstrun.sh): $1" >&2
}
error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR (firstrun.sh): $1" >&2
}

# --- Helper Function to Run Sub-script (Unchanged from original) ---
run_script() {
    local script_name="$1"
    local script_path="${SETUP_SCRIPTS_DIR}/${script_name}" # Uses conditionally set path

    if [[ -f "$script_path" ]]; then
        log "Executing sub-script: $script_name from $script_path"
        chmod +x "$script_path" || warn "Failed to chmod +x $script_path"
        bash "$script_path"
        local return_code=$?
        if [[ $return_code -ne 0 ]]; then
            error "Sub-script '$script_name' failed with exit code $return_code. Check its log in $LOG_DIR or /var/log."
        else
            log "Sub-script '$script_name' completed successfully."
        fi
        return $return_code
    else
        warn "Sub-script '$script_name' not found at $script_path. Skipping."
        return 1
    fi
}

# --- Main Execution (Unchanged from original logic) ---
log "Starting first boot orchestration main steps..."
# 0. Wait for Network...
log "Waiting for network connectivity..."
NETWORK_RETRIES=10
NETWORK_OK=0
for (( i=1; i<=NETWORK_RETRIES; i++ )); do
    if ping -c 1 8.8.8.8 &> /dev/null || ping -c 1 1.1.1.1 &> /dev/null; then
        log "Network connectivity established."
        NETWORK_OK=1
        break
    fi
    log "Network check attempt $i/$NETWORK_RETRIES failed. Waiting 5 seconds..."
    sleep 5
done
if [[ $NETWORK_OK -eq 0 ]]; then
    warn "Could not establish network connectivity after $NETWORK_RETRIES attempts. Some setup steps might fail."
fi

# 1. Setup Autologin
run_script "setup_autologin.sh"
# 2. Setup VPN
run_script "setup_vpn.sh"
# 3. Setup Storage and Samba (Initial Scan)
run_script "manage_storage.sh"
# 4. Copy udev rules (original logic, uses conditional UDEV_RULES_SOURCE_DIR)
# Assuming manage_storage.sh doesn't copy them, adjust if needed
log "Copying udev rules (if source dir exists)..."
if [[ -d "$UDEV_RULES_SOURCE_DIR" ]]; then
    # Check if source dir actually contains rules before copying
    if ls -A "$UDEV_RULES_SOURCE_DIR"/*.rules >/dev/null 2>&1; then
       cp -vf "$UDEV_RULES_SOURCE_DIR"/*.rules "$UDEV_RULES_TARGET_DIR/" || warn "Failed to copy udev rules."
       log "Reloading udev rules..."
       udevadm control --reload-rules && udevadm trigger || warn "Failed to reload udev rules."
    else
        log "udev rules source directory '$UDEV_RULES_SOURCE_DIR' is empty. Skipping copy."
    fi
else
    warn "udev rules source directory '$UDEV_RULES_SOURCE_DIR' not found. Skipping copy."
fi
# 5. Setup File Browser
run_script "setup_filebrowser.sh"
# 6. Setup Monitoring UI
run_script "setup_monitoring.sh"

# --- Final Cleanup (Conditional) ---
log "All setup scripts executed. Performing cleanup (Mode: $RUN_MODE)..."

if [[ "$RUN_MODE" == "QEMU" ]]; then
    # QEMU Mode: Create a flag file in the script's directory (on the USB share)
    FLAG_FILE="${SCRIPT_BASE_DIR}/.firstrun_complete"
    log "Creating completion flag for QEMU mode: $FLAG_FILE"
    touch "$FLAG_FILE" || error "Failed to create completion flag file."
else
    # Real Hardware Mode: Remove trigger from cmdline.txt (Original Logic)
    CMDLINE_PATH=""
    # Determine the path from which this script *should* have been run in real HW mode
    # This assumes the flash script placed it correctly.
    if [[ -f /boot/firmware/cmdline.txt ]]; then
        CMDLINE_PATH="/boot/firmware/cmdline.txt"
        # Assume the flash script put THIS script at /boot/firmware/firstrun.sh
        # Use SCRIPT_REAL_PATH which points to /boot/firmware/firstrun.sh in this mode
        FIRST_RUN_PATH="$SCRIPT_REAL_PATH"
    elif [[ -f /boot/cmdline.txt ]]; then
        CMDLINE_PATH="/boot/cmdline.txt"
        FIRST_RUN_PATH="$SCRIPT_REAL_PATH" # Should be /boot/firstrun.sh
    fi

    if [[ -n "$CMDLINE_PATH" ]] && [[ -n "$FIRST_RUN_PATH" ]]; then
        # Check if the trigger path is actually this script's path
        if [[ "$SCRIPT_REAL_PATH" == "$FIRST_RUN_PATH" ]]; then
             log "Removing trigger systemd.run=${FIRST_RUN_PATH} from $CMDLINE_PATH..."
             # Use sed with a different delimiter and ensure backup/restore logic
             sed -i.bak "s| systemd.run=${FIRST_RUN_PATH}||" "$CMDLINE_PATH"
             if [[ $? -eq 0 ]]; then
                  rm -f "${CMDLINE_PATH}.bak"
             else
                  warn "sed command failed for $CMDLINE_PATH. Trigger might remain."
                  # Restore from backup if sed failed
                  mv -f "${CMDLINE_PATH}.bak" "$CMDLINE_PATH" || warn "Failed to restore cmdline.txt from backup."
             fi
        else
             warn "Script path ($SCRIPT_REAL_PATH) doesn't match expected trigger path ($FIRST_RUN_PATH). Not attempting removal."
        fi
    else
        warn "Could not find cmdline.txt or determine trigger path to remove."
    fi
fi

log "First boot orchestration finished."
exit 0