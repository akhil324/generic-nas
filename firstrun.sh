#!/bin/bash

# Main orchestrator script executed once on first boot via cmdline.txt trigger.

# Exit immediately if a command exits with a non-zero status.
# set -e # Disable global exit on error, check return codes of sub-scripts
# Treat unset variables as an error when substituting.
# set -u # Disable temporarily for grep/cut
# Ensure pipeline failures are caught.
set -o pipefail

# --- Configuration ---
LOG_DIR="/var/log/firstrun"
MAIN_LOG_FILE="${LOG_DIR}/firstrun_orchestrator.log"
ENV_FILE="/boot/firmware/.env"
SETUP_SCRIPTS_DIR="/boot/firmware/setup_scripts"
UDEV_RULES_SOURCE_DIR="/boot/firmware/udev_rules"
UDEV_RULES_TARGET_DIR="/etc/udev/rules.d"

# --- Logging Setup ---
mkdir -p "$LOG_DIR" || echo "WARN (firstrun.sh): Could not create log directory $LOG_DIR" >&2
exec > >(tee -a "$MAIN_LOG_FILE") 2>&1

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (firstrun.sh): $1"
}

warn() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN (firstrun.sh): $1" >&2
}

error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR (firstrun.sh): $1" >&2
}

# --- Helper Function to Run Sub-script ---
run_script() {
    local script_name="$1"
    local script_path="${SETUP_SCRIPTS_DIR}/${script_name}"

    if [[ -f "$script_path" ]]; then
        log "Executing sub-script: $script_name"
        # Make sure it's executable (should be set by host script, but double-check)
        chmod +x "$script_path" || warn "Failed to chmod +x $script_path"
        # Execute and capture return code
        bash "$script_path"
        local return_code=$?
        if [[ $return_code -ne 0 ]]; then
            error "Sub-script '$script_name' failed with exit code $return_code. Check its log in $LOG_DIR or /var/log."
            # Decide whether to continue or halt on error
            # For now, let's continue but log the error prominently
            # exit 1 # Uncomment to halt on first error
        else
            log "Sub-script '$script_name' completed successfully."
        fi
        return $return_code
    else
        warn "Sub-script '$script_name' not found at $script_path. Skipping."
        return 1 # Indicate script was not run
    fi
}

# --- Main Execution ---
log "Starting first boot orchestration..."

# 0. Wait for Network (Optional but recommended)
# Simple check - adjust retries/sleep as needed
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
    # Continue anyway, maybe local network is up for package cache?
fi


# 1. Setup Autologin
run_script "setup_autologin.sh"

# 2. Setup VPN
run_script "setup_vpn.sh"

# 3. Setup Storage and Samba (Initial Scan)
# This script also copies the udev rule internally now, let's remove separate copy step
run_script "manage_storage.sh" # Run without arguments for initial scan

# 4. Copy udev rules (if manage_storage doesn't do it)
# Let's assume manage_storage.sh handles its own udev rule placement now.
# If not, uncomment below:
# log "Copying udev rules..."
# if [[ -d "$UDEV_RULES_SOURCE_DIR" ]]; then
#     cp -v "$UDEV_RULES_SOURCE_DIR"/* "$UDEV_RULES_TARGET_DIR/" || warn "Failed to copy udev rules."
#     log "Reloading udev rules..."
#     udevadm control --reload-rules && udevadm trigger || warn "Failed to reload udev rules."
# else
#     warn "udev rules source directory '$UDEV_RULES_SOURCE_DIR' not found."
# fi

# 5. Setup File Browser
run_script "setup_filebrowser.sh"

# 6. Setup Monitoring UI
run_script "setup_monitoring.sh"

# --- Final Cleanup ---
log "All setup scripts executed. Performing cleanup..."

# Remove the trigger from cmdline.txt to prevent re-running
CMDLINE_PATH=""
FIRST_RUN_PATH=""
if [[ -f /boot/firmware/cmdline.txt ]]; then # RPi OS >= Bookworm path
    CMDLINE_PATH="/boot/firmware/cmdline.txt"
    FIRST_RUN_PATH="/boot/firmware/firstrun.sh"
elif [[ -f /boot/cmdline.txt ]]; then # Older RPi OS path
    CMDLINE_PATH="/boot/cmdline.txt"
    FIRST_RUN_PATH="/boot/firstrun.sh"
fi

if [[ -n "$CMDLINE_PATH" ]]; then
    log "Removing trigger from $CMDLINE_PATH..."
    # Use sed with a different delimiter just in case paths contain '/'
    # Make sure to match the exact trigger added by the host script
    sed -i "s| systemd.run=${FIRST_RUN_PATH}||" "$CMDLINE_PATH" || warn "sed command failed for $CMDLINE_PATH"
else
    warn "Could not find cmdline.txt to remove trigger."
fi

# Optional: Remove the setup scripts and related files from boot partition?
# This saves space and prevents accidental re-runs, but makes debugging harder.
# log "Removing setup files from boot partition..."
# rm -rf "$SETUP_SCRIPTS_DIR" "$UDEV_RULES_SOURCE_DIR" /boot/firmware/monitoring_app "$FIRST_RUN_PATH" || warn "Failed to remove some setup files."

log "First boot orchestration finished."
log "System should continue booting normally. A reboot might occur depending on setup steps."

exit 0