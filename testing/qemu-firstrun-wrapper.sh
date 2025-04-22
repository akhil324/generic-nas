#!/bin/bash
# Wrapper script at /usr/local/bin/qemu-firstrun-wrapper.sh
# Triggered by systemd.run= in cmdline.txt

SHARE_DEVICE_TRY1="/dev/sda1"
SHARE_DEVICE_TRY2="/dev/sdb1"
MOUNT_POINT="/mnt/qemu_share"
LOG_FILE="/var/log/qemu-firstrun-wrapper.log"
RUN_FLAG_FILE="${MOUNT_POINT}/.firstrun_complete" # Flag created by firstrun.sh in QEMU mode

echo "Starting QEMU Wrapper at $(date)" > "$LOG_FILE"
# ... (device detection logic as before) ...

if [ -n "$SHARE_DEVICE" ]; then
    echo "Found potential share device: $SHARE_DEVICE" >> "$LOG_FILE"
    mkdir -p "$MOUNT_POINT"
    # Mount RW needed because firstrun.sh will create flag file on success
    if mount -t vfat "$SHARE_DEVICE" "$MOUNT_POINT" -o rw,uid=0,gid=0,utf8,dmask=002,fmask=113; then # Added mount options
        echo "Mounted $SHARE_DEVICE RW to $MOUNT_POINT" >> "$LOG_FILE"
        if [ -f "$RUN_FLAG_FILE" ]; then
            echo "Completion flag '$RUN_FLAG_FILE' found. Doing nothing." >> "$LOG_FILE"
        else
            echo "Completion flag not found. Attempting to execute firstrun.sh from share in QEMU mode." >> "$LOG_FILE"
            FIRST_RUN_SCRIPT="${MOUNT_POINT}/firstrun.sh"
            if [ -f "$FIRST_RUN_SCRIPT" ]; then
                # Ensure it's executable *before* running
                chmod +x "$FIRST_RUN_SCRIPT" || warn "Wrapper failed to chmod $FIRST_RUN_SCRIPT" >> "$LOG_FILE"

                echo "Executing: bash $FIRST_RUN_SCRIPT QEMU" >> "$LOG_FILE"
                # Execute script, passing "QEMU" as the first argument
                bash "$FIRST_RUN_SCRIPT" QEMU >> "$LOG_FILE" 2>&1 # Log stdout/stderr of script here
                EXEC_STATUS=$?
                echo "Execution finished with status: $EXEC_STATUS" >> "$LOG_FILE"
                # Check if flag file was created by firstrun.sh if successful
                if [[ $EXEC_STATUS -eq 0 ]] && [[ ! -f "$RUN_FLAG_FILE" ]]; then
                     warn "firstrun.sh exited successfully but did not create flag file $RUN_FLAG_FILE" >> "$LOG_FILE"
                fi
            else
                echo "ERROR: $FIRST_RUN_SCRIPT not found on share." >> "$LOG_FILE"
            fi
        fi
        echo "Unmounting $MOUNT_POINT." >> "$LOG_FILE"
        umount "$MOUNT_POINT"
    else
        echo "ERROR: Failed to mount $SHARE_DEVICE RW." >> "$LOG_FILE"
    fi
else
    echo "ERROR: Share device ($SHARE_DEVICE_TRY1 or $SHARE_DEVICE_TRY2) not found." >> "$LOG_FILE"
fi

echo "QEMU Wrapper finished at $(date)." >> "$LOG_FILE"
exit 0