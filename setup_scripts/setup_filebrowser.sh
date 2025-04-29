#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Disable temporarily for grep/cut
# Ensure pipeline failures are caught.
set -o pipefail

ENV_FILE="/boot/firmware/.env" # Path to the config file on the Pi's boot partition
FILEBROWSER_BIN_PATH="/usr/local/bin/filebrowser"
FILEBROWSER_DB_PATH="/etc/filebrowser/filebrowser.db" # Database location
FILEBROWSER_SERVICE_FILE="/etc/systemd/system/filebrowser.service"
LOG_FILE="/var/log/setup_filebrowser.log" # Specific log for this script

# --- Logging ---
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (setup_filebrowser.sh): $1"
}

warn() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN (setup_filebrowser.sh): $1" >&2
}

error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR (setup_filebrowser.sh): $1" >&2
  exit 1
}

# --- Check Prerequisites ---
if [[ ! -f "$ENV_FILE" ]]; then
  error "Environment file '$ENV_FILE' not found."
fi

# --- Read Configuration ---
ENABLE_FILEBROWSER=$(grep '^ENABLE_FILEBROWSER=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//' | tr '[:upper:]' '[:lower:]')
FILEBROWSER_PORT=$(grep '^FILEBROWSER_PORT=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
FILEBROWSER_BASE_DIR=$(grep '^FILEBROWSER_BASE_DIR=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
FILEBROWSER_USER=$(grep '^FILEBROWSER_USER=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
FILEBROWSER_PASSWORD=$(grep '^FILEBROWSER_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
# Re-enable set -u if desired
# set -u

# --- Check if Enabled ---
if [[ "$ENABLE_FILEBROWSER" != "true" ]]; then
    log "File Browser is disabled (ENABLE_FILEBROWSER is not 'true'). Skipping setup."
    exit 0
fi

# --- Validate Configuration ---
if [[ -z "$FILEBROWSER_PORT" || -z "$FILEBROWSER_BASE_DIR" || -z "$FILEBROWSER_USER" || -z "$FILEBROWSER_PASSWORD" ]]; then
    error "Required File Browser variables (PORT, BASE_DIR, USER, PASSWORD) not set or empty in $ENV_FILE."
fi
if ! [[ "$FILEBROWSER_PORT" =~ ^[0-9]+$ ]] || [[ "$FILEBROWSER_PORT" -lt 1 ]] || [[ "$FILEBROWSER_PORT" -gt 65535 ]]; then
    error "Invalid FILEBROWSER_PORT specified: $FILEBROWSER_PORT"
fi
# Base directory existence checked later

# --- Install Dependencies ---
log "Checking for necessary tools (curl, tar, jq)..."
if ! command -v curl &> /dev/null || ! command -v tar &> /dev/null || ! command -v jq &> /dev/null; then
    log "Installing curl, tar, jq..."
    apt-get update || warn "apt-get update failed"
    apt-get install -y curl tar jq || error "Failed to install curl, tar, or jq."
fi

# --- Download and Install File Browser ---
if [[ -f "$FILEBROWSER_BIN_PATH" ]]; then
    log "File Browser binary already exists at $FILEBROWSER_BIN_PATH. Skipping download."
else
    log "Downloading File Browser binary for linux-arm64..."
    log "Fetching latest release URL from GitHub API..."
    LATEST_URL=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | jq -r '.assets[] | select(.name | endswith("linux-arm64-filebrowser.tar.gz")) | .browser_download_url')

    if [[ -z "$LATEST_URL" || "$LATEST_URL" == "null" ]]; then
        error "Could not determine latest File Browser download URL for linux-arm64 using jq."
        exit 1
    fi

    log "Latest download URL: $LATEST_URL"
    TEMP_DIR=$(mktemp -d)
    log "Downloading to $TEMP_DIR/filebrowser.tar.gz"
    if ! curl -L "$LATEST_URL" -o "$TEMP_DIR/filebrowser.tar.gz"; then
        error "Download failed from $LATEST_URL."
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    log "Extracting File Browser..."
    if ! tar -xzf "$TEMP_DIR/filebrowser.tar.gz" -C "$TEMP_DIR" filebrowser; then
         error "Extraction failed for $TEMP_DIR/filebrowser.tar.gz."
         rm -rf "$TEMP_DIR"
         exit 1
    fi

    log "Installing File Browser binary to $FILEBROWSER_BIN_PATH..."
    mv "$TEMP_DIR/filebrowser" "$FILEBROWSER_BIN_PATH" || { error "Failed to move binary."; rm -rf "$TEMP_DIR"; exit 1; }
    chmod +x "$FILEBROWSER_BIN_PATH" || { error "Failed to make binary executable."; rm -rf "$TEMP_DIR"; exit 1; }

    log "Cleaning up temporary download files..."
    rm -rf "$TEMP_DIR"
fi

# --- Create Configuration/Database Directory ---
log "Ensuring File Browser config directory exists: $(dirname "$FILEBROWSER_DB_PATH")"
mkdir -p "$(dirname "$FILEBROWSER_DB_PATH")" || error "Failed to create directory for File Browser database."
"$FILEBROWSER_BIN_PATH" config init -d "$FILEBROWSER_DB_PATH"

# --- Configure File Browser User ---
# The 'users add' command should initialize the DB if it doesn't exist.
log "Configuring File Browser user: $FILEBROWSER_USER"
# Run users add command
"$FILEBROWSER_BIN_PATH" users add "$FILEBROWSER_USER" "$FILEBROWSER_PASSWORD" --perm.admin --database "$FILEBROWSER_DB_PATH" || error "Failed to add/configure File Browser user '$FILEBROWSER_USER'."

# --- Verification Step ---
log "Verifying user '$FILEBROWSER_USER' exists in database..."
if ! "$FILEBROWSER_BIN_PATH" users ls --database "$FILEBROWSER_DB_PATH" | grep -q " $FILEBROWSER_USER "; then
    error "Verification failed: User '$FILEBROWSER_USER' not found in database after add command."
    # Optional: Dump user list for debugging
    # "$FILEBROWSER_BIN_PATH" users ls --database "$FILEBROWSER_DB_PATH"
    exit 1
fi
log "User '$FILEBROWSER_USER' verified successfully."

# --- Ensure Base Directory Exists ---
log "Ensuring File Browser base directory exists: $FILEBROWSER_BASE_DIR"
mkdir -p "$FILEBROWSER_BASE_DIR" || error "Failed to create File Browser base directory: $FILEBROWSER_BASE_DIR"

# --- Create systemd Service File ---
log "Creating systemd service file: $FILEBROWSER_SERVICE_FILE"
cat << EOF > "$FILEBROWSER_SERVICE_FILE"
[Unit]
Description=File Browser Web UI
# Make sure storage is mounted before starting (if base dir is on external storage)
# Consider adding RequiresMountsFor=/mnt/shares (or variable) if needed
After=network.target

[Service]
# Running as root is simpler for now, but consider a dedicated user later
User=root
Group=root
# Setting WorkingDirectory might be safer than relying on default '/'
WorkingDirectory=$FILEBROWSER_BASE_DIR
ExecStart=$FILEBROWSER_BIN_PATH \\
    --address 0.0.0.0 \\
    --port $FILEBROWSER_PORT \\
    --database "$FILEBROWSER_DB_PATH" \\
    --root "$FILEBROWSER_BASE_DIR" \\
    --log stdout
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

if [[ $? -ne 0 ]]; then
    error "Failed to write systemd service file: $FILEBROWSER_SERVICE_FILE"
fi

# --- Enable and Start Service ---
log "Reloading systemd daemon..."
systemctl daemon-reload || warn "systemctl daemon-reload failed."

log "Enabling and starting File Browser service..."
# Stop it first in case a previous failed attempt left it in a weird state
systemctl stop filebrowser.service || true # Ignore error if not running
systemctl enable --now filebrowser.service || error "Failed to enable or start filebrowser.service."

# Add a small delay and final check
sleep 2
log "Final check of service status:"
systemctl status filebrowser.service --no-pager || log "Service status check reported an issue."


log "File Browser setup completed successfully."
log "Access the UI at: http://<container-ip-or-localhost>:$FILEBROWSER_PORT"
log "Login with user '$FILEBROWSER_USER' and the password from your .env file."

exit 0