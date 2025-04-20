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
if [[ ! -d "$FILEBROWSER_BASE_DIR" ]]; then
    warn "FILEBROWSER_BASE_DIR '$FILEBROWSER_BASE_DIR' does not exist. Attempting to create."
    mkdir -p "$FILEBROWSER_BASE_DIR" || error "Failed to create FILEBROWSER_BASE_DIR."
fi


# --- Install Dependencies ---
log "Checking for necessary tools (curl, tar)..."
if ! command -v curl &> /dev/null || ! command -v tar &> /dev/null; then
    log "Installing curl and tar..."
    apt-get update || warn "apt-get update failed"
    apt-get install -y curl tar || error "Failed to install curl or tar."
fi

# --- Download and Install File Browser ---
if [[ -f "$FILEBROWSER_BIN_PATH" ]]; then
    log "File Browser binary already exists at $FILEBROWSER_BIN_PATH. Skipping download."
    # Optionally add version check here later if needed
else
    log "Downloading File Browser binary for linux-arm64..."
    # Fetch the latest release URL from GitHub API
    LATEST_URL=$(curl -s https://api.github.com/repos/filebrowser/filebrowser/releases/latest | grep browser_download_url.*linux-arm64\.tar\.gz | cut -d '"' -f 4)

    if [[ -z "$LATEST_URL" ]]; then
        error "Could not determine latest File Browser download URL for linux-arm64."
    fi

    log "Latest download URL: $LATEST_URL"
    TEMP_DIR=$(mktemp -d)
    log "Downloading to $TEMP_DIR/filebrowser.tar.gz"
    curl -L "$LATEST_URL" -o "$TEMP_DIR/filebrowser.tar.gz" || error "Download failed."

    log "Extracting File Browser..."
    tar -xzf "$TEMP_DIR/filebrowser.tar.gz" -C "$TEMP_DIR" filebrowser || error "Extraction failed."

    log "Installing File Browser binary to $FILEBROWSER_BIN_PATH..."
    mv "$TEMP_DIR/filebrowser" "$FILEBROWSER_BIN_PATH" || error "Failed to move binary."
    chmod +x "$FILEBROWSER_BIN_PATH" || error "Failed to make binary executable."

    log "Cleaning up temporary download files..."
    rm -rf "$TEMP_DIR"
fi

# --- Create Configuration Directory and Database Parent ---
log "Ensuring File Browser config directory exists: $(dirname "$FILEBROWSER_DB_PATH")"
mkdir -p "$(dirname "$FILEBROWSER_DB_PATH")" || error "Failed to create directory for File Browser database."

# --- Configure File Browser (Initial User Setup) ---
# File Browser can initialize its database and add users via command line.
# We run this once to set up the initial user. If the DB exists, it might update the password.
log "Configuring initial File Browser user: $FILEBROWSER_USER"
# Note: The '--database' flag ensures it uses our specified location.
"$FILEBROWSER_BIN_PATH" users add "$FILEBROWSER_USER" "$FILEBROWSER_PASSWORD" --perm.admin --database "$FILEBROWSER_DB_PATH" || error "Failed to add/configure File Browser user."
log "Initial user configured."

# --- Create systemd Service File ---
log "Creating systemd service file: $FILEBROWSER_SERVICE_FILE"
cat << EOF > "$FILEBROWSER_SERVICE_FILE"
[Unit]
Description=File Browser Web UI
After=network.target

[Service]
User=root # Run as root to access all files in base dir, consider a dedicated user later if needed
Group=root
WorkingDirectory=/ # Or maybe FILEBROWSER_BASE_DIR? Check Filebrowser docs.
ExecStart=$FILEBROWSER_BIN_PATH \\
    --address 0.0.0.0 \\
    --port $FILEBROWSER_PORT \\
    --database "$FILEBROWSER_DB_PATH" \\
    --root "$FILEBROWSER_BASE_DIR" \\
    --log stdout
# Add other flags as needed, e.g., --no-auth if desired (not recommended)
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
systemctl enable --now filebrowser.service || error "Failed to enable or start filebrowser.service."

log "File Browser setup completed successfully."
log "Access the UI at: http://<your-pi-ip-or-zerotier-ip>:$FILEBROWSER_PORT"
log "Login with user '$FILEBROWSER_USER' and the password from your .env file."

exit 0