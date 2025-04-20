#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Disable temporarily for grep/cut
# Ensure pipeline failures are caught.
set -o pipefail

ENV_FILE="/boot/firmware/.env" # Path to the config file on the Pi's boot partition
APP_SOURCE_DIR="/boot/firmware/monitoring_app" # Location of app files copied by flash script
MONITOR_APP_DIR="/opt/rpimon"
MONITOR_VENV_DIR="${MONITOR_APP_DIR}/venv"
MONITOR_SERVICE_FILE="/etc/systemd/system/rpimon.service"
MONITOR_SERVICE_USER="rpimon" # Dedicated user for the monitoring app
SUDOERS_FILE="/etc/sudoers.d/rpimon-reboot"
LOG_FILE="/var/log/setup_monitoring.log" # Specific log for this script

# --- Logging ---
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') INFO (setup_monitoring.sh): $1"
}

warn() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') WARN (setup_monitoring.sh): $1" >&2
}

error() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR (setup_monitoring.sh): $1" >&2
  exit 1
}

# --- Check Prerequisites ---
if [[ ! -f "$ENV_FILE" ]]; then
  error "Environment file '$ENV_FILE' not found."
fi
if [[ ! -d "$APP_SOURCE_DIR" ]]; then
  error "Application source directory '$APP_SOURCE_DIR' not found. Was it copied correctly?"
fi

# --- Read Configuration ---
ENABLE_MONITORING=$(grep '^ENABLE_MONITORING=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//' | tr '[:upper:]' '[:lower:]')
MONITORING_PORT=$(grep '^MONITORING_PORT=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
MONITORING_USER=$(grep '^MONITORING_USER=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
MONITORING_PASSWORD=$(grep '^MONITORING_PASSWORD=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
VPN_PROVIDER=$(grep '^VPN_PROVIDER=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
SHARE_BASE_PATH=$(grep '^SHARE_BASE_PATH=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
# Re-enable set -u if desired
# set -u

# --- Check if Enabled ---
if [[ "$ENABLE_MONITORING" != "true" ]]; then
    log "Monitoring UI is disabled (ENABLE_MONITORING is not 'true'). Skipping setup."
    exit 0
fi

# --- Validate Configuration ---
if [[ -z "$MONITORING_PORT" || -z "$MONITORING_USER" || -z "$MONITORING_PASSWORD" ]]; then
    error "Required Monitoring variables (PORT, USER, PASSWORD) not set or empty in $ENV_FILE."
fi
# Basic validation, more in Python app
if ! [[ "$MONITORING_PORT" =~ ^[0-9]+$ ]]; then error "Invalid MONITORING_PORT."; fi

# --- Install Dependencies ---
log "Installing Python3, pip, venv, and build essentials..."
apt-get update || warn "apt-get update failed"
apt-get install -y python3 python3-pip python3-venv build-essential sudo || error "Failed to install Python prerequisites."

# --- Create Dedicated User ---
if id -u "$MONITOR_SERVICE_USER" &>/dev/null; then
    log "User '$MONITOR_SERVICE_USER' already exists."
else
    log "Creating user '$MONITOR_SERVICE_USER'..."
    useradd -r -s /usr/sbin/nologin "$MONITOR_SERVICE_USER" || error "Failed to create user $MONITOR_SERVICE_USER."
fi

# --- Create App Directory & Copy App Files ---
log "Creating application directory: $MONITOR_APP_DIR"
mkdir -p "$MONITOR_APP_DIR" || error "Failed to create $MONITOR_APP_DIR."

log "Copying application files from $APP_SOURCE_DIR to $MONITOR_APP_DIR..."
# Use rsync or cp -a to preserve structure and permissions if needed
cp -a "$APP_SOURCE_DIR"/* "$MONITOR_APP_DIR/" || error "Failed to copy application files."

# Set ownership after copying
chown -R "$MONITOR_SERVICE_USER:$MONITOR_SERVICE_USER" "$MONITOR_APP_DIR" || warn "Failed to chown $MONITOR_APP_DIR."

# --- Create Virtual Environment & Install Python Libs ---
log "Setting up Python virtual environment in $MONITOR_VENV_DIR..."
sudo -u "$MONITOR_SERVICE_USER" python3 -m venv "$MONITOR_VENV_DIR" || error "Failed to create virtual environment."

log "Installing Python libraries (Flask, psutil, Flask-HTTPAuth, gunicorn)..."
# Activate venv and install packages
source "$MONITOR_VENV_DIR/bin/activate" || error "Failed to activate virtualenv."
# Check for requirements.txt first? For now, install directly.
pip install Flask psutil Flask-HTTPAuth gunicorn || error "Failed to install Python libraries."
deactivate || log "Failed to deactivate virtualenv (non-critical)."

# --- Configure Sudoers for Reboot ---
log "Configuring sudoers for passwordless reboot..."
echo "$MONITOR_SERVICE_USER ALL=(ALL) NOPASSWD: /sbin/reboot" > "$SUDOERS_FILE" || error "Failed to write sudoers file."
chmod 0440 "$SUDOERS_FILE" || error "Failed to set permissions on sudoers file."

# --- Create systemd Service File ---
log "Creating systemd service file: $MONITOR_SERVICE_FILE"
cat << EOF > "$MONITOR_SERVICE_FILE"
[Unit]
Description=RPi Monitoring Web UI
After=network.target # May need adjustment based on dependencies

[Service]
User=$MONITOR_SERVICE_USER
Group=$MONITOR_SERVICE_USER
WorkingDirectory=$MONITOR_APP_DIR
# Pass config via environment variables
Environment="MONITOR_USER=$MONITORING_USER"
Environment="MONITOR_PASSWORD=$MONITORING_PASSWORD"
Environment="VPN_PROVIDER=$VPN_PROVIDER"
Environment="SHARE_BASE_PATH=$SHARE_BASE_PATH"
# Add FLASK_ENV=production?
# Environment="FLASK_ENV=production"
# Run using Gunicorn (installed in venv)
ExecStart=$MONITOR_VENV_DIR/bin/gunicorn --workers 1 --bind 0.0.0.0:$MONITORING_PORT app:app
Restart=on-failure
RestartSec=5
# Optional: Add logging config if needed, though stdout/stderr capture might suffice
# StandardOutput=journal
# StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

if [[ $? -ne 0 ]]; then
    error "Failed to write systemd service file: $MONITOR_SERVICE_FILE"
fi

# --- Enable and Start Service ---
log "Reloading systemd daemon..."
systemctl daemon-reload || warn "systemctl daemon-reload failed."

log "Enabling and starting Monitoring UI service..."
systemctl enable --now rpimon.service || error "Failed to enable or start rpimon.service."

log "Monitoring UI setup completed successfully."

exit 0