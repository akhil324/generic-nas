#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
# set -u # Temporarily disable -u as grep might return empty strings legitimately
# Ensure pipeline failures are caught.
set -o pipefail

ENV_FILE="/boot/firmware/.env" # Path to the config file on the Pi's boot partition

log() {
  echo "INFO (setup_vpn.sh): $1"
}

warn() {
  echo "WARN (setup_vpn.sh): $1" >&2
}

error() {
  echo "ERROR (setup_vpn.sh): $1" >&2
  exit 1
}

# --- Check Prerequisites ---
if [[ ! -f "$ENV_FILE" ]]; then
  error "Environment file '$ENV_FILE' not found."
fi

if ! command -v curl &> /dev/null; then
    log "curl not found, attempting to install..."
    apt-get update || warn "apt-get update failed"
    apt-get install -y curl || error "Failed to install curl."
fi

# --- Read Configuration ---
# Use grep/cut for safety, remove potential surrounding quotes
VPN_PROVIDER=$(grep '^VPN_PROVIDER=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
ZEROTIER_NETWORK_ID=$(grep '^ZEROTIER_NETWORK_ID=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
TAILSCALE_AUTH_KEY=$(grep '^TAILSCALE_AUTH_KEY=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
TAILSCALE_HOSTNAME=$(grep '^TAILSCALE_HOSTNAME=' "$ENV_FILE" | cut -d '=' -f2- | sed -e 's/^"//' -e 's/"$//')
# Re-enable set -u after reading variables that might be empty
set -u

# --- Main Logic ---
log "Starting VPN setup..."

case "$VPN_PROVIDER" in
  "tailscale")
    log "Selected VPN Provider: Tailscale"

    if [[ -z "$TAILSCALE_AUTH_KEY" ]]; then
      error "TAILSCALE_AUTH_KEY is not set in $ENV_FILE for Tailscale."
    fi

    log "Installing Tailscale..."
    # Use the official install script
    curl -fsSL https://tailscale.com/install.sh | sh || error "Tailscale installation script failed."

    log "Configuring Tailscale..."
    TAILSCALE_UP_CMD="tailscale up --authkey=${TAILSCALE_AUTH_KEY} --accept-routes" # Accept routes by default for NAS access
    if [[ -n "$TAILSCALE_HOSTNAME" ]]; then
      TAILSCALE_UP_CMD+=" --hostname=${TAILSCALE_HOSTNAME}"
      log "Using custom hostname: $TAILSCALE_HOSTNAME"
    fi

    # Run the command
    eval "$TAILSCALE_UP_CMD" || error "tailscale up command failed."

    log "Enabling and starting Tailscale service..."
    systemctl enable --now tailscaled || error "Failed to enable/start tailscaled service."

    log "Tailscale setup completed successfully."
    log "NOTE: Check your Tailscale Admin Console to ensure the device appears and is authorized."
    ;;

  "zerotier")
    log "Selected VPN Provider: ZeroTier"

    if [[ -z "$ZEROTIER_NETWORK_ID" ]]; then
      error "ZEROTIER_NETWORK_ID is not set in $ENV_FILE for ZeroTier."
    fi

    log "Installing ZeroTier..."
    # Use the official install script
    curl -s https://install.zerotier.com | bash || error "ZeroTier installation script failed."

    # Wait a moment for the service to potentially start
    sleep 5

    log "Joining ZeroTier network: $ZEROTIER_NETWORK_ID"
    zerotier-cli join "$ZEROTIER_NETWORK_ID" || error "Failed to join ZeroTier network."

    log "Enabling ZeroTier service (already started by installer)..."
    systemctl enable zerotier-one || error "Failed to enable zerotier-one service."

    log "ZeroTier setup completed successfully."
    log "IMPORTANT: You MUST authorize this device in your ZeroTier Central account (https://my.zerotier.com)!"
    ;;

  *)
    if [[ -z "$VPN_PROVIDER" ]]; then
      warn "VPN_PROVIDER is not set in $ENV_FILE. Skipping VPN setup."
    else
      warn "Invalid VPN_PROVIDER specified: '$VPN_PROVIDER'. Must be 'tailscale' or 'zerotier'. Skipping VPN setup."
    fi
    ;;
esac

log "VPN setup script finished."
exit 0