import os
import psutil
import subprocess
import datetime
import platform
from flask import Flask, render_template, request, redirect, url_for, Response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# --- Detect OS for local testing adjustments ---
IS_LINUX = platform.system() == 'Linux'
IS_MACOS = platform.system() == 'Darwin'

app = Flask(__name__)
auth = HTTPBasicAuth()

# --- Configuration ---
# Read from environment variables passed by systemd service or shell
# Provide defaults matching typical .env setup values as fallback
USERNAME = os.environ.get('MONITOR_USER', 'monitor')
PASSWORD = os.environ.get('MONITOR_PASSWORD', 'YourSecureMonitorPassword')
VPN_PROVIDER = os.environ.get('VPN_PROVIDER', 'tailscale') # Default to one for testing
SHARE_BASE_PATH = os.environ.get('SHARE_BASE_PATH', '/mnt/shares') # Pi default

# For local testing, maybe override share base path if needed
# if not IS_LINUX:
#     SHARE_BASE_PATH = '/Volumes' # Example for macOS

users = {
    USERNAME: generate_password_hash(PASSWORD)
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

# --- Helper Functions ---
def get_uptime():
    try:
        boot_time_timestamp = psutil.boot_time()
        elapsed_time = datetime.datetime.now() - datetime.datetime.fromtimestamp(boot_time_timestamp)
        return str(elapsed_time).split('.')[0] # Remove microseconds
    except Exception:
        return "N/A"

def get_disk_info():
    disks = []
    try:
        # On Linux, only look under SHARE_BASE_PATH
        # On other OS (like macOS for testing), maybe show all non-removable?
        # Let's stick to SHARE_BASE_PATH for consistency, local testing might show nothing here.
        for part in psutil.disk_partitions():
            is_relevant = False
            if IS_LINUX:
                 # Check if it starts with the base path AND is a physical device (not tmpfs etc)
                 if part.mountpoint.startswith(SHARE_BASE_PATH) and \
                    any(opt in part.opts for opt in ['rw', 'ro']) and \
                    not any(fs in part.fstype for fs in ['tmpfs', 'squashfs']):
                     is_relevant = True
            # Add local testing logic here if desired, e.g., show '/' on macOS
            # elif IS_MACOS and part.mountpoint == '/':
            #    is_relevant = True

            if is_relevant and os.path.exists(part.mountpoint):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    display_name = part.mountpoint.replace(SHARE_BASE_PATH, '').strip('/') or 'RootShare'
                    disks.append({
                        'mountpoint': display_name,
                        'total': f"{usage.total / (1024**3):.1f} GB",
                        'used': f"{usage.used / (1024**3):.1f} GB",
                        'percent': usage.percent
                    })
                except Exception:
                    display_name = part.mountpoint.replace(SHARE_BASE_PATH, '').strip('/') or 'RootShare'
                    disks.append({'mountpoint': display_name, 'error': 'Usage N/A'})
    except Exception as e:
        print(f"Error getting disk info: {e}") # Log error for debugging
        pass
    return disks

def run_command(cmd_list, timeout=5):
    """Helper to run commands and handle errors/timeouts."""
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout, check=False) # check=False to handle non-zero exit codes
        if result.returncode != 0:
            # Log stderr but don't crash the app
            print(f"Command failed: {' '.join(cmd_list)}. Error: {result.stderr.strip()}")
            return None
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"Command not found: {cmd_list[0]}")
        return None
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd_list)}")
        return None
    except Exception as e:
        print(f"Error running command {' '.join(cmd_list)}: {e}")
        return None


def get_connected_devices():
    devices = {'type': 'N/A', 'peers': [], 'smb_clients': []}
    try:
        devices['type'] = VPN_PROVIDER if VPN_PROVIDER in ['tailscale', 'zerotier'] else 'None'

        # --- VPN Peers ---
        if VPN_PROVIDER == 'tailscale':
            # Check service status first (Linux only)
            if IS_LINUX and run_command(['systemctl', 'is-active', '--quiet', 'tailscaled']) is None:
                 devices['peers'].append("Tailscale service not active")
            else:
                status_output = run_command(['tailscale', 'status'])
                if status_output:
                    for line in status_output.split('\n'):
                        parts = line.split()
                        if len(parts) >= 2:
                            devices['peers'].append(f"{parts[1]} ({parts[0]})") # Name (IP)
                elif IS_LINUX: # Only report command failure if expected to work
                     devices['peers'].append("Failed to get Tailscale status")

        elif VPN_PROVIDER == 'zerotier':
            if IS_LINUX and run_command(['systemctl', 'is-active', '--quiet', 'zerotier-one']) is None:
                devices['peers'].append("ZeroTier service not active")
            else:
                status_output = run_command(['zerotier-cli', 'listpeers'])
                if status_output:
                    for line in status_output.split('\n'):
                        parts = line.split()
                        # Basic parsing, might need adjustment based on actual output format
                        if len(parts) >= 3 and parts[2] == 'LEAF':
                            devices['peers'].append(f"Node {parts[1]} ({parts[0]})")
                elif IS_LINUX:
                     devices['peers'].append("Failed to get ZeroTier status")

        # --- SMB Clients (Linux only for now) ---
        if IS_LINUX:
            smb_output = run_command(['smbstatus', '-b'])
            if smb_output:
                lines = smb_output.strip().split('\n')
                if len(lines) > 3: # Skip header lines
                    for line in lines[3:]:
                        parts = line.split()
                        if len(parts) >= 2:
                            # User (Machine) - limited info
                            devices['smb_clients'].append(f"{parts[0]} ({parts[1]})")
            # else: # Don't report error if smbstatus just isn't installed or running
            #    devices['smb_clients'].append("Failed to get SMB status")


    except Exception as e:
        devices['error'] = str(e)
        print(f"Error getting connection info: {e}")
    return devices

# --- Routes ---
@app.route('/')
@auth.login_required
def index():
    data = {
        'cpu_percent': psutil.cpu_percent(),
        'ram_percent': psutil.virtual_memory().percent,
        'uptime': get_uptime(),
        'disks': get_disk_info(),
        'connections': get_connected_devices(),
        'is_linux': IS_LINUX # Pass OS type to template
    }
    # Pass SHARE_BASE_PATH to template for display purposes
    return render_template('index.html', data=data, SHARE_BASE_PATH=SHARE_BASE_PATH)

@app.route('/reboot', methods=['POST'])
@auth.login_required
def reboot():
    if not IS_LINUX:
        return "Reboot only supported on Linux.", 403 # Forbidden

    try:
        # Use sudo because this app runs as non-root user rpimon
        result = subprocess.run(['sudo', '/sbin/reboot'], check=True, capture_output=True, text=True, timeout=10)
        # Might not get a response if reboot is fast
        return "Reboot command issued successfully.", 200
    except subprocess.CalledProcessError as e:
        print(f"Reboot failed: {e.stderr}")
        return f"Reboot failed: {e.stderr}", 500
    except Exception as e:
        print(f"Reboot failed: {str(e)}")
        return f"Reboot failed: {str(e)}", 500

# --- Main execution for local testing ---
if __name__ == '__main__':
    print("Starting Flask development server...")
    print(f"Monitor User: {USERNAME}")
    print(f"Monitor Pass: {PASSWORD}")
    print(f"VPN Provider: {VPN_PROVIDER}")
    print(f"Share Path: {SHARE_BASE_PATH}")
    print(f"OS Type: {platform.system()}")
    # Make sure to set environment variables in your shell before running for local testing
    # e.g., export MONITOR_USER=test MONITOR_PASSWORD=test VPN_PROVIDER=none SHARE_BASE_PATH=/tmp
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8081)), debug=True)