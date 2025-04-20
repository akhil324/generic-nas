import os
import psutil
import subprocess
import datetime
import platform
import math
import time
import re # For parsing nethogs
from collections import namedtuple
from flask import Flask, render_template, request, redirect, url_for, Response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# --- Detect OS ---
IS_LINUX = platform.system() == 'Linux'
IS_MACOS = platform.system() == 'Darwin'
IS_FREEBSD = platform.system() == 'FreeBSD'

app = Flask(__name__)
auth = HTTPBasicAuth()

# --- Configuration ---
USERNAME = os.environ.get('MONITOR_USER', 'monitor')
PASSWORD = os.environ.get('MONITOR_PASSWORD', 'YourSecureMonitorPassword')
VPN_PROVIDER = os.environ.get('VPN_PROVIDER', 'tailscale')
SHARE_BASE_PATH = os.environ.get('SHARE_BASE_PATH', '/mnt/shares')

users = {
    USERNAME: generate_password_hash(PASSWORD)
}

# --- Globals for Rate Calculation ---
last_check_time = 0
last_net_io = {}
last_disk_io = {}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

# --- Helper Functions ---
def bytes_to_human(n_bytes, suffix='B'):
    # (No changes needed)
    if n_bytes is None: return "N/A"
    if n_bytes == 0: return f'0 {suffix}'
    unit_suffix = ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi']
    i = 0; num = abs(n_bytes)
    while num >= 1024 and i < len(unit_suffix)-1: num /= 1024.; i += 1
    f = ('%.1f' % num).rstrip('0').rstrip('.'); sign = '-' if n_bytes < 0 else ''
    return f'{sign}{f} {unit_suffix[i]}{suffix}'

def get_uptime():
    # (No changes needed)
    try:
        boot_time_timestamp = psutil.boot_time(); elapsed_time = datetime.datetime.now() - datetime.datetime.fromtimestamp(boot_time_timestamp)
        total_seconds = int(elapsed_time.total_seconds()); days, remainder = divmod(total_seconds, 86400); hours, remainder = divmod(remainder, 3600); minutes, seconds = divmod(remainder, 60)
        if days > 0: return f"{days}d {hours:02}:{minutes:02}:{seconds:02}"
        else: return f"{hours:02}:{minutes:02}:{seconds:02}"
    except Exception: return "N/A"

# Removed get_load_average

def get_cpu_core_details():
    # (No changes needed)
    try: return psutil.cpu_percent(percpu=True, interval=None)
    except Exception: return []

def get_memory_info():
    # (No changes needed - swap data collected but ignored in template)
    mem = {'error': None}; swap = {'error': None}
    try:
        vmem = psutil.virtual_memory(); mem['total'] = bytes_to_human(vmem.total); mem['available'] = bytes_to_human(vmem.available); mem['used'] = bytes_to_human(vmem.used)
        mem['free'] = bytes_to_human(vmem.free); mem['percent'] = vmem.percent
        if IS_LINUX:
            mem['active'] = bytes_to_human(vmem.active) if hasattr(vmem, 'active') else 'N/A'; mem['inactive'] = bytes_to_human(vmem.inactive) if hasattr(vmem, 'inactive') else 'N/A'
            mem['buffers'] = bytes_to_human(vmem.buffers) if hasattr(vmem, 'buffers') else 'N/A'; mem['cached'] = bytes_to_human(vmem.cached) if hasattr(vmem, 'cached') else 'N/A'
            mem['shared'] = bytes_to_human(vmem.shared) if hasattr(vmem, 'shared') else 'N/A'
    except Exception as e: mem['error'] = str(e)
    try:
        smem = psutil.swap_memory(); swap['total'] = bytes_to_human(smem.total); swap['used'] = bytes_to_human(smem.used)
        swap['free'] = bytes_to_human(smem.free); swap['percent'] = smem.percent
    except Exception as e: swap['error'] = str(e)
    return {'virtual': mem, 'swap': swap}

def get_disk_fs_info():
    # (No changes needed)
    disks = []
    try:
        for part in psutil.disk_partitions():
            is_relevant = False
            if IS_LINUX:
                 if part.mountpoint.startswith(SHARE_BASE_PATH) and any(opt in part.opts for opt in ['rw', 'ro']) and not any(fs in part.fstype for fs in ['tmpfs', 'squashfs']): is_relevant = True
            if is_relevant and os.path.exists(part.mountpoint):
                try:
                    usage = psutil.disk_usage(part.mountpoint); display_name = part.mountpoint.replace(SHARE_BASE_PATH, '').strip('/') or 'RootShare'
                    disks.append({'mountpoint': display_name, 'total_b': usage.total, 'used_b': usage.used, 'total': bytes_to_human(usage.total), 'used': bytes_to_human(usage.used), 'percent': usage.percent})
                except Exception: display_name = part.mountpoint.replace(SHARE_BASE_PATH, '').strip('/') or 'RootShare'; disks.append({'mountpoint': display_name, 'error': 'Usage N/A'})
    except Exception as e: print(f"Error getting disk fs info: {e}")
    return disks

def get_network_io(top_n=4):
    # (No changes needed)
    global last_check_time, last_net_io; nics_with_rates = []; current_time = time.time(); interval = current_time - last_check_time if last_check_time > 0 else 0
    try:
        current_io = psutil.net_io_counters(pernic=True)
        for nic, stats in current_io.items():
            if nic.startswith(('lo', 'docker', 'veth', 'vmnet', 'bridge', 'gif', 'stf')): continue # Added more filters
            rx_rate_bytes = 0; tx_rate_bytes = 0
            if interval > 0 and nic in last_net_io:
                rx_rate_bytes = (stats.bytes_recv - last_net_io[nic].bytes_recv) / interval; tx_rate_bytes = (stats.bytes_sent - last_net_io[nic].bytes_sent) / interval
            nics_with_rates.append({'name': nic, 'rx_total': bytes_to_human(stats.bytes_recv), 'tx_total': bytes_to_human(stats.bytes_sent), 'rx_rate': bytes_to_human(rx_rate_bytes, suffix='B/s'), 'tx_rate': bytes_to_human(tx_rate_bytes, suffix='B/s'), 'combined_rate': rx_rate_bytes + tx_rate_bytes})
        nics_with_rates.sort(key=lambda x: x['combined_rate'], reverse=True); last_net_io = current_io
    except Exception as e: print(f"Error getting network IO: {e}")
    return nics_with_rates[:top_n]

def get_disk_io():
    # (No changes needed)
    global last_check_time, last_disk_io; disks = {}; current_time = time.time(); interval = current_time - last_check_time if last_check_time > 0 else 0
    try:
        current_io = psutil.disk_io_counters(perdisk=True)
        for disk, stats in current_io.items():
            if disk.startswith(('loop', 'ram', 'dm-', 'md')): continue
            is_partition = any(char.isdigit() for char in disk.replace('nvme', '')[-2:]); base_disk = disk.rstrip('0123456789')
            if is_partition and base_disk in current_io: continue
            read_rate = "N/A"; write_rate = "N/A"
            if interval > 0 and disk in last_disk_io:
                read_diff = stats.read_bytes - last_disk_io[disk].read_bytes; write_diff = stats.write_bytes - last_disk_io[disk].write_bytes
                read_rate = bytes_to_human(read_diff / interval, suffix='B/s'); write_rate = bytes_to_human(write_diff / interval, suffix='B/s')
            disks[disk] = {'read_total': bytes_to_human(stats.read_bytes), 'write_total': bytes_to_human(stats.write_bytes), 'read_rate': read_rate, 'write_rate': write_rate}
        last_disk_io = current_io; last_check_time = current_time
    except Exception as e: print(f"Error getting disk IO: {e}")
    return disks

def get_temperature():
    """Attempts to get CPU temperature across Linux, macOS, FreeBSD."""
    temp_c = "N/A"
    try:
        # 1. psutil (Linux primarily, might work elsewhere)
        if hasattr(psutil, "sensors_temperatures"):
            all_temps = psutil.sensors_temperatures()
            # Prioritize keys commonly found
            keys_to_check = ['cpu_thermal', 'coretemp', 'k10temp', 'cpu_temp'] # Linux common
            for key in keys_to_check:
                if key in all_temps and all_temps[key]:
                    temp_c = f"{all_temps[key][0].current:.1f}°C"
                    break
        # 2. Linux /sys fallback
        if temp_c == 'N/A' and IS_LINUX and os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
             with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                 temp_milli_c = int(f.read().strip())
                 temp_c = f"{temp_milli_c / 1000.0:.1f}°C"
        # 3. macOS osx-cpu-temp fallback (requires external tool)
        elif temp_c == 'N/A' and IS_MACOS:
            osx_temp_output = run_command(['osx-cpu-temp']) # Assumes installed via brew
            if osx_temp_output and '°C' in osx_temp_output:
                temp_c = osx_temp_output.strip() # Use the tool's output directly
        # 4. FreeBSD sysctl fallback
        elif temp_c == 'N/A' and IS_FREEBSD:
            # Common sysctl OIDs - may need adjustment based on hardware
            oids_to_check = ['dev.cpu.0.temperature', 'hw.acpi.thermal.tz0.temperature']
            for oid in oids_to_check:
                sysctl_output = run_command(['sysctl', '-n', oid])
                if sysctl_output and 'C' in sysctl_output: # Check if output looks like temp
                    temp_c = sysctl_output.strip().replace(" ", "") # Cleanup output
                    break # Found one

    except Exception as e:
        print(f"Error getting temperature: {e}")
        temp_c = "Error" # Indicate an error occurred
    return temp_c

def get_top_processes(count=8):
    # (No changes needed)
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'username', 'cpu_percent', 'memory_percent', 'name']):
            try: processes.append({'pid': proc.info['pid'], 'user': proc.info['username'][:10], 'cpu': proc.info['cpu_percent'], 'mem': proc.info['memory_percent'], 'name': proc.info['name']})
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
            except Exception as e: print(f"Error processing PID {proc.info.get('pid', 'N/A')}: {e}")
        processes.sort(key=lambda p: p['mem'], reverse=True)
    except Exception as e: print(f"Error getting process list: {e}"); return [{'pid': 'ERR', 'user': '', 'cpu': 0, 'mem': 0, 'name': 'Could not retrieve process list'}]
    return processes[:count]

def run_command(cmd_list, timeout=5):
    # (No changes needed)
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0: print(f"Command failed: {' '.join(cmd_list)}. Error: {result.stderr.strip()}"); return None
        return result.stdout.strip()
    except FileNotFoundError: return None
    except subprocess.TimeoutExpired: return None
    except Exception as e: print(f"Error running command {' '.join(cmd_list)}: {e}"); return None

def get_connected_devices():
    # (No changes needed)
    devices = {'type': 'N/A', 'peers': [], 'smb_clients': []}
    try:
        devices['type'] = VPN_PROVIDER if VPN_PROVIDER in ['tailscale', 'zerotier'] else 'None'
        if VPN_PROVIDER == 'tailscale':
            if IS_LINUX and run_command(['systemctl', 'is-active', '--quiet', 'tailscaled']) is None: devices['peers'].append("Tailscale service not active")
            else:
                status_output = run_command(['tailscale', 'status']);
                if status_output:
                    for line in status_output.split('\n'): parts = line.split();
                    if len(parts) >= 2: devices['peers'].append(f"{parts[1]} ({parts[0]})")
                elif IS_LINUX: devices['peers'].append("Failed to get Tailscale status")
        elif VPN_PROVIDER == 'zerotier':
            if IS_LINUX and run_command(['systemctl', 'is-active', '--quiet', 'zerotier-one']) is None: devices['peers'].append("ZeroTier service not active")
            else:
                status_output = run_command(['zerotier-cli', 'listpeers']);
                if status_output:
                    for line in status_output.split('\n'): parts = line.split();
                    if len(parts) >= 3 and parts[2] == 'LEAF': devices['peers'].append(f"Node {parts[1]} ({parts[0]})")
                elif IS_LINUX: devices['peers'].append("Failed to get ZeroTier status")
        if IS_LINUX:
            smb_output = run_command(['smbstatus', '-b']);
            if smb_output:
                lines = smb_output.strip().split('\n');
                if len(lines) > 3:
                    for line in lines[3:]: parts = line.split();
                    if len(parts) >= 2: devices['smb_clients'].append(f"{parts[0]} ({parts[1]})")
    except Exception as e: devices['error'] = str(e); print(f"Error getting connection info: {e}")
    return devices

def get_service_network_io():
    # (No changes needed - keep Linux only)
    if not IS_LINUX: return {'error': 'Service I/O only available on Linux'}
    services = {};
    try:
        cmd = ['sudo', 'nethogs', '-t', '-c', '1', '-k']; nethogs_output = run_command(cmd, timeout=10)
        if nethogs_output is None:
            if run_command(['which', 'nethogs']) is None: return {'error': 'nethogs command not found. Please install it.'}
            else: return {'error': 'Failed to run or parse nethogs output. Check permissions or logs.'}
        known_services = {'smbd': 'Samba', 'nmbd': 'Samba (NetBIOS)', 'filebrowser': 'File Browser', 'gunicorn': 'Monitoring UI', 'tailscaled': 'Tailscale', 'zerotier-one': 'ZeroTier'}
        temp_stats = {name: {'sent': 0.0, 'recv': 0.0} for name in known_services.values()}
        process_pattern = re.compile(r"^(?:.*/)?([^\s/]+)(?:/\d+/\S+)?.*?\s+(\d+\.?\d*)\s+(\d+\.?\d*)$", re.MULTILINE)
        for line in nethogs_output.splitlines():
             match = process_pattern.search(line)
             if match:
                 proc_name, sent_kb, recv_kb = match.groups()
                 for key, display_name in known_services.items():
                     if key in proc_name:
                         try: temp_stats[display_name]['sent'] += float(sent_kb); temp_stats[display_name]['recv'] += float(recv_kb)
                         except ValueError: pass
                         break
        for name, stats in temp_stats.items():
            if stats['sent'] > 0 or stats['recv'] > 0: services[name] = {'sent_rate': bytes_to_human(stats['sent'] * 1024, suffix='B/s'), 'recv_rate': bytes_to_human(stats['recv'] * 1024, suffix='B/s')}
        if not services: services['info'] = 'No significant I/O detected for known services.'
    except Exception as e: services['error'] = f"Error processing service I/O: {str(e)}"; print(f"Error getting service network IO: {e}")
    return services

def get_relevant_ip_addresses():
    """Gets primary LAN IP and VPN IP if available."""
    ips = {'vpn': 'N/A', 'lan': 'N/A'}
    lan_if_name = 'N/A'

    try:
        all_addrs = psutil.net_if_addrs()

        # --- Find LAN IP ---
        # Prioritize common wired/wireless interfaces
        lan_candidates = {}
        preferred_prefixes = ['eth', 'en', 'wlan'] # Linux/macOS/Linux wireless
        other_prefixes = ['eno', 'ens'] # Other common Linux names

        for iface, addrs in all_addrs.items():
            if iface == 'lo': continue # Skip loopback

            priority = 2 # Lower priority for non-preferred
            for prefix in preferred_prefixes:
                if iface.startswith(prefix):
                    priority = 0
                    break
            if priority > 0:
                 for prefix in other_prefixes:
                     if iface.startswith(prefix):
                         priority = 1
                         break

            for addr in addrs:
                # Look for non-link-local IPv4 addresses
                if addr.family == psutil.AF_INET and not addr.address.startswith(('127.', '169.254.')):
                    # Store candidate with its priority and interface name
                    lan_candidates[addr.address] = {'priority': priority, 'iface': iface}
                    break # Take first valid IPv4 on this interface

        # Select the best candidate based on priority
        if lan_candidates:
            best_lan_ip = min(lan_candidates, key=lambda k: lan_candidates[k]['priority'])
            ips['lan'] = best_lan_ip
            lan_if_name = lan_candidates[best_lan_ip]['iface']


        # --- Find VPN IP (keep previous logic) ---
        vpn_if = None
        if VPN_PROVIDER == 'tailscale': vpn_if = 'tailscale0'
        # ZeroTier handled below

        if vpn_if and vpn_if in all_addrs:
            for addr in all_addrs[vpn_if]:
                if addr.family == psutil.AF_INET: ips['vpn'] = addr.address; break
        if ips['vpn'] == 'N/A':
             for iface, addrs in all_addrs.items():
                 if iface.startswith(('zt', 'tailscale', 'utun')): # Added utun for macOS VPNs
                     for addr in addrs:
                         if addr.family == psutil.AF_INET: ips['vpn'] = addr.address; break
                 if ips['vpn'] != 'N/A': break

        # --- Format Output ---
        # Prioritize showing LAN IP
        ip_string = f"{ips['lan']} ({lan_if_name})" if ips['lan'] != 'N/A' else "No LAN IP Found"
        if ips['vpn'] != 'N/A':
            ip_string += f" / VPN: {ips['vpn']}" # Append VPN IP if found

        return ip_string

    except Exception as e:
        print(f"Error getting IP addresses: {e}")
        return "Error retrieving IPs"


# --- Routes ---
@app.route('/')
@auth.login_required
def index():
    # Get CPU% first
    cpu_total = psutil.cpu_percent(interval=None); cpu_cores = get_cpu_core_details()
    data = {
        'hostname': platform.node(), 'os_name': f"{platform.system()} {platform.release()}",
        'ip_address': get_relevant_ip_addresses(), # Changed from load_avg
        'cpu_total': cpu_total, 'cpu_cores': cpu_cores, 'memory': get_memory_info(),
        'uptime': get_uptime(), 'temperature': get_temperature(),
        'disk_fs': get_disk_fs_info(), 'disk_io': get_disk_io(), 'net_io': get_network_io(),
        'service_net_io': get_service_network_io(),
        'connections': get_connected_devices(), 'top_procs': get_top_processes(), 'is_linux': IS_LINUX
    }
    return render_template('index.html', data=data, SHARE_BASE_PATH=SHARE_BASE_PATH)

@app.route('/reboot', methods=['POST'])
@auth.login_required
def reboot():
    # (No changes needed)
    if not IS_LINUX: return "Reboot only supported on Linux.", 403
    try:
        result = subprocess.run(['sudo', '/sbin/reboot'], check=True, capture_output=True, text=True, timeout=10)
        return "Reboot command issued successfully.", 200
    except subprocess.CalledProcessError as e: print(f"Reboot failed: {e.stderr}"); return f"Reboot failed: {e.stderr}", 500
    except Exception as e: print(f"Reboot failed: {str(e)}"); return f"Reboot failed: {str(e)}", 500

# --- Main execution for local testing ---
if __name__ == '__main__':
    print("Starting Flask development server...")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8081)), debug=True)