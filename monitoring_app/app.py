#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import psutil
import subprocess
import datetime
import platform
import math
import time
import re
import sys
import socket
from collections import namedtuple
from flask import Flask, render_template, request, redirect, url_for, Response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# --- Constants & OS Detection ---
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"
IS_FREEBSD = platform.system() == "FreeBSD"

# --- Configuration (Read Once) ---
# SHARE_BASE_PATH is read in SystemMonitor init now
PORT = int(os.environ.get('PORT', 8081))
MONITOR_USER = os.environ.get('MONITOR_USER', 'monitor')
MONITOR_PASSWORD = os.environ.get('MONITOR_PASSWORD', 'YourSecureMonitorPassword')
VPN_PROVIDER = os.environ.get('VPN_PROVIDER', 'tailscale').lower() # Keep VPN provider here

# --- Helper Functions (Remain Standalone) ---
def bytes_to_human(n_bytes, suffix='B'):
    if n_bytes is None: return "N/A"
    if n_bytes == 0: return f"0 {suffix}"
    size_name = ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi")
    i = int(math.floor(math.log(n_bytes, 1024))) if n_bytes > 0 else 0
    p = math.pow(1024, i)
    # Use 2 decimal places for GiB and higher for better precision on large disks
    s = round(n_bytes / p, 2 if i >= 3 else (1 if i > 0 else 0))
    return f"{s} {size_name[i]}{suffix}"

def run_command(cmd_list, timeout=5):
    try:
        result = subprocess.run(
            cmd_list, capture_output=True, text=True, check=False, timeout=timeout
        )
        if result.returncode != 0:
            # Suppress specific errors if needed, otherwise log
            # if not (cmd_list[0] == 'udevadm' and 'No such file or directory' in result.stderr):
            print(f"Error running command '{' '.join(cmd_list)}': {result.stderr.strip()}", file=sys.stderr)
            return None
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"Error: Command not found: {cmd_list[0]}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"Error: Command '{' '.join(cmd_list)}' timed out after {timeout}s", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error executing command '{' '.join(cmd_list)}': {e}", file=sys.stderr)
        return None

# --- System Monitor Class ---
class SystemMonitor:
    def __init__(self):
        """Initialize state and read configuration."""
        self.last_check_time = 0
        self.last_disk_io = {}

        # Read Disk Filtering Config
        self.share_base_path = os.environ.get('SHARE_BASE_PATH', '/mnt/shares')
        allowed_fs_str = os.environ.get('ALLOWED_FILESYSTEMS', 'ext4,exfat,ntfs,vfat,btrfs,xfs,apfs,hfsplus') # Added macOS defaults
        # Process into a set for efficient lookup
        self.allowed_fs_set = {fs.strip().lower() for fs in allowed_fs_str.split(',') if fs.strip()}
        print(f"Debug: Initialized with SHARE_BASE_PATH='{self.share_base_path}', ALLOWED_FILESYSTEMS={self.allowed_fs_set}", file=sys.stderr)


        # --- Caches for external command paths (optional but good practice) ---
        self._nethogs_path = None
        # Udevadm check removed as it's no longer used for filtering
        # self._udevadm_path = None
        # self._warned_udevadm = False
        # Root device check removed as it's no longer used for filtering
        # self._root_device_base_name = self._find_root_device_base_name() if IS_LINUX else None

    # _find_root_device_base_name method removed
    # _is_usb3_device method removed

    # --- Other get_* methods remain the same as the previous OOP version ---
    # get_uptime, get_cpu_info, get_memory_info, get_disk_io, get_temperature,
    # get_top_processes, get_connected_devices, get_service_network_io,
    # get_relevant_ip_addresses
    # ... (Keep the code for these methods exactly as in the previous response) ...
    def get_uptime(self):
        try:
            uptime_seconds = int(time.time() - psutil.boot_time())
            delta = datetime.timedelta(seconds=uptime_seconds)
            d = delta.days
            h, rem = divmod(delta.seconds, 3600)
            m, s = divmod(rem, 60)
            return f"{d}d {h:02d}:{m:02d}:{s:02d}" if d > 0 else f"{h:02d}:{m:02d}:{s:02d}"
        except Exception as e: print(f"Error getting uptime: {e}", file=sys.stderr); return "N/A"

    def get_cpu_info(self):
        try:
            total = psutil.cpu_percent(interval=None)
            cores = psutil.cpu_percent(percpu=True, interval=None)
            return {'total': total, 'cores': cores}
        except Exception as e: print(f"Error getting CPU info: {e}", file=sys.stderr); return {'total': "Error", 'cores': []}

    def get_memory_info(self):
        mem_info = {'virtual': {'error': None}, 'swap': {'error': None}}
        try:
            vmem = psutil.virtual_memory()
            mem_info['virtual'] = {'total': bytes_to_human(vmem.total), 'available': bytes_to_human(vmem.available),'used': bytes_to_human(vmem.used), 'free': bytes_to_human(vmem.free),'percent': vmem.percent, 'error': None}
            if IS_LINUX: mem_info['virtual'].update({attr: bytes_to_human(getattr(vmem, attr, None)) for attr in ['active', 'inactive', 'buffers', 'cached', 'shared']})
        except Exception as e: print(f"Error getting virtual memory info: {e}", file=sys.stderr); mem_info['virtual']['error'] = f"Error: {e}"
        try:
            swap = psutil.swap_memory()
            mem_info['swap'] = {'total': bytes_to_human(swap.total), 'used': bytes_to_human(swap.used),'free': bytes_to_human(swap.free), 'percent': swap.percent, 'error': None}
        except Exception as e: print(f"Error getting swap memory info: {e}", file=sys.stderr); mem_info['swap']['error'] = f"Error: {e}"
        return mem_info

    def get_disk_fs_info(self):
        """
        Gets disk usage information based on SHARE_BASE_PATH and ALLOWED_FILESYSTEMS,
        reflecting the setup of manage_storage.sh.
        """
        fs_info = []
        # print(f"Debug: Checking partitions against SHARE_BASE_PATH='{self.share_base_path}', ALLOWED_FILESYSTEMS={self.allowed_fs_set}", file=sys.stderr)

        try:
            # all=False is generally preferred here to skip pseudo/memory filesystems
            partitions = psutil.disk_partitions(all=False)
            # print(f"Debug: Found partitions: {[p.mountpoint for p in partitions]}", file=sys.stderr)

            for part in partitions:
                # print(f"Debug: Evaluating partition: {part.device} mounted at {part.mountpoint} type {part.fstype}", file=sys.stderr)

                # 1. Filter by Mount Point Prefix
                if not part.mountpoint.startswith(self.share_base_path):
                    # print(f"Debug: Skipping {part.mountpoint} - does not start with {self.share_base_path}", file=sys.stderr)
                    continue

                # 2. Filter by Allowed Filesystem Type (case-insensitive)
                if part.fstype.lower() not in self.allowed_fs_set:
                    # print(f"Debug: Skipping {part.mountpoint} - fstype '{part.fstype}' not in {self.allowed_fs_set}", file=sys.stderr)
                    continue

                # 3. Check if Mount Point Exists
                if not os.path.exists(part.mountpoint):
                    # print(f"Debug: Skipping {part.mountpoint} - path does not exist", file=sys.stderr)
                    continue

                # --- If all checks pass, get usage ---
                # print(f"Debug: Passed filters for {part.mountpoint}", file=sys.stderr)
                try:
                    usage = psutil.disk_usage(part.mountpoint)

                    # Create display name relative to SHARE_BASE_PATH
                    relative_path = part.mountpoint[len(self.share_base_path):].lstrip('/')
                    # Use the relative path directly, or a placeholder if it's empty (mounted at base path itself)
                    display_name = relative_path if relative_path else os.path.basename(self.share_base_path) or "RootShare"

                    fs_info.append({
                        'mountpoint': display_name,
                        # Use GB for total/used for potentially better readability on large disks
                        'total': bytes_to_human(usage.total, suffix='B'), # Keep original B suffix for consistency maybe? Let's stick to B.
                        'used': bytes_to_human(usage.used, suffix='B'),
                        'percent': usage.percent,
                    })
                    # print(f"Debug: Added {display_name} - {usage.percent}% used", file=sys.stderr)

                except (OSError, Exception) as e: # Catch specific usage errors
                    print(f"Error getting disk usage for {part.mountpoint}: {e}", file=sys.stderr)
                    # Still show the mountpoint even if usage fails
                    relative_path = part.mountpoint[len(self.share_base_path):].lstrip('/')
                    display_name = relative_path if relative_path else os.path.basename(self.share_base_path) or "RootShare"
                    fs_info.append({'mountpoint': display_name, 'error': f"Usage Error"}) # Simplified error

        except Exception as e: # Catch partition listing errors
            print(f"Error listing disk partitions: {e}", file=sys.stderr)
            return [{'error': f"Partition List Error: {e}"}]

        # Sort by mountpoint name (alphabetical) for consistent order
        fs_info.sort(key=lambda x: x.get('mountpoint', ''))
        # print(f"Debug: Final fs_info: {fs_info}", file=sys.stderr)
        return fs_info

    def get_disk_io(self):
        disk_io_rates = {}
        try:
            now = time.monotonic()
            current_disk_io = psutil.disk_io_counters(perdisk=True)
            time_delta = now - self.last_check_time if self.last_check_time else 0
            disk_bases = {name.rstrip('0123456789') for name in current_disk_io}
            filtered_disks = { name: counters for name, counters in current_disk_io.items() if not name.startswith(('loop', 'ram', 'dm-', 'md')) and not (name != name.rstrip('0123456789') and name.rstrip('0123456789') in disk_bases) }
            for name, current_counters in filtered_disks.items():
                last_counters = self.last_disk_io.get(name)
                read_rate_bytes, write_rate_bytes = 0, 0
                if last_counters and time_delta > 0:
                    read_rate_bytes = max(0, (current_counters.read_bytes - last_counters.read_bytes) / time_delta)
                    write_rate_bytes = max(0, (current_counters.write_bytes - last_counters.write_bytes) / time_delta)
                disk_io_rates[name] = {'read_total': bytes_to_human(current_counters.read_bytes),'write_total': bytes_to_human(current_counters.write_bytes),'read_rate': bytes_to_human(read_rate_bytes, suffix='B/s'),'write_rate': bytes_to_human(write_rate_bytes, suffix='B/s'),}
            self.last_disk_io = current_disk_io
            self.last_check_time = now
            return disk_io_rates
        except Exception as e: print(f"Error getting disk I/O: {e}", file=sys.stderr); return {}

    def get_temperature(self):
        temp_c = None
        try:
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                priority_keys = ['coretemp', 'k10temp', 'cpu_thermal', 'cpu-thermal', 'acpitz', 'pch_skylake', 'soc_thermal']
                all_temps = [(k, entry) for k, entries in temps.items() for entry in entries if entry.current > 0]
                for key in priority_keys:
                    for k_temp, entry in all_temps:
                        if key in k_temp.lower(): temp_c = entry.current; break
                    if temp_c: break
                if not temp_c and all_temps: temp_c = all_temps[0][1].current
            if temp_c is None and IS_LINUX:
                try:
                    path = '/sys/class/thermal/thermal_zone0/temp'
                    with open(path, 'r') as f: temp_raw = int(f.read().strip())
                    if temp_raw > 0: temp_c = temp_raw / 1000.0
                except (IOError, ValueError): pass
            if temp_c is None and IS_MACOS:
                output = run_command(['osx-cpu-temp'], timeout=2)
                if output: temp_match = re.search(r'(\d+\.?\d*)', output); temp_c = float(temp_match.group(1)) if temp_match else None
            if temp_c is None and IS_FREEBSD:
                for oid in ['dev.cpu.0.temperature', 'hw.acpi.thermal.tz0.temperature']:
                    output = run_command(['sysctl', '-n', oid], timeout=2)
                    if output:
                        try:
                            temp_val = float(output.replace('C', '').strip())
                            temp_c = temp_val / 10.0 - 273.15 if temp_val > 273 else temp_val
                            if temp_c is not None: break
                        except ValueError: pass
            return f"{temp_c:.1f}°C" if temp_c is not None else "N/A"
        except Exception as e: print(f"Error getting temperature: {e}", file=sys.stderr); return "Error"

    def get_top_processes(self, count=8):
        processes = []
        attrs = ['pid', 'username', 'cpu_percent', 'memory_percent', 'name', 'memory_info']
        try:
            for p in psutil.process_iter(attrs=attrs, ad_value=None):
                try:
                    info = p.info
                    if info['pid'] is None or info['name'] in ('System Idle Process', 'kernel_task'): continue
                    if info['username'] is None and not (IS_LINUX and info['pid'] is not None and info['pid'] <= 2): continue
                    mem_rss = info['memory_info'].rss if info.get('memory_info') else 0
                    processes.append({'pid': info['pid'], 'username': info['username'] or 'N/A','cpu_percent': info['cpu_percent'] or 0.0,'memory_percent': info['memory_percent'] or 0.0,'memory_rss_human': bytes_to_human(mem_rss),'name': info['name']})
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
                except Exception as e: print(f"Error getting info for proc {p.pid if hasattr(p, 'pid') else '?'}: {e}", file=sys.stderr)
            processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            return processes[:count]
        except Exception as e: print(f"Error listing processes: {e}", file=sys.stderr); return [{'error': f"Process List Error: {e}"}]

    def get_connected_devices(self):
        connections = {'type': 'None', 'peers': [], 'smb_clients': [], 'error': None}
        hostname = platform.node().split('.')[0]
        def check_service(name): return run_command(['systemctl', 'is-active', '--quiet', name]) is not None if IS_LINUX else True
        try:
            if VPN_PROVIDER == 'tailscale':
                connections['type'] = 'Tailscale'
                if check_service('tailscaled'):
                    output = run_command(['tailscale', 'status'])
                    if output:
                        peer_pattern = re.compile(r"^\s*[\d\.]+\s+([\w\-\.]+)\s+.*?(?:active|idle|offline)", re.M)
                        connections['peers'] = [f"{name} ({match.group(0).split()[0]})" for match in peer_pattern.finditer(output) if (name := match.group(1)) != hostname]
                        if not connections['peers']: connections['peers'].append("No active peers found.")
                    else: connections['peers'].append("Failed to get Tailscale status.")
                else: connections['peers'].append("Tailscale service not active.")
            elif VPN_PROVIDER == 'zerotier':
                connections['type'] = 'ZeroTier'
                if check_service('zerotier-one'):
                    output = run_command(['zerotier-cli', 'listpeers'])
                    if output:
                        peer_pattern = re.compile(r"^200 listpeers (\w+) ([\d\.]+)/\d+ \S+ \S+ \S+ LEAF", re.M)
                        connections['peers'] = [f"Node {ztaddr} ({ip})" for ztaddr, ip in peer_pattern.findall(output)]
                        if not connections['peers']: connections['peers'].append("No active LEAF peers found.")
                    else: connections['peers'].append("Failed to get ZeroTier status.")
                else: connections['peers'].append("ZeroTier service not active.")
            if IS_LINUX:
                output = run_command(['smbstatus', '-b'])
                if output:
                    try:
                        header = "-------------------------------------------------------"
                        if header in output:
                            client_section = output.split(header, 1)[1]
                            client_pattern = re.compile(r"^\s*\d+\s+\S+\s+\S+\s+([\w\-\.]+)\s+\(ipv4:([\d\.]+):")
                            clients = {machine if machine != ip else ip for line in client_section.strip().split('\n') if (match := client_pattern.match(line.strip())) for machine, ip in [match.groups()]}
                            connections['smb_clients'] = sorted(list(clients)) if clients else ["No active clients found."]
                        else: connections['smb_clients'].append("No active clients found (unexpected format).")
                    except Exception as e: print(f"Error parsing smbstatus: {e}", file=sys.stderr); connections['smb_clients'].append("Error parsing smbstatus.")
                else: connections['smb_clients'].append("smbstatus command failed or Samba not running.")
            else: connections['smb_clients'].append("SMB status only checked on Linux.")
        except Exception as e: print(f"Error getting connections: {e}", file=sys.stderr); connections['error'] = f"Connection Error: {e}"
        if any("service not active" in p for p in connections['peers']): connections['error'] = connections['peers'][0]
        return connections

    def get_service_network_io(self):
        if not IS_LINUX: return {'error': 'Service I/O monitoring is only available on Linux.'}
        if self._nethogs_path is None: self._nethogs_path = run_command(['which', 'nethogs'])
        if not self._nethogs_path: return {'error': 'nethogs command not found. Please install it.'}
        nethogs_output = run_command(['sudo', self._nethogs_path, '-t', '-c', '1', '-k'], timeout=10)
        if nethogs_output is None: return {'error': 'Failed to execute nethogs. Check sudo permissions.'}
        lines = nethogs_output.strip().split('\n')
        if not lines or len(lines) <= 1 or "Refreshing" in lines[0]: return {'info': 'No network activity detected by nethogs.'}
        known_services = {'smbd': 'Samba', 'nmbd': 'Samba', 'tailscaled': 'Tailscale', 'zerotier-one': 'ZeroTier', 'sshd': 'SSH', 'nginx': 'Nginx', 'apache2': 'Apache', 'httpd': 'Apache', 'docker-proxy': 'Docker', 'containerd': 'Docker', 'influxd': 'InfluxDB', 'grafana-server': 'Grafana', 'prometheus': 'Prometheus', 'python': 'Python App', 'node': 'Node.js App'}
        process_pattern = re.compile(r"^(?:.*/)?(.*?)/\d+\s+.*?\s+(\d+\.?\d*)\s+(\d+\.?\d*)$")
        aggregated_rates = {}
        try:
            if lines[0].startswith("Refreshing"): lines = lines[1:]
            for line in lines:
                match = process_pattern.match(line.strip())
                if match:
                    proc_name, sent_kbs, recv_kbs = match.groups()
                    sent_kbs_f, recv_kbs_f = float(sent_kbs), float(recv_kbs)
                    if sent_kbs_f == 0 and recv_kbs_f == 0: continue
                    matched_service, best_match_len = None, 0
                    for service_key, display_name in known_services.items():
                        if service_key in proc_name.lower() and len(service_key) > best_match_len: matched_service, best_match_len = display_name, len(service_key)
                    if matched_service:
                        rates = aggregated_rates.setdefault(matched_service, {'sent': 0.0, 'recv': 0.0})
                        rates['sent'] += sent_kbs_f; rates['recv'] += recv_kbs_f
            service_io = { name: {'sent_rate': bytes_to_human(rates['sent'] * 1024, 'B/s'), 'recv_rate': bytes_to_human(rates['recv'] * 1024, 'B/s')} for name, rates in aggregated_rates.items() if rates['sent'] > 0 or rates['recv'] > 0 }
            return service_io if service_io else {'info': 'No network activity detected for known services.'}
        except Exception as e: print(f"Error parsing nethogs output: {e}\nOutput was:\n{nethogs_output}", file=sys.stderr); return {'error': f'Error parsing nethogs output: {e}'}

    def get_relevant_ip_addresses(self):
        lan_ip, lan_iface, vpn_ip, best_lan_prio = None, None, None, 99
        prio_map = {'eth': 0, 'enp': 0, 'eno': 0, 'ens': 0, 'wlan': 1, 'wlp': 1, 'en': 2, 'wl': 3}
        try:
            if_addrs = psutil.net_if_addrs()
            for name, snic_list in if_addrs.items():
                current_prio = min((prio_map[p] for p in prio_map if name.startswith(p)), default=99)
                if name == 'tailscale0' or name.startswith(('zt', 'utun')): vpn_ip = next((s.address for s in snic_list if s.family == socket.AF_INET), vpn_ip)
                if current_prio < best_lan_prio:
                    current_lan_ip = next((s.address for s in snic_list if s.family == socket.AF_INET and not s.address.startswith(('127.', '169.254.'))), None)
                    if current_lan_ip: lan_ip, lan_iface, best_lan_prio = current_lan_ip, name, current_prio
            result = f"{lan_ip} ({lan_iface})" if lan_ip and lan_iface else ("No LAN IP Found" if not lan_ip else f"{lan_ip} (Unknown IF)")
            if vpn_ip: result += f" / VPN: {vpn_ip}"
            return result
        except Exception as e: print(f"Error retrieving IP addresses: {e}", file=sys.stderr); return "Error retrieving IPs"


    def get_all_data(self):
        """Calls all getter methods and assembles the final data dictionary."""
        cpu_data = self.get_cpu_info()
        data = {
            'hostname': platform.node(), 'os_name': f"{platform.system()} {platform.release()}",
            'is_linux': IS_LINUX, 'uptime': self.get_uptime(),
            'cpu_total': cpu_data['total'], 'cpu_cores': cpu_data['cores'],
            'memory': self.get_memory_info(),
            'disk_fs': self.get_disk_fs_info(), # Uses the NEW logic
            'disk_io': self.get_disk_io(), 'temperature': self.get_temperature(),
            'top_procs': self.get_top_processes(), 'connections': self.get_connected_devices(),
            'service_net_io': self.get_service_network_io(), 'ip_address': self.get_relevant_ip_addresses(),
        }
        return data

# --- Flask App Setup ---
app = Flask(__name__)
auth = HTTPBasicAuth()
users = {MONITOR_USER: generate_password_hash(MONITOR_PASSWORD)}

# --- Authentication Callback ---
@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

# --- Global Monitor Instance ---
system_monitor = SystemMonitor()

# --- Flask Routes ---
@app.route('/')
@auth.login_required
def index():
    all_data = system_monitor.get_all_data()
    # Title reflects the filtering logic based on manage_storage.sh setup
    shares_title = f"Managed Disks ({system_monitor.share_base_path})"
    return render_template('index.html', data=all_data, shares_title=shares_title)

@app.route('/reboot', methods=['POST'])
@auth.login_required
def reboot():
    if not IS_LINUX: return Response("Reboot functionality is only available on Linux.", status=403)
    try:
        result = run_command(['sudo', '/sbin/reboot'], timeout=10)
        if result is not None: return Response("Reboot command issued successfully.", status=200)
        else: return Response("Reboot command failed. Check logs.", status=500)
    except Exception as e:
        error_message = f"An unexpected error occurred during reboot route: {e}"
        print(error_message, file=sys.stderr); return Response(error_message, status=500)

# --- Main Execution Block ---
if __name__ == '__main__':
    print("Starting Flask Monitoring Dashboard (OOP Version)...")
    print(f"URL: http://0.0.0.0:{PORT}")
    print(f"Authentication User: {MONITOR_USER}")
    print(f"Auth Password: {'Set via MONITOR_PASSWORD' if MONITOR_PASSWORD != 'YourSecureMonitorPassword' else 'Default'}")
    print(f"Config: SHARE_BASE_PATH='{system_monitor.share_base_path}'") # Show effective config
    print(f"Config: ALLOWED_FILESYSTEMS={system_monitor.allowed_fs_set}") # Show effective config
    print(f"Config: VPN_PROVIDER='{VPN_PROVIDER}'")
    if IS_LINUX:
        print("Note: Reboot requires passwordless sudo for '/sbin/reboot'.")
        print("Note: Service Network I/O requires 'nethogs' and passwordless sudo.")
        # print("Note: USB 3.0 Disk Filter requires 'udevadm'.") # No longer relevant
    app.run(host='0.0.0.0', port=PORT, debug=True)