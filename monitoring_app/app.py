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
from collections import namedtuple
from flask import Flask, render_template, request, redirect, url_for, Response
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# --- OS Detection ---
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"
IS_FREEBSD = platform.system() == "FreeBSD"

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Authentication ---
auth = HTTPBasicAuth()
MONITOR_USER = os.environ.get('MONITOR_USER', 'monitor')
MONITOR_PASSWORD = os.environ.get('MONITOR_PASSWORD', 'YourSecureMonitorPassword')
users = {
    MONITOR_USER: generate_password_hash(MONITOR_PASSWORD)
}

@auth.verify_password
def verify_password(username, password):
    """Verify user credentials for basic auth."""
    if username in users and \
            check_password_hash(users.get(username), password):
        return username
    return None

# --- Configuration ---
VPN_PROVIDER = os.environ.get('VPN_PROVIDER', 'tailscale').lower()
SHARE_BASE_PATH = os.environ.get('SHARE_BASE_PATH', '/mnt/shares')
PORT = int(os.environ.get('PORT', 8081))

# --- Global Variables for Rate Calculation ---
last_check_time = 0
last_net_io = {}
last_disk_io = {}

# --- Helper Functions ---

def bytes_to_human(n_bytes, suffix='B'):
    """Converts bytes to a human-readable string (KiB, MiB, GiB, etc.)."""
    if n_bytes is None:
        return "N/A"
    if n_bytes == 0:
        return f"0 {suffix}"
    size_name = ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi", "Yi")
    i = int(math.floor(math.log(n_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(n_bytes / p, 1 if i > 0 else 0) # Show decimal for KiB upwards
    return f"{s} {size_name[i]}{suffix}"

def run_command(cmd_list, timeout=5):
    """Executes a shell command and returns its stdout or None on error."""
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            check=False, # Handle errors manually
            timeout=timeout
        )
        if result.returncode != 0:
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

# --- Data Gathering Functions ---

def get_uptime():
    """Calculates system uptime."""
    try:
        boot_time_timestamp = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time_timestamp)
        delta = datetime.timedelta(seconds=uptime_seconds)
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if days > 0:
            return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except Exception as e:
        print(f"Error getting uptime: {e}", file=sys.stderr)
        return "N/A"

def get_cpu_core_details():
    """Gets per-CPU core utilization percentages."""
    try:
        # interval=None gets utilization since last call (or system boot)
        # A small interval like 0.1 might be better for responsiveness but uses more CPU
        return psutil.cpu_percent(percpu=True, interval=None)
    except Exception as e:
        print(f"Error getting CPU core details: {e}", file=sys.stderr)
        return []

def get_memory_info():
    """Gets virtual and swap memory details."""
    mem_info = {'virtual': {}, 'swap': {}}
    try:
        vmem = psutil.virtual_memory()
        mem_info['virtual'] = {
            'total': bytes_to_human(vmem.total),
            'available': bytes_to_human(vmem.available),
            'used': bytes_to_human(vmem.used),
            'free': bytes_to_human(vmem.free),
            'percent': vmem.percent,
        }
        if IS_LINUX:
            # Linux specific memory details
            for attr in ['active', 'inactive', 'buffers', 'cached', 'shared']:
                try:
                    mem_info['virtual'][attr] = bytes_to_human(getattr(vmem, attr))
                except AttributeError:
                    mem_info['virtual'][attr] = "N/A" # Handle older kernels/systems
    except Exception as e:
        print(f"Error getting virtual memory info: {e}", file=sys.stderr)
        mem_info['virtual']['error'] = f"Error: {e}"

    try:
        swap = psutil.swap_memory()
        mem_info['swap'] = {
            'total': bytes_to_human(swap.total),
            'used': bytes_to_human(swap.used),
            'free': bytes_to_human(swap.free),
            'percent': swap.percent,
        }
    except Exception as e:
        print(f"Error getting swap memory info: {e}", file=sys.stderr)
        mem_info['swap']['error'] = f"Error: {e}"

    return mem_info

def get_disk_fs_info():
    """Gets disk usage for relevant filesystems."""
    fs_info = []
    try:
        partitions = psutil.disk_partitions()
        for p in partitions:
            try:
                # --- Filtering Logic ---
                is_relevant = False
                if IS_LINUX:
                    # Linux: Filter by SHARE_BASE_PATH, opts, and fstype
                    if p.mountpoint.startswith(SHARE_BASE_PATH) and \
                       ('rw' in p.opts.split(',') or 'ro' in p.opts.split(',')) and \
                       p.fstype not in ('tmpfs', 'squashfs'):
                        is_relevant = True
                else:
                     # Basic check for other OS (might need refinement)
                     # Avoid obviously virtual/temporary filesystems
                    if p.mountpoint == '/' or \
                       (not p.mountpoint.startswith(('/dev', '/proc', '/sys', '/run', '/var/run')) and \
                        p.fstype not in ('tmpfs', 'devfs', 'procfs')):
                         is_relevant = True # Include root and potentially others

                if is_relevant and os.path.exists(p.mountpoint):
                    usage = psutil.disk_usage(p.mountpoint)

                    # Create display name
                    if IS_LINUX and p.mountpoint.startswith(SHARE_BASE_PATH):
                        display_name = p.mountpoint[len(SHARE_BASE_PATH):].lstrip('/')
                        if not display_name:
                            display_name = "RootShare" # Or BaseShare?
                    else:
                        display_name = p.mountpoint # Use full path for others/non-Linux

                    fs_info.append({
                        'mountpoint': display_name,
                        'total_b': usage.total,
                        'used_b': usage.used,
                        'total': bytes_to_human(usage.total),
                        'used': bytes_to_human(usage.used),
                        'percent': usage.percent,
                    })
            except OSError as e:
                 # Ignore errors like "permission denied" or "no such file or directory" for specific partitions
                 # print(f"Skipping disk usage for {p.mountpoint}: {e}", file=sys.stderr)
                 pass
            except Exception as e:
                print(f"Error getting disk usage for {p.mountpoint}: {e}", file=sys.stderr)
                fs_info.append({'mountpoint': p.mountpoint, 'error': f"Error: {e}"})

    except Exception as e:
        print(f"Error listing disk partitions: {e}", file=sys.stderr)
        # Return an error indicator if the whole process fails
        return [{'error': f"Failed to list partitions: {e}"}]

    return fs_info


def get_network_io(top_n=4):
    """Calculates network I/O rates for top N interfaces."""
    global last_check_time, last_net_io
    net_io_list = []

    try:
        now = time.monotonic()
        current_net_io = psutil.net_io_counters(pernic=True)
        time_delta = now - last_check_time if last_check_time else 0

        for name, current_counters in current_net_io.items():
            # Filter out common virtual/loopback interfaces
            if name.startswith(('lo', 'docker', 'veth', 'vmnet', 'bridge', 'gif', 'stf')):
                continue

            last_counters = last_net_io.get(name)
            rx_rate_bytes = 0
            tx_rate_bytes = 0

            if last_counters and time_delta > 0:
                rx_rate_bytes = (current_counters.bytes_recv - last_counters.bytes_recv) / time_delta
                tx_rate_bytes = (current_counters.bytes_sent - last_counters.bytes_sent) / time_delta
                # Ensure rates are not negative (e.g., counter reset)
                rx_rate_bytes = max(0, rx_rate_bytes)
                tx_rate_bytes = max(0, tx_rate_bytes)

            combined_rate = rx_rate_bytes + tx_rate_bytes

            net_io_list.append({
                'name': name,
                'rx_total': bytes_to_human(current_counters.bytes_recv),
                'tx_total': bytes_to_human(current_counters.bytes_sent),
                'rx_rate': bytes_to_human(rx_rate_bytes, suffix='B/s'),
                'tx_rate': bytes_to_human(tx_rate_bytes, suffix='B/s'),
                'combined_rate': combined_rate # Used for sorting
            })

        # Sort by combined rate descending and take top N
        net_io_list.sort(key=lambda x: x['combined_rate'], reverse=True)

        # Update last state *after* calculations for the next run
        last_net_io = current_net_io
        # last_check_time is updated in get_disk_io

        return net_io_list[:top_n]

    except Exception as e:
        print(f"Error getting network I/O: {e}", file=sys.stderr)
        return [] # Return empty list on error

def get_disk_io():
    """Calculates disk I/O rates."""
    global last_check_time, last_disk_io
    disk_io_rates = {}

    try:
        now = time.monotonic()
        current_disk_io = psutil.disk_io_counters(perdisk=True)
        time_delta = now - last_check_time if last_check_time else 0

        # --- Filter out partitions if base disk exists ---
        # Create a set of base disk names (e.g., 'sda' from 'sda1')
        disk_bases = set()
        for name in current_disk_io.keys():
             # Simple approach: remove trailing digits
             base_name = name.rstrip('0123456789')
             disk_bases.add(base_name)

        filtered_disk_io = {}
        for name, counters in current_disk_io.items():
            # Filter loop, ram, device mapper, md raid devices
            if name.startswith(('loop', 'ram', 'dm-', 'md')):
                continue

            # Check if it's a partition (e.g., sda1) and the base disk (sda) also exists
            base_name = name.rstrip('0123456789')
            if name != base_name and base_name in current_disk_io:
                continue # Skip partition if base disk is present

            filtered_disk_io[name] = counters
        # --- End Filtering ---


        for name, current_counters in filtered_disk_io.items():
            last_counters = last_disk_io.get(name)
            read_rate_bytes = 0
            write_rate_bytes = 0

            if last_counters and time_delta > 0:
                read_rate_bytes = (current_counters.read_bytes - last_counters.read_bytes) / time_delta
                write_rate_bytes = (current_counters.write_bytes - last_counters.write_bytes) / time_delta
                # Ensure rates are not negative
                read_rate_bytes = max(0, read_rate_bytes)
                write_rate_bytes = max(0, write_rate_bytes)

            disk_io_rates[name] = {
                'read_total': bytes_to_human(current_counters.read_bytes),
                'write_total': bytes_to_human(current_counters.write_bytes),
                'read_rate': bytes_to_human(read_rate_bytes, suffix='B/s'),
                'write_rate': bytes_to_human(write_rate_bytes, suffix='B/s'),
            }

        # Update last state *after* calculations for the next run
        last_disk_io = current_disk_io
        last_check_time = now # Update the global time marker here

        return disk_io_rates

    except Exception as e:
        print(f"Error getting disk I/O: {e}", file=sys.stderr)
        return {} # Return empty dict on error


def get_temperature():
    """Attempts to get CPU temperature using various methods."""
    temp_c = None
    try:
        # 1. psutil sensors_temperatures (covers many Linux sensors)
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            # Prioritize common keys
            keys_to_check = ['coretemp', 'k10temp', 'cpu_thermal', 'cpu-thermal', 'acpitz', 'pch_skylake', 'soc_thermal']
            # Check specific package/core temps first if available
            for key in temps:
                 if key.startswith(('coretemp', 'k10temp')) or 'package id' in key.lower():
                     for entry in temps[key]:
                         if entry.current > 0: # Ignore zero readings sometimes reported
                            temp_c = entry.current
                            break
                     if temp_c: break
            # Fallback to broader keys
            if not temp_c:
                for key in keys_to_check:
                    if key in temps:
                        for entry in temps[key]:
                             if entry.current > 0:
                                temp_c = entry.current
                                break # Take the first valid reading from prioritized keys
                        if temp_c: break
            # Generic fallback if specific keys failed
            if not temp_c:
                 for key in temps:
                     for entry in temps[key]:
                         if entry.current > 0:
                             temp_c = entry.current
                             break
                     if temp_c: break


        # 2. Linux fallback: /sys/class/thermal
        if temp_c is None and IS_LINUX:
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp_raw = int(f.read().strip())
                    if temp_raw > 0: # Check if valid reading
                       temp_c = temp_raw / 1000.0
            except (FileNotFoundError, ValueError, OSError):
                pass # Ignore if file doesn't exist or has bad data

        # 3. macOS fallback: osx-cpu-temp (external dependency)
        if temp_c is None and IS_MACOS:
            output = run_command(['osx-cpu-temp'], timeout=2)
            if output:
                try:
                    # Expects output like "XX.Y°C"
                    temp_match = re.search(r'(\d+\.?\d*)', output)
                    if temp_match:
                        temp_c = float(temp_match.group(1))
                except (ValueError, TypeError):
                     print(f"Could not parse osx-cpu-temp output: {output}", file=sys.stderr)


        # 4. FreeBSD fallback: sysctl
        if temp_c is None and IS_FREEBSD:
            oids = [
                'dev.cpu.0.temperature', # Modern Intel/AMD
                'hw.acpi.thermal.tz0.temperature' # ACPI thermal zone
            ]
            for oid in oids:
                 output = run_command(['sysctl', '-n', oid], timeout=2)
                 if output:
                     try:
                         # Output is often like "50.0C" or just "500" (tenths of K)
                         temp_str = output.replace('C', '').strip()
                         temp_val = float(temp_str)
                         if temp_val > 273: # Assume Kelvin tenths if large number
                             temp_c = temp_val / 10.0 - 273.15
                         else: # Assume Celsius
                             temp_c = temp_val
                         if temp_c is not None: break # Found one
                     except (ValueError, TypeError):
                          print(f"Could not parse sysctl output for {oid}: {output}", file=sys.stderr)


        # Format the result
        if temp_c is not None:
            return f"{temp_c:.1f}°C"
        else:
            return "N/A"

    except Exception as e:
        print(f"Error getting temperature: {e}", file=sys.stderr)
        return "Error"


def get_top_processes(count=8):
    """Gets top processes sorted by memory usage."""
    processes = []
    try:
        # Define attributes to fetch once
        attrs = ['pid', 'username', 'cpu_percent', 'memory_percent', 'name']
        for p in psutil.process_iter(attrs=attrs, ad_value=None):
            try:
                # p.info is already populated by process_iter with attrs
                proc_info = p.info
                # Skip kernel threads (often username=None or pid=0/1/2)
                if proc_info['pid'] is None or proc_info['username'] is None:
                     if not (IS_LINUX and proc_info['pid'] is not None and proc_info['pid'] <= 2): # Allow PID 1/2 on Linux
                         continue
                # Skip idle process (common on Windows/macOS)
                if proc_info['name'] == 'System Idle Process' or proc_info['name'] == 'kernel_task':
                    continue

                # Ensure values are valid floats
                proc_info['cpu_percent'] = proc_info['cpu_percent'] or 0.0
                proc_info['memory_percent'] = proc_info['memory_percent'] or 0.0

                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process might have terminated between iter and info access
                continue
            except Exception as e:
                 print(f"Error accessing info for process {p.pid if hasattr(p, 'pid') else '?'}: {e}", file=sys.stderr)


        # Sort by memory percentage descending
        processes.sort(key=lambda x: x['memory_percent'], reverse=True)

        return processes[:count]

    except Exception as e:
        print(f"Error listing processes: {e}", file=sys.stderr)
        # Return an indicator of failure
        return [{'error': f"Failed to list processes: {e}"}]


def get_connected_devices():
    """Gets connected VPN peers and SMB clients."""
    connections = {
        'type': 'None',
        'peers': [],
        'smb_clients': [],
        'error': None
    }
    service_active = True # Assume active unless checked otherwise

    # --- VPN Peers ---
    if VPN_PROVIDER == 'tailscale':
        connections['type'] = 'Tailscale'
        if IS_LINUX:
            # Check if service is active
            status_output = run_command(['systemctl', 'is-active', '--quiet', 'tailscaled'])
            if status_output is None: # Command failed or service not active/found
                service_active = False
                connections['peers'].append("Tailscale service not active or status check failed.")

        if service_active:
            output = run_command(['tailscale', 'status'])
            if output:
                # Example line: 100.x.y.z machine-name os via relay (ip)
                # Example line: 100.a.b.c other-peer linux active; direct ip:port, tx N rx M
                peer_pattern = re.compile(r"^\s*([\d\.]+)\s+([\w\-\.]+)\s+.*?(?:active|idle|offline)", re.MULTILINE)
                for match in peer_pattern.finditer(output):
                    ip, name = match.groups()
                    # Exclude self (often listed) - might need a better way if hostname matches peer name
                    if name != platform.node().split('.')[0]: # Basic check against local hostname
                       connections['peers'].append(f"{name} ({ip})")
                if not connections['peers'] and "Tailscale service not active" not in connections['peers'][0]:
                     connections['peers'].append("No active peers found.")
            elif service_active: # Command failed but service was thought active
                connections['peers'].append("Failed to get Tailscale status.")

    elif VPN_PROVIDER == 'zerotier':
        connections['type'] = 'ZeroTier'
        if IS_LINUX:
             status_output = run_command(['systemctl', 'is-active', '--quiet', 'zerotier-one'])
             if status_output is None:
                 service_active = False
                 connections['peers'].append("ZeroTier service not active or status check failed.")

        if service_active:
            # Use 'listpeers' which shows direct connections
            output = run_command(['zerotier-cli', 'listpeers'])
            if output:
                 # Example line: 200 listpeers <ztaddr> <ip/mask> <last_seen> <latency> <version> <role>
                 peer_pattern = re.compile(r"^200 listpeers (\w+) ([\d\.]+)/\d+ \S+ \S+ \S+ LEAF", re.MULTILINE)
                 for match in peer_pattern.finditer(output):
                     ztaddr, ip = match.groups()
                     # We don't easily get the hostname here, use ZT address
                     connections['peers'].append(f"Node {ztaddr} ({ip})")
                 if not connections['peers'] and "ZeroTier service not active" not in connections['peers'][0]:
                     connections['peers'].append("No active LEAF peers found.")
            elif service_active:
                 connections['peers'].append("Failed to get ZeroTier status.")

    # --- SMB Clients (Linux Only) ---
    if IS_LINUX:
        output = run_command(['smbstatus', '-b'])
        if output:
            try:
                # Find the start of the client list
                header_line = "-------------------------------------------------------"
                if header_line in output:
                    client_section = output.split(header_line, 1)[1]
                    lines = client_section.strip().split('\n')
                    # Example line: PID   Username   Group      Machine          Protocol Version SMB Encryption   SMB Signing
                    # Example line: 12345 user       group      192.168.1.100 (ipv4:192.168.1.100:port) SMB3_11 -            -
                    # Example line: 67890 user       group      client-pc (ipv4:192.168.1.101:port) SMB3_11 -            -
                    client_pattern = re.compile(r"^\s*\d+\s+\S+\s+\S+\s+([\w\-\.]+)\s+\(ipv4:([\d\.]+):")
                    found_clients = set() # Use set to avoid duplicates if machine name and IP are same
                    for line in lines:
                        match = client_pattern.match(line.strip())
                        if match:
                            machine, ip = match.groups()
                            # Prefer machine name if it's not just the IP
                            display = machine if machine != ip else ip
                            found_clients.add(display)
                    if found_clients:
                         connections['smb_clients'].extend(list(found_clients))
                    else:
                         connections['smb_clients'].append("No active clients found.")
                else:
                     # Handle case where smbstatus runs but shows no connections (e.g., empty output after header)
                     connections['smb_clients'].append("No active clients found (or unexpected format).")

            except Exception as e:
                print(f"Error parsing smbstatus output: {e}", file=sys.stderr)
                connections['smb_clients'].append("Error parsing smbstatus output.")
        else:
            # Check if samba service is running? Could add 'systemctl is-active smbd nmbd'
            connections['smb_clients'].append("smbstatus command failed or Samba not running.")
    else:
         connections['smb_clients'].append("SMB status only checked on Linux.")


    # Consolidate potential errors
    if not service_active and connections['type'] != 'None':
         connections['error'] = f"{connections['type']} service not active."
    elif not output and connections['type'] != 'None':
         connections['error'] = f"Failed to run {connections['type']} status command."


    # If no peers/clients found and no specific error message added, add generic ones
    if connections['type'] != 'None' and not connections['peers']:
         connections['peers'].append(f"No {connections['type']} peers detected.")
    if IS_LINUX and not connections['smb_clients']:
         connections['smb_clients'].append("No SMB clients detected.")


    return connections

def get_service_network_io():
    """Gets network I/O per known service using nethogs (Linux only)."""
    if not IS_LINUX:
        return {'error': 'Service I/O monitoring is only available on Linux.'}

    service_io = {}
    nethogs_path = run_command(['which', 'nethogs'])
    if not nethogs_path:
         return {'error': 'nethogs command not found. Please install it (e.g., sudo apt install nethogs).'}

    # Run nethogs in trace mode (-t) for one refresh cycle (-c 1), show KB (-k)
    # Requires sudo privileges
    # Increase timeout as nethogs might take a moment to capture traffic
    nethogs_output = run_command(['sudo', 'nethogs', '-t', '-c', '1', '-k'], timeout=10)

    if nethogs_output is None:
        return {'error': 'Failed to execute nethogs. Check sudo permissions or nethogs installation.'}
    if not nethogs_output.strip():
         return {'info': 'No network activity detected by nethogs in the last cycle.'}

    # Known services mapping (process name substring -> display name)
    known_services = {
        'smbd': 'Samba',
        'nmbd': 'Samba', # Also part of Samba
        'tailscaled': 'Tailscale',
        'zerotier-one': 'ZeroTier',
        'sshd': 'SSH',
        'nginx': 'Nginx',
        'apache2': 'Apache',
        'httpd': 'Apache', # Common name on RHEL/CentOS
        'docker-proxy': 'Docker',
        'containerd': 'Docker', # Part of Docker runtime
        'influxd': 'InfluxDB',
        'grafana-server': 'Grafana',
        'prometheus': 'Prometheus',
        'python': 'Python App', # Generic, might need refinement
        'node': 'Node.js App'   # Generic
        # Add more services as needed
    }

    # Regex to parse nethogs trace output (KB/s version)
    # Example: program/pid user	sent_kb/s	received_kb/s
    # Example: /usr/sbin/smbd/12345	root	0.123	4.567
    # Example: unknown TCP/0/0     0.000   0.000 (ignore this)
    # Using non-capturing group for optional path: (?:.*/)?
    process_pattern = re.compile(r"^(?:.*/)?(.*?)/(\d+)\s+.*?\s+(\d+\.?\d*)\s+(\d+\.?\d*)$")

    aggregated_rates = {} # { 'DisplayName': {'sent': total_kb_s, 'recv': total_kb_s} }

    try:
        lines = nethogs_output.strip().split('\n')
        if not lines or lines[0].startswith("Refreshing"): # Skip header if present
             lines = lines[1:]

        for line in lines:
            match = process_pattern.match(line.strip())
            if match:
                proc_name, pid, sent_kbs, recv_kbs = match.groups()
                sent_kbs_f = float(sent_kbs)
                recv_kbs_f = float(recv_kbs)

                if sent_kbs_f == 0 and recv_kbs_f == 0:
                    continue # Skip processes with no I/O in this cycle

                matched_service = None
                for service_key, display_name in known_services.items():
                    if service_key in proc_name.lower():
                        matched_service = display_name
                        break

                if matched_service:
                    if matched_service not in aggregated_rates:
                        aggregated_rates[matched_service] = {'sent': 0.0, 'recv': 0.0}
                    aggregated_rates[matched_service]['sent'] += sent_kbs_f
                    aggregated_rates[matched_service]['recv'] += recv_kbs_f

        # Convert aggregated KB/s to human-readable B/s
        for display_name, rates in aggregated_rates.items():
            sent_bps = rates['sent'] * 1024 # KB/s to B/s
            recv_bps = rates['recv'] * 1024 # KB/s to B/s
            service_io[display_name] = {
                'sent_rate': bytes_to_human(sent_bps, suffix='B/s'),
                'recv_rate': bytes_to_human(recv_bps, suffix='B/s')
            }

        if not service_io:
             return {'info': 'No network activity detected for known services.'}

        return service_io

    except Exception as e:
        print(f"Error parsing nethogs output: {e}\nOutput was:\n{nethogs_output}", file=sys.stderr)
        return {'error': f'Error parsing nethogs output: {e}'}


def get_relevant_ip_addresses():
    """Finds the primary LAN IP and VPN IP."""
    lan_ip = None
    lan_iface = None
    vpn_ip = None
    best_lan_prio = -1 # Lower number = higher priority

    try:
        if_addrs = psutil.net_if_addrs()
        for interface_name, snic_list in if_addrs.items():
            current_prio = -1
            # Prioritize common physical/wireless interfaces
            if interface_name.startswith(('eth', 'enp', 'eno', 'ens', 'wlan', 'wlp')):
                current_prio = 0 # Highest priority
            elif interface_name.startswith(('en', 'wl')): # General prefixes
                 current_prio = 1
            # Check for VPN interfaces
            elif interface_name == 'tailscale0' or interface_name.startswith(('zt', 'utun')):
                 for snic in snic_list:
                     if snic.family == socket.AF_INET:
                         vpn_ip = snic.address
                         break # Take first IPv4 on VPN interface

            if current_prio > best_lan_prio: # Found a potentially better LAN interface
                for snic in snic_list:
                    if snic.family == socket.AF_INET:
                        ip = snic.address
                        # Exclude loopback and link-local
                        if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                            lan_ip = ip
                            lan_iface = interface_name
                            best_lan_prio = current_prio
                            break # Take first valid IPv4 on this interface

        # Format output string
        result = ""
        if lan_ip and lan_iface:
            result = f"{lan_ip} ({lan_iface})"
        else:
            result = "No LAN IP Found"

        if vpn_ip:
            result += f" / VPN: {vpn_ip}"

        return result

    except Exception as e:
        print(f"Error retrieving IP addresses: {e}", file=sys.stderr)
        return "Error retrieving IPs"


# --- Flask Routes ---

@app.route('/')
@auth.login_required
def index():
    """Main route to display the dashboard."""
    # Get total CPU first to set baseline for other psutil calls in this request
    try:
        cpu_total = psutil.cpu_percent(interval=None)
    except Exception as e:
        print(f"Error getting total CPU%: {e}", file=sys.stderr)
        cpu_total = -1 # Indicate error

    # Gather all system data
    data = {
        'hostname': platform.node(),
        'os_name': f"{platform.system()} {platform.release()}",
        'is_linux': IS_LINUX,
        'uptime': get_uptime(),
        'cpu_total': cpu_total if cpu_total >= 0 else "Error",
        'cpu_cores': get_cpu_core_details(),
        'memory': get_memory_info(),
        'disk_fs': get_disk_fs_info(),
        'net_io': get_network_io(top_n=4),
        'disk_io': get_disk_io(),
        'temperature': get_temperature(),
        'top_procs': get_top_processes(count=8),
        'connections': get_connected_devices(),
        'service_net_io': get_service_network_io(),
        'ip_address': get_relevant_ip_addresses(),
    }

    return render_template('index.html', data=data, SHARE_BASE_PATH=SHARE_BASE_PATH)

@app.route('/reboot', methods=['POST'])
@auth.login_required
def reboot():
    """Handles the reboot request."""
    if not IS_LINUX:
        return Response("Reboot functionality is only available on Linux.", status=403)

    try:
        # Execute reboot command with sudo
        # Ensure the user running Flask has passwordless sudo rights for /sbin/reboot
        result = subprocess.run(
            ['sudo', '/sbin/reboot'],
            check=True, # Raise exception on non-zero exit code
            capture_output=True,
            text=True,
            timeout=10
        )
        # If check=True passes, it means return code was 0
        return Response("Reboot command issued successfully.", status=200)
    except subprocess.CalledProcessError as e:
        error_message = f"Reboot command failed with exit code {e.returncode}.\nStderr: {e.stderr.strip()}"
        print(error_message, file=sys.stderr)
        return Response(error_message, status=500)
    except FileNotFoundError:
         error_message = "Error: /sbin/reboot command not found or sudo not available."
         print(error_message, file=sys.stderr)
         return Response(error_message, status=500)
    except subprocess.TimeoutExpired:
        error_message = "Reboot command timed out."
        print(error_message, file=sys.stderr)
        return Response(error_message, status=500)
    except Exception as e:
        error_message = f"An unexpected error occurred during reboot: {e}"
        print(error_message, file=sys.stderr)
        return Response(error_message, status=500)


# --- Main Execution Block ---
if __name__ == '__main__':
    print("Starting Flask Monitoring Dashboard...")
    print(f"URL: http://0.0.0.0:{PORT}")
    print(f"Authentication User: {MONITOR_USER}")
    print(f"Authentication Password: {'Set via MONITOR_PASSWORD env var' if MONITOR_PASSWORD != 'YourSecureMonitorPassword' else 'Default (YourSecureMonitorPassword)'}")
    print(f"Share Base Path: {SHARE_BASE_PATH}")
    print(f"VPN Provider: {VPN_PROVIDER}")
    if IS_LINUX:
        print("Note: Reboot function requires passwordless sudo for '/sbin/reboot'.")
        print("Note: Service Network I/O requires 'nethogs' installed and passwordless sudo for 'nethogs'.")
    # Use debug=False for production environments
    app.run(host='0.0.0.0', port=PORT, debug=True)