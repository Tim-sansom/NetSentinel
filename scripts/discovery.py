#!/usr/bin/env python3
import sys
import json
import ipaddress
import subprocess
import platform
import concurrent.futures
import socket

def ping_host(ip: str, timeout: int = 1) -> bool:
    """Send a single ICMP echo request to check if host is alive."""
    is_windows = platform.system().lower() == 'windows'
    param = '-n' if is_windows else '-c'
    timeout_param = '-w' if is_windows else '-W'
    timeout_val = '1000' if is_windows else str(timeout)
    
    try:
        result = subprocess.run(
            ['ping', param, '1', timeout_param, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def get_arp_table() -> dict:
    """Parse the system ARP table to get IP -> MAC mappings."""
    arp_map = {}
    os_name = platform.system().lower()
    
    try:
        if os_name == 'windows':
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and '.' in parts[0]:
                    arp_map[parts[0]] = parts[1].replace('-', ':').lower()
                    
        elif os_name == 'darwin':  # macOS
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                if '(' in line and ')' in line and ' at ' in line:
                    try:
                        ip_part = line.split('(')[1].split(')')[0]
                        mac_part = line.split(' at ')[1].split(' ')[0]
                        arp_map[ip_part] = mac_part.lower()
                    except (IndexError, ValueError):
                        continue
                    
        else:  # Linux (Docker container)
            # Try 'ip neigh' first (most reliable in containers)
            result = subprocess.run(['ip', '-4', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                parts = line.split()
                # Format: IP dev eth0 lladdr MAC REACHABLE/STALE/PERMANENT
                if len(parts) >= 5:
                    ip = parts[0]
                    # Look for lladdr keyword
                    for i, part in enumerate(parts):
                        if part == 'lladdr' and i + 1 < len(parts):
                            mac = parts[i + 1].lower()
                            arp_map[ip] = mac
                            break
            
            # Fallback: try traditional 'arp -n' if ip command didn't work
            if not arp_map:
                try:
                    result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=5)
                    for line in result.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and '.' in parts[0]:
                            ip = parts[0]
                            mac = parts[2].lower()
                            if mac != '(incomplete)':
                                arp_map[ip] = mac
                except Exception:
                    pass
                    
    except Exception as e:
        print(f"ARP table parsing error: {e}", file=sys.stderr)
        
    return arp_map

def get_hostname(ip: str) -> str:
    """Perform reverse DNS lookup for an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return 'unknown'

def scan_subnet(network_config: dict, arp_table: dict) -> list:
    """Scan a single subnet and return discovered devices."""
    cidr = network_config.get('cidr', '')
    name = network_config.get('name', 'Unknown')
    vlan = network_config.get('vlan_id')
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []  # Invalid CIDR, skip
    
    # Step 1: Ping all IPs concurrently
    alive_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in network.hosts()}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                alive_hosts.append(futures[future])
    
    # Step 2: Match with ARP table and get hostnames
    devices = []
    for ip in alive_hosts:
        # Get MAC from ARP table
        mac = arp_table.get(ip, 'unknown')
        
        # Get hostname via reverse DNS
        hostname = get_hostname(ip)
        
        devices.append({
            'ip': ip,
            'mac': mac,
            'network_name': name if name else 'Unknown',
            'vlan_id': str(vlan) if vlan is not None else 'N/A',
            'hostname': hostname
        })
    
    return devices

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No network configuration provided"}))
        sys.exit(1)
    
    try:
        networks = json.loads(sys.argv[1])
    except json.JSONDecodeError:
        print(json.dumps({"error": "Invalid JSON configuration"}))
        sys.exit(1)
    
    arp_table = get_arp_table()
    all_devices = []
    
    for net in networks:
        all_devices.extend(scan_subnet(net, arp_table))
    
    # Output valid JSON for PHP to parse
    print(json.dumps(all_devices))

if __name__ == "__main__":
    main()