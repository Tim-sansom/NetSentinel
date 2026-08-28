#!/usr/bin/env python3
"""
NetSentinel Network Discovery Script

Detects active devices, MAC addresses, hostnames, and OS types.
Uses MAC OUI, Hostname Intelligence, and TTL heuristics for accurate device identification.
"""

import sys
import json
import ipaddress
import subprocess
import platform
import concurrent.futures
import socket
import time
import re


def ping_host(ip: str, timeout: int = 1) -> dict:
    """
    Ping a host and return TTL info for OS detection.
    Returns dict with 'alive': bool, 'ttl': int
    """
    result = {
        'alive': False,
        'ttl': None
    }
    
    try:
        # Use ping with verbose output to get TTL
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-W' if platform.system().lower() != 'windows' else '-w'
        timeout_val = '1000' if platform.system().lower() == 'windows' else str(timeout)
        
        proc = subprocess.run(
            ['ping', param, '1', timeout_param, timeout_val, ip],
            capture_output=True,
            text=True,
            timeout=timeout + 2
        )
        
        if proc.returncode == 0:
            result['alive'] = True
            # Extract TTL from ping output
            ttl_match = re.search(r'TTL[=:]?(\d+)', proc.stdout, re.IGNORECASE)
            if ttl_match:
                result['ttl'] = int(ttl_match.group(1))
                
    except Exception:
        pass
        
    return result


def detect_device_type(ttl: int, hostname: str, mac: str, ip: str) -> str:
    """
    Detect device type using MAC OUI, Hostname Intelligence, and TTL.
    """
    
    # 1. MAC OUI LOOKUP (Most Accurate - Works best on Proxmox Host)
    # We check the first 8 chars (3 octets) of the MAC address.
    if mac and mac != 'unknown' and len(mac) >= 8:
        oui = mac[:8].lower()
        
        # Common SME/Home Lab OUIs
        if oui in ['b8:27:eb', 'dc:a6:32', 'e4:5f:01', '28:cd:c1']:
            return 'Raspberry Pi'
        if oui in ['a4:83:e7', '3c:06:30', '8c:85:90', 'f0:18:98']: 
            # These are common Apple OUIs (sample)
            return 'Apple Device (macOS/iOS)'
        if oui in ['60:01:94', '18:fe:34', '24:0a:c4']:
            return 'IoT Device (Espressif/Tuya)'
        if oui in ['00:1a:11', '00:17:c5', '00:18:4d']:
            return 'Network Device (Router/AP)'

    # 2. HOSTNAME INTELLIGENCE
    if hostname and hostname != 'unknown':
        h_lower = hostname.lower()
        if any(x in h_lower for x in ['iphone', 'ipad', 'mac', 'apple', '.local']):
            return 'Apple Device (macOS/iOS)'
        if any(x in h_lower for x in ['pi', 'raspberry', 'debian', 'ubuntu']):
            return 'Linux (Pi/Debian/Ubuntu)'
        if any(x in h_lower for x in ['router', 'gateway', 'fritz', 'ubiquiti']):
            return 'Network Device (Router/AP)'
        if any(x in h_lower for x in ['iot', 'cam', 'bulb', 'plug']):
            return 'IoT Device'

    # 3. HEURISTICS (IP Address & TTL)
    # If IP ends in .1, it's almost always the Gateway/Router
    if ip.endswith('.1'):
        return 'Likely Gateway/Router'

    # TTL Fallback
    if not ttl:
        return 'Unknown'
    
    if ttl >= 120:
        return 'Windows'
    elif ttl >= 64:
        return 'Linux/Unix (Direct)'
    elif ttl >= 50:
        return 'Linux/Unix (Routed)'
    elif ttl >= 250:
        return 'Network Device (Infrastructure)'
    else:
        return 'Unknown'


def get_arp_table() -> dict:
    """
    Parse the system ARP table to get IP -> MAC mappings.
    MUST be called AFTER ping sweep.
    """
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
                        
        else:  # Linux
            # Try 'ip neigh' first
            result = subprocess.run(['ip', '-4', 'neigh', 'show'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[0]
                    for i, part in enumerate(parts):
                        if part == 'lladdr' and i + 1 < len(parts):
                            mac = parts[i + 1].lower()
                            arp_map[ip] = mac
                            break
                            
            # Fallback to 'arp -n'
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
        pass
        
    return arp_map


def get_hostname(ip: str) -> str:
    """Perform reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return 'unknown'


def scan_subnet(network_config: dict, vlan: str = None) -> list:
    """
    Scan a subnet and return discovered devices with OS detection.
    """
    cidr = network_config.get('cidr', '')
    name = network_config.get('name', 'Unknown')
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
        
    # STEP 1: Ping all IPs to populate ARP cache and get TTL
    alive_hosts = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in network.hosts()}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            result = future.result()
            if result['alive']:
                alive_hosts[ip] = result['ttl']
    
    # STEP 2: Wait for ARP cache
    time.sleep(2)
    
    # STEP 3: Read ARP table
    arp_table = get_arp_table()
    
    # STEP 4: Build device list with Hostname Intelligence + TTL
    devices = []
    for ip, ttl in alive_hosts.items():
        mac = arp_table.get(ip, 'unknown')
        hostname = get_hostname(ip)
        
        # UPDATED: Pass TTL, hostname, MAC, and IP for multi-layered detection
        os_type = detect_device_type(ttl, hostname, mac, ip)
        
        devices.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'device_type': os_type,
            'network_name': name if name else 'Unknown',
            'vlan_id': str(vlan) if vlan is not None else 'N/A'
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
        
    all_devices = []
    
    for net in networks:
        vlan = net.get('vlan_id')
        all_devices.extend(scan_subnet(net, vlan))
        
    print(json.dumps(all_devices))


if __name__ == "__main__":
    main()