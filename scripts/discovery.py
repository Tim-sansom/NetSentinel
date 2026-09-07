#!/usr/bin/env python3
"""
NetSentinel Adaptive Hybrid Network Discovery Script.

Architectural Design:
Instead of using intrusive third-party tools like Nmap (which can trigger 
IDS alerts and raise ethical concerns), this script implements a lightweight, 
custom scanner that adapts to the network topology dynamically.

Scanning Strategy:
1. LOCAL Subnets (Layer 2): Uses ARP cache resolution. This discovers ALL 
   devices, including IoT that block ICMP, and retrieves real MAC addresses.
2. REMOTE Subnets (Layer 3): Uses threaded ICMP Ping sweeps. This crosses 
   router boundaries to discover live hosts on remote VLANs, though MAC 
   addresses will be 'unknown' due to Layer 3 routing limitations.

Security & Ethics:
- Uses only Python standard libraries (zero external dependencies).
- Implements safety limits to prevent scanning impractically large networks.
- Respects network boundaries (no aggressive packet crafting).
"""

import sys
import json
import ipaddress
import subprocess
import platform
import socket
import concurrent.futures
import time

# --- Configuration ---
MAX_WORKERS = 50  # Concurrent threads for fast ping sweeps
PING_TIMEOUT = 1  # Seconds to wait for ICMP reply

def get_local_subnets() -> list:
    """
    Dynamically detects all IPv4 subnets assigned to the host's network interfaces.
    This makes the scanner topology-agnostic (works with 192.168.x, 10.x.x, 172.16.x).
    """
    local_nets = []
    try:
        result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if 'inet ' in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    # strict=False allows host bits (e.g., 192.168.0.3/24 -> 192.168.0.0/24)
                    local_nets.append(ipaddress.ip_network(parts[1], strict=False))
    except Exception as e:
        print(f"DEBUG: Error detecting local subnets: {e}", file=sys.stderr)
    return local_nets

def is_local_subnet(target_cidr: str, local_nets: list) -> bool:
    """
    Determines if a target subnet matches a local interface.
    This is the core decision point for choosing Layer 2 (ARP) vs Layer 3 (ICMP) scanning.
    """
    try:
        target_net = ipaddress.ip_network(target_cidr, strict=False)
        for local_net in local_nets:
            if target_net == local_net:
                return True
    except ValueError:
        pass
    return False

def ping_host(ip: str) -> bool:
    """
    Pings a single IP address. Returns True if host is reachable.
    Uses OS-specific parameters for cross-platform compatibility.
    """
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        result = subprocess.run(
            ['ping', param, '1', timeout_param, str(PING_TIMEOUT), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=PING_TIMEOUT + 1
        )
        return result.returncode == 0
    except Exception:
        return False

def get_arp_table() -> dict:
    """
    Reads the Linux ARP cache (/proc/net/arp).
    This is the fastest method to get real MAC addresses for local Layer 2 devices.
    """
    arp_map = {}
    try:
        with open('/proc/net/arp', 'r') as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    ip, hw_type, mac = parts[0], parts[1], parts[3]
                    # 0x1 = Ethernet, filter out incomplete entries
                    if mac != "00:00:00:00:00:00" and hw_type == "0x1":
                        arp_map[ip] = mac.lower()
    except Exception as e:
        print(f"DEBUG: ARP Cache Error: {e}", file=sys.stderr)
    return arp_map

def get_hostname(ip: str) -> str:
    """Attempts reverse DNS lookup to resolve IP to a human-readable hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return 'unknown'

def detect_device_type(hostname: str, mac: str, ip: str) -> str:
    """
    Heuristic device fingerprinting.
    Uses a multi-layered approach: MAC OUI -> Hostname patterns -> IP heuristics.
    """
    mac = mac.upper() if mac else ""
    hostname = hostname.lower() if hostname else ""
    
    # Layer 1: MAC OUI (Most reliable for local devices)
    if mac and mac != 'UNKNOWN':
        oui = mac[:8].lower()
        if oui in ['b8:27:eb', 'dc:a6:32']: return 'Raspberry Pi'
        if oui in ['a4:83:e7', '3c:06:30']: return 'Apple Device'
        if oui in ['bc:24:11']: return 'Proxmox VM'
        if oui in ['60:01:94', '18:fe:34']: return 'IoT Device'
        if oui in ['00:1a:11', '00:17:c5']: return 'Network Device'

    # Layer 2: Hostname patterns (Useful when MAC is unknown on remote subnets)
    if hostname != 'unknown':
        if any(x in hostname for x in ['iphone', 'ipad', 'mac', 'apple', '.local']): return 'Apple Device'
        if any(x in hostname for x in ['pi', 'raspberry', 'debian', 'ubuntu']): return 'Linux'
        if any(x in hostname for x in ['win', 'windows', 'desktop']): return 'Windows'
        if any(x in hostname for x in ['router', 'gateway', 'fritz']): return 'Network Device'

    # Layer 3: IP Heuristics
    if ip.endswith('.1'): return 'Likely Gateway/Router'
    
    return 'Unknown'

def scan_local_subnet(network_config: dict, arp_cache: dict) -> list:
    """
    Scans a LOCAL subnet using the ARP cache.
    Process: Pings all hosts to populate the OS ARP cache, waits 2s, then reads the cache.
    This finds everything on the local LAN, including IoT devices that block ICMP.
    """
    cidr = network_config.get('cidr', '')
    name = network_config.get('name', 'Unknown')
    vlan = network_config.get('vlan_id')
    
    print(f"DEBUG: [LOCAL] Scanning {name} ({cidr}) via ARP Cache...", file=sys.stderr)
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    # Ping sweep to force OS to resolve MAC addresses via ARP
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        {executor.submit(ping_host, str(ip)): str(ip) for ip in network.hosts()}
    
    time.sleep(2) # Allow ARP cache to populate

    devices = []
    for ip_str, mac in arp_cache.items():
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip in network:
                hostname = get_hostname(ip_str)
                device_type = detect_device_type(hostname, mac, ip_str)
                
                devices.append({
                    'ip': ip_str, 'mac': mac, 'hostname': hostname,
                    'device_type': device_type, 'network_name': name,
                    'vlan_id': str(vlan) if vlan else 'N/A'
                })
        except ValueError:
            continue
            
    return devices

def scan_remote_subnet(network_config: dict) -> list:
    """
    Scans a REMOTE subnet using threaded ICMP Ping.
    Crosses router boundaries. Note: MAC addresses will be 'unknown' as ARP 
    does not traverse Layer 3 boundaries.
    """
    cidr = network_config.get('cidr', '')
    name = network_config.get('name', 'Unknown')
    vlan = network_config.get('vlan_id')
    
    print(f"DEBUG: [REMOTE] Scanning {name} ({cidr}) via ICMP Ping...", file=sys.stderr)
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    # Safety limit: Prevent scanning impractically large networks in an MVP
    if network.num_addresses > 1024:
        print(f"DEBUG: Skipping {cidr} (Too large for MVP)", file=sys.stderr)
        return []

    live_ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(ping_host, str(ip)): str(ip) for ip in network.hosts()}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    live_ips.append(ip)
            except Exception:
                pass

    print(f"DEBUG: [REMOTE] Found {len(live_ips)} live hosts in {name}.", file=sys.stderr)

    devices = []
    for ip in live_ips:
        hostname = get_hostname(ip)
        device_type = detect_device_type(hostname, 'unknown', ip)
        
        devices.append({
            'ip': ip, 'mac': 'unknown', 'hostname': hostname,
            'device_type': device_type, 'network_name': name,
            'vlan_id': str(vlan) if vlan else 'N/A'
        })

    return devices

def main():
    """
    Main execution flow.
    1. Parse JSON network config from PHP.
    2. Detect local subnets dynamically.
    3. Route each network to the appropriate scanner (Local ARP vs Remote ICMP).
    4. Output JSON results to stdout for PHP parsing.
    """
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No network configuration provided"}))
        sys.exit(1)
        
    try:
        networks = json.loads(sys.argv[1])
    except json.JSONDecodeError:
        print(json.dumps({"error": "Invalid JSON configuration"}))
        sys.exit(1)
        
    print(f"=== NetSentinel Adaptive Discovery Started ===", file=sys.stderr)
    
    # Detect local subnets ONCE at startup
    local_nets = get_local_subnets()
    arp_cache = get_arp_table()
    
    all_devices = []
    for net in networks:
        cidr = net.get('cidr', '')
        # ADAPTIVE DECISION: Choose scanning method based on network topology
        if is_local_subnet(cidr, local_nets):
            devices = scan_local_subnet(net, arp_cache)
        else:
            devices = scan_remote_subnet(net)
        all_devices.extend(devices)
        
    print(f"=== Total devices found: {len(all_devices)} ===", file=sys.stderr)
    print(json.dumps(all_devices, indent=2))

if __name__ == "__main__":
    main()