"""
NetSentinel Docker/Legacy Collector

This module serves as an alternative or container-based agent implementation.
It orchestrates the collection of system metadata, port status, and firewall 
state, then submits the findings to the backend API.

Designed specifically for environments where the agent runs inside a 
Docker container (hence the default API URL pointing to 'dashboard:80'),
or as a lightweight standalone script using the 'schedule' library.
"""

import os
import time
import json
import logging
import platform
import socket
import subprocess
import schedule
import requests
import psutil
from datetime import datetime

# --- Configuration ---
# Default API URL points to the internal Docker network name of the dashboard service.
# In a production environment, this would be overridden by environment variables.
API_URL = os.getenv("API_URL", "http://dashboard:80/api/submit.php")
DEVICE_ID = os.getenv("DEVICE_ID", f"agent-{platform.node().lower()}")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Configure basic logging for the container/script
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL), 
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class SystemInfoCollector:
    """
    Collects cross-platform OS and hardware metadata.
    
    Normalizes data from different operating systems into a consistent 
    dictionary format for the backend API.
    """
    
    @staticmethod
    def get_info() -> dict:
        """
        Gather basic system telemetry.
        
        Returns:
            A dictionary containing OS family, version, CPU/RAM usage, and hostname.
        """
        return {
            "os_family": platform.system(),       # e.g., 'Windows', 'Linux', 'Darwin'
            "os_version": platform.release(),     # e.g., '10', '22.04', '14.0'
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "hostname": platform.node()
        }


class PortCheck:
    """
    Checks for specific high-risk/common ports using standard TCP sockets.
    
    Focuses on a curated list of ports that are most relevant to SME security:
    - 22 (SSH): Remote access (High risk if exposed)
    - 80/443 (HTTP/HTTPS): Standard web traffic (Expected)
    - 3389 (RDP): Remote Desktop (Critical risk if exposed)
    - 445 (SMB): File sharing (Critical risk for ransomware lateral movement)
    - 8080 (Alt-HTTP): Common for dev servers/proxies (Medium risk)
    """
    
    TARGET_PORTS = [22, 80, 443, 3389, 445, 8080]

    @classmethod
    def run(cls) -> list:
        """
        Execute the port scan against TARGET_PORTS.
        
        Returns:
            A list of dictionaries describing any open ports found.
        """
        findings = []
        for port in cls.TARGET_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1) # 1-second timeout to prevent hanging
            
            # connect_ex returns 0 if the connection succeeds (port is open)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                # Determine if this port is "expected" for a standard workstation
                is_expected = port in [80, 443]
                
                # Assign severity based on the risk profile of the port
                severity = "High" if port in [3389, 445] else "Medium"
                
                findings.append({
                    "port_number": port,
                    "protocol": "TCP",
                    "status": "open",
                    "is_expected": is_expected,
                    "severity": severity,
                    "process_name": "unknown" # Process identification requires root/admin
                })
        return findings


class FirewallCheck:
    """
    Cross-platform firewall status check using subprocess.
    
    Queries the native firewall utility for the detected OS (UFW for Linux, 
    netsh for Windows, socketfilterfw for macOS) to determine if the host 
    is protected.
    """
    
    @staticmethod
    def run() -> dict:
        """
        Check the active state of the host firewall.
        
        Returns:
            A dictionary containing the firewall profile name, enabled status, 
            and a simplified security status string.
        """
        os_type = platform.system()
        enabled = False
        profile = "Unknown"
        
        try:
            if os_type == "Linux":
                # Check UFW (Uncomplicated Firewall) status
                result = subprocess.run(
                    ['ufw', 'status'], 
                    capture_output=True, text=True, timeout=5
                )
                if 'active' in result.stdout.lower():
                    enabled = True
                profile = "UFW"
                
            elif os_type == "Windows":
                # Check Windows Defender Firewall current profile state
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'currentprofile'], 
                    capture_output=True, text=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if 'State' in result.stdout and 'ON' in result.stdout.upper():
                    enabled = True
                profile = "Windows Defender"
                
            elif os_type == "Darwin":
                # Check macOS Application Layer Firewall (ALF)
                result = subprocess.run(
                    ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'], 
                    capture_output=True, text=True, timeout=5
                )
                if 'enabled' in result.stdout.lower():
                    enabled = True
                profile = "macOS ALF"
                
        except Exception as e:
            logging.warning(f"Firewall check failed on {os_type}: {e}")
            
        return {
            "profile": profile,
            "enabled": enabled,
            "risky_rule_count": 0, # Placeholder for future rule analysis
            "status": "Secure" if enabled else "Warning"
        }


class HealthCheckRunner:
    """
    Orchestrates the individual checks and handles API submission.
    
    Acts as the main controller for the collector script, aggregating 
    data from SystemInfo, Port, and Firewall checks into a single 
    JSON payload.
    """
    
    def __init__(self, device_id: str, api_url: str):
        """
        Initialize the runner with device identity and API endpoint.
        
        Args:
            device_id: Unique identifier for this endpoint.
            api_url: The URL of the backend submission endpoint.
        """
        self.device_id = device_id
        self.api_url = api_url

    def run_checks(self):
        """
        Execute all security checks and submit the aggregated payload.
        """
        logging.info(f"Starting security health check for {self.device_id}...")
        
        # 1. Gather Telemetry
        system_info = SystemInfoCollector.get_info()
        ports = PortCheck.run()
        firewall = FirewallCheck.run()
        
        # 2. Construct Payload
        # We calculate a simple overall status: Secure only if firewall is on 
        # and no unexpected high-risk ports are open.
        payload = {
            "hostname": system_info["hostname"],
            "system_info": system_info,
            "latency_ms": 0,  # Placeholder; LatencyCheck is handled separately in the main agent
            "overall_status": "Secure" if (firewall["enabled"] and len(ports) == 0) else "Warning",
            "findings": {
                "ports": ports,
                "firewall": firewall
            }
        }
        
        # 3. Submit to PHP API
        try:
            headers = {"Content-Type": "application/json"}
            response = requests.post(
                self.api_url, 
                json=payload, 
                headers=headers, 
                timeout=10
            )
            
            if response.status_code == 200:
                logging.info(f"Telemetry submitted successfully. API Response: {response.text}")
            else:
                logging.error(f"API rejected data: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to connect to API: {e}")


def main():
    """
    Main execution loop for the collector script.
    
    Runs an immediate check on startup to verify connectivity, then 
    schedules subsequent checks every 5 minutes using the 'schedule' library.
    """
    logging.info("NetSentinel Agent (Collector) starting...")
    
    runner = HealthCheckRunner(device_id=DEVICE_ID, api_url=API_URL)
    
    # Run once immediately on startup to verify connectivity
    runner.run_checks()
    
    # Schedule to run every 5 minutes
    schedule.every(5).minutes.do(runner.run_checks)
    logging.info("Scheduled checks to run every 5 minutes.")
    
    # Keep the script running in the foreground (Required for Docker containers)
    # In a production environment, this might be handled by systemd or cron instead.
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()