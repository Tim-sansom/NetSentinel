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
API_URL = os.getenv("API_URL", "http://dashboard:80/api/submit.php")

# CRITICAL FIX 1: Read the API Token from the environment (passed via docker-compose.yml)
API_TOKEN = os.getenv("API_TOKEN", "NetSentinel2026!")

# Use a static ID for the lab environment to ensure it matches the database record
DEVICE_ID = os.getenv("DEVICE_ID", "agent-001") 

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Configure basic logging for the container/script
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL), 
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class SystemInfoCollector:
    """
    Collects cross-platform OS and hardware metadata.
    """
    
    @staticmethod
    def get_info() -> dict:
        return {
            "os_family": platform.system(),
            "os_version": platform.release(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "hostname": platform.node(),
            "architecture": platform.machine(),
            "uptime_seconds": int(time.time() - psutil.boot_time())
        }


class PortCheck:
    """
    Checks for specific high-risk/common ports using standard TCP sockets.
    """
    
    TARGET_PORTS = [22, 80, 443, 3389, 445, 8080]

    @classmethod
    def run(cls) -> list:
        findings = []
        for port in cls.TARGET_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                is_expected = port in [80, 443]
                severity = "high" if port in [3389, 445] else "medium"
                
                findings.append({
                    "port": port,
                    "protocol": "TCP",
                    "service": "unknown",
                    "is_expected": is_expected,
                    "severity": severity
                })
        return findings


class FirewallCheck:
    """
    Cross-platform firewall status check using subprocess.
    """
    
    @staticmethod
    def run() -> dict:
        os_type = platform.system()
        enabled = False
        profile = "Unknown"
        
        try:
            if os_type == "Linux":
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
                if 'active' in result.stdout.lower():
                    enabled = True
                profile = "UFW"
            elif os_type == "Windows":
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'currentprofile'], capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                if 'State' in result.stdout and 'ON' in result.stdout.upper():
                    enabled = True
                profile = "Windows Defender"
            elif os_type == "Darwin":
                result = subprocess.run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'], capture_output=True, text=True, timeout=5)
                if 'enabled' in result.stdout.lower():
                    enabled = True
                profile = "macOS ALF"
        except Exception as e:
            logging.warning(f"Firewall check failed on {os_type}: {e}")
            
        return {
            "profile": profile,
            "enabled": enabled,
            "risky_rule_count": 0,
            "status": "Secure" if enabled else "Warning"
        }


class HealthCheckRunner:
    """
    Orchestrates the individual checks and handles API submission.
    """
    
    def __init__(self, device_id: str, api_url: str, api_token: str):
        self.device_id = device_id
        self.api_url = api_url
        self.api_token = api_token # Store the token

    def run_checks(self):
        logging.info(f"Starting security health check for {self.device_id}...")
        
        # 1. Gather Telemetry
        system_info = SystemInfoCollector.get_info()
        ports = PortCheck.run()
        firewall = FirewallCheck.run()
        
        # 2. Construct Payload
        # CRITICAL FIX 2: Format payload to exactly match what submit.php expects
        payload = {
            "device_uuid": self.device_id,
            "timestamp": datetime.now().isoformat(),
            "checks": [
                {
                    "check_name": "system_info",
                    "status": "pass",
                    "severity": "info",
                    "details": system_info
                },
                {
                    "check_name": "port_check",
                    "status": "fail" if any(p["severity"] == "high" for p in ports) else ("warning" if ports else "pass"),
                    "severity": "high" if any(p["severity"] == "high" for p in ports) else ("medium" if ports else "info"),
                    "details": {"open_ports": ports}
                },
                {
                    "check_name": "firewall_check",
                    "status": "pass" if firewall["enabled"] else "fail",
                    "severity": "high" if not firewall["enabled"] else "info",
                    "details": firewall
                }
            ]
        }
        
        # 3. Submit to PHP API
        try:
            # CRITICAL FIX 3: Add the Authorization Bearer token to the headers
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_token}"
            }
            
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
    """
    logging.info("NetSentinel Agent (Collector) starting...")
    
    # Pass the API_TOKEN to the runner
    runner = HealthCheckRunner(device_id=DEVICE_ID, api_url=API_URL, api_token=API_TOKEN)
    
    # Run once immediately on startup
    runner.run_checks()
    
    # Schedule to run every 5 minutes
    schedule.every(5).minutes.do(runner.run_checks)
    logging.info("Scheduled checks to run every 5 minutes.")
    
    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()