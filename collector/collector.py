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
# Points to the internal Docker network name of the dashboard service
API_URL = os.getenv("API_URL", "http://dashboard:80/api/submit.php")
DEVICE_ID = os.getenv("DEVICE_ID", f"agent-{platform.node().lower()}")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(level=getattr(logging, LOG_LEVEL), format="%(asctime)s - %(levelname)s - %(message)s")

class SystemInfoCollector:
    """Collects cross-platform OS and hardware metadata."""
    @staticmethod
    def get_info():
        return {
            "os_family": platform.system(), # Windows, Linux, Darwin
            "os_version": platform.release(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "hostname": platform.node()
        }

class PortCheck:
    """Checks for specific high-risk/common ports using standard sockets."""
    TARGET_PORTS = [22, 80, 443, 3389, 445, 8080]

    @classmethod
    def run(cls):
        findings = []
        for port in cls.TARGET_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                findings.append({
                    "port_number": port,
                    "protocol": "TCP",
                    "status": "open",
                    "is_expected": port in [80, 443], # 80/443 expected, others suspicious
                    "severity": "High" if port in [3389, 445] else "Medium",
                    "process_name": "unknown"
                })
        return findings

class FirewallCheck:
    """Cross-platform firewall status check using subprocess."""
    @staticmethod
    def run():
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
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'currentprofile'], capture_output=True, text=True, timeout=5)
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
    """Orchestrates the checks and API submission."""
    def __init__(self, device_id, api_url):
        self.device_id = device_id
        self.api_url = api_url

    def run_checks(self):
        logging.info(f"Starting security health check for {self.device_id}...")
        
        system_info = SystemInfoCollector.get_info()
        ports = PortCheck.run()
        firewall = FirewallCheck.run()

        payload = {
            "hostname": system_info["hostname"],
            "system_info": system_info,
            "latency_ms": 0, 
            "overall_status": "Secure" if firewall["enabled"] and len(ports) == 0 else "Warning",
            "findings": {
                "ports": ports,
                "firewall": firewall
            }
        }

        # Submit to PHP API
        try:
            headers = {"Content-Type": "application/json"}
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                logging.info(f"Telemetry submitted successfully. API Response: {response.text}")
            else:
                logging.error(f"API rejected data: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to connect to API: {e}")

if __name__ == "__main__":
    logging.info("NetSentinel Agent starting...")
    
    runner = HealthCheckRunner(device_id=DEVICE_ID, api_url=API_URL)
    
    # Run once immediately on startup to verify connectivity
    runner.run_checks()
    
    # Schedule to run every 5 minutes
    schedule.every(5).minutes.do(runner.run_checks)
    logging.info("Scheduled checks to run every 5 minutes.")

    # Keep the script running in the foreground (Required for Docker)
    while True:
        schedule.run_pending()
        time.sleep(1)