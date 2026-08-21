"""
Anomaly Check
Detects unexpected open ports and dangerous services.
Fulfills FR2 (Port/Service checks) and NFR1 (Lightweight).
"""
import socket
import platform
import logging
from typing import List, Dict
from .base_check import BaseCheck, CheckResult


class AnomalyCheck(BaseCheck):
    """Detects unexpected or dangerous open ports and services."""
    
    # Expected ports for typical SME workstations
    EXPECTED_PORTS = {
        'Windows': [135, 139, 445, 3389, 5357],  # Common Windows services
        'Darwin': [5353, 62078],  # macOS Bonjour/AirPlay
        'Linux': []  # Minimal expected on Linux workstations
    }
    
    # Known dangerous ports that should NEVER be open on an endpoint
    DANGEROUS_PORTS = {
        23: "Telnet (unencrypted)",
        21: "FTP (unencrypted)",
        135: "MSRPC (Windows)",
        139: "NetBIOS",
        445: "SMB (if not required)",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB"
    }
    
    def __init__(self):
        super().__init__(
            name="anomaly_check",
            description="Detects unexpected or dangerous open ports and services"
        )
        self.logger = logging.getLogger("netsentinel.checks.anomaly_check")
    
    def check(self) -> CheckResult:
        os_type = platform.system()
        open_ports = self._scan_all_ports()
        anomalies = []
        dangerous = []
        
        for port in open_ports:
            if port in self.DANGEROUS_PORTS:
                dangerous.append({
                    "port": port,
                    "service": self.DANGEROUS_PORTS[port],
                    "severity": "critical"
                })
            elif port not in self.EXPECTED_PORTS.get(os_type, []):
                anomalies.append({
                    "port": port,
                    "service": self._identify_service(port),
                    "severity": "medium"
                })
        
        if dangerous:
            return CheckResult(
                check_name=self.name,
                status="fail",
                message=f"Found {len(dangerous)} dangerous open ports",
                severity="critical",
                details={"dangerous_ports": dangerous, "anomalies": anomalies}
            )
        elif anomalies:
            return CheckResult(
                check_name=self.name,
                status="warning",
                message=f"Found {len(anomalies)} unexpected open ports",
                severity="medium",
                details={"anomalies": anomalies}
            )
        else:
            return CheckResult(
                check_name=self.name,
                status="pass",
                message="No anomalous ports detected",
                severity="low",
                details={}
            )
    
    def _scan_all_ports(self, ports: List[int] = None) -> List[int]:
        """Scan common ports."""
        if ports is None:
            ports = self._get_common_ports()
        
        open_ports = []
        for port in ports:
            if self._is_port_open(port, timeout=0.2): # Reduced timeout for speed
                open_ports.append(port)
        
        return open_ports
    
    def _get_common_ports(self) -> List[int]:
        """Top commonly scanned/attacked ports."""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 144, 443, 445, 993, 995, 1433, 1521, 1723,
            2049, 2181, 2375, 2376, 3306, 3389, 5000, 5001,
            5432, 5900, 5901, 6379, 8080, 8081, 8443, 8888,
            9000, 9090, 9200, 9300, 11211, 27017, 27018
        ]
    
    def _is_port_open(self, port: int, timeout: float = 0.2) -> bool:
        """Check if a specific TCP port is open on localhost."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                result = s.connect_ex(('127.0.0.1', port))
                return result == 0
            except socket.error:
                return False

    def _identify_service(self, port: int) -> str:
        """Try to identify the service on a port."""
        try:
            return socket.getservbyport(port)
        except Exception:
            return "Unknown"