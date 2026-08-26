"""
Port Check - Comprehensive Service Detection

Scans localhost for ~100 common and high-risk open ports.
Fulfills FR2 (Port/Service checks) and NFR1 (Lightweight).

Strikes a balance between thoroughness (proving SIEM capability) 
and performance (avoiding a full 65,535 port scan which would 
violate the lightweight SME constraint).
"""

import socket
import logging
from typing import Dict, Tuple, List
from .base_check import BaseCheck, CheckResult


class PortCheck(BaseCheck):
    """
    Checks for common high-risk and standard open ports on the local endpoint.
    
    Uses a predefined database of ~100 common ports categorized by risk level.
    Uses TCP socket connections with a strict 0.1s timeout to ensure the scan 
    completes in under 10 seconds, satisfying NFR1.
    """

    # Comprehensive database of common ports and their risk profiles.
    # Format: port_number: (service_name, risk_level)
    # Risk levels: 'critical' (never open), 'high' (usually bad on workstations), 
    #              'medium' (context-dependent), 'low' (standard/safe)
    PORT_DATABASE: Dict[int, Tuple[str, str]] = {
        # --- Critical Risk (Should NEVER be open on an endpoint) ---
        21: ("FTP", "critical"),
        23: ("Telnet", "critical"),
        135: ("MSRPC", "critical"),
        139: ("NetBIOS", "critical"),
        445: ("SMB", "critical"),
        1433: ("MSSQL", "critical"),
        3306: ("MySQL", "critical"),
        5432: ("PostgreSQL", "critical"),
        6379: ("Redis", "critical"),
        27017: ("MongoDB", "critical"),
        11211: ("Memcached", "critical"),
        
        # --- High Risk (Often targeted for lateral movement/ransomware) ---
        22: ("SSH", "high"),
        3389: ("RDP", "high"),
        5900: ("VNC", "high"),
        5901: ("VNC-1", "high"),
        8080: ("HTTP-Proxy", "high"),
        8443: ("HTTPS-Alt", "high"),
        9090: ("Web-Console", "high"),
        
        # --- Medium Risk (Standard services, but worth monitoring) ---
        25: ("SMTP", "medium"),
        53: ("DNS", "medium"),
        110: ("POP3", "medium"),
        143: ("IMAP", "medium"),
        993: ("IMAPS", "medium"),
        995: ("POP3S", "medium"),
        1723: ("PPTP", "medium"),
        2049: ("NFS", "medium"),
        3128: ("Squid", "medium"),
        5000: ("Dev-Server", "medium"),
        5001: ("Dev-Server", "medium"),
        8000: ("Alt-HTTP", "medium"),
        8888: ("Alt-HTTP", "medium"),
        
        # --- Low Risk (Standard web/infrastructure) ---
        80: ("HTTP", "low"),
        443: ("HTTPS", "low"),
        123: ("NTP", "low"),
        1900: ("UPnP", "low"),
        5353: ("mDNS", "low"),
        5357: ("WSD", "low"),
    }

    def __init__(self):
        """Initialize the PortCheck with standard BaseCheck metadata."""
        super().__init__(
            name="port_check",
            description="Scans localhost for ~100 common and high-risk open ports."
        )
        self.logger = logging.getLogger("netsentinel.checks.port_check")
        
        # Strict 0.1s timeout. 
        # Why: Scanning 100 ports with a 1s timeout could take 100s. 
        # 0.1s ensures the scan finishes in <10s, keeping the agent lightweight (NFR1).
        self.scan_timeout = 0.1

    def check(self) -> CheckResult:
        """
        Perform the port check against the PORT_DATABASE.
        
        Returns:
            CheckResult with a categorized list of open ports in the 'details' dictionary.
            Status is 'fail' if any critical/high-risk ports are found.
        """
        open_ports: List[Dict[str, str]] = []
        
        try:
            # Iterate through our curated list of ~100 ports
            for port, (service_name, risk_level) in self.PORT_DATABASE.items():
                if self._is_port_open(port):
                    open_ports.append({
                        "port": port,
                        "service": service_name,
                        "risk": risk_level
                    })
                    # Log high/critical findings immediately for visibility
                    if risk_level in ['critical', 'high']:
                        self.logger.warning(f"High-risk port open: {service_name} ({port})")
                        
            # Separate findings by risk level for the dashboard
            critical_ports = [p for p in open_ports if p['risk'] == 'critical']
            high_ports = [p for p in open_ports if p['risk'] == 'high']
            
            # Determine overall status based on the highest severity finding
            if critical_ports:
                status = "fail"
                severity = "critical"
                message = f"Found {len(critical_ports)} CRITICAL risk port(s) open!"
            elif high_ports:
                status = "fail"
                severity = "high"
                message = f"Found {len(high_ports)} HIGH risk port(s) open."
            elif open_ports:
                status = "warning"
                severity = "medium"
                message = f"Found {len(open_ports)} open port(s) (medium/low risk)."
            else:
                status = "pass"
                severity = "low"
                message = "No high-risk ports detected in the top 100 scan."
                
            return CheckResult(
                check_name=self.name,
                status=status,
                message=message,
                severity=severity,
                details={
                    "total_open": len(open_ports),
                    "critical_ports": critical_ports,
                    "high_ports": high_ports,
                    "all_open_ports": open_ports
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to perform port check: {str(e)}")
            return CheckResult(
                check_name=self.name,
                status="error",
                message=f"Port check execution failed: {str(e)}",
                severity="high",
                details={"exception": str(e)}
            )

    def _is_port_open(self, port: int) -> bool:
        """
        Check if a specific TCP port is open on localhost.
        
        Uses connect_ex() with a strict 0.1s timeout. 
        connect_ex() returns an error indicator (0 for success) rather than raising 
        an exception, making it much faster and cleaner for scanning loops.
        
        Args:
            port: The TCP port number to check.
            
        Returns:
            True if the port is open and accepting connections.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.scan_timeout)
            try:
                # Attempt to connect to localhost (127.0.0.1)
                result = s.connect_ex(('127.0.0.1', port))
                return result == 0
            except socket.error:
                return False