"""
Port Check
Scans localhost for common high-risk open ports (SSH, SMB, RDP).
Fulfills FR2 and NFR2 (Cross-platform).
"""
import socket
import logging
from .base_check import BaseCheck, CheckResult


class PortCheck(BaseCheck):
    """Checks for common high-risk open ports on the local endpoint."""

    # Define the ports we care about for SME security posture
    TARGET_PORTS = [
        (22, 'SSH'),
        (445, 'SMB'),
        (3389, 'RDP')
    ]

    def __init__(self):
        super().__init__(
            name="port_check",
            description="Scans localhost for common high-risk open ports (SSH, SMB, RDP)."
        )
        self.logger = logging.getLogger("netsentinel.checks.port_check")

    def check(self) -> CheckResult:
        """
        Perform the port check.
        
        Returns:
            CheckResult with a list of open ports in the 'details' dictionary.
        """
        open_ports = []
        
        try:
            for port, service_name in self.TARGET_PORTS:
                if self._is_port_open(port):
                    open_ports.append({"port": port, "service": service_name})
                    self.logger.warning(f"High-risk port open: {service_name} ({port})")
                else:
                    self.logger.debug(f"Port closed: {service_name} ({port})")

            # Determine status based on findings
            if open_ports:
                status = "fail"
                severity = "high"
                message = f"Found {len(open_ports)} high-risk open port(s): {', '.join([p['service'] for p in open_ports])}"
            else:
                status = "pass"
                severity = "low"
                message = "No high-risk ports (SSH, SMB, RDP) are open on localhost."

            return CheckResult(
                check_name=self.name,
                status=status,
                message=message,
                severity=severity,
                details={"open_ports": open_ports}
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

    def _is_port_open(self, port: int, timeout: float = 1.0) -> bool:
        """
        Check if a specific TCP port is open on localhost.
        Works identically on Windows, macOS, and Linux.
        
        Args:
            port: The TCP port number to check.
            timeout: Connection timeout in seconds.
            
        Returns:
            True if the port is open and accepting connections.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                # Attempt to connect to localhost
                result = s.connect_ex(('127.0.0.1', port))
                # connect_ex returns 0 if the connection succeeded (port is open)
                return result == 0
            except socket.error:
                return False