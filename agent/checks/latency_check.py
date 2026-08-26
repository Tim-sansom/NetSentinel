"""
Latency Check - Network Connectivity Measurement

Measures basic ICMP latency to the backend API server.
Fulfills FR3 (Connectivity checks) and helps identify network 
segmentation or routing issues in hybrid SME environments.
"""

import platform
import subprocess
import re
import logging
import urllib.parse
from .base_check import BaseCheck, CheckResult


class LatencyCheck(BaseCheck):
    """
    Measures network latency to the backend API server using ICMP ping.
    
    Handles the significant differences in ping command syntax between 
    Windows, Linux, and macOS to ensure cross-platform reliability.
    """

    def __init__(self, target: str = "8.8.8.8"):
        """
        Initialize the LatencyCheck.
        
        Args:
            target: The URL or IP address to ping. Defaults to Google DNS 
                    as a fallback if the API URL is unreachable.
        """
        super().__init__(
            name="latency_check",
            description=f"Measures network latency to {target}."
        )
        self.target = target
        self.logger = logging.getLogger("netsentinel.checks.latency_check")

    def check(self) -> CheckResult:
        """
        Execute the ping command and parse the results.
        
        Returns:
            CheckResult with latency in milliseconds and a status 
            based on predefined SME network thresholds.
        """
        # Strip scheme/port/path so ping receives a bare host (e.g., 192.168.0.7)
        parsed = urllib.parse.urlparse(self.target)
        host_to_ping = parsed.hostname if parsed.hostname else self.target
        
        os_name = platform.system().lower()
        
        try:
            # Build the OS-specific ping command
            # Note: The timeout flag syntax varies wildly between OSes!
            if os_name == "windows":
                cmd = ["ping", "-n", "1", "-w", "2000", host_to_ping]
            elif os_name == "darwin":
                # macOS: -W is in milliseconds
                cmd = ["ping", "-c", "1", "-W", "2000", host_to_ping]
            else:
                # Linux: -W is in seconds
                cmd = ["ping", "-c", "1", "-W", "2", host_to_ping]

            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": 10
            }
            
            # creationflags is a Windows-only argument to hide the console window
            if os_name == "windows":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
                
            result = subprocess.run(cmd, **kwargs)
            latency_ms = self._parse_ping_output(result.stdout, os_name)

            # Evaluate latency against SME network thresholds
            if latency_ms is not None:
                if latency_ms < 100:
                    severity = "low"
                    status = "pass"
                    message = f"Good latency to {host_to_ping}: {latency_ms}ms"
                elif latency_ms < 300:
                    severity = "medium"
                    status = "pass"
                    message = f"Acceptable latency to {host_to_ping}: {latency_ms}ms"
                else:
                    severity = "high"
                    status = "warning"
                    message = f"High latency to {host_to_ping}: {latency_ms}ms"
                    
                return CheckResult(
                    check_name=self.name,
                    status=status,
                    message=message,
                    severity=severity,
                    details={"target": self.target, "latency_ms": latency_ms}
                )
            else:
                return CheckResult(
                    check_name=self.name,
                    status="fail",
                    message=f"Could not reach {host_to_ping} or parse ping output.",
                    severity="high",
                    details={"target": self.target, "raw_output": result.stdout.strip()[:200]}
                )
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Ping to {host_to_ping} timed out.")
            return CheckResult(
                check_name=self.name,
                status="fail",
                message=f"Connection to {host_to_ping} timed out.",
                severity="high",
                details={"target": self.target}
            )
        except FileNotFoundError:
            self.logger.error("Ping command not found on this system.")
            return CheckResult(
                check_name=self.name,
                status="error",
                message="System 'ping' command not found.",
                severity="high",
                details={"os": os_name}
            )
        except Exception as e:
            self.logger.error(f"Latency check failed: {str(e)}")
            return CheckResult(
                check_name=self.name,
                status="error",
                message=f"Latency check execution failed: {str(e)}",
                severity="high",
                details={"exception": str(e)}
            )

    def _parse_ping_output(self, output: str, os_name: str) -> float:
        """
        Extract the latency value from the raw ping command output.
        
        Uses a flexible regex to handle the slight variations in output 
        format between Windows ('time<1ms') and Linux/macOS ('time=1.23 ms').
        
        Args:
            output: The raw stdout string from the ping command.
            os_name: The operating system identifier.
            
        Returns:
            The latency in milliseconds as a float, or None if parsing fails.
        """
        match = re.search(r"time[=<]([\d.]+)\s*ms", output, re.IGNORECASE)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                return None
        return None