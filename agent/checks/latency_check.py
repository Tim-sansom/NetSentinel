"""
Latency Check
Measures basic network connectivity and latency to the target server.
Fulfills FR3 and NFR2 (Cross-platform).
"""
import platform
import subprocess
import re
import logging
from .base_check import BaseCheck, CheckResult


class LatencyCheck(BaseCheck):
    """Measures network latency to the backend API server using ICMP ping."""

    def __init__(self, target: str = "8.8.8.8"):
        """
        Initialize the latency check.
        
        Args:
            target: The hostname or IP address to ping. 
                    Defaults to 8.8.8.8 (Google DNS) if not specified.
        """
        super().__init__(
            name="latency_check",
            description=f"Measures network latency to {target}."
        )
        self.target = target
        self.logger = logging.getLogger("netsentinel.checks.latency_check")

    def check(self) -> CheckResult:
        """
        Perform the latency check.
        
        Returns:
            CheckResult with latency details in milliseconds.
        """
        os_name = platform.system().lower()
        
        try:
            # Build the ping command based on the OS
            if os_name == "windows":
                # -n 1: send 1 packet, -w 2000: timeout after 2000ms
                cmd = ["ping", "-n", "1", "-w", "2000", self.target]
            else:
                # macOS and Linux
                # -c 1: send 1 packet, -W 2: timeout after 2 seconds
                cmd = ["ping", "-c", "1", "-W", "2", self.target]

            # Run the command
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if os_name == "windows" else 0
            )

            # Parse the output to find the latency
            latency_ms = self._parse_ping_output(result.stdout, os_name)

            if latency_ms is not None:
                # Determine severity based on latency thresholds
                if latency_ms < 100:
                    severity = "low"
                    status = "pass"
                    message = f"Good latency to {self.target}: {latency_ms}ms"
                elif latency_ms < 300:
                    severity = "medium"
                    status = "pass"
                    message = f"Acceptable latency to {self.target}: {latency_ms}ms"
                else:
                    severity = "high"
                    status = "warning"
                    message = f"High latency to {self.target}: {latency_ms}ms"
                
                return CheckResult(
                    check_name=self.name,
                    status=status,
                    message=message,
                    severity=severity,
                    details={"target": self.target, "latency_ms": latency_ms}
                )
            else:
                # Ping command ran, but we couldn't parse a time (e.g., host unreachable)
                return CheckResult(
                    check_name=self.name,
                    status="fail",
                    message=f"Could not reach {self.target} or parse ping output.",
                    severity="high",
                    details={"target": self.target, "raw_output": result.stdout.strip()[:200]}
                )

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Ping to {self.target} timed out.")
            return CheckResult(
                check_name=self.name,
                status="fail",
                message=f"Connection to {self.target} timed out.",
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
        Extract the latency in milliseconds from the ping command output.
        Works for Windows, Linux, and macOS.
        """
        # Regex looks for "time=12ms" (Windows) or "time=0.5 ms" (Linux/Mac)
        match = re.search(r"time[=<]([\d.]+)\s*ms", output, re.IGNORECASE)
        
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                return None
        return None