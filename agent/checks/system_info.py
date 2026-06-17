"""
System Information Check
Collects OS metadata, version, architecture, and uptime.
Fulfills FR1.
"""
import platform
import psutil
import logging
from datetime import datetime
from .base_check import BaseCheck, CheckResult


class SystemInfoCheck(BaseCheck):
    """Collects basic system and OS metadata."""

    def __init__(self):
        super().__init__(
            name="system_info",
            description="Collects OS metadata, version, architecture, and uptime."
        )
        self.logger = logging.getLogger("netsentinel.checks.system_info")

    def check(self) -> CheckResult:
        """
        Perform the system info check.
        
        Returns:
            CheckResult with OS details in the 'details' dictionary.
        """
        try:
            # Gather OS and platform details using built-in 'platform' module
            os_name = platform.system()           # e.g., 'Windows', 'Linux', 'Darwin'
            os_release = platform.release()       # e.g., '10', '22.04', 'Darwin'
            os_version = platform.version()       # Detailed build string
            architecture = platform.machine()     # e.g., 'x86_64', 'AMD64'
            hostname = platform.node()            # Computer name
            python_version = platform.python_version() # Agent runtime version

            # Calculate system uptime using 'psutil'
            boot_time_timestamp = psutil.boot_time()
            boot_time = datetime.fromtimestamp(boot_time_timestamp)
            uptime_delta = datetime.now() - boot_time
            
            # Format uptime into a readable string (Days, Hours, Minutes)
            days = uptime_delta.days
            hours, remainder = divmod(uptime_delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            uptime_str = f"{days}d {hours}h {minutes}m"

            # Compile all details
            details = {
                "hostname": hostname,
                "os_name": os_name,
                "os_release": os_release,
                "os_version": os_version,
                "architecture": architecture,
                "uptime": uptime_str,
                "uptime_seconds": int(uptime_delta.total_seconds()),
                "agent_python_version": python_version,
                "last_boot_time": boot_time.isoformat()
            }

            self.logger.debug(f"System info collected for {hostname}: {os_name} {os_release}")

            return CheckResult(
                check_name=self.name,
                status="pass",
                message=f"Successfully collected system info for {hostname} ({os_name} {os_release})",
                severity="info",
                details=details
            )

        except Exception as e:
            self.logger.error(f"Failed to collect system info: {str(e)}")
            return CheckResult(
                check_name=self.name,
                status="error",
                message=f"Failed to collect system information: {str(e)}",
                severity="high",
                details={"exception": str(e)}
            )