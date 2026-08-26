"""
System Information Check - Asset Metadata Collection

Collects OS metadata, version, architecture, and uptime.
Fulfills FR1 (System/OS metadata). 

Provides the foundational asset data required for the dashboard to 
categorize and filter endpoints by operating system and health status.
"""

import platform
import psutil
import logging
from datetime import datetime
from .base_check import BaseCheck, CheckResult


class SystemInfoCheck(BaseCheck):
    """
    Collects basic system and OS metadata.
    
    Normalizes OS naming conventions across Windows, Linux, and macOS 
    to ensure consistent data storage in the MySQL backend.
    """

    def __init__(self):
        """Initialize the SystemInfoCheck with standard BaseCheck metadata."""
        super().__init__(
            name="system_info",
            description="Collects OS metadata, version, architecture, and uptime."
        )
        self.logger = logging.getLogger("netsentinel.checks.system_info")

    def _normalize_os_info(self) -> tuple:
        """
        Normalizes OS data across Windows, Linux, and macOS.
        
        Handles the significant differences in how each OS reports 
        its version and edition (e.g., distinguishing Windows Server from Windows 10).
        
        Returns:
            A tuple of (os_family, os_version).
        """
        os_system = platform.system()
        
        # --- macOS Handling ---
        if os_system == 'Darwin':
            os_family = 'macOS'
            # mac_ver() returns the actual macOS version (e.g., '14.0')
            os_version = platform.mac_ver()[0] 
            
        # --- Windows Handling ---
        elif os_system == 'Windows':
            os_family = 'Windows'
            os_version = platform.release() # e.g., '10' or '11'
            # Detect Windows Server specifically to separate it from workstations
            try:
                edition = platform.win32_edition()
                if edition and 'Server' in str(edition):
                    os_family = 'Windows Server'
            except Exception:
                pass
                
        # --- Linux Handling ---
        elif os_system == 'Linux':
            os_family = 'Linux'
            # Python 3.10+ allows us to read /etc/os-release safely
            try:
                os_info = platform.freedesktop_os_release()
                distro_name = os_info.get('NAME', 'Linux')
                distro_ver = os_info.get('VERSION_ID', '')
                os_version = f"{distro_name} {distro_ver}".strip()
            except (AttributeError, OSError):
                # Fallback to kernel version if os-release fails
                os_version = platform.release()
        else:
            os_family = os_system
            os_version = platform.release()
            
        return os_family, os_version

    def check(self) -> CheckResult:
        """
        Perform the system info check.
        
        Returns:
            CheckResult containing hostname, OS family/version, architecture, 
            and formatted uptime string.
        """
        try:
            # Get normalized OS data
            os_family, os_version = self._normalize_os_info()
            
            # Gather additional platform details
            architecture = platform.machine()     # e.g., 'x86_64', 'AMD64', 'arm64'
            hostname = platform.node()            # Computer name
            python_version = platform.python_version() 
            
            # Calculate system uptime using 'psutil'
            boot_time_timestamp = psutil.boot_time()
            boot_time = datetime.fromtimestamp(boot_time_timestamp)
            uptime_delta = datetime.now() - boot_time
            
            # Format uptime into a human-readable string (e.g., "12d 4h 30m")
            days = uptime_delta.days
            hours, remainder = divmod(uptime_delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            uptime_str = f"{days}d {hours}h {minutes}m"
            
            # Compile all details for the API payload
            details = {
                "hostname": hostname,
                "os_family": os_family,       # Maps directly to DB 'os_family'
                "os_version": os_version,     # Maps directly to DB 'os_version'
                "architecture": architecture,
                "uptime": uptime_str,
                "uptime_seconds": int(uptime_delta.total_seconds()),
                "agent_python_version": python_version,
                "last_boot_time": boot_time.isoformat()
            }
            
            self.logger.info(f"System info collected: {os_family} {os_version} ({hostname})")
            return CheckResult(
                check_name=self.name,
                status="pass",
                message=f"Successfully collected system info for {hostname}",
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