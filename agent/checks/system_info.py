"""
System Information Check - Asset Metadata Collection

Collects OS metadata, version, architecture, uptime, and IP address.
Fulfils FR1 (System/OS metadata). 

Provides the foundational asset data required for the dashboard to 
categorize and filter endpoints by operating system, health status, and IP.
"""

import platform
import psutil
import logging
import socket
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
            description="Collects OS metadata, version, architecture, uptime, and IP address."
        )
        self.logger = logging.getLogger("netsentinel.checks.system_info")

    def _get_primary_ip(self) -> str:
        """
        Determines the primary IP address of the host.
        Works cross-platform (Windows, Linux, macOS) without requiring 
        external network access or root privileges.
        """
        try:
            # Create a UDP socket (doesn't actually send any packets)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            try:
                # Connect to a non-routable address to find the default interface IP
                s.connect(('10.255.255.255', 1))
                ip = s.getsockname()[0]
            except Exception:
                ip = '127.0.0.1'
            finally:
                s.close()
            return ip
        except Exception as e:
            self.logger.warning(f"Could not determine IP address: {e}")
            return "unknown"

    def _normalize_os_info(self) -> tuple:
        """
        Normalizes OS data across Windows, Linux, and macOS.
        """
        os_system = platform.system()
        
        # --- macOS Handling ---
        if os_system == 'Darwin':
            os_family = 'macOS'
            os_version = platform.mac_ver()[0] 
            
        # --- Windows Handling ---
        elif os_system == 'Windows':
            os_family = 'Windows'
            os_version = platform.release() 
            try:
                edition = platform.win32_edition()
                if edition and 'Server' in str(edition):
                    os_family = 'Windows Server'
            except Exception:
                pass
                
        # --- Linux Handling ---
        elif os_system == 'Linux':
            os_family = 'Linux'
            try:
                os_info = platform.freedesktop_os_release()
                distro_name = os_info.get('NAME', 'Linux')
                distro_ver = os_info.get('VERSION_ID', '')
                os_version = f"{distro_name} {distro_ver}".strip()
            except (AttributeError, OSError):
                os_version = platform.release()
        else:
            os_family = os_system
            os_version = platform.release()
            
        return os_family, os_version

    def check(self) -> CheckResult:
        """
        Perform the system info check.
        """
        try:
            # Get normalized OS data
            os_family, os_version = self._normalize_os_info()
            
            # Gather additional platform details
            architecture = platform.machine()     
            hostname = platform.node()            
            python_version = platform.python_version() 
            ip_address = self._get_primary_ip()   # <--- NEW: Get IP address
            
            # Calculate system uptime using 'psutil'
            boot_time_timestamp = psutil.boot_time()
            boot_time = datetime.fromtimestamp(boot_time_timestamp)
            uptime_delta = datetime.now() - boot_time
            
            # Format uptime into a human-readable string
            days = uptime_delta.days
            hours, remainder = divmod(uptime_delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            uptime_str = f"{days}d {hours}h {minutes}m"
            
            # Compile all details for the API payload
            details = {
                "hostname": hostname,
                "ip_address": ip_address,         # <--- NEW: Added to payload
                "os_family": os_family,       
                "os_version": os_version,     
                "architecture": architecture,
                "uptime": uptime_str,
                "uptime_seconds": int(uptime_delta.total_seconds()),
                "agent_python_version": python_version,
                "last_boot_time": boot_time.isoformat()
            }
            
            self.logger.info(f"System info collected: {os_family} {os_version} ({hostname}) @ {ip_address}")
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