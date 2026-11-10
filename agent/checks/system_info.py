"""
System Information Check - Asset Metadata & Network Context Collection
======================================================================
Collects OS metadata, version, architecture, uptime, IP address, MAC address,
and evaluates the network context (Internal vs. Remote).

ACADEMIC SIGNIFICANCE (Privacy vs. Utility Trade-off):
This module implements a privacy-preserving telemetry approach for hybrid-working 
SMEs. While the MAC address is collected for administrative utility (e.g., NAC 
or IP binding), the IP address is evaluated against RFC1918 private address spaces 
to determine the 'network_context'. This allows the SME dashboard to display 
whether a hybrid worker is 'In Office' or 'Remote' without storing sensitive 
public IP addresses that could be used for geolocation, satisfying GDPR data 
minimization principles.

Fulfils FR1 (System/OS metadata).
"""
import platform
import psutil
import logging
import socket
import ipaddress
from datetime import datetime
from .base_check import BaseCheck, CheckResult

class SystemInfoCheck(BaseCheck):
    """
    Collects basic system and OS metadata, plus privacy-preserving network context.
    Normalizes OS naming conventions across Windows, Linux, and macOS 
    to ensure consistent data storage in the MySQL backend.
    """
    
    def __init__(self):
        """Initialize the SystemInfoCheck with standard BaseCheck metadata."""
        super().__init__(
            name="system_info",
            description="Collects OS metadata, version, architecture, uptime, IP, MAC, and network context."
        )
        self.logger = logging.getLogger("netsentinel.checks.system_info")

    def _get_primary_ip(self) -> str:
        """
        Determines the primary IP address of the host.
        Works cross-platform (Windows, Linux, macOS) without requiring 
        external network access or root privileges.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            try:
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

    def _get_primary_mac(self) -> str:
        """
        Determines the primary MAC address of the host.
        Iterates through active network interfaces to find the MAC associated 
        with the primary network connection.
        """
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            
            for iface, iface_addrs in addrs.items():
                if iface in ['lo', 'lo0', 'docker0', 'veth*']:
                    continue
                
                iface_stat = stats.get(iface)
                if not iface_stat or not iface_stat.isup:
                    continue
                
                for addr in iface_addrs:
                    if hasattr(addr.family, 'name') and addr.family.name in ['AF_LINK', 'AF_PACKET']:
                        return addr.address
        except Exception as e:
            self.logger.warning(f"Could not determine MAC address: {e}")
        return "unknown"

    def _evaluate_network_context(self, ip_address: str) -> str:
        """
        Evaluates the IP address to determine the network context.
        Implements the Privacy vs. Utility trade-off by classifying the 
        connection as 'internal' (RFC1918 private space) or 'remote' (public IP).
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return "internal"
            else:
                return "remote"
        except ValueError:
            return "unknown"

    def _normalize_os_info(self) -> tuple:
        """Normalizes OS data across Windows, Linux, and macOS."""
        os_system = platform.system()
        
        if os_system == 'Darwin':
            os_family = 'macOS'
            os_version = platform.mac_ver()[0] 
        elif os_system == 'Windows':
            os_family = 'Windows'
            os_version = platform.release() 
            try:
                edition = platform.win32_edition()
                if edition and 'Server' in str(edition):
                    os_family = 'Windows Server'
            except Exception:
                pass
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
        """Perform the system info check."""
        try:
            os_family, os_version = self._normalize_os_info()
            architecture = platform.machine()     
            hostname = platform.node()            
            python_version = platform.python_version() 
            
            # Collect Network Identity & Privacy Context
            ip_address = self._get_primary_ip()
            mac_address = self._get_primary_mac()
            network_context = self._evaluate_network_context(ip_address)
            
            # Calculate system uptime using 'psutil'
            boot_time_timestamp = psutil.boot_time()
            boot_time = datetime.fromtimestamp(boot_time_timestamp)
            uptime_delta = datetime.now() - boot_time
            
            days = uptime_delta.days
            hours, remainder = divmod(uptime_delta.seconds, 3600)
            minutes, _ = divmod(remainder, 60)
            uptime_str = f"{days}d {hours}h {minutes}m"
            
            # Compile all details for the API payload
            details = {
                "hostname": hostname,
                "ip_address": ip_address,
                "mac_address": mac_address,
                "network_context": network_context,
                "os_family": os_family,       
                "os_version": os_version,     
                "architecture": architecture,
                "uptime": uptime_str,
                "uptime_seconds": int(uptime_delta.total_seconds()),
                "agent_python_version": python_version,
                "last_boot_time": boot_time.isoformat()
            }
            
            self.logger.info(f"System info collected: {os_family} {os_version} ({hostname}) @ {ip_address} [{network_context}]")
            
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