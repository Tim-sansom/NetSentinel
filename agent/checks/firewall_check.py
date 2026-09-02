"""
Firewall Check - Cross-Platform Status Verification

Determines if the host's native firewall is active.
Fulfils FR2 (Firewall status) and NFR2 (Cross-platform support).
Uses native OS commands that do not require elevated (admin/root) privileges.
"""

import platform
import subprocess
import logging
from .base_check import BaseCheck, CheckResult


class FirewallCheck(BaseCheck):
    """
    Checks the status of the host firewall on Windows, Linux, or macOS.
    
    Returns a simple boolean state (active/inactive) to keep the payload 
    lightweight, while capturing raw output for debugging if needed.
    """

    def __init__(self):
        """Initialize the FirewallCheck with standard BaseCheck metadata."""
        super().__init__(
            name="firewall_check",
            description="Checks if the host firewall is active."
        )
        self.logger = logging.getLogger("netsentinel.checks.firewall_check")

    def check(self) -> CheckResult:
        """
        Perform the firewall check based on the host OS.
        
        Returns:
            CheckResult indicating if the firewall is active or inactive.
        """
        os_name = platform.system().lower()
        
        try:
            if os_name == "windows":
                is_active, details = self._check_windows_firewall()
            elif os_name == "linux":
                is_active, details = self._check_linux_firewall()
            elif os_name == "darwin":  # macOS
                is_active, details = self._check_macos_firewall()
            else:
                return CheckResult(
                    check_name=self.name,
                    status="error",
                    message=f"Unsupported operating system: {os_name}",
                    severity="high"
                )

            # Determine pass/fail based on firewall state
            if is_active:
                status = "pass"
                severity = "low"
                message = "Host firewall is active."
            else:
                status = "fail"
                severity = "high"
                message = "Host firewall is INACTIVE or disabled!"

            return CheckResult(
                check_name=self.name,
                status=status,
                message=message,
                severity=severity,
                details=details
            )
        except Exception as e:
            self.logger.error(f"Failed to perform firewall check: {str(e)}")
            return CheckResult(
                check_name=self.name,
                status="error",
                message=f"Firewall check execution failed: {str(e)}",
                severity="high",
                details={"exception": str(e)}
            )

    def _check_windows_firewall(self) -> tuple:
        """
        Check Windows Defender Firewall status using netsh.
        
        Note: netsh can be run without admin privileges to read the state.
        For MVP, we consider the firewall 'active' if any profile is ON.
        """
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=10, 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout.lower()
            
            # Check if any profile is enabled
            is_active = "state                                 on" in output or "state on" in output.replace(" ", "")
            
            return is_active, {"os": "windows", "raw_output": output.strip()[:200]}
        except Exception as e:
            return False, {"os": "windows", "error": str(e)}

    def _check_linux_firewall(self) -> tuple:
        """
        Check Linux firewall status (ufw or firewalld).
        
        Checks systemctl status without requiring sudo. Covers both 
        Debian/Ubuntu (ufw) and RHEL/CentOS/Fedora (firewalld) families.
        """
        try:
            # Try UFW first (standard on Ubuntu)
            result = subprocess.run(
                ["systemctl", "is-active", "ufw"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip() == "active":
                return True, {"os": "linux", "firewall": "ufw", "status": "active"}
                
            # Fallback to firewalld (standard on RHEL/CentOS/Fedora)
            result = subprocess.run(
                ["systemctl", "is-active", "firewalld"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip() == "active":
                return True, {"os": "linux", "firewall": "firewalld", "status": "active"}
                
            return False, {"os": "linux", "firewall": "none_detected", "status": "inactive"}
        except Exception as e:
            return False, {"os": "linux", "error": str(e)}

    def _check_macos_firewall(self) -> tuple:
        """
        Check macOS Application Firewall (ALF) status.
        
        Reads the global state from the preferences plist.
        0 = Off, 1 = On, 2 = On (Stealth mode enabled).
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True, text=True, timeout=10
            )
            state = result.stdout.strip()
            is_active = state in ["1", "2"]
            
            return is_active, {"os": "macos", "globalstate": state}
        except Exception as e:
            return False, {"os": "macos", "error": str(e)}