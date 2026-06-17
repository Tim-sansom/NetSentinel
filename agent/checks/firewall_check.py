"""
Firewall Check
Checks if the host firewall is active.
Fulfills FR2 and NFR2 (Cross-platform).
"""
import platform
import subprocess
import logging
from .base_check import BaseCheck, CheckResult


class FirewallCheck(BaseCheck):
    """Checks the status of the host firewall on Windows, Linux, or macOS."""

    def __init__(self):
        super().__init__(
            name="firewall_check",
            description="Checks if the host firewall is active."
        )
        self.logger = logging.getLogger("netsentinel.checks.firewall_check")

    def check(self) -> CheckResult:
        """
        Perform the firewall check.
        
        Returns:
            CheckResult indicating if the firewall is active or inactive.
        """
        os_name = platform.system().lower()
        
        try:
            if os_name == "windows":
                is_active, details = self._check_windows_firewall()
            elif os_name == "linux":
                is_active, details = self._check_linux_firewall()
            elif os_name == "darwin": # macOS
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

    def _check_windows_firewall(self) -> tuple[bool, dict]:
        """Check Windows Defender Firewall status using netsh (no admin required)."""
        try:
            # netsh advfirewall show allprofiles state
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output = result.stdout.lower()
            # If all profiles are OFF, it's inactive. If any are ON, we consider it active for MVP.
            is_active = "state                                 on" in output or "state on" in output.replace(" ", "")
            
            return is_active, {"os": "windows", "raw_output": output.strip()[:200]}
            
        except Exception as e:
            return False, {"os": "windows", "error": str(e)}

    def _check_linux_firewall(self) -> tuple[bool, dict]:
        """Check Linux firewall status (ufw or firewalld) without sudo."""
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

    def _check_macos_firewall(self) -> tuple[bool, dict]:
        """Check macOS Application Firewall status using defaults (no sudo required)."""
        try:
            # Read the global state of the Application Firewall
            # 0 = Off, 1 = On, 2 = On (Stealth mode)
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True, text=True, timeout=10
            )
            
            state = result.stdout.strip()
            is_active = state in ["1", "2"]
            
            return is_active, {"os": "macos", "globalstate": state}
            
        except Exception as e:
            return False, {"os": "macos", "error": str(e)}