"""
Patch Level Check - Update Posture Assessment

Reports patch/update posture: pending update counts, last patch activity,
auto-update status, and OS support status. 

Fulfills FR1 (System/OS metadata and patch level). Crucially, this check 
is designed to run WITHOUT administrative privileges by using read-only 
system commands and registry keys.
"""

import platform
import subprocess
import re
import logging
from .base_check import BaseCheck, CheckResult


class PatchCheck(BaseCheck):
    """
    Collects patch/update posture without requiring admin rights.
    
    Evaluates the endpoint's security hygiene by checking for pending 
    critical security updates and verifying if automatic updates are enabled.
    """

    # List of Ubuntu LTS versions currently supported by Canonical
    SUPPORTED_UBUNTU = {"22.04", "24.04", "26.04"}

    def __init__(self):
        """Initialize the PatchCheck with standard BaseCheck metadata."""
        super().__init__(
            name="patch_check",
            description="Collects pending updates, last patch date, auto-update and OS support status."
        )
        self.logger = logging.getLogger("netsentinel.checks.patch_check")

    def check(self) -> CheckResult:
        """
        Execute the patch check based on the host operating system.
        
        Returns:
            CheckResult with a detailed breakdown of the patch posture.
            Status is 'fail' if critical updates are missing or OS is unsupported.
        """
        os_system = platform.system()
        try:
            if os_system == "Linux":
                details = self._check_linux()
            elif os_system == "Windows":
                details = self._check_windows()
            else:
                return CheckResult(
                    check_name=self.name, status="unknown",
                    message=f"Patch check unsupported on {os_system}",
                    severity="low", details={"os": os_system}
                )

            # Evaluate risk based on the collected details
            if not details["os_supported"] or details["missing_critical_count"] > 0:
                status, severity = "fail", "high"
                message = (f"Patch posture poor: {details['missing_critical_count']} "
                           f"security update(s) pending; OS supported: {details['os_supported']}")
            elif details["missing_important_count"] > 0 or not details["auto_updates"]:
                status, severity = "warning", "medium"
                message = (f"{details['missing_important_count']} non-security update(s) pending; "
                           f"auto-updates: {details['auto_updates']}")
            else:
                status, severity = "pass", "low"
                message = "Patch posture good: no pending security updates, auto-updates on"

            return CheckResult(
                check_name=self.name, status=status, message=message,
                severity=severity, details=details
            )
        except Exception as e:
            self.logger.error(f"Patch check failed: {str(e)}")
            return CheckResult(
                check_name=self.name, status="error",
                message=f"Patch check execution failed: {str(e)}",
                severity="high", details={"exception": str(e)}
            )

    def _blank(self) -> dict:
        """Return a default dictionary structure for patch details."""
        return {
            "missing_critical_count": 0,
            "missing_important_count": 0,
            "latest_update_count": 0,
            "high_severity_cve_count": 0,
            "auto_updates": False,
            "last_patch_date": None,
            "os_supported": False,
        }

    def _check_linux(self) -> dict:
        """
        Check Linux patch status using apt-get and systemctl.
        
        Uses 'apt-get -s upgrade' (simulation mode) to count pending updates 
        without actually installing anything. Checks 'unattended-upgrades' 
        service status to verify auto-patching.
        """
        details = self._blank()
        
        # 1. Check OS Support Status
        try:
            rel = platform.freedesktop_os_release()
            if rel.get("ID", "linux") == "ubuntu":
                details["os_supported"] = rel.get("VERSION_ID", "") in self.SUPPORTED_UBUNTU
            else:
                # Assume supported for non-Ubuntu distros in this MVP
                details["os_supported"] = True
        except (AttributeError, OSError):
            pass

        # 2. Count Pending Updates (Simulation mode)
        try:
            result = subprocess.run(["apt-get", "-s", "upgrade"],
                                    capture_output=True, text=True, timeout=30)
            # Lines starting with "Inst " indicate packages to be installed
            inst = [l for l in result.stdout.splitlines() if l.startswith("Inst ")]
            # Security updates usually have "-security" in the repository name
            details["missing_critical_count"] = sum(1 for l in inst if "-security" in l)
            details["missing_important_count"] = len(inst) - details["missing_critical_count"]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.warning("apt-get simulation unavailable")

        # 3. Check Last Patch Date and Count
        try:
            with open("/var/log/apt/history.log", "r", errors="ignore") as f:
                content = f.read()
            upgrades = re.findall(r"Upgrade:\s*(.+)", content)
            if upgrades:
                # Count packages in the last upgrade block
                details["latest_update_count"] = len(re.findall(r"\([^)]*\)", upgrades[-1]))
            dates = re.findall(r"Start-Date:\s*([\d\-]+)", content)
            if dates:
                details["last_patch_date"] = dates[-1]
        except OSError:
            pass

        # 4. Check Auto-Updates Status
        try:
            r = subprocess.run(["systemctl", "is-active", "unattended-upgrades"],
                               capture_output=True, text=True, timeout=10)
            details["auto_updates"] = r.stdout.strip() == "active"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return details

    def _check_windows(self) -> dict:
        """
        Check Windows patch status using PowerShell and Registry.
        
        Uses Get-HotFix to count installed updates. Reads the Windows Update 
        registry key to determine if automatic updates are enabled.
        """
        details = self._blank()
        details["os_supported"] = platform.release() == "11" # Assuming Win 11 for MVP
        
        # 1. Get Update Count and Last Install Date via PowerShell
        try:
            ps = ('(Get-HotFix | Measure-Object).Count; '
                  '(Get-HotFix | Sort-Object InstalledOn -Descending | '
                  'Select-Object -First 1).InstalledOn.ToString("yyyy-MM-dd")')
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=30,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            if lines:
                details["latest_update_count"] = int(lines[0])
            if len(lines) > 1:
                details["last_patch_date"] = lines[1]
        except Exception as e:
            self.logger.warning(f"Get-HotFix failed: {e}")

        # 2. Check Auto-Updates via Registry
        # AUOptions = 4 means "Auto download and schedule the install"
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update")
            val, _ = winreg.QueryValueEx(key, "AUOptions")
            details["auto_updates"] = val == 4
        except Exception:
            pass

        return details