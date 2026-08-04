s"""
Patch Level Check
Reports patch/update posture: pending update counts, last patch activity,
auto-update status and OS support status.
Fulfills FR1 (System/OS metadata and patch level).
"""
import platform
import subprocess
import re
import logging
from .base_check import BaseCheck, CheckResult


class PatchCheck(BaseCheck):
    """Collects patch/update posture without requiring admin rights."""

    SUPPORTED_UBUNTU = {"22.04", "24.04", "26.04"}

    def __init__(self):
        super().__init__(
            name="patch_check",
            description="Collects pending updates, last patch date, auto-update and OS support status."
        )
        self.logger = logging.getLogger("netsentinel.checks.patch_check")

    def check(self) -> CheckResult:
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

    def _blank(self):
        return {
            "missing_critical_count": 0,
            "missing_important_count": 0,
            "latest_update_count": 0,
            "high_severity_cve_count": 0,
            "auto_updates": False,
            "last_patch_date": None,
            "os_supported": False,
        }

    def _check_linux(self):
        details = self._blank()

        try:
            rel = platform.freedesktop_os_release()
            if rel.get("ID", "linux") == "ubuntu":
                details["os_supported"] = rel.get("VERSION_ID", "") in self.SUPPORTED_UBUNTU
            else:
                details["os_supported"] = True
        except (AttributeError, OSError):
            pass

        try:
            result = subprocess.run(["apt-get", "-s", "upgrade"],
                                    capture_output=True, text=True, timeout=30)
            inst = [l for l in result.stdout.splitlines() if l.startswith("Inst ")]
            details["missing_critical_count"] = sum(1 for l in inst if "-security" in l)
            details["missing_important_count"] = len(inst) - details["missing_critical_count"]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.warning("apt-get simulation unavailable")

        try:
            with open("/var/log/apt/history.log", "r", errors="ignore") as f:
                content = f.read()
            upgrades = re.findall(r"Upgrade:\s*(.+)", content)
            if upgrades:
                details["latest_update_count"] = len(re.findall(r"\([^)]*\)", upgrades[-1]))
            dates = re.findall(r"Start-Date:\s*([\d\-]+)", content)
            if dates:
                details["last_patch_date"] = dates[-1]
        except OSError:
            pass

        try:
            r = subprocess.run(["systemctl", "is-active", "unattended-upgrades"],
                               capture_output=True, text=True, timeout=10)
            details["auto_updates"] = r.stdout.strip() == "active"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return details

    def _check_windows(self):
        details = self._blank()
        details["os_supported"] = platform.release() == "11"

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

        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update")
            val, _ = winreg.QueryValueEx(key, "AUOptions")
            details["auto_updates"] = val == 4
        except Exception:
            pass

        return details
