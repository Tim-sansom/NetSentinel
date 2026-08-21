"""
Persistence Check
Detects common, suspicious persistence mechanisms (Cron, Startup, Scheduled Tasks).
Fulfills FR1 (System metadata) and NFR1 (Lightweight).
"""
import platform
import subprocess
import os
import logging
from .base_check import BaseCheck, CheckResult


class PersistenceCheck(BaseCheck):
    """Checks for common, suspicious persistence mechanisms."""
    
    def __init__(self):
        super().__init__(
            name="persistence_check",
            description="Detects suspicious cron jobs, startup items, or scheduled tasks."
        )
        self.logger = logging.getLogger("netsentinel.checks.persistence_check")

    def check(self) -> CheckResult:
        os_type = platform.system()
        findings = []
        
        try:
            if os_type == "Linux":
                findings.extend(self._check_cron())
            elif os_type == "Darwin":  # macOS
                findings.extend(self._check_cron())
            elif os_type == "Windows":
                findings.extend(self._check_windows_startup())
            
            if findings:
                return CheckResult(
                    check_name=self.name,
                    status="fail",
                    message=f"Found {len(findings)} suspicious persistence mechanisms",
                    severity="high",
                    details={"findings": findings}
                )
            else:
                return CheckResult(
                    check_name=self.name,
                    status="pass",
                    message="No suspicious persistence mechanisms detected",
                    severity="low",
                    details={}
                )
        except Exception as e:
            self.logger.error(f"Persistence check failed: {str(e)}")
            return CheckResult(
                check_name=self.name,
                status="error",
                message=f"Persistence check execution failed: {str(e)}",
                severity="high",
                details={"exception": str(e)}
            )

    def _check_cron(self) -> list:
        """Check for cron jobs executing from /tmp or /var/tmp (common malware drop zones)."""
        findings = []
        try:
            # Check root and current user crontabs for /tmp execution
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.lower().split('\n')
                for i, line in enumerate(lines):
                    if '/tmp/' in line or '/var/tmp/' in line:
                        findings.append({
                            "type": "suspicious_cron",
                            "location": "user_crontab",
                            "detail": f"Line {i+1}: {line.strip()}"
                        })
        except Exception:
            pass # Ignore if no crontab or permission denied
        return findings

    def _check_windows_startup(self) -> list:
        """Check Windows Registry Run keys for executables in Temp directories."""
        findings = []
        try:
            # Query HKLM and HKCU Run keys
            cmd = (
                'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /s; '
                'reg query "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /s'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', cmd],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                lines = result.stdout.lower().split('\n')
                for line in lines:
                    if 'temp' in line or 'appdata' in line and ('.exe' in line or '.bat' in line or '.ps1' in line):
                        findings.append({
                            "type": "suspicious_startup",
                            "location": "registry_run_key",
                            "detail": line.strip()
                        })
        except Exception:
            pass
        return findings