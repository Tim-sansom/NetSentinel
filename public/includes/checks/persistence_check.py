"""
Persistence Check - Malware Indicator Detection

Detects common, suspicious persistence mechanisms (Cron, Startup, Scheduled Tasks).
Fulfills FR1 (System metadata) and NFR1 (Lightweight).

Instead of scanning the entire filesystem (which would violate NFR1), 
this check targets specific high-risk vectors commonly used by malware 
to survive reboots.
"""

import platform
import subprocess
import os
import logging
from .base_check import BaseCheck, CheckResult


class PersistenceCheck(BaseCheck):
    """
    Checks for common, suspicious persistence mechanisms.
    
    Focuses on:
    1. Linux/macOS: Cron jobs executing from temporary directories (/tmp).
    2. Windows: Registry Run keys pointing to temporary or AppData directories.
    """

    def __init__(self):
        """Initialize the PersistenceCheck with standard BaseCheck metadata."""
        super().__init__(
            name="persistence_check",
            description="Detects suspicious cron jobs, startup items, or scheduled tasks."
        )
        self.logger = logging.getLogger("netsentinel.checks.persistence_check")

    def check(self) -> CheckResult:
        """
        Execute the persistence check based on the host operating system.
        
        Returns:
            CheckResult with status 'fail' if suspicious mechanisms are found.
        """
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
        """
        Check for cron jobs executing from /tmp or /var/tmp.
        
        Why: /tmp and /var/tmp are world-writable directories. Malware droppers 
        often place executable scripts here and use cron to run them on reboot 
        because it doesn't require root privileges to write to /tmp.
        """
        findings = []
        try:
            # Check root and current user crontabs for /tmp execution
            result = subprocess.run(
                ['crontab', '-l'], 
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.lower().split('\n')
                for i, line in enumerate(lines):
                    # Ignore comments
                    if line.strip().startswith('#'):
                        continue
                        
                    if '/tmp/' in line or '/var/tmp/' in line:
                        findings.append({
                            "type": "suspicious_cron",
                            "location": "user_crontab",
                            "detail": f"Line {i+1}: {line.strip()}"
                        })
        except Exception:
            # Ignore if no crontab exists or permission is denied
            pass 
            
        return findings

    def _check_windows_startup(self) -> list:
        """
        Check Windows Registry Run keys for executables in Temp directories.
        
        Why: Malware often hides in %APPDATA%\Local\Temp or %TEMP% and adds 
        a registry key to HKCU\...\Run to execute itself every time the user logs in.
        """
        findings = []
        try:
            # Query HKLM and HKCU Run keys
            # Using 'reg query' is faster and requires fewer permissions than PowerShell Get-ItemProperty
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
                    # Look for suspicious paths combined with executable extensions
                    if ('temp' in line or 'appdata' in line) and \
                       ('.exe' in line or '.bat' in line or '.ps1' in line):
                        findings.append({
                            "type": "suspicious_startup",
                            "location": "registry_run_key",
                            "detail": line.strip()
                        })
        except Exception:
            pass
            
        return findings