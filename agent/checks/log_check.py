"""
Log Anomaly Check
Lightweight SIEM-style check for authentication failures and suspicious log events.
Fulfills FR1 (Log analysis) and NFR1 (Lightweight).
"""
import subprocess
import platform
import os
import logging
from .base_check import BaseCheck, CheckResult


class LogCheck(BaseCheck):
    """Checks system logs for anomalies like brute-force attempts."""

    def __init__(self):
        super().__init__(
            name="log_check",
            description="Scans system logs for authentication failures and anomalies."
        )
        self.logger = logging.getLogger("netsentinel.checks.log_check")

    def check(self) -> CheckResult:
        os_type = platform.system()
        anomalies = []

        try:
            if os_type == "Linux":
                anomalies = self._check_linux_logs()
            elif os_type == "Windows":
                anomalies = self._check_windows_logs()
            else:
                return CheckResult(
                    check_name=self.name, status="unknown",
                    message=f"Log check unsupported on {os_type}",
                    severity="low", details={}
                )

            # Determine status based on findings
            if anomalies:
                # If any critical/high anomalies found, fail the check
                high_severity = any(a['severity'] in ['high', 'critical'] for a in anomalies)
                status = "fail" if high_severity else "warning"
                severity = "high" if high_severity else "medium"
                message = f"Found {len(anomalies)} log anomalies."
            else:
                status = "pass"
                severity = "low"
                message = "No suspicious log activity detected."

            return CheckResult(
                check_name=self.name, status=status, message=message,
                severity=severity, details={"anomalies": anomalies}
            )

        except Exception as e:
            self.logger.error(f"Log check failed: {str(e)}")
            return CheckResult(
                check_name=self.name, status="error",
                message=f"Log check execution failed: {str(e)}",
                severity="high", details={"exception": str(e)}
            )

    def _check_linux_logs(self) -> list:
        """Check Linux auth.log for failed SSH logins."""
        anomalies = []
        log_file = "/var/log/auth.log"
        
        # Fallback for some distros that use secure log
        if not os.path.exists(log_file):
            log_file = "/var/log/secure"

        if not os.path.exists(log_file):
            self.logger.warning(f"Log file not found: {log_file}")
            return anomalies

        # Check if we have read permissions
        if not os.access(log_file, os.R_OK):
            self.logger.warning(f"No read permission for {log_file}. Run agent with sudo.")
            return anomalies

        try:
            # Lightweight: only check recent entries
            result = subprocess.run(
                ['tail', '-n', '500', log_file], 
                capture_output=True, text=True, timeout=5
            )
            failed_count = result.stdout.lower().count('failed password')
            
            if failed_count > 0:
                anomalies.append({
                    "source": "auth.log",
                    "anomaly_type": "brute_force_ssh",
                    "event_count": failed_count,
                    "severity": "high" if failed_count > 5 else "medium",
                    "details": f"{failed_count} failed SSH login attempts detected recently."
                })
        except Exception as e:
            self.logger.error(f"Error reading Linux logs: {e}")
            
        return anomalies

    def _check_windows_logs(self) -> list:
        """Check Windows Security Log for Event ID 4625 (Failed Logon)."""
        anomalies = []
        try:
            # Query last 50 security events for ID 4625
            cmd = [
                'wevtutil', 'qe', 'Security', 
                '/q:*[System[(EventID=4625)]]', 
                '/c:50', '/f:text'
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Count occurrences
            failed_count = result.stdout.count('EventID')
            
            if failed_count > 0:
                anomalies.append({
                    "source": "Windows Security Log",
                    "anomaly_type": "failed_logon",
                    "event_count": failed_count,
                    "severity": "high" if failed_count > 5 else "medium",
                    "details": f"{failed_count} failed Windows logon attempts detected."
                })
        except Exception as e:
            self.logger.error(f"Error reading Windows logs: {e}")
            
        return anomalies