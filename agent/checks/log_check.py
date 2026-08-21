import subprocess
import platform

class LogRiskCheck:
    def run(self):
        os_type = platform.system().lower()
        findings = []

        if os_type == 'linux':
            # Check for failed SSH logins in the last 1000 lines of auth.log
            try:
                # Lightweight: only check recent entries
                result = subprocess.run(
                    ['tail', '-n', '500', '/var/log/auth.log'], 
                    capture_output=True, text=True, timeout=5
                )
                failed_count = result.stdout.lower().count('failed password')
                
                if failed_count > 0:
                    findings.append({
                        "category": "log_anomaly",
                        "type": "auth_failure",
                        "severity": "High" if failed_count > 5 else "Medium",
                        "details": f"{failed_count} failed SSH login attempts detected recently."
                    })
            except Exception as e:
                pass # Handle permission errors gracefully

        elif os_type == 'windows':
            # Check Windows Security Log for Event ID 4625 (Failed Logon)
            try:
                # Query last 50 security events for ID 4625
                cmd = ['wevtutil', 'qe', 'Security', '/q:*[System[(EventID=4625)]]', '/c:50', '/f:text']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                # Count occurrences
                failed_count = result.stdout.count('EventID')
                
                if failed_count > 0:
                    findings.append({
                        "category": "log_anomaly",
                        "type": "auth_failure",
                        "severity": "High" if failed_count > 5 else "Medium",
                        "details": f"{failed_count} failed Windows logon attempts detected."
                    })
            except Exception as e:
                pass

        return findings