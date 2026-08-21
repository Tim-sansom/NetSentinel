import platform
import subprocess

class LogHealthCheck:
    def run(self):
        os_name = platform.system().lower()
        
        if os_name == 'windows':
            # Check if Windows Audit Policy is enabled for logon events
            try:
                result = subprocess.run(['auditpol', '/get', '/category:"Logon/Logoff"'], 
                                        capture_output=True, text=True, timeout=5)
                if 'Success and Failure' in result.stdout or 'Success' in result.stdout:
                    return {"category": "logging", "status": "pass", "details": "Logon auditing is enabled"}
                else:
                    return {"category": "logging", "status": "fail", "details": "Logon auditing is disabled"}
            except Exception:
                return {"category": "logging", "status": "unknown", "details": "Could not query audit policy"}
                
        elif os_name == 'linux':
            # Check if auditd or rsyslog is active
            try:
                result = subprocess.run(['systemctl', 'is-active', 'rsyslog'], 
                                        capture_output=True, text=True, timeout=5)
                if result.stdout.strip() == 'active':
                    return {"category": "logging", "status": "pass", "details": "rsyslog is active"}
                else:
                    return {"category": "logging", "status": "fail", "details": "rsyslog is not active"}
            except Exception:
                return {"category": "logging", "status": "unknown", "details": "Could not check syslog status"}