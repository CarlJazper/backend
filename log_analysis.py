#log_analysis.py
import re
from datetime import datetime, timedelta
import pandas as pd
from collections import defaultdict

def analyze_logs(log_data, debug=False):
    logs = log_data.split("\n")
    events = []
    failed_login_attempts = defaultdict(list)

    # Define patterns to detect specific security breaches
    patterns = {
    'Multiple Failed Login Attempts': r'failed login.*from (\d+\.\d+\.\d+\.\d+)',  # Multiple failed login attempts
    'Unusual Login Time': r'logged in',  # Unusual login times (e.g., outside working hours)
    'Unauthorized Admin Access': r'accessed /admin',  # Unauthorized access to /admin
    'SQL Injection Attempt': r'(DROP|SELECT|INSERT|--|\;|\' OR \'1\'=\'1)|wget|curl',  # SQL injection or dangerous commands
    'Excessive Requests': r'too many requests',  # DDoS or excessive requests
    'Suspicious Data Access': r'(downloaded|accessed)',  # Suspicious data access
    'Privilege Escalation': r'privilege escalation',  # Privilege escalation attempt
    'Port Scanning Attempt': r'attempted access to port',  # Port scanning attempts
    'Failed API Key Use': r'failed API key',  # Failed API key use
    'Suspicious File Manipulation': r'(rm|chmod|chown|mv)',  # Suspicious file manipulation
    'Buffer Overflow Attempt': r'(AAAA|BBBB|CCCC)',  # Potential buffer overflow
    'Brute Force Attack': r'Brute force attack detected',  # Brute force attack detection
    'Cross-Site Scripting (XSS) Attempt': r'(<script.*>.*</script>)|<.*on.*=.*>',  # Cross-site scripting (XSS) attack
    'Remote File Inclusion (RFI)': r'(http://|https://).*\.php\?file=',  # Remote file inclusion (RFI)
    'Denial of Service (DoS) Attack': r'(DoS|Denial of Service|flood)',  # Denial of Service attacks
    'Phishing Attempt': r'(click here|urgent|immediate action required)',  # Phishing attempts in email/logs
    'Command Injection': r'(\|.*\||&&.*&&|;.*;)',  # Command injection attempt
    'Session Hijacking': r'(set-cookie:|sessionid=)',  # Session hijacking attempts
    'Malware Detection': r'(exe|.dll|.bat|.sh)',  # Malware attempts (e.g., file extensions)
    'Credential Stuffing': r'(login|authentication).*from (\d+\.\d+\.\d+\.\d+)',  # Credential stuffing
    'Insecure Deserialization': r'(deserialize|unserialize)',  # Insecure deserialization attack
}

    for log in logs:
        event = {}

        if log.strip():  # Ensure non-empty log line
            match = re.match(r"(\S+ \S+) (\S+) (.*)", log)

            if match:
                event['timestamp'] = match.group(1)
                event['source'] = match.group(2)
                event['message'] = match.group(3)
                event['suspicious'] = 'No'
                event['severity'] = 'Low'

        
                try:
                    timestamp = datetime.strptime(event['timestamp'], "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    if debug:
                        print(f"Skipping log due to invalid timestamp: {log}")
                    continue  # Skip logs with invalid timestamps

                # Check if any security breach patterns match this log
                for breach_type, pattern in patterns.items():
                    pattern_match = re.search(pattern, event['message'])
                    if pattern_match:
                        event['suspicious'] = 'Yes'
                        event['reason'] = breach_type
                        event['severity'] = 'High'  # Default high severity for matched patterns
                        event['match'] = pattern_match.groups()

                        # Adjust severity for specific patterns
                        if breach_type in ['Multiple Failed Login Attempts', 'SQL Injection Attempt']:
                            event['severity'] = 'Medium'

                events.append(event)

    df = pd.DataFrame(events)

    return events
