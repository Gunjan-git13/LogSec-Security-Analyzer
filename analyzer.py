import re
from collections import Counter

FAILED_LOGIN_THRESHOLD = 3


def extract_ip_address(log_line):
    """Extract and validate an IPv4 address."""

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(pattern, log_line)

    if not match:
        return None

    ip_address = match.group()
    parts = ip_address.split(".")

    if all(0 <= int(part) <= 255 for part in parts):
        return ip_address

    return None


def get_severity(attempts):
    """Determine alert severity based on failed attempts."""

    if attempts >= 10:
        return "High"
    elif attempts >= 5:
        return "Medium"
    else:
        return "Low"


def analyze_logs(log_lines):
    """Analyze login logs and detect suspicious activity."""

    total_entries = 0
    successful_logins = 0
    failed_logins = 0
    invalid_entries = 0

    failed_ips = []

    for log in log_lines:
        log = log.strip()

        if not log:
            continue

        total_entries += 1
        normalized_log = log.lower()

        if "login successful" in normalized_log:
            successful_logins += 1

        elif "failed login" in normalized_log:
            failed_logins += 1

            ip_address = extract_ip_address(log)

            if ip_address:
                failed_ips.append(ip_address)
            else:
                invalid_entries += 1

        else:
            invalid_entries += 1

    ip_counts = Counter(failed_ips)
    alerts = []

    for ip_address, attempts in sorted(ip_counts.items()):
        if attempts >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "ip_address": ip_address,
                "attempts": attempts,
                "severity": get_severity(attempts)
            })

    return {
        "total_entries": total_entries,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "invalid_entries": invalid_entries,
        "alerts": alerts
    }