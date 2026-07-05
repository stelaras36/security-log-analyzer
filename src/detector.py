from collections import defaultdict


def count_failed_attempts_by_ip(parsed_logs):
    ip_counter = defaultdict(int)

    for log in parsed_logs:
        if log["event_type"] == "FAILED":
            ip = log["ip"]

            if ip:
                ip_counter[ip] += 1

    return ip_counter


def get_targeted_users_by_ip(parsed_logs):
    targeted_users = defaultdict(set)

    for log in parsed_logs:
        if log["event_type"] == "FAILED":
            ip = log["ip"]
            user = log["user"]

            if ip and user:
                targeted_users[ip].add(user)

    return targeted_users


def calculate_risk(attempts):
    if attempts >= 5:
        return "HIGH"
    elif attempts >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def detect_success_after_failures(parsed_logs):
    failed_counter = defaultdict(int)
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]
        user = log["user"]

        if not ip:
            continue

        if log["event_type"] == "FAILED":
            failed_counter[ip] += 1

        elif log["event_type"] == "SUCCESS":
            if failed_counter[ip] >= 3:
                alerts.append({
                    "ip": ip,
                    "user": user,
                    "failed_attempts_before_success": failed_counter[ip],
                    "alert": "Possible successful brute-force"
                })

    return alerts