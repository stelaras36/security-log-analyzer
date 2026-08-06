from collections import defaultdict
from datetime import timedelta


BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

PASSWORD_SPRAY_USER_THRESHOLD = 4
PASSWORD_SPRAY_WINDOW_MINUTES = 5

PRIVILEGED_USERS = {
    "admin",
    "administrator",
    "root"
}

MITRE_BRUTE_FORCE = {
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic": "Credential Access"
}

MITRE_PASSWORD_SPRAYING = {
    "technique_id": "T1110.003",
    "technique_name": "Password Spraying",
    "tactic": "Credential Access"
}


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


def detect_brute_force_attempts(parsed_logs):
    failed_attempts = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        if log["event_type"] != "FAILED":
            continue

        ip = log["ip"]
        user = log["user"]
        timestamp = log["timestamp"]

        if not ip or not user or not timestamp:
            continue

        failed_attempts[(ip, user)].append(timestamp)

    for (ip, user), timestamps in failed_attempts.items():
        timestamps.sort()

        for start_index, start_time in enumerate(timestamps):
            window_end = start_time + timedelta(
                minutes=BRUTE_FORCE_WINDOW_MINUTES
            )

            attempts_in_window = [
                timestamp
                for timestamp in timestamps[start_index:]
                if timestamp <= window_end
            ]

            if len(attempts_in_window) >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "ip": ip,
                    "user": user,
                    "attempts": len(attempts_in_window),
                    "start_time": start_time,
                    "end_time": attempts_in_window[-1],
                    "severity": (
                        "HIGH"
                        if user.lower() in PRIVILEGED_USERS
                        else "MEDIUM"
                    ),
                    "mitre_technique_id": (
                        MITRE_BRUTE_FORCE["technique_id"]
                    ),
                    "mitre_technique_name": (
                        MITRE_BRUTE_FORCE["technique_name"]
                    ),
                    "mitre_tactic": MITRE_BRUTE_FORCE["tactic"]
                })
                break

    return alerts


def detect_password_spraying(parsed_logs):
    failed_attempts_by_ip = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        if log["event_type"] != "FAILED":
            continue

        ip = log["ip"]
        user = log["user"]
        timestamp = log["timestamp"]

        if not ip or not user or not timestamp:
            continue

        failed_attempts_by_ip[ip].append({
            "user": user,
            "timestamp": timestamp
        })

    for ip, attempts in failed_attempts_by_ip.items():
        attempts.sort(key=lambda item: item["timestamp"])

        for start_index, start_attempt in enumerate(attempts):
            start_time = start_attempt["timestamp"]

            window_end = start_time + timedelta(
                minutes=PASSWORD_SPRAY_WINDOW_MINUTES
            )

            attempts_in_window = [
                attempt
                for attempt in attempts[start_index:]
                if attempt["timestamp"] <= window_end
            ]

            targeted_users = {
                attempt["user"]
                for attempt in attempts_in_window
            }

            if len(targeted_users) >= PASSWORD_SPRAY_USER_THRESHOLD:
                privileged_targeted = any(
                    user.lower() in PRIVILEGED_USERS
                    for user in targeted_users
                )

                alerts.append({
                    "type": "PASSWORD_SPRAYING",
                    "ip": ip,
                    "users": sorted(targeted_users),
                    "user_count": len(targeted_users),
                    "attempts": len(attempts_in_window),
                    "start_time": start_time,
                    "end_time": attempts_in_window[-1]["timestamp"],
                    "severity": (
                        "HIGH"
                        if privileged_targeted
                        else "MEDIUM"
                    ),
                    "mitre_technique_id": (
                        MITRE_PASSWORD_SPRAYING["technique_id"]
                    ),
                    "mitre_technique_name": (
                        MITRE_PASSWORD_SPRAYING["technique_name"]
                    ),
                    "mitre_tactic": MITRE_PASSWORD_SPRAYING["tactic"]
                })
                break

    return alerts