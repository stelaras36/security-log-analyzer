from collections import defaultdict
from datetime import timedelta


BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

SUCCESS_AFTER_FAILURES_THRESHOLD = 3
SUCCESS_AFTER_FAILURES_WINDOW_MINUTES = 5

PASSWORD_SPRAY_USER_THRESHOLD = 4
PASSWORD_SPRAY_WINDOW_MINUTES = 5

CREDENTIAL_STUFFING_USER_THRESHOLD = 3
CREDENTIAL_STUFFING_FAILURE_THRESHOLD = 5
CREDENTIAL_STUFFING_WINDOW_MINUTES = 10

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

MITRE_SUCCESS_AFTER_FAILURES = {
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic": "Credential Access"
}

MITRE_PASSWORD_SPRAYING = {
    "technique_id": "T1110.003",
    "technique_name": "Password Spraying",
    "tactic": "Credential Access"
}

MITRE_CREDENTIAL_STUFFING = {
    "technique_id": "T1110.004",
    "technique_name": "Credential Stuffing",
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
    failed_attempts = defaultdict(list)
    alerts = []

    valid_logs = [
        log
        for log in parsed_logs
        if (
            log["ip"]
            and log["user"]
            and log["timestamp"]
        )
    ]

    valid_logs.sort(
        key=lambda log: log["timestamp"]
    )

    for log in valid_logs:
        ip = log["ip"]
        user = log["user"]
        timestamp = log["timestamp"]

        key = (
            ip,
            user
        )

        if log["event_type"] == "FAILED":
            failed_attempts[key].append(
                timestamp
            )
            continue

        if log["event_type"] != "SUCCESS":
            continue

        window_start = (
            timestamp
            - timedelta(
                minutes=SUCCESS_AFTER_FAILURES_WINDOW_MINUTES
            )
        )

        recent_failures = [
            failure_time
            for failure_time in failed_attempts[key]
            if (
                window_start
                <= failure_time
                <= timestamp
            )
        ]

        if (
            len(recent_failures)
            >= SUCCESS_AFTER_FAILURES_THRESHOLD
        ):
            alerts.append({
                "type": "SUCCESS_AFTER_FAILURES",
                "ip": ip,
                "user": user,
                "failed_attempts_before_success": (
                    len(recent_failures)
                ),
                "start_time": recent_failures[0],
                "success_time": timestamp,
                "severity": (
                    "HIGH"
                    if user.lower() in PRIVILEGED_USERS
                    else "MEDIUM"
                ),
                "alert": (
                    "Possible successful brute-force"
                ),
                "mitre_technique_id": (
                    MITRE_SUCCESS_AFTER_FAILURES[
                        "technique_id"
                    ]
                ),
                "mitre_technique_name": (
                    MITRE_SUCCESS_AFTER_FAILURES[
                        "technique_name"
                    ]
                ),
                "mitre_tactic": (
                    MITRE_SUCCESS_AFTER_FAILURES[
                        "tactic"
                    ]
                )
            })

        failed_attempts[key] = []

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
        attempts.sort(
            key=lambda item: item["timestamp"]
        )

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
                    "mitre_tactic": (
                        MITRE_PASSWORD_SPRAYING["tactic"]
                    )
                })
                break

    return alerts


def detect_credential_stuffing(parsed_logs):
    events_by_ip = defaultdict(list)
    alerts = []

    for log in parsed_logs:
        ip = log["ip"]
        user = log["user"]
        timestamp = log["timestamp"]

        if not ip or not user or not timestamp:
            continue

        events_by_ip[ip].append({
            "event_type": log["event_type"],
            "user": user,
            "timestamp": timestamp
        })

    for ip, events in events_by_ip.items():
        events.sort(
            key=lambda item: item["timestamp"]
        )

        for start_index, start_event in enumerate(events):
            start_time = start_event["timestamp"]

            window_end = start_time + timedelta(
                minutes=CREDENTIAL_STUFFING_WINDOW_MINUTES
            )

            events_in_window = [
                event
                for event in events[start_index:]
                if event["timestamp"] <= window_end
            ]

            failed_events = [
                event
                for event in events_in_window
                if event["event_type"] == "FAILED"
            ]

            successful_events = [
                event
                for event in events_in_window
                if event["event_type"] == "SUCCESS"
            ]

            targeted_users = {
                event["user"]
                for event in events_in_window
            }

            if (
                len(targeted_users)
                >= CREDENTIAL_STUFFING_USER_THRESHOLD
                and len(failed_events)
                >= CREDENTIAL_STUFFING_FAILURE_THRESHOLD
                and len(successful_events) >= 1
            ):
                successful_users = sorted({
                    event["user"]
                    for event in successful_events
                })

                privileged_targeted = any(
                    user.lower() in PRIVILEGED_USERS
                    for user in targeted_users
                )

                alerts.append({
                    "type": "CREDENTIAL_STUFFING",
                    "ip": ip,
                    "users": sorted(targeted_users),
                    "successful_users": successful_users,
                    "user_count": len(targeted_users),
                    "failed_attempts": len(failed_events),
                    "successful_logins": len(successful_events),
                    "start_time": start_time,
                    "end_time": events_in_window[-1]["timestamp"],
                    "severity": (
                        "HIGH"
                        if privileged_targeted
                        else "MEDIUM"
                    ),
                    "mitre_technique_id": (
                        MITRE_CREDENTIAL_STUFFING[
                            "technique_id"
                        ]
                    ),
                    "mitre_technique_name": (
                        MITRE_CREDENTIAL_STUFFING[
                            "technique_name"
                        ]
                    ),
                    "mitre_tactic": (
                        MITRE_CREDENTIAL_STUFFING[
                            "tactic"
                        ]
                    )
                })

                break

    return alerts