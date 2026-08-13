import csv
import os

from detector import (
    calculate_risk,
    BRUTE_FORCE_WINDOW_MINUTES,
    SUCCESS_AFTER_FAILURES_WINDOW_MINUTES,
    PASSWORD_SPRAY_WINDOW_MINUTES,
    CREDENTIAL_STUFFING_WINDOW_MINUTES,
    MULTI_ACCOUNT_TARGET_WINDOW_MINUTES,
    ANOMALOUS_LOGIN_BURST_WINDOW_MINUTES
)


REPORT_FILE = "reports/suspicious_report.csv"


def print_suspicious_ips(ip_counter, targeted_users):
    print("Suspicious IPs:")
    suspicious_found = False

    for ip, attempts in ip_counter.items():
        risk = calculate_risk(attempts)

        if risk in {"MEDIUM", "HIGH"}:
            suspicious_found = True
            users = ", ".join(
                sorted(targeted_users[ip])
            )

            print(
                f"{ip} -> {attempts} failed attempts -> "
                f"Users: {users} -> Risk: {risk}"
            )

    if not suspicious_found:
        print("No suspicious IPs found.")


def print_success_after_failures_alerts(alerts):
    print()
    print("Success-after-failures alerts:")

    if not alerts:
        print(
            "No successful brute-force "
            "indicators found."
        )
        return

    for alert in alerts:
        print(
            f"{alert['ip']} -> "
            f"User: {alert['user']} -> "
            f"{alert['failed_attempts_before_success']} "
            f"failed attempts before success within "
            f"{SUCCESS_AFTER_FAILURES_WINDOW_MINUTES} minutes -> "
            f"Severity: {alert['severity']} -> "
            f"MITRE ATT&CK: "
            f"{alert['mitre_technique_id']} "
            f"({alert['mitre_technique_name']}) -> "
            f"Tactic: {alert['mitre_tactic']} -> "
            f"{alert['alert']}"
        )


def print_brute_force_alerts(alerts):
    print()
    print("Brute-force detection alerts:")

    if not alerts:
        print("No brute-force attacks detected.")
        return

    for alert in alerts:
        print(
            f"{alert['ip']} -> "
            f"User: {alert['user']} -> "
            f"{alert['attempts']} failed attempts within "
            f"{BRUTE_FORCE_WINDOW_MINUTES} minutes -> "
            f"Severity: {alert['severity']} -> "
            f"MITRE ATT&CK: "
            f"{alert['mitre_technique_id']} "
            f"({alert['mitre_technique_name']}) -> "
            f"Tactic: {alert['mitre_tactic']}"
        )


def print_password_spray_alerts(alerts):
    print()
    print("Password spraying detection alerts:")

    if not alerts:
        print(
            "No password spraying attacks detected."
        )
        return

    for alert in alerts:
        users = ", ".join(
            alert["users"]
        )

        print(
            f"{alert['ip']} -> "
            f"{alert['user_count']} targeted users: "
            f"{users} -> "
            f"{alert['attempts']} failed attempts within "
            f"{PASSWORD_SPRAY_WINDOW_MINUTES} minutes -> "
            f"Severity: {alert['severity']} -> "
            f"MITRE ATT&CK: "
            f"{alert['mitre_technique_id']} "
            f"({alert['mitre_technique_name']}) -> "
            f"Tactic: {alert['mitre_tactic']}"
        )


def print_credential_stuffing_alerts(alerts):
    print()
    print("Credential stuffing detection alerts:")

    if not alerts:
        print(
            "No credential stuffing attacks detected."
        )
        return

    for alert in alerts:
        users = ", ".join(
            alert["users"]
        )

        successful_users = ", ".join(
            alert["successful_users"]
        )

        print(
            f"{alert['ip']} -> "
            f"{alert['user_count']} targeted users: "
            f"{users} -> "
            f"{alert['failed_attempts']} failed attempts -> "
            f"{alert['successful_logins']} successful login(s): "
            f"{successful_users} -> "
            f"within {CREDENTIAL_STUFFING_WINDOW_MINUTES} minutes -> "
            f"Severity: {alert['severity']} -> "
            f"MITRE ATT&CK: "
            f"{alert['mitre_technique_id']} "
            f"({alert['mitre_technique_name']}) -> "
            f"Tactic: {alert['mitre_tactic']}"
        )


def print_multiple_account_targeting_alerts(alerts):
    print()
    print("Multiple-account targeting detection alerts:")

    if not alerts:
        print(
            "No multiple-account targeting detected."
        )
        return

    for alert in alerts:
        users = ", ".join(
            alert["users"]
        )

        print(
            f"{alert['ip']} -> "
            f"{alert['user_count']} targeted users: "
            f"{users} -> "
            f"{alert['attempts']} failed attempts within "
            f"{MULTI_ACCOUNT_TARGET_WINDOW_MINUTES} minutes -> "
            f"Severity: {alert['severity']} -> "
            f"MITRE ATT&CK: "
            f"{alert['mitre_technique_id']} "
            f"({alert['mitre_technique_name']}) -> "
            f"Tactic: {alert['mitre_tactic']}"
        )


def print_anomalous_login_burst_alerts(alerts):
    print()
    print("Anomalous login burst detection alerts:")

    if not alerts:
        print(
            "No anomalous login bursts detected."
        )
        return

    for alert in alerts:
        users = ", ".join(
            alert["users"]
        )

        print(
            f"{alert['ip']} -> "
            f"{alert['events']} login events within "
            f"{ANOMALOUS_LOGIN_BURST_WINDOW_MINUTES} minute(s) -> "
            f"{alert['failed_attempts']} failed -> "
            f"{alert['successful_logins']} successful -> "
            f"Users: {users} -> "
            f"Severity: {alert['severity']} -> "
            f"MITRE ATT&CK: "
            f"{alert['mitre_technique_id']} "
            f"({alert['mitre_technique_name']}) -> "
            f"Tactic: {alert['mitre_tactic']}"
        )


def format_timestamp(timestamp):
    if timestamp is None:
        return ""

    return timestamp.strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def write_detection_row(
    writer,
    detection_type,
    ip,
    users,
    user_count,
    failed_attempts,
    successful_logins,
    event_count,
    severity,
    alert_text,
    mitre_technique_id,
    mitre_technique_name,
    mitre_tactic,
    event_start,
    event_end
):
    writer.writerow([
        detection_type,
        ip,
        users,
        user_count,
        failed_attempts,
        successful_logins,
        event_count,
        severity,
        alert_text,
        mitre_technique_id,
        mitre_technique_name,
        mitre_tactic,
        format_timestamp(event_start),
        format_timestamp(event_end)
    ])


def generate_csv_report(
    ip_counter,
    targeted_users,
    success_alerts,
    brute_force_alerts,
    password_spray_alerts,
    credential_stuffing_alerts,
    multiple_account_targeting_alerts,
    anomalous_login_burst_alerts
):
    os.makedirs(
        "reports",
        exist_ok=True
    )

    detected_ips = set()

    with open(
        REPORT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:
        writer = csv.writer(
            csvfile
        )

        writer.writerow([
            "Detection Type",
            "IP Address",
            "Users",
            "User Count",
            "Failed Attempts",
            "Successful Logins",
            "Event Count",
            "Severity",
            "Alert",
            "MITRE Technique ID",
            "MITRE Technique Name",
            "MITRE Tactic",
            "Event Start",
            "Event End"
        ])

        for alert in success_alerts:
            detected_ips.add(
                alert["ip"]
            )

            write_detection_row(
                writer,
                alert["type"],
                alert["ip"],
                alert["user"],
                1,
                alert["failed_attempts_before_success"],
                1,
                (
                    alert["failed_attempts_before_success"]
                    + 1
                ),
                alert["severity"],
                alert["alert"],
                alert["mitre_technique_id"],
                alert["mitre_technique_name"],
                alert["mitre_tactic"],
                alert["start_time"],
                alert["success_time"]
            )

        for alert in brute_force_alerts:
            detected_ips.add(
                alert["ip"]
            )

            write_detection_row(
                writer,
                alert["type"],
                alert["ip"],
                alert["user"],
                1,
                alert["attempts"],
                0,
                alert["attempts"],
                alert["severity"],
                (
                    f"Brute-force detected: "
                    f"{alert['attempts']} failed attempts "
                    f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes"
                ),
                alert["mitre_technique_id"],
                alert["mitre_technique_name"],
                alert["mitre_tactic"],
                alert["start_time"],
                alert["end_time"]
            )

        for alert in password_spray_alerts:
            detected_ips.add(
                alert["ip"]
            )

            users = ", ".join(
                alert["users"]
            )

            write_detection_row(
                writer,
                alert["type"],
                alert["ip"],
                users,
                alert["user_count"],
                alert["attempts"],
                0,
                alert["attempts"],
                alert["severity"],
                (
                    f"Password spraying detected: "
                    f"{alert['user_count']} targeted users "
                    f"within {PASSWORD_SPRAY_WINDOW_MINUTES} minutes"
                ),
                alert["mitre_technique_id"],
                alert["mitre_technique_name"],
                alert["mitre_tactic"],
                alert["start_time"],
                alert["end_time"]
            )

        for alert in credential_stuffing_alerts:
            detected_ips.add(
                alert["ip"]
            )

            users = ", ".join(
                alert["users"]
            )

            write_detection_row(
                writer,
                alert["type"],
                alert["ip"],
                users,
                alert["user_count"],
                alert["failed_attempts"],
                alert["successful_logins"],
                (
                    alert["failed_attempts"]
                    + alert["successful_logins"]
                ),
                alert["severity"],
                (
                    f"Credential stuffing detected: "
                    f"{alert['failed_attempts']} failed attempts, "
                    f"{alert['successful_logins']} successful login(s) "
                    f"across {alert['user_count']} users "
                    f"within {CREDENTIAL_STUFFING_WINDOW_MINUTES} minutes"
                ),
                alert["mitre_technique_id"],
                alert["mitre_technique_name"],
                alert["mitre_tactic"],
                alert["start_time"],
                alert["end_time"]
            )

        for alert in multiple_account_targeting_alerts:
            detected_ips.add(
                alert["ip"]
            )

            users = ", ".join(
                alert["users"]
            )

            write_detection_row(
                writer,
                alert["type"],
                alert["ip"],
                users,
                alert["user_count"],
                alert["attempts"],
                0,
                alert["attempts"],
                alert["severity"],
                (
                    f"Multiple-account targeting detected: "
                    f"{alert['user_count']} targeted users "
                    f"with {alert['attempts']} failed attempts "
                    f"within {MULTI_ACCOUNT_TARGET_WINDOW_MINUTES} minutes"
                ),
                alert["mitre_technique_id"],
                alert["mitre_technique_name"],
                alert["mitre_tactic"],
                alert["start_time"],
                alert["end_time"]
            )

        for alert in anomalous_login_burst_alerts:
            detected_ips.add(
                alert["ip"]
            )

            users = ", ".join(
                alert["users"]
            )

            write_detection_row(
                writer,
                alert["type"],
                alert["ip"],
                users,
                alert["user_count"],
                alert["failed_attempts"],
                alert["successful_logins"],
                alert["events"],
                alert["severity"],
                (
                    f"Anomalous login burst detected: "
                    f"{alert['events']} login events "
                    f"within "
                    f"{ANOMALOUS_LOGIN_BURST_WINDOW_MINUTES} minute(s)"
                ),
                alert["mitre_technique_id"],
                alert["mitre_technique_name"],
                alert["mitre_tactic"],
                alert["start_time"],
                alert["end_time"]
            )

        for ip, attempts in ip_counter.items():
            risk = calculate_risk(
                attempts
            )

            if (
                risk not in {"MEDIUM", "HIGH"}
                or ip in detected_ips
            ):
                continue

            users = ", ".join(
                sorted(targeted_users[ip])
            )

            write_detection_row(
                writer,
                "SUSPICIOUS_IP_SUMMARY",
                ip,
                users,
                len(targeted_users[ip]),
                attempts,
                0,
                attempts,
                risk,
                (
                    "Suspicious failed login activity "
                    "without advanced detection match"
                ),
                "",
                "",
                "",
                None,
                None
            )