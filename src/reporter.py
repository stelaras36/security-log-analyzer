import csv
import os

from detector import (
    calculate_risk,
    BRUTE_FORCE_WINDOW_MINUTES,
    SUCCESS_AFTER_FAILURES_WINDOW_MINUTES,
    PASSWORD_SPRAY_WINDOW_MINUTES,
    CREDENTIAL_STUFFING_WINDOW_MINUTES,
    MULTI_ACCOUNT_TARGET_WINDOW_MINUTES
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
            f"{alert['successful_logins']} successful logins: "
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


def generate_csv_report(
    ip_counter,
    targeted_users,
    success_alerts
):
    os.makedirs(
        "reports",
        exist_ok=True
    )

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
            "IP Address",
            "Failed Attempts",
            "Targeted Users",
            "Risk Level",
            "Alert"
        ])

        for ip, attempts in ip_counter.items():
            risk = calculate_risk(
                attempts
            )

            if risk in {"MEDIUM", "HIGH"}:
                users = ", ".join(
                    sorted(targeted_users[ip])
                )

                alert_text = ""

                for alert in success_alerts:
                    if alert["ip"] == ip:
                        alert_text = alert["alert"]
                        break

                writer.writerow([
                    ip,
                    attempts,
                    users,
                    risk,
                    alert_text
                ])