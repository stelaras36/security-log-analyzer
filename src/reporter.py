import csv
import os

from detector import calculate_risk


REPORT_FILE = "reports/suspicious_report.csv"


def print_suspicious_ips(ip_counter, targeted_users):
    print("Suspicious IPs:")
    suspicious_found = False

    for ip, attempts in ip_counter.items():
        risk = calculate_risk(attempts)

        if risk == "MEDIUM" or risk == "HIGH":
            suspicious_found = True
            users = ", ".join(targeted_users[ip])

            print(f"{ip} -> {attempts} failed attempts -> Users: {users} -> Risk: {risk}")

    if not suspicious_found:
        print("No suspicious IPs found.")


def print_success_after_failures_alerts(alerts):
    print()
    print("Success-after-failures alerts:")

    if not alerts:
        print("No successful brute-force indicators found.")
        return

    for alert in alerts:
        print(
            f"{alert['ip']} -> User: {alert['user']} -> "
            f"{alert['failed_attempts_before_success']} failed attempts before success -> "
            f"{alert['alert']}"
        )


def generate_csv_report(ip_counter, targeted_users, success_alerts):
    os.makedirs("reports", exist_ok=True)

    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow([
            "IP Address",
            "Failed Attempts",
            "Targeted Users",
            "Risk Level",
            "Alert"
        ])

        for ip, attempts in ip_counter.items():
            risk = calculate_risk(attempts)

            if risk == "MEDIUM" or risk == "HIGH":
                users = ", ".join(targeted_users[ip])
                alert_text = ""

                for alert in success_alerts:
                    if alert["ip"] == ip:
                        alert_text = alert["alert"]

                writer.writerow([ip, attempts, users, risk, alert_text])