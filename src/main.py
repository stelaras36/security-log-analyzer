from parser import read_log_file, parse_logs
from detector import (
    count_failed_attempts_by_ip,
    get_targeted_users_by_ip,
    detect_success_after_failures,
    calculate_risk
)
from reporter import (
    print_suspicious_ips,
    print_success_after_failures_alerts,
    generate_csv_report
)
from database import (
    create_incidents_table,
    clear_incidents,
    save_incidents,
    get_all_incidents
)


def print_saved_incidents(incidents):
    print()
    print("Saved incidents in database:")

    if not incidents:
        print("No incidents saved in database.")
        return

    for incident in incidents:
        incident_id = incident[0]
        ip_address = incident[1]
        failed_attempts = incident[2]
        targeted_users = incident[3]
        risk_level = incident[4]
        alert = incident[5]
        created_at = incident[6]

        print(
            f"{incident_id} | {ip_address} | {failed_attempts} failed attempts | "
            f"Users: {targeted_users} | Risk: {risk_level} | Alert: {alert} | {created_at}"
        )


def main():
    print("Security Log Analyzer")
    print("---------------------")
    print("Reading log file: logs/auth.log")

    create_incidents_table()

    logs = read_log_file()
    parsed_logs = parse_logs(logs)

    ip_counter = count_failed_attempts_by_ip(parsed_logs)
    targeted_users = get_targeted_users_by_ip(parsed_logs)
    success_alerts = detect_success_after_failures(parsed_logs)

    failed_logins_count = sum(1 for log in parsed_logs if log["event_type"] == "FAILED")

    print(f"Total log lines found: {len(logs)}")
    print(f"Failed login attempts found: {failed_logins_count}")
    print()

    print_suspicious_ips(ip_counter, targeted_users)
    print_success_after_failures_alerts(success_alerts)

    generate_csv_report(ip_counter, targeted_users, success_alerts)

    clear_incidents()
    save_incidents(ip_counter, targeted_users, success_alerts, calculate_risk)

    incidents = get_all_incidents()
    print_saved_incidents(incidents)

    print()
    print("CSV report generated: reports/suspicious_report.csv")
    print("Incidents saved to SQLite database: security_logs.db")


if __name__ == "__main__":
    main()