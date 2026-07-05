from parser import read_log_file, parse_logs
from detector import (
    count_failed_attempts_by_ip,
    get_targeted_users_by_ip,
    detect_success_after_failures
)
from reporter import (
    print_suspicious_ips,
    print_success_after_failures_alerts,
    generate_csv_report
)


def main():
    print("Security Log Analyzer")
    print("---------------------")
    print("Reading log file: logs/auth.log")

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

    print()
    print("CSV report generated: reports/suspicious_report.csv")


if __name__ == "__main__":
    main()