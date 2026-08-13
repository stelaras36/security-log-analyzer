from parser import read_log_file, parse_logs

from detector import (
    count_failed_attempts_by_ip,
    get_targeted_users_by_ip,
    detect_success_after_failures,
    detect_brute_force_attempts,
    detect_password_spraying,
    calculate_risk
)

from reporter import (
    print_suspicious_ips,
    print_success_after_failures_alerts,
    print_brute_force_alerts,
    print_password_spray_alerts,
    generate_csv_report
)

from database import (
    create_incidents_table,
    create_incident_status_history_table,
    create_incident_notes_table,
    save_incidents,
    get_all_incidents,
    get_incident_status_history,
    get_incident_notes,
    update_incident_status
)


def print_incident_status_history(incident_id):
    history = get_incident_status_history(
        incident_id
    )

    if not history:
        print("    Status History: N/A")
        return

    print("    Status History:")

    for history_entry in history:
        old_status = history_entry[2]
        new_status = history_entry[3]
        changed_at = history_entry[4]

        print(
            f"      {old_status} -> "
            f"{new_status} | "
            f"{changed_at}"
        )


def print_incident_notes(incident_id):
    notes = get_incident_notes(
        incident_id
    )

    if not notes:
        print("    Analyst Notes History: N/A")
        return

    print("    Analyst Notes History:")

    for note_entry in notes:
        note_id = note_entry[0]
        note = note_entry[2]
        created_at = note_entry[3]

        print(
            f"      Note #{note_id} | "
            f"{note} | "
            f"{created_at}"
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
        detection_type = incident[6]
        mitre_technique_id = incident[7]
        mitre_technique_name = incident[8]
        mitre_tactic = incident[9]
        status = incident[10]
        analyst_notes = incident[11]
        updated_at = incident[12]
        created_at = incident[13]

        print(
            f"{incident_id} | "
            f"{ip_address} | "
            f"{failed_attempts} failed attempts | "
            f"Users: {targeted_users} | "
            f"Risk: {risk_level} | "
            f"Status: {status} | "
            f"Alert: {alert or 'N/A'} | "
            f"Detection: {detection_type or 'N/A'} | "
            f"MITRE: {mitre_technique_id or 'N/A'} "
            f"({mitre_technique_name or 'N/A'}) | "
            f"Tactic: {mitre_tactic or 'N/A'} | "
            f"Legacy Analyst Note: "
            f"{analyst_notes or 'N/A'} | "
            f"Updated: {updated_at or 'N/A'} | "
            f"Created: {created_at}"
        )

        print_incident_status_history(
            incident_id
        )

        print_incident_notes(
            incident_id
        )


def main():
    print("Security Log Analyzer")
    print("---------------------")
    print("Reading log file: logs/auth.log")

    create_incidents_table()
    create_incident_status_history_table()
    create_incident_notes_table()

    logs = read_log_file()
    parsed_logs = parse_logs(logs)

    ip_counter = count_failed_attempts_by_ip(
        parsed_logs
    )

    targeted_users = get_targeted_users_by_ip(
        parsed_logs
    )

    success_alerts = detect_success_after_failures(
        parsed_logs
    )

    brute_force_alerts = detect_brute_force_attempts(
        parsed_logs
    )

    password_spray_alerts = detect_password_spraying(
        parsed_logs
    )

    failed_logins_count = sum(
        1
        for log in parsed_logs
        if log["event_type"] == "FAILED"
    )

    print(
        f"Total log lines found: "
        f"{len(logs)}"
    )

    print(
        f"Failed login attempts found: "
        f"{failed_logins_count}"
    )

    print()

    print_suspicious_ips(
        ip_counter,
        targeted_users
    )

    print_success_after_failures_alerts(
        success_alerts
    )

    print_brute_force_alerts(
        brute_force_alerts
    )

    print_password_spray_alerts(
        password_spray_alerts
    )

    generate_csv_report(
        ip_counter,
        targeted_users,
        success_alerts
    )

    save_incidents(
        ip_counter,
        targeted_users,
        success_alerts,
        brute_force_alerts,
        password_spray_alerts,
        calculate_risk
    )

    incidents = get_all_incidents()

    print_saved_incidents(
        incidents
    )

    print()

    print(
        "CSV report generated: "
        "reports/suspicious_report.csv"
    )

    print(
        "Incidents saved to SQLite database: "
        "security_logs.db"
    )


if __name__ == "__main__":
    main()