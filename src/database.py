import sqlite3


DATABASE_FILE = "security_logs.db"


def create_connection():
    connection = sqlite3.connect(DATABASE_FILE)
    return connection


def create_incidents_table():
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL,
            targeted_users TEXT,
            risk_level TEXT NOT NULL,
            alert TEXT,
            detection_type TEXT,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            mitre_tactic TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("PRAGMA table_info(incidents)")

    existing_columns = {
        column[1]
        for column in cursor.fetchall()
    }

    new_columns = {
        "detection_type": "TEXT",
        "mitre_technique_id": "TEXT",
        "mitre_technique_name": "TEXT",
        "mitre_tactic": "TEXT"
    }

    for column_name, column_type in new_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE incidents "
                f"ADD COLUMN {column_name} {column_type}"
            )

    connection.commit()
    connection.close()


def clear_incidents():
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM incidents")
    cursor.execute(
        "DELETE FROM sqlite_sequence "
        "WHERE name = 'incidents'"
    )

    connection.commit()
    connection.close()


def add_unique_value(values, value):
    if value and value not in values:
        values.append(value)


def save_incidents(
    ip_counter,
    targeted_users,
    success_alerts,
    brute_force_alerts,
    password_spray_alerts,
    calculate_risk
):
    connection = create_connection()
    cursor = connection.cursor()

    for ip, attempts in ip_counter.items():
        risk = calculate_risk(attempts)

        if risk not in {"MEDIUM", "HIGH"}:
            continue

        users = ", ".join(sorted(targeted_users[ip]))

        alert_messages = []
        detection_types = []
        mitre_ids = []
        mitre_names = []
        mitre_tactics = []

        for alert in success_alerts:
            if alert["ip"] == ip:
                add_unique_value(
                    alert_messages,
                    alert["alert"]
                )

        for alert in brute_force_alerts:
            if alert["ip"] != ip:
                continue

            add_unique_value(
                alert_messages,
                (
                    f"Brute-force detected: "
                    f"{alert['attempts']} failed attempts "
                    f"within 5 minutes"
                )
            )

            add_unique_value(
                detection_types,
                alert["type"]
            )

            add_unique_value(
                mitre_ids,
                alert["mitre_technique_id"]
            )

            add_unique_value(
                mitre_names,
                alert["mitre_technique_name"]
            )

            add_unique_value(
                mitre_tactics,
                alert["mitre_tactic"]
            )

            if alert["severity"] == "HIGH":
                risk = "HIGH"

        for alert in password_spray_alerts:
            if alert["ip"] != ip:
                continue

            add_unique_value(
                alert_messages,
                (
                    f"Password spraying detected: "
                    f"{alert['user_count']} targeted users "
                    f"within 5 minutes"
                )
            )

            add_unique_value(
                detection_types,
                alert["type"]
            )

            add_unique_value(
                mitre_ids,
                alert["mitre_technique_id"]
            )

            add_unique_value(
                mitre_names,
                alert["mitre_technique_name"]
            )

            add_unique_value(
                mitre_tactics,
                alert["mitre_tactic"]
            )

            if alert["severity"] == "HIGH":
                risk = "HIGH"

        alert_text = " | ".join(alert_messages)
        detection_type = " | ".join(detection_types)
        mitre_technique_id = " | ".join(mitre_ids)
        mitre_technique_name = " | ".join(mitre_names)
        mitre_tactic = " | ".join(mitre_tactics)

        cursor.execute("""
            INSERT INTO incidents (
                ip_address,
                failed_attempts,
                targeted_users,
                risk_level,
                alert,
                detection_type,
                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            attempts,
            users,
            risk,
            alert_text,
            detection_type,
            mitre_technique_id,
            mitre_technique_name,
            mitre_tactic
        ))

    connection.commit()
    connection.close()


def get_all_incidents():
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            ip_address,
            failed_attempts,
            targeted_users,
            risk_level,
            alert,
            detection_type,
            mitre_technique_id,
            mitre_technique_name,
            mitre_tactic,
            created_at
        FROM incidents
        ORDER BY id ASC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return incidents