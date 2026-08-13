import sqlite3


DATABASE_FILE = "security_logs.db"

DEFAULT_INCIDENT_STATUS = "NEW"

VALID_INCIDENT_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE"
}


def create_connection():
    return sqlite3.connect(DATABASE_FILE)


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
            status TEXT NOT NULL DEFAULT 'NEW',
            analyst_notes TEXT DEFAULT '',
            updated_at TIMESTAMP,
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
        "mitre_tactic": "TEXT",
        "status": "TEXT NOT NULL DEFAULT 'NEW'",
        "analyst_notes": "TEXT DEFAULT ''",
        "updated_at": "TIMESTAMP"
    }

    for column_name, column_definition in new_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE incidents "
                f"ADD COLUMN {column_name} {column_definition}"
            )

    connection.commit()
    connection.close()


def create_incident_status_history_table():
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT NOT NULL,
            analyst TEXT NOT NULL DEFAULT 'system',
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
        )
    """)

    cursor.execute(
        "PRAGMA table_info(incident_status_history)"
    )

    existing_columns = {
        column[1]
        for column in cursor.fetchall()
    }

    if "analyst" not in existing_columns:
        cursor.execute("""
            ALTER TABLE incident_status_history
            ADD COLUMN analyst TEXT NOT NULL DEFAULT 'system'
        """)

    connection.commit()
    connection.close()


def create_incident_notes_table():
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            analyst TEXT NOT NULL DEFAULT 'system',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id)
                REFERENCES incidents(id)
        )
    """)

    cursor.execute(
        "PRAGMA table_info(incident_notes)"
    )

    existing_columns = {
        column[1]
        for column in cursor.fetchall()
    }

    if "analyst" not in existing_columns:
        cursor.execute("""
            ALTER TABLE incident_notes
            ADD COLUMN analyst TEXT NOT NULL DEFAULT 'system'
        """)

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


def incident_exists(
    cursor,
    ip_address,
    detection_type,
    alert_text
):
    cursor.execute("""
        SELECT id
        FROM incidents
        WHERE ip_address = ?
          AND COALESCE(detection_type, '') = ?
          AND COALESCE(alert, '') = ?
        LIMIT 1
    """, (
        ip_address,
        detection_type,
        alert_text
    ))

    return cursor.fetchone() is not None


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

        users = ", ".join(
            sorted(targeted_users[ip])
        )

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

        alert_text = " | ".join(
            alert_messages
        )

        detection_type = " | ".join(
            detection_types
        )

        mitre_technique_id = " | ".join(
            mitre_ids
        )

        mitre_technique_name = " | ".join(
            mitre_names
        )

        mitre_tactic = " | ".join(
            mitre_tactics
        )

        if incident_exists(
            cursor,
            ip,
            detection_type,
            alert_text
        ):
            continue

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
                mitre_tactic,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            attempts,
            users,
            risk,
            alert_text,
            detection_type,
            mitre_technique_id,
            mitre_technique_name,
            mitre_tactic,
            DEFAULT_INCIDENT_STATUS
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
            status,
            analyst_notes,
            updated_at,
            created_at
        FROM incidents
        ORDER BY id ASC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return incidents


def update_incident_status(
    incident_id,
    new_status,
    analyst="system"
):
    normalized_status = (
        new_status.strip().upper()
    )

    analyst_name = analyst.strip()

    if not analyst_name:
        analyst_name = "system"

    if normalized_status not in VALID_INCIDENT_STATUSES:
        raise ValueError(
            f"Invalid incident status: {new_status}"
        )

    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT status
        FROM incidents
        WHERE id = ?
    """, (
        incident_id,
    ))

    result = cursor.fetchone()

    if result is None:
        connection.close()
        return False

    old_status = result[0]

    if old_status == normalized_status:
        connection.close()
        return True

    cursor.execute("""
        UPDATE incidents
        SET status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        normalized_status,
        incident_id
    ))

    cursor.execute("""
        INSERT INTO incident_status_history (
            incident_id,
            old_status,
            new_status,
            analyst
        )
        VALUES (?, ?, ?, ?)
    """, (
        incident_id,
        old_status,
        normalized_status,
        analyst_name
    ))

    connection.commit()
    connection.close()

    return True


def update_incident_notes(
    incident_id,
    notes
):
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE incidents
        SET analyst_notes = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        notes.strip(),
        incident_id
    ))

    incident_found = cursor.rowcount > 0

    connection.commit()
    connection.close()

    return incident_found


def get_incident_status_history(incident_id):
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            incident_id,
            old_status,
            new_status,
            analyst,
            changed_at
        FROM incident_status_history
        WHERE incident_id = ?
        ORDER BY id ASC
    """, (
        incident_id,
    ))

    history = cursor.fetchall()

    connection.close()

    return history


def add_incident_note(
    incident_id,
    note,
    analyst="system"
):
    cleaned_note = note.strip()
    analyst_name = analyst.strip()

    if not cleaned_note:
        return False

    if not analyst_name:
        analyst_name = "system"

    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id
        FROM incidents
        WHERE id = ?
    """, (
        incident_id,
    ))

    if cursor.fetchone() is None:
        connection.close()
        return False

    cursor.execute("""
        INSERT INTO incident_notes (
            incident_id,
            note,
            analyst
        )
        VALUES (?, ?, ?)
    """, (
        incident_id,
        cleaned_note,
        analyst_name
    ))

    cursor.execute("""
        UPDATE incidents
        SET updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        incident_id,
    ))

    connection.commit()
    connection.close()

    return True


def get_incident_notes(incident_id):
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            incident_id,
            note,
            analyst,
            created_at
        FROM incident_notes
        WHERE incident_id = ?
        ORDER BY id ASC
    """, (
        incident_id,
    ))

    notes = cursor.fetchall()

    connection.close()

    return notes