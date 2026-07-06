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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def clear_incidents():
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='incidents'")

    connection.commit()
    connection.close()


def save_incidents(ip_counter, targeted_users, success_alerts, calculate_risk):
    connection = create_connection()
    cursor = connection.cursor()

    for ip, attempts in ip_counter.items():
        risk = calculate_risk(attempts)

        if risk == "MEDIUM" or risk == "HIGH":
            users = ", ".join(targeted_users[ip])
            alert_text = ""

            for alert in success_alerts:
                if alert["ip"] == ip:
                    alert_text = alert["alert"]

            cursor.execute("""
                INSERT INTO incidents (
                    ip_address,
                    failed_attempts,
                    targeted_users,
                    risk_level,
                    alert
                )
                VALUES (?, ?, ?, ?, ?)
            """, (ip, attempts, users, risk, alert_text))

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
            created_at
        FROM incidents
        ORDER BY id ASC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return incidents