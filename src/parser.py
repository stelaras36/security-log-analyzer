from datetime import datetime


LOG_FILE = "logs/auth.log"

FAILED_LOGIN_KEYWORD = "LOGIN_FAILED"
SUCCESS_LOGIN_KEYWORD = "LOGIN_SUCCESS"


def read_log_file():
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        lines = file.readlines()

    return lines


def extract_value(line, key):
    parts = line.strip().split()

    for part in parts:
        if part.startswith(key + "="):
            return part.split("=", 1)[1]

    return None


def extract_timestamp(line):
    parts = line.strip().split()

    if len(parts) < 2:
        return None

    timestamp_text = f"{parts[0]} {parts[1]}"

    try:
        return datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def parse_logs(logs):
    parsed_logs = []

    for line in logs:
        event_type = None

        if FAILED_LOGIN_KEYWORD in line:
            event_type = "FAILED"

        elif SUCCESS_LOGIN_KEYWORD in line:
            event_type = "SUCCESS"

        if event_type:
            ip = extract_value(line, "ip")
            user = extract_value(line, "user")
            timestamp = extract_timestamp(line)

            parsed_logs.append({
                "event_type": event_type,
                "ip": ip,
                "user": user,
                "timestamp": timestamp,
                "raw_log": line.strip()
            })

    return parsed_logs