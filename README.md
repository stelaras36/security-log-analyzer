# Security Log Analyzer

A Python-based mini SOC tool that analyzes authentication logs and detects suspicious login activity.

## Features

- Reads authentication log files
- Detects failed login attempts
- Counts failed attempts by IP address
- Identifies targeted users
- Assigns risk levels: LOW, MEDIUM, HIGH
- Detects possible successful brute-force attempts
- Generates a CSV security report

## Detection Logic

The tool detects suspicious activity based on:

- Multiple failed login attempts from the same IP address
- Medium risk: 3-4 failed attempts
- High risk: 5 or more failed attempts
- Possible successful brute-force when an IP has 3 or more failed attempts followed by a successful login

## Project Structure

```txt
security-log-analyzer/
├── logs/
│   └── auth.log
├── reports/
│   └── suspicious_report.csv
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── detector.py
│   └── reporter.py
└── README.md
```

## Example Log Input

```txt
2026-07-05 10:21:11 LOGIN_FAILED user=admin ip=192.168.1.20
2026-07-05 10:21:18 LOGIN_FAILED user=admin ip=192.168.1.20
2026-07-05 10:21:30 LOGIN_FAILED user=admin ip=192.168.1.20
2026-07-05 10:22:01 LOGIN_SUCCESS user=admin ip=192.168.1.20
```

## Example Output

```txt
Suspicious IPs:
192.168.1.20 -> 3 failed attempts -> Users: admin -> Risk: MEDIUM

Success-after-failures alerts:
192.168.1.20 -> User: admin -> 3 failed attempts before success -> Possible successful brute-force
```

## CSV Report Example

```csv
IP Address,Failed Attempts,Targeted Users,Risk Level,Alert
192.168.1.20,3,admin,MEDIUM,Possible successful brute-force
172.16.0.8,4,root,MEDIUM,
```

## How to Run

From the project root folder, run:

```bash
python src/main.py
```

If Python is installed as `py` on Windows:

```bash
py src/main.py
```

## Technologies Used

- Python
- CSV
- Log parsing
- Basic detection rules

## Purpose

This project was created as a cybersecurity portfolio project to demonstrate basic SOC-style log analysis, brute-force detection, risk scoring, and report generation.