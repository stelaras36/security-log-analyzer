# Security Log Analyzer v3.0 — Mini SIEM

![Python](https://img.shields.io/badge/Python-3.x-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-green)
![SQLite](https://img.shields.io/badge/SQLite-Incident%20Database-lightgrey)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red)
![Sigma](https://img.shields.io/badge/Sigma-Compatible-purple)
![Status](https://img.shields.io/badge/Status-v3.0%20Mini%20SIEM-success)

A Python-based **Mini SIEM and authentication security monitoring platform** designed to analyze authentication logs, detect suspicious behavior, manage security incidents, map detections to MITRE ATT&CK, expose incident data through a REST API, and provide an interactive SOC-style web dashboard.

The project started as a simple failed-login analyzer and evolved into a modular security monitoring application with detection engineering, incident management, SQLite persistence, FastAPI, automated tests, Sigma-compatible rules, and a web-based analyst interface.

---

## Key Features

### Authentication Log Analysis

The analyzer parses authentication events from log files and identifies:

- Failed login attempts
- Successful login attempts
- Source IP addresses
- Targeted user accounts
- Authentication timestamps

Example log format:

```text
2026-07-05 10:21:11 LOGIN_FAILED user=admin ip=192.168.1.20
2026-07-05 10:22:01 LOGIN_SUCCESS user=admin ip=192.168.1.20
Detection Engine

Security Log Analyzer v3.0 includes multiple time-based behavioral detections.

Brute Force

Detects:

5 or more failed authentication attempts
Same IP address
Same user account
Within 5 minutes

MITRE ATT&CK:

T1110 — Brute Force
Tactic: Credential Access
Successful Login After Multiple Failures

Detects:

3 or more failed login attempts
Same IP address
Same user account
Followed by a successful login
Within 5 minutes

This can indicate a potentially successful brute-force attack.

MITRE ATT&CK:

T1110 — Brute Force
Tactic: Credential Access
Password Spraying

Detects:

Failed login attempts from the same IP
Against 4 or more distinct user accounts
Within 5 minutes

MITRE ATT&CK:

T1110.003 — Password Spraying
Tactic: Credential Access
Credential Stuffing

Heuristic detection for:

5 or more failed authentication attempts
3 or more targeted user accounts
At least one successful login
Same source IP
Within 10 minutes

MITRE ATT&CK:

T1110.004 — Credential Stuffing
Tactic: Credential Access

Note: This is a behavioral heuristic. Authentication logs alone cannot prove that previously breached credentials were used.

Multiple Account Targeting

Detects:

Failed login attempts
Same source IP
Against 3 or more distinct user accounts
Within 10 minutes

MITRE ATT&CK:

T1110 — Brute Force
Tactic: Credential Access
Anomalous Login Burst

Detects:

5 or more authentication events
Same source IP
Within 1 minute

Both successful and failed authentication events are considered.

MITRE ATT&CK:

T1110 — Brute Force
Tactic: Credential Access
Configurable Detection Thresholds

Detection thresholds are separated from the detection engine in:

src/config.py

This allows detection behavior to be modified without changing the core detection logic.

Current configuration includes:

Brute-force thresholds and time windows
Success-after-failures thresholds
Password spraying thresholds
Credential stuffing thresholds
Multiple-account targeting thresholds
Anomalous login burst thresholds
Privileged account definitions

Default privileged accounts:

admin
administrator
root

Privileged account targeting can increase alert severity.

Risk Classification

Failed-login activity is classified as:

Failed Attempts	Risk
0–2	LOW
3–4	MEDIUM
5+	HIGH

Advanced detections can also assign severity according to attack behavior and whether privileged accounts are targeted.

MITRE ATT&CK Mapping

Detections include MITRE ATT&CK metadata such as:

Technique ID
Technique name
Tactic

Examples:

Detection	Technique
Brute Force	T1110
Successful Login After Failures	T1110
Password Spraying	T1110.003
Credential Stuffing	T1110.004
Multiple Account Targeting	T1110
Anomalous Login Burst	T1110
SQLite Incident Management

Detected activity can be stored as incidents inside:

security_logs.db

Incident information includes:

Incident ID
Source IP
Failed attempts
Targeted users
Risk level
Detection type
Alert description
MITRE ATT&CK metadata
Incident status
Analyst notes
Creation timestamp
Update timestamp
Event start
Event end
Incident fingerprint
Incident Status Workflow

Supported incident statuses:

NEW
INVESTIGATING
RESOLVED
FALSE_POSITIVE

Every status change can record:

Previous status
New status
Analyst
Timestamp

This creates a persistent investigation history similar to a basic SOC case-management workflow.

Analyst Notes

Multiple analyst notes can be attached to each incident.

Each note stores:

Incident ID
Note content
Analyst
Creation timestamp

This allows investigation activity to remain associated with the incident.

Incident Fingerprinting

Version 3 includes SHA-256 incident fingerprinting.

Fingerprints are generated using security-event characteristics including:

Source IP
Detection information
Alert data
Event timestamps

This helps prevent identical detections from repeatedly creating duplicate incidents when the same log data is analyzed again.

CSV Security Reporting

The analyzer generates:

reports/suspicious_report.csv

The advanced CSV report contains:

Detection type
IP address
Targeted users
User count
Failed attempts
Successful logins
Event count
Severity
Alert
MITRE Technique ID
MITRE Technique Name
MITRE Tactic
Event start timestamp
Event end timestamp

Each advanced detection is exported as an individual report row.

FastAPI REST API

Version 3 introduces a REST API built with FastAPI.

Start the API with:

python -m uvicorn src.api:app --reload

Then open:

http://127.0.0.1:8000/
API Endpoints
Dashboard
GET /

Serves the Mini SIEM web dashboard.

API Information
GET /api

Returns application information and API status.

Health Check
GET /health
List Incidents
GET /incidents

Returns all stored incidents.

Get Specific Incident
GET /incidents/{incident_id}

Example:

GET /incidents/12
Incident Status History
GET /incidents/{incident_id}/status-history

Returns the complete status-change history for an incident.

Update Incident Status
PATCH /incidents/{incident_id}/status

Example request:

{
  "status": "INVESTIGATING",
  "analyst": "Stelios"
}
Get Analyst Notes
GET /incidents/{incident_id}/notes
Add Analyst Note
POST /incidents/{incident_id}/notes

Example:

{
  "note": "Investigated suspicious authentication activity",
  "analyst": "Stelios"
}
Swagger API Documentation

FastAPI automatically provides interactive API documentation.

Start the server and visit:

http://127.0.0.1:8000/docs
Mini SIEM Web Dashboard

Version 3 includes a browser-based SOC-style dashboard.

Features include:

API health indicator
Total incident counter
High-risk incident counter
New incident counter
Investigating incident counter
Resolved incident counter
Incident search
Risk filtering
Status filtering
Incident table
MITRE ATT&CK information
Incident details panel
Status updates
Analyst identification
Analyst note creation
Status-history viewer
Analyst-note history

The dashboard communicates directly with the FastAPI backend.

Sigma-Compatible Detection Rules

The project contains Sigma-compatible detection and correlation rules inside:

rules/

Current rules:

rules/
├── anomalous_login_burst.yml
├── brute_force.yml
├── credential_stuffing.yml
├── multiple_account_targeting.yml
├── password_spraying.yml
└── success_after_failures.yml

The rules use Sigma correlation concepts such as:

event_count
value_count
temporal
temporal_ordered
group-by
time-based correlation windows

These rules provide portable detection-engineering representations of the Python detection logic.

Automated Tests

Version 3 includes automated tests using Python's built-in unittest framework.

Run:

python -m unittest tests/test_detector.py

Current test coverage includes:

Risk classification
Successful login after failures
Brute-force detection
Password spraying
Credential stuffing
Multiple-account targeting
Anomalous login bursts

Expected output:

.......
----------------------------------------------------------------------
Ran 7 tests

OK
Project Structure
security-log-analyzer/
│
├── dashboard/
│   └── index.html
│
├── logs/
│   └── auth.log
│
├── reports/
│   └── suspicious_report.csv
│
├── rules/
│   ├── anomalous_login_burst.yml
│   ├── brute_force.yml
│   ├── credential_stuffing.yml
│   ├── multiple_account_targeting.yml
│   ├── password_spraying.yml
│   └── success_after_failures.yml
│
├── src/
│   ├── api.py
│   ├── config.py
│   ├── database.py
│   ├── detector.py
│   ├── main.py
│   ├── parser.py
│   └── reporter.py
│
├── tests/
│   └── test_detector.py
│
├── README.md
├── requirements.txt
└── security_logs.db
Installation

Clone the repository:

git clone https://github.com/stelaras36/security-log-analyzer.git

Enter the project directory:

cd security-log-analyzer

Install dependencies:

python -m pip install -r requirements.txt
Running the Log Analyzer

From the project root:

python src/main.py

The analyzer will:

Read authentication logs
Parse authentication events
Run security detections
Calculate risk
Map alerts to MITRE ATT&CK
Generate the CSV report
Store incidents in SQLite
Prevent duplicate incidents using fingerprinting
Display stored incidents and investigation history
Running the Mini SIEM

Start the FastAPI application:

python -m uvicorn src.api:app --reload

Open the dashboard:

http://127.0.0.1:8000/

Open Swagger API documentation:

http://127.0.0.1:8000/docs
Technology Stack
Python
FastAPI
Uvicorn
SQLite
HTML
CSS
JavaScript
REST API
Sigma detection rules
MITRE ATT&CK
Python unittest
Git / GitHub
Development Evolution
Version 1

Initial authentication log analyzer.

Features included:

Failed-login parsing
Failed attempts by IP
Basic risk classification
CSV reporting
Successful-login-after-failures detection
Version 2

Added persistent incident storage using SQLite.

Features included:

SQLite incident database
Persistent detection records
Expanded security incident information
Version 3 — Mini SIEM

Version 3 transforms the project into a small SOC-style security monitoring platform.

Added:

Time-based brute-force detection
Password spraying detection
Credential stuffing heuristic
Multiple-account targeting
Anomalous login bursts
MITRE ATT&CK mapping
Incident status workflow
Status history
Multiple analyst notes
Analyst attribution
Incident timestamps
Incident fingerprinting
Duplicate prevention
Configurable detection thresholds
Advanced CSV reporting
Automated tests
FastAPI REST API
Swagger documentation
Interactive Mini SIEM dashboard
Dashboard incident management
Sigma-compatible correlation rules
Security Engineering Concepts Demonstrated

This project demonstrates practical implementation of:

Log parsing
Detection engineering
Authentication attack detection
Time-window correlation
Behavioral security analytics
SOC alert triage concepts
Incident management
Security case history
MITRE ATT&CK mapping
Sigma correlation rules
Incident deduplication
REST API development
SQLite persistence
Security reporting
Automated security testing
Analyst workflow design
Disclaimer

This project is intended for educational, portfolio, and defensive cybersecurity purposes.

Credential-stuffing detection is heuristic because the analyzed authentication logs do not contain information proving that credentials originated from a previously compromised credential set.

The project is not intended to replace a production SIEM, EDR, IAM monitoring platform, or enterprise security operations environment.

Author

Stelios Kyrikos

BSc (Hons) Computer Science — First Class Honours

Cybersecurity / Software Development Portfolio Project

GitHub: stelaras36

Version

Security Log Analyzer v3.0 — Mini SIEM