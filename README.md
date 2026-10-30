
# Phishy

Automated phishing email detection and incident creation system.

Phishy monitors incoming emails, analyzes them for phishing indicators, checks suspicious URLs/IPs/domains using threat intelligence services, calculates a risk score, stores the results, and automatically creates a Jira incident when a phishing email is detected.

---

# Overview

The workflow:

```

Gmail
|
v
n8n Automation
|
v
FastAPI Backend
|
+--> Extract Indicators
|
+--> Threat Intelligence
|
+--> Risk Analysis
|
+--> PostgreSQL Storage
|
v
Phishing Detection Result
|
v
Jira Incident Creation

```

---

# Features

- Automatic email monitoring through Gmail
- Phishing email analysis
- URL extraction
- Domain extraction
- IP extraction
- Threat intelligence enrichment
- Risk scoring system
- PostgreSQL database storage
- Automatic incident creation in Jira
- Dockerized deployment
- n8n workflow automation

---

<img width="8889" height="5626" alt="diagram (3)" src="https://github.com/user-attachments/assets/0b900b0a-d985-4273-8325-7d887977a461" />

---
# Technologies

## Backend

- FastAPI
- SQLAlchemy
- Alembic
- PostgreSQL

## Automation

- n8n

## Threat Intelligence

- VirusTotal API
- AbuseIPDB API

## Incident Management

- Jira

## Infrastructure

- Docker
- Docker Compose

---

# Project Structure

```

phishy/

├── backend/
│
│   ├── app/
│   │
│   │   ├── analyzer/
│   │   │   ├── analyzer.py
│   │   │   └── risk_engine.py
│   │   │
│   │   ├── threat_intel/
│   │   │   └── threat_intel.py
│   │   │
│   │   ├── services/
│   │   │   └── email_service.py
│   │   │
│   │   ├── models.py
│   │   └── main.py
│   │
│   ├── migrations/
│   ├── alembic.ini
│   ├── Dockerfile
│   └── requirements.txt
│
├── docker/
│
│   └── docker-compose.yml
│
└── README.md

````

---

# Installation

## Clone Repository

```bash
git clone <repository-url>

cd phishy
````

---

# Environment Variables

Create an environment file:

```
VIRUSTOTAL_API_KEY=

ABUSEIPDB_API_KEY=

N8N_INCIDENT_WEBHOOK=
```

---

# Running With Docker

Start services:

```bash
docker compose up -d
```

Check containers:

```bash
docker ps
```

Expected containers:

```
phishy-api
phishy-postgres
phishy-n8n
```

---

# Database Migration

Run inside backend container:

```bash
alembic upgrade head
```

Create a new migration:

```bash
alembic revision --autogenerate -m "migration name"
```

---

# Backend API

## Analyze Email

Endpoint:

```
POST /emails
```

Example request:

```json
{
  "sender_email": "attack@example.com",
  "receiver_email": "employee@test.com",
  "subject": "Urgent account verification",
  "body": "Click http://185.220.101.15/login",
  "message_id": "test-001"
}
```

---

# Example Response

```json
{
  "email_id": 101,
  "indicators": {
    "urls": [
      "http://185.220.101.15/login"
    ],
    "ips": [
      "185.220.101.15"
    ],
    "domains": []
  },
  "threat_intel": [],
  "risk": {
    "risk_score": 95,
    "verdict": "PHISHING",
    "reasons": [
      "Suspicious URL detected",
      "Suspicious IP detected"
    ]
  }
}
```

---

# Risk Engine

The system evaluates:

* Suspicious URLs
* Malicious IP addresses
* Suspicious domains
* Credential harvesting keywords
* Urgency language
* Threat intelligence results

Example:

```
Risk Score: 95

Verdict: PHISHING
```

---

# n8n Workflow

Final workflow:

```
Gmail Trigger

↓

Get Message

↓

HTTP Request
(FastAPI)

↓

IF

risk.verdict == PHISHING

↓

Edit Fields

↓

Jira Create Issue
```

---

# Jira Integration

When a phishing email is detected, a Jira issue is automatically created.

Example:

```
Title:

PHISHING EMAIL DETECTED


Description:

Email ID: 101

Risk Score: 95

Verdict: PHISHING

Reasons:
- Suspicious URL detected
- Malicious IP detected
```

---

# Testing

Send an email containing:

```
Subject:
Urgent account verification


Body:

Your account will be disabled.

Verify your password immediately:

http://185.220.101.15/login
```

Expected result:

```
Gmail
 |
 n8n
 |
 FastAPI
 |
 PHISHING detected
 |
 Jira ticket created
```

---

# Database Tables

## emails

Stores received emails.

---

## email_urls

Stores extracted URLs.

---

## email_domains

Stores extracted domains.

---

## email_ips

Stores extracted IP addresses.

---

## threat_analysis

Stores risk analysis results.

---

## incidents

Stores phishing incidents.

---

# Troubleshooting

## n8n webhook not found

Make sure the workflow is published/active.

---

## Jira Summary required error

Check Jira node mapping:

```
Summary:
{{$json.alert}}
```

---

## Gmail Get Message error

The message ID must come from the Gmail Trigger output.

---

## Alembic revision missing

If migration history is broken:

Create a new baseline migration and upgrade:

```bash
alembic revision --autogenerate -m "baseline"

alembic upgrade head
```

---

# Current Status

Completed:

* Email ingestion
* Phishing analysis
* Indicator extraction
* Threat intelligence
* Risk scoring
* Database storage
* n8n automation
* Jira incident creation

---

# Future Improvements

Possible additions:

* Duplicate incident detection
* Email attachment scanning
* User notification system
* Dashboard
* Machine learning phishing classifier
* More threat intelligence providers
