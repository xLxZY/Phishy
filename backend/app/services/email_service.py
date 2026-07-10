import requests
import os


from sqlalchemy.orm import Session

from app.models import (
    Email,
    EmailURL,
    EmailDomain,
    EmailIP,
    ThreatAnalysis,
    Incident
)

from app.analyzer.analyzer import analyze_email
from app.analyzer.risk_engine import calculate_risk
from app.threat_intel.threat_intel import enrich_indicator


# ==========================================
# Save Email
# ==========================================

def save_email(email_data, db):

    email = Email(
        sender_email=email_data.sender_email,
        receiver_email=email_data.receiver_email,
        subject=email_data.subject,
        body=email_data.body,
        message_id=email_data.message_id
    )

    db.add(email)
    db.commit()
    db.refresh(email)

    return email



# ==========================================
# Extract Indicators
# ==========================================

def extract_indicators(email):

    indicators = analyze_email(
        email.body
    )

    indicators["text"] = (
        email.subject +
        " " +
        email.body
    )

    return indicators



# ==========================================
# Save Indicators
# ==========================================

def save_indicators(email_id, indicators, db):

    for url in indicators["urls"]:

        db.add(
            EmailURL(
                email_id=email_id,
                url=url
            )
        )


    for domain in indicators["domains"]:

        db.add(
            EmailDomain(
                email_id=email_id,
                domain=domain
            )
        )


    for ip in indicators["ips"]:

        db.add(
            EmailIP(
                email_id=email_id,
                ip_address=ip
            )
        )


    db.commit()



# ==========================================
# Threat Intelligence
# ==========================================

def get_threat_intel(indicators):

    results = []


    # Domain intelligence

    for domain in indicators["domains"]:

        vt, whois = enrich_indicator(
            "domain",
            domain
        )

        results.append(vt)
        results.append(whois)



    # IP intelligence

    for ip in indicators["ips"]:

        abuse = enrich_indicator(
            "ip",
            ip
        )

        results.append(abuse)


    return results



# ==========================================
# Save Threat Analysis + Create Incident
# ==========================================

def save_analysis(
    email_id,
    risk,
    db: Session
):

    analysis = ThreatAnalysis(

        email_id=email_id,

        risk_score=risk["risk_score"],

        verdict=risk["verdict"],

        ai_reason=", ".join(
            risk["reasons"]
        )
    )


    db.add(analysis)



    # Create incident only for phishing

    if risk["verdict"] == "PHISHING":

        incident = Incident(

            email_id=email_id,

            severity="HIGH",

            title="Phishing email detected",

            description=", ".join(
                risk["reasons"]
            ),

            status="OPEN"
        )


        db.add(incident)

        send_incident_to_n8n(
            email_id,
            risk
        )



    db.commit()

    db.refresh(analysis)


    return analysis


def send_incident_to_n8n(email_id, risk):

    webhook_url = os.getenv(
        "N8N_INCIDENT_WEBHOOK"
    )

    if not webhook_url:
        return {
            "status": "missing_webhook"
        }


    payload = {

        "email_id": email_id,

        "severity": "HIGH",

        "verdict": risk["verdict"],

        "risk_score": risk["risk_score"],

        "reasons": risk["reasons"]

    }


    response = requests.post(
        webhook_url,
        json=payload,
        timeout=10
    )


    return {
        "status": "sent",
        "code": response.status_code
    }

# ==========================================
# Main Email Pipeline
# ==========================================

def process_email(email_data, db):


    # 1. Store email

    email = save_email(
        email_data,
        db
    )



    # 2. Extract URLs/IPs/Domains

    indicators = extract_indicators(
        email
    )



    # 3. Save extracted indicators

    save_indicators(
        email.id,
        indicators,
        db
    )



    # 4. Threat Intelligence APIs

    threat_intel = get_threat_intel(
        indicators
    )



    # 5. Calculate risk

    risk = calculate_risk(
        indicators,
        threat_intel
    )



    # 6. Save analysis + incident if phishing

    save_analysis(
        email.id,
        risk,
        db
    )



    return {

        "email_id": email.id,

        "indicators": indicators,

        "threat_intel": threat_intel,

        "risk": risk

    }
