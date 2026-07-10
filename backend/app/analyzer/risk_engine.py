def calculate_risk(
    indicators,
    threat_intel
):

    risk = 0
    reasons = []


    # URLs
    if indicators.get("urls"):
        risk += 10
        reasons.append(
            "URL detected"
        )


    # IPs
    if indicators.get("ips"):
        risk += 10
        reasons.append(
            "IP address detected"
        )


    # Keywords
    text = indicators.get(
        "text",
        ""
    ).lower()


    keywords = [
        "urgent",
        "password",
        "verify",
        "login",
        "reset",
        "suspended"
    ]


    for keyword in keywords:

        if keyword in text:
            risk += 10
            reasons.append(
                f"Suspicious keyword: {keyword}"
            )


    # Threat Intel
    for item in threat_intel:

        if item.get("provider") == "VirusTotal":

            if item.get("malicious", 0) > 0:
                risk += 40
                reasons.append(
                    "VirusTotal malicious detection"
                )


        if item.get("provider") == "AbuseIPDB":

            if item.get("abuse_score", 0) > 50:
                risk += 40
                reasons.append(
                    "AbuseIPDB reputation warning"
                )


    if risk >= 70:
        verdict = "PHISHING"

    elif risk >= 40:
        verdict = "SUSPICIOUS"

    else:
        verdict = "LOW RISK"


    return {
        "risk_score": min(risk,100),
        "verdict": verdict,
        "reasons": reasons
    }
