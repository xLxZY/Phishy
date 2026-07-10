import os
import json
import requests


def ai_analyze_email(text):

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        return None


    prompt = f"""
You are a phishing email detection assistant.

Analyze this email text and decide if it is phishing.

Return ONLY valid JSON:

{{
    "phishing": true,
    "confidence": 90,
    "reason": "explanation"
}}

Email:

{text}
"""


    try:

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "gpt-4.1-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0
            },
            timeout=15
        )


        data = response.json()

        content = data["choices"][0]["message"]["content"]

        return json.loads(content)


    except Exception:

        return None



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

            if item.get("malicious",0) > 0:

                risk += 40

                reasons.append(
                    "VirusTotal malicious detection"
                )


        if item.get("provider") == "AbuseIPDB":

            if item.get("abuse_score",0) > 50:

                risk += 40

                reasons.append(
                    "AbuseIPDB reputation warning"
                )


    # AI layer

    ai_result = ai_analyze_email(text)


    if ai_result:


        if ai_result.get("phishing") is True:


            confidence = ai_result.get(
                "confidence",
                50
            )


            if confidence >= 80:

                risk += 40

                reasons.append(
                    "AI phishing detection: "
                    + ai_result.get(
                        "reason",
                        "Suspicious email behavior"
                    )
                )


    risk = min(
        risk,
        100
    )


    if risk >= 70:

        verdict = "PHISHING"


    elif risk >= 40:

        verdict = "SUSPICIOUS"


    else:

        verdict = "LOW RISK"



    return {

        "risk_score": risk,

        "verdict": verdict,

        "reasons": reasons

    }
