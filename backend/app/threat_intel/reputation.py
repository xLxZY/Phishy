def calculate_reputation(
    vt_score=0,
    abuse_score=0,
    domain_age_days=9999
):

    risk = 0


    if vt_score > 5:
        risk += 40


    if abuse_score > 50:
        risk += 40


    if domain_age_days < 30:
        risk += 20


    if risk >= 70:
        verdict = "HIGH RISK"

    elif risk >= 40:
        verdict = "SUSPICIOUS"

    else:
        verdict = "LOW RISK"


    return {
        "risk_score": risk,
        "verdict": verdict
    }
