import os
import requests


# ==========================
# VirusTotal
# ==========================

def check_virustotal_domain(domain):

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "provider": "VirusTotal",
            "status": "missing_api_key"
        }


    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": api_key
    }


    response = requests.get(
        url,
        headers=headers,
        timeout=10
    )


    if response.status_code != 200:
        return {
            "provider": "VirusTotal",
            "status": "error",
            "code": response.status_code
        }


    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]


    return {
        "provider": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0)
    }



# ==========================
# AbuseIPDB
# ==========================

def check_abuseipdb(ip):

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "provider": "AbuseIPDB",
            "status": "missing_api_key"
        }


    url = "https://api.abuseipdb.com/api/v2/check"


    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }


    params = {
        "ipAddress": ip
    }


    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=10
    )


    if response.status_code != 200:
        return {
            "provider": "AbuseIPDB",
            "status": "error",
            "code": response.status_code
        }


    data = response.json()


    result = data["data"]


    return {
        "provider": "AbuseIPDB",
        "abuse_score": result.get(
            "abuseConfidenceScore",
            0
        ),
        "country": result.get(
            "countryCode"
        ),
        "isp": result.get(
            "isp"
        )
    }



# ==========================
# WHOIS placeholder
# ==========================

def check_whois(domain):

    #  will add real WHOIS lookup later

    return {
        "domain": domain,
        "age_days": None,
        "registrar": None
    }



# ==========================
# Main TI Function
# ==========================

def enrich_indicator(
    indicator_type,
    value
):

    if indicator_type == "domain":

        return check_virustotal_domain(value), check_whois(value)


    if indicator_type == "ip":

        return check_abuseipdb(value)


    return {
        "status": "unsupported"
    }
