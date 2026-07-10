from .url_extractor import extract_urls
from .ip_extractor import extract_ips
from .domain_extractor import extract_domains


def analyze_email(body):

    urls = extract_urls(body)

    ips = extract_ips(body)

    domains = extract_domains(body)


    return {
        "urls": urls,
        "ips": ips,
        "domains": domains
    }
