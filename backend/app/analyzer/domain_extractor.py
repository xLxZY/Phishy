import re


def extract_domains(text):

    if not text:
        return []

    pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

    domains = re.findall(pattern, text)

    return list(set(domains))
