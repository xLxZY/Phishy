import re


def extract_ips(text):

    if not text:
        return []

    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    ips = re.findall(pattern, text)

    return ips
