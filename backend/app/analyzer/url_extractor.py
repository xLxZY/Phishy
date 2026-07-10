import re


def extract_urls(text):

    if not text:
        return []

    pattern = r'https?://[^\s]+'

    urls = re.findall(pattern, text)

    return urls
