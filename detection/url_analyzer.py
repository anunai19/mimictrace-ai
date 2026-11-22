import re
import ipaddress
from urllib.parse import urlsplit


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "signin",
    "banking"
]


def analyze_url(url):
    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Please enter a valid HTTP or HTTPS URL.")

    hostname = parsed.hostname.lower()

    try:
        ipaddress.ip_address(hostname)
        uses_ip_address = 1
    except ValueError:
        uses_ip_address = 0

    full_url = url.lower()

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(parsed.path),
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "at_symbol_count": url.count("@"),
        "digit_count": sum(char.isdigit() for char in url),
        "uses_https": int(parsed.scheme == "https"),
        "uses_ip_address": uses_ip_address,
        "suspicious_keyword_count": sum(
            word in full_url for word in SUSPICIOUS_WORDS
        )
    }

    return {
        "normalized_url": url,
        "hostname": hostname,
        "features": features
    }
