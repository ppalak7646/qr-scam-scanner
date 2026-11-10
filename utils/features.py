
import re
import math
import ipaddress
from urllib.parse import urlparse

import tldextract

# Offline extraction: does not download suffix lists
extract_domain = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure",
    "update", "password", "banking", "confirm",
    "signin", "wallet", "payment", "free",
    "bonus", "claim", "prize"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "shorturl.at"
]


def calculate_entropy(text):
    if not text:
        return 0.0

    entropy = 0.0

    for char in set(text):
        probability = text.count(char) / len(text)
        entropy -= probability * math.log2(probability)

    return entropy


def extract_url_features(url):

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty")

    url = url.strip()

    # Reject unsupported URL formats
    if len(url) > 2048:
        raise ValueError("URL is too long")

    if any(ord(char) < 32 for char in url):
        raise ValueError("URL contains invalid control characters")

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    lower_url = url.lower()

    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    extracted = extract_domain(hostname)

    features = {
        "url_length": len(url),

        "hostname_length": len(hostname),

        "path_length": len(parsed.path),

        "query_length": len(parsed.query),

        "num_dots": url.count("."),

        "num_hyphens": url.count("-"),

        "num_underscores": url.count("_"),

        "num_digits": sum(c.isdigit() for c in url),

        "num_special_chars": sum(
            not c.isalnum() for c in url
        ),

        "has_https": int(parsed.scheme.lower() == "https"),

        "has_http": int(parsed.scheme.lower() == "http"),

        "has_ip_address": is_ip,

        "has_at_symbol": int("@" in url),

        "has_double_slash_redirect": int(
            "//" in parsed.path
        ),

        "subdomain_count": (
            len(extracted.subdomain.split("."))
            if extracted.subdomain else 0
        ),

        "has_suspicious_keyword": int(
            any(word in lower_url for word in SUSPICIOUS_WORDS)
        ),

        "is_shortened_url": int(
            hostname.lower() in SHORTENERS
        ),

        "url_entropy": calculate_entropy(url),

        "has_fragment": int(bool(parsed.fragment)),

        "domain_length": len(extracted.domain),

        "has_valid_domain_suffix": int(bool(extracted.suffix))
    }

    return features  

