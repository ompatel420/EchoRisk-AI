"""
Input validation and sanitization utilities for EchoRisk AI.
Ensures emails are well-formed, normalized, and safely handled.
"""
import re
import socket
from typing import Tuple, Optional

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

DOMAIN_ALIASES = {
    "protonmial.com": "proton.me",
    "protonmai.com": "proton.me",
    "protonmail.com": "proton.me",
    "proton.cm": "proton.me"
}

POPULAR_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "icloud.com", "proton.me", "protonmail.com", "aol.com", "zoho.com"
]

ALLOWED_TEST_DOMAINS = {"example.com", "example.org", "example.net", "test.com", "localhost"}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates edit distance between two strings."""
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        new_row = [i + 1] + [0] * len(s2)
        for j, c2 in enumerate(s2):
            new_row[j + 1] = min(row[j + 1] + 1, new_row[j] + 1, row[j] + (c1 != c2))
        row = new_row
    return row[-1]


def check_domain_dns(domain: str) -> Tuple[bool, Optional[str]]:
    """Checks if a domain exists in DNS with fast popular-domain bypass and offline fail-open."""
    d = domain.lower()
    if d in ALLOWED_TEST_DOMAINS or d in POPULAR_DOMAINS:
        return True, None
    try:
        socket.setdefaulttimeout(1.5)
        socket.getaddrinfo(domain, None)
        return True, None
    except socket.gaierror:
        try:
            socket.getaddrinfo("dns.google", None)
            return False, f"The email domain '@{domain}' does not exist."
        except Exception:
            return True, None
    except Exception:
        return True, None


def validate_and_normalize_email(raw_email: Optional[str]) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """
    Validates and normalizes user email input.
    Returns: (is_valid, normalized_email, error_message, suggestion)
    """
    if not raw_email or not isinstance(raw_email, str) or not raw_email.strip():
        return False, None, "Please provide an email address.", None

    cleaned = raw_email.strip()
    if len(cleaned) > 254:
        return False, None, "Email address exceeds maximum allowed length of 254 characters.", None

    if "@" not in cleaned or cleaned.count("@") != 1:
        return False, None, "Please enter a valid email address with a single '@'.", None

    user, domain = [part.strip() for part in cleaned.split("@", 1)]
    domain = domain.lower()

    if not user or len(user) > 64 or user.startswith(".") or user.endswith(".") or ".." in user:
        return False, None, "Email username is invalid or exceeds 64 characters.", None

    if not domain or "." not in domain or domain.startswith(".") or domain.endswith(".") or ".." in domain:
        return False, None, "Email domain appears invalid (e.g. name@domain.com).", None

    tld = domain.split(".")[-1]
    if not re.match(r"^[a-zA-Z]{2,}$", tld):
        return False, None, f"Invalid domain extension '.{tld}'. Please enter a valid email.", None

    # Check for domain alias or typo suggestion
    if domain in DOMAIN_ALIASES:
        suggested = f"{user}@{DOMAIN_ALIASES[domain]}"
        return False, None, f"Invalid email domain '@{domain}'. Did you mean '{suggested}'?", suggested

    if domain not in POPULAR_DOMAINS and domain not in ALLOWED_TEST_DOMAINS:
        for popular in POPULAR_DOMAINS:
            if levenshtein_distance(domain, popular) <= 2:
                suggested = f"{user}@{popular}"
                return False, None, f"Invalid email domain '@{domain}'. Did you mean '{suggested}'?", suggested

    if not EMAIL_REGEX.match(cleaned):
        return False, None, "Please enter a valid email address (e.g., name@domain.com).", None

    is_dns_valid, dns_err = check_domain_dns(domain)
    if not is_dns_valid:
        return False, None, dns_err, None

    return True, f"{user}@{domain}".lower(), None, None


def mask_email(email: str) -> str:
    """Masks an email for privacy (e.g. 'alexander@example.com' -> 'a***r@example.com')."""
    if not email or "@" not in email:
        return "hidden@anonymous"
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        masked = user[0] + "*"
    else:
        stars = "**" if len(user) <= 4 else "***"
        masked = f"{user[0]}{stars}{user[-1]}"
    return f"{masked}@{domain}"
