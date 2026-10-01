"""
Breach Intelligence Service for EchoRisk AI.
Integrates with the official XposedOrNot API to verify whether an email has appeared
in verified data breaches, with normalization and demo mock support.
"""
import os
import logging
from datetime import datetime
from typing import Dict, Any, List
import requests

logger = logging.getLogger(__name__)

XON_BASE_URL = os.environ.get("XPOSEDORNOT_API_URL", "https://api.xposedornot.com/v1")
MOCK_MODE = os.environ.get("MOCK_MODE", "false").lower() in ("true", "1", "yes")

_BREACH_METADATA_CACHE: Dict[str, Dict[str, Any]] = {}

# Known common breach information fallback directory
KNOWN_BREACHES: Dict[str, Dict[str, Any]] = {
    "adobe": {
        "title": "Adobe Systems", "domain": "adobe.com", "date": "2013-10-04",
        "pwn_count": 152445165, "industry": "Creative Software",
        "logo": "https://xposedornot.com/static/logos/Adobe.png",
        "description": "In October 2013, Adobe suffered a massive data breach exposing 153 million user accounts.",
        "exposed_data": ["Email Addresses", "Password Hints", "Passwords", "Usernames"]
    },
    "linkedin": {
        "title": "LinkedIn", "domain": "linkedin.com", "date": "2016-05-18",
        "pwn_count": 164611595, "industry": "Professional Network",
        "logo": "https://xposedornot.com/static/logos/LinkedIn.png",
        "description": "In 2012 (released 2016), millions of LinkedIn member credentials were compromised online.",
        "exposed_data": ["Email Addresses", "Passwords", "Job Titles"]
    },
    "canva": {
        "title": "Canva", "domain": "canva.com", "date": "2019-05-24",
        "pwn_count": 137000000, "industry": "Graphic Design Platform",
        "logo": "https://xposedornot.com/static/logos/Canva.png",
        "description": "In May 2019, Canva suffered a security incident compromising account names and passwords.",
        "exposed_data": ["Email Addresses", "Names", "Passwords", "Locations"]
    },
    "memechat": {
        "title": "MemeChat", "domain": "memechat.app", "date": "2022-07-01",
        "pwn_count": 4512118, "industry": "Entertainment",
        "logo": "https://xposedornot.com/static/logos/MemeChat.png",
        "description": "MemeChat endured a breach in 2022, exposing 7.4 million records including emails and usernames.",
        "exposed_data": ["Email Addresses", "Usernames"]
    },
    "dropbox": {
        "title": "Dropbox", "domain": "dropbox.com", "date": "2016-08-31",
        "pwn_count": 68648009, "industry": "Cloud Storage & Collaboration",
        "logo": "https://xposedornot.com/static/logos/Dropbox.png",
        "description": "Dropbox was breached with user emails and hashed/salted passwords leaked.",
        "exposed_data": ["Email Addresses", "Passwords"]
    },
    "myfitnesspal": {
        "title": "MyFitnessPal", "domain": "myfitnesspal.com", "date": "2018-02-15",
        "pwn_count": 144000000, "industry": "Health & Fitness",
        "logo": "https://xposedornot.com/static/logos/MyFitnessPal.png",
        "description": "MyFitnessPal app data was breached exposing usernames and hashed passwords.",
        "exposed_data": ["Email Addresses", "IP Addresses", "Passwords", "Usernames"]
    }
}

def _build_mock_entry(b_key: str) -> Dict[str, Any]:
    b = KNOWN_BREACHES.get(b_key, {})
    return {
        "breach_id": b.get("title", b_key),
        "breach_title": b.get("title", b_key),
        "domain": b.get("domain", ""),
        "logo_url": b.get("logo", ""),
        "industry": b.get("industry", "Web & Cloud Platform"),
        "breach_date": b.get("date", "Unknown Date"),
        "pwn_count": b.get("pwn_count", 0),
        "description": b.get("description", ""),
        "exposed_data": b.get("exposed_data", ["Email Addresses"]),
        "reference_url": f"/breach/{b.get('title', b_key)}"
    }

DEMO_MOCK_DATA: Dict[str, List[Dict[str, Any]]] = {
    "compromised@example.com": [_build_mock_entry("linkedin"), _build_mock_entry("adobe"), _build_mock_entry("canva")],
    "safe@example.com": []
}


def _get_request_headers() -> Dict[str, str]:
    return {
        "User-Agent": "EchoRisk-AI-Breach-Tracker/1.0 (College-Cybersecurity-Project)",
        "Accept": "application/json"
    }


def fetch_all_breaches_catalog() -> Dict[str, Dict[str, Any]]:
    """Fetches the catalog of known data breaches from XposedOrNot."""
    global _BREACH_METADATA_CACHE
    if _BREACH_METADATA_CACHE:
        return _BREACH_METADATA_CACHE

    try:
        resp = requests.get(f"{XON_BASE_URL}/breaches", headers=_get_request_headers(), timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            items = data if isinstance(data, list) else (data.get("exposedBreaches") or data.get("breaches") or [])
            for item in items:
                b_id = str(item.get("breachID") or item.get("breach_id") or item.get("name", "")).lower().strip()
                if b_id:
                    _BREACH_METADATA_CACHE[b_id] = item
    except Exception as e:
        logger.warning(f"Could not refresh XposedOrNot breach catalog: {e}")
    
    return _BREACH_METADATA_CACHE


def _detect_industry(key: str) -> str:
    categories = {
        "Entertainment": ("meme", "chat", "game", "video", "music", "play", "wattpad"),
        "Creative Software": ("adobe", "canva", "design", "figma"),
        "Professional Network": ("linkedin", "job", "career", "work"),
        "Health & Fitness": ("fitness", "health", "diet", "gym"),
        "Social Network": ("twitter", "face", "insta", "social", "reddit")
    }
    for cat, words in categories.items():
        if any(w in key for w in words):
            return cat
    return "Web & Cloud Platform"


def _normalize_breach_detail(breach_id: str, catalog: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    clean_id = breach_id.strip()
    key = clean_id.lower()
    meta = catalog.get(key) or {}
    fb = KNOWN_BREACHES.get(key, {})

    title = meta.get("breachID") or meta.get("breach_title") or meta.get("title") or fb.get("title") or clean_id
    domain = meta.get("domain") or fb.get("domain") or f"{key.replace(' ', '')}.com"
    raw_date = meta.get("breachedDate") or meta.get("breach_date") or meta.get("date") or fb.get("date") or "Unknown Date"
    date_str = str(raw_date).split("T")[0]
    pwn_count = meta.get("exposedRecords") or meta.get("pwn_count") or meta.get("records") or fb.get("pwn_count") or 0
    desc = meta.get("exposureDescription") or meta.get("description") or fb.get("description") or f"Data from {title} was identified in compromised records on public databases."
    industry = meta.get("industry") or meta.get("category") or fb.get("industry") or _detect_industry(key)
    logo_url = meta.get("logo") or fb.get("logo") or f"https://xposedornot.com/static/logos/{clean_id}.png"

    raw_exposed = meta.get("exposedData") or meta.get("exposed_data") or fb.get("exposed_data") or ["Email Addresses"]
    if isinstance(raw_exposed, str):
        exposed = [x.strip() for x in raw_exposed.split(";") if x.strip()]
    elif isinstance(raw_exposed, list):
        exposed = [str(x).strip() for x in raw_exposed]
    else:
        exposed = ["Email Addresses"]

    return {
        "breach_id": clean_id,
        "breach_title": title,
        "domain": domain,
        "logo_url": logo_url,
        "industry": industry,
        "breach_date": date_str,
        "pwn_count": pwn_count,
        "description": desc,
        "exposed_data": exposed,
        "reference_url": f"/breach/{clean_id}"
    }


def get_breach_detail(breach_identifier: str) -> Dict[str, Any]:
    """Retrieves and normalizes detailed metadata for a specific breach incident."""
    catalog = fetch_all_breaches_catalog()
    detail = _normalize_breach_detail(breach_identifier, catalog)

    exposed_lower = [str(x).lower() for x in detail.get("exposed_data", [])]
    has_pwd = any("password" in x or "hash" in x for x in exposed_lower)
    has_pii = any("phone" in x or "address" in x or "ssn" in x or "name" in x for x in exposed_lower)
    has_financial = any("card" in x or "bank" in x or "credit" in x for x in exposed_lower)

    if has_financial or (has_pwd and has_pii):
        risk_level, threat_score, threat_color = "Critical", 92, "#DC2626"
    elif has_pwd:
        risk_level, threat_score, threat_color = "High", 78, "#EA580C"
    elif has_pii:
        risk_level, threat_score, threat_color = "Moderate", 55, "#D97706"
    else:
        risk_level, threat_score, threat_color = "Low", 32, "#16A34A"

    pwn_count = detail.get("pwn_count", 0)
    try:
        formatted_count = f"{int(pwn_count):,}"
    except (ValueError, TypeError):
        formatted_count = str(pwn_count) if pwn_count else "Not Disclosed"

    domain = detail.get("domain") or "the platform"
    recommendations = []
    if has_pwd:
        recommendations.append(f"Change your password on {domain} immediately.")
        recommendations.append("If you reused this password on other accounts, update them with unique passphrases.")
    recommendations.append(f"Enable Multi-Factor Authentication (MFA / 2FA) on {domain} to block unauthorized logins.")
    if has_pii:
        recommendations.append(f"Watch out for targeted phishing emails or SMS messages impersonating {detail.get('breach_title', breach_identifier)}.")
    recommendations.extend([
        f"Audit recent active sessions and authorized third-party applications on {domain}.",
        "Regularly check your credentials on EchoRisk AI to detect newly discovered exposures early."
    ])

    years_ago = ""
    try:
        yr = int(str(detail.get("breach_date", "")).split("-")[0])
        diff = max(1, datetime.now().year - yr)
        years_ago = f"{diff} years ago" if diff > 1 else "1 year ago"
    except Exception:
        pass

    raw_ind = (detail.get("industry") or "Entertainment").lower()
    ind_map = {
        "entertainment": ("Entertainment", "entertainment"),
        "tech": ("Technology", "technology"),
        "social": ("Social Network", "social"),
        "health": ("Health & Fitness", "health"),
        "creative": ("Creative Software", "creative")
    }
    industry_name, industry_type = detail.get("industry", "General"), "general"
    for k, (name, itype) in ind_map.items():
        if k in raw_ind:
            industry_name, industry_type = name, itype
            break

    detail.update({
        "has_password_exposure": has_pwd,
        "has_pii": has_pii,
        "has_financial": has_financial,
        "risk_level": risk_level,
        "threat_score": threat_score,
        "threat_color": threat_color,
        "formatted_pwn_count": formatted_count,
        "recommendations": recommendations,
        "years_ago": years_ago,
        "industry": industry_name,
        "industry_type": industry_type
    })
    return detail


def _empty_breach_response(status: str = "success", message: str = "No matching breaches found in checked source.") -> Dict[str, Any]:
    return {
        "breach_count": 0, "breaches": [], "exposed_data_types": [],
        "has_password_exposure": False, "source": "XposedOrNot",
        "status": status, "message": message
    }


def check_email_breaches(normalized_email: str) -> Dict[str, Any]:
    """Queries XposedOrNot to detect data breaches for the given email address."""
    # 1. Demo / Mock Mode
    if MOCK_MODE or normalized_email in DEMO_MOCK_DATA:
        breaches = DEMO_MOCK_DATA.get(normalized_email, DEMO_MOCK_DATA["compromised@example.com"])
        data_types = sorted(list({item for b in breaches for item in b.get("exposed_data", [])}))
        has_pwd = any("password" in item.lower() for item in data_types)
        return {
            "breach_count": len(breaches),
            "breaches": breaches,
            "exposed_data_types": data_types,
            "has_password_exposure": has_pwd,
            "source": "XposedOrNot (Demo Mode)",
            "status": "success",
            "message": "Lookup completed via demonstration mock fixture."
        }

    # 2. Live API Request
    api_url = f"{XON_BASE_URL}/check-email/{normalized_email}"
    catalog = fetch_all_breaches_catalog()

    try:
        resp = requests.get(api_url, headers=_get_request_headers(), timeout=8)
        if resp.status_code == 404:
            return _empty_breach_response("success", "No matching breaches found in checked source.")
        if resp.status_code != 200:
            return _empty_breach_response("error", f"Breach provider responded with error code {resp.status_code}.")

        try:
            data = resp.json()
        except Exception:
            return _empty_breach_response("error", "Invalid response from breach intelligence provider.")

        if not isinstance(data, dict):
            return _empty_breach_response("success", "No matching breaches found in checked source.")

        raw_breaches = data.get("breaches", [])
        breach_names: List[str] = []
        if raw_breaches and isinstance(raw_breaches, list):
            first = raw_breaches[0]
            breach_names = [str(x).strip() for x in (first if isinstance(first, list) else raw_breaches) if x]

        if not breach_names:
            return _empty_breach_response("success", "No matching breaches found in checked source.")

        normalized_breaches = []
        all_data_types = set()
        has_password = False

        for name in breach_names:
            b_detail = _normalize_breach_detail(name, catalog)
            normalized_breaches.append(b_detail)
            for dt in b_detail["exposed_data"]:
                all_data_types.add(dt)
                if "password" in dt.lower():
                    has_password = True

        return {
            "breach_count": len(normalized_breaches),
            "breaches": normalized_breaches,
            "exposed_data_types": sorted(list(all_data_types)),
            "has_password_exposure": has_password,
            "source": "XposedOrNot",
            "status": "success",
            "message": f"Found {len(normalized_breaches)} verified breach entries."
        }

    except requests.exceptions.Timeout:
        return _empty_breach_response("error", "Breach database query timed out. Please try again in a few moments.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error querying XposedOrNot: {e}")
        return _empty_breach_response("error", "Unable to contact breach intelligence provider at this time.")
    except Exception as e:
        logger.error(f"Unexpected error processing breach data: {e}")
        return _empty_breach_response("error", "An unexpected error occurred while parsing breach information.")
