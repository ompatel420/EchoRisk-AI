"""
Claude AI Risk Reasoning Service for EchoRisk AI.
Translates verified breach facts into transparent risk explanations and actionable
defensive security recommendations without hallucinating breach events.
"""
import os
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")


def _generate_fallback_assessment(breach_facts: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic rule-based risk evaluation used when Claude API is unavailable."""
    count = breach_facts.get("breach_count", 0)
    has_pwd = breach_facts.get("has_password_exposure", False)
    data_types = breach_facts.get("exposed_data_types", [])

    if count == 0:
        return {
            "risk_level": "Low",
            "risk_score": 10,
            "short_summary": "No matching breaches were identified for this email in checked database sources.",
            "key_findings": [
                "No public breach records currently associate this address with compromised credentials.",
                "Zero password or sensitive profile exposures detected in checked logs."
            ],
            "exposed_categories": [],
            "recommended_actions": [
                "Maintain strong security hygiene with unique, 14+ character passwords on every service.",
                "Enable Multi-Factor Authentication (MFA / 2FA) on your primary email and financial accounts.",
                "Stay vigilant against spear-phishing messages requesting verification codes or urgent actions."
            ],
            "disclaimer": "This assessment indicates absence of records in checked breach collections, not immunity from all cyber threats.",
            "ai_powered": False,
            "fallback_used": True
        }

    score = min(98, 30 + min(count * 15, 45) + (25 if has_pwd else 0))
    if score >= 80 or (count >= 2 and has_pwd):
        risk_level = "Critical" if has_pwd and count >= 3 else "High"
    else:
        risk_level = "High" if has_pwd else "Moderate"

    findings = [f"Email identified in {count} documented security incident{'s' if count != 1 else ''}."]
    findings.append(
        "Credentials include confirmed exposure of passwords, hashes, or security hints." if has_pwd
        else "No direct password leakage flagged; exposure predominantly involves identifiers or metadata."
    )
    high_impact = [t for t in data_types if any(k in t.lower() for k in ["phone", "ip", "location", "financial", "credit"])]
    if high_impact:
        findings.append(f"Additional sensitive data fields leaked: {', '.join(high_impact[:3])}.")

    actions: List[str] = []
    if has_pwd:
        actions.extend([
            "Immediately change passwords on all services where this email or similar passwords are used.",
            "Enable app-based Multi-Factor Authentication (Authenticator App/Security Key) on your accounts.",
            "Review active login sessions and terminate unfamiliar connected devices."
        ])
    else:
        actions.extend([
            "Verify whether the affected services use shared or reused passwords and update them.",
            "Turn on Two-Factor Authentication (2FA) across critical online services."
        ])
    actions.extend([
        "Beware of phishing emails or SMS lures referencing leaked details (names, usernames, or phone numbers).",
        "Consider adopting a dedicated password manager to generate and store distinct, complex credentials."
    ])

    summary = (
        f"Your email address appeared in {count} known data breach{'es' if count != 1 else ''} "
        f"with {len(data_types)} exposed information categories. "
        f"{'Password material was leaked, representing elevated credential-stuffing risk.' if has_pwd else 'Identifiers were exposed, elevating susceptibility to targeted phishing.'}"
    )

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "short_summary": summary,
        "key_findings": findings,
        "exposed_categories": data_types,
        "recommended_actions": actions,
        "disclaimer": "Assessment derived via EchoRisk Rule Engine based on verified facts from breach records.",
        "ai_powered": False,
        "fallback_used": True
    }


def analyze_risk_with_claude(breach_facts: Dict[str, Any]) -> Dict[str, Any]:
    """Sends verified breach facts to Claude AI for clear risk reasoning with automatic fallback."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return _generate_fallback_assessment(breach_facts)

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        verified_payload = {
            "breach_count": breach_facts.get("breach_count", 0),
            "breaches_overview": [
                {"title": b.get("breach_title"), "date": b.get("breach_date"), "exposed_data": b.get("exposed_data")}
                for b in breach_facts.get("breaches", [])
            ],
            "exposed_categories": breach_facts.get("exposed_data_types", []),
            "has_password_exposure": breach_facts.get("has_password_exposure", False),
            "source": breach_facts.get("source", "XposedOrNot")
        }

        system_prompt = (
            "You are an expert cybersecurity risk advisor for EchoRisk AI. "
            "Analyze the verified breach facts provided and return a defensive, objective security report. "
            "RULES:\n"
            "1. ONLY reason over the supplied verified breach facts. DO NOT invent, hallucinate, or extrapolate new breaches or dates.\n"
            "2. Keep the tone calm, objective, educational, and professional.\n"
            "3. DO NOT output any passwords, hashes, malicious attack instructions, or personal insults.\n"
            "4. Provide strictly valid JSON with no markdown backticks, matching this exact schema:\n"
            '{"risk_level": "Low"|"Moderate"|"High"|"Critical", "risk_score": <1-100>, "short_summary": "<text>", '
            '"key_findings": ["<item>"], "exposed_categories": ["<item>"], "recommended_actions": ["<item>"], "disclaimer": "<text>"}'
        )

        message = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=600,
            temperature=0.2,
            system=system_prompt,
            messages=[{"role": "user", "content": f"Verified Breach Evidence:\n{json.dumps(verified_payload, indent=2)}"}]
        )

        raw_text = message.content[0].text.strip()
        if "{" in raw_text and "}" in raw_text:
            json_str = raw_text[raw_text.find("{"):raw_text.rfind("}") + 1]
        else:
            json_str = raw_text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        parsed = json.loads(json_str)
        parsed["ai_powered"] = True
        parsed["fallback_used"] = False
        return parsed

    except Exception as e:
        logger.error(f"Claude AI analysis error or unavailable: {e}. Falling back to rule engine.")
        fallback = _generate_fallback_assessment(breach_facts)
        fallback["ai_error_note"] = "EchoRisk AI reasoning temporarily unavailable. Served via deterministic security engine."
        return fallback
