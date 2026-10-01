"""
Report Assembly Service for EchoRisk AI.
Combines verified breach records, risk assessments, and security guidance into
a comprehensive, user-friendly JSON payload.
"""
from datetime import datetime, timezone
from typing import Dict, Any

def assemble_final_report(
    masked_email: str,
    breach_facts: Dict[str, Any],
    ai_assessment: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Constructs the final normalized report structure sent to the frontend.
    """
    breach_count = breach_facts.get("breach_count", 0)
    has_breaches = breach_count > 0
    has_pwd = breach_facts.get("has_password_exposure", False)
    exposed_data_types = breach_facts.get("exposed_data_types", [])
    
    risk_level = ai_assessment.get("risk_level", "Low" if not has_breaches else "Moderate")
    risk_score = ai_assessment.get("risk_score", 10 if not has_breaches else 50)

    return {
        "status": "success",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email_masked": masked_email,
        "summary": {
            "breach_count": breach_count,
            "has_breaches": has_breaches,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "has_password_exposure": has_pwd,
            "exposed_data_types": exposed_data_types
        },
        "ai_analysis": {
            "risk_level": risk_level,
            "short_summary": ai_assessment.get("short_summary", "Report generated successfully."),
            "key_findings": ai_assessment.get("key_findings", []),
            "exposed_categories": ai_assessment.get("exposed_categories", exposed_data_types),
            "recommended_actions": ai_assessment.get("recommended_actions", []),
            "disclaimer": ai_assessment.get(
                "disclaimer",
                "Based on publicly documented breach records. Continuous cyber vigilance is recommended."
            ),
            "ai_powered": ai_assessment.get("ai_powered", False),
            "fallback_used": ai_assessment.get("fallback_used", False),
            "ai_error_note": ai_assessment.get("ai_error_note")
        },
        "breaches": breach_facts.get("breaches", []),
        "attribution": {
            "provider": "XposedOrNot",
            "url": "https://xposedornot.com",
            "notice": "Breach intelligence verified via XposedOrNot public threat database."
        }
    }
