# 06 — Claude AI + Risk Report Prompt

## Goal
Use Claude only for reasoning over verified breach facts, while keeping the final report understandable and transparent.

## Copy-paste prompt for Antigravity

```text
Implement the AI analysis layer for EchoRisk AI.

CORE DESIGN PRINCIPLE
Do not ask Claude to discover breaches. The application must first obtain verified breach facts from the breach-data provider, normalize them, and only then send those facts to Claude for explanation and recommendations.

AI INPUT
Send structured facts such as:
- number of matching breaches
- breach names
- breach dates when available
- exposed data categories
- password-risk indicator when supplied by the provider
- source/provider name

Do not send unnecessary secrets or entire raw provider payloads.

PYTHON IMPLEMENTATION
Use the official Anthropic Python SDK or the currently recommended Anthropic integration documented by Anthropic.
Keep the AI call in `services/ai_service.py`.
Read the model name/API credentials from environment variables.
Never put Claude credentials in frontend code.

AI OUTPUT
Ask Claude to return a compact JSON-like structure with:
- risk_level: Low / Moderate / High / Critical
- short_summary
- key_findings: array of short strings
- exposed_categories: array
- recommended_actions: array ordered by priority
- disclaimer

PROMPT RULES FOR CLAUDE
1. Only reason from the supplied verified facts.
2. Do not invent breaches, dates, companies, or exposed fields.
3. Clearly distinguish facts from interpretation.
4. If there is not enough evidence for a conclusion, say so.
5. Never ask the model to output passwords, secret credentials, or harmful attack instructions.
6. Recommendations should be defensive: unique passwords, MFA, session review, monitoring, and account-security checks.
7. Keep the output short enough for a clean web report.

RISK SCORING NOTE
Do not pretend the AI score is a scientifically validated cybersecurity score. Label it as an application assessment based on the supplied breach evidence.

FAILURE HANDLING
If Claude fails or is unavailable:
- still show the verified breach results
- provide a basic deterministic fallback summary from the backend
- tell the user that the AI explanation is temporarily unavailable

REPORT SERVICE
Create a final response that combines:
1. verified breach facts
2. transparent risk assessment
3. practical security recommendations
4. provider attribution
5. a short limitation/disclaimer

Do not store prompts, responses, or user emails permanently in version 1.
```

## Expected result

A safe AI layer where Claude explains the verified breach evidence instead of generating breach facts itself.
