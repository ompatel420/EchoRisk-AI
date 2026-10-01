# 05 — XposedOrNot Integration Prompt

## Goal
Integrate a real breach lookup into the Flask backend and normalize its response for the frontend.

## Copy-paste prompt for Antigravity

```text
Implement the XposedOrNot breach lookup for EchoRisk AI.

IMPORTANT
Use the current official XposedOrNot API documentation rather than guessing endpoint formats. Prefer the official Python SDK when it is practical; otherwise use requests with the documented REST endpoint.

REFERENCE
The public API documentation describes an email breach check under the XposedOrNot API and provides a Python SDK. Follow the currently documented interface and response schema.

IMPLEMENTATION
1. Put the provider integration in `services/breach_service.py`.
2. Keep provider-specific response parsing inside that file.
3. The frontend must never call XposedOrNot directly.
4. Do not hard-code provider secrets or API keys.
5. Respect documented rate limits.
6. Set sensible request timeouts.
7. Handle provider 4xx, 5xx, timeout and malformed JSON responses.
8. Return a small normalized object to the rest of the application.

NORMALIZED OUTPUT
Return:
- breach_count
- breaches
- exposed_data_types
- password_exposed (boolean when the source provides sufficient evidence)
- source
- status

BREACH ITEM
Keep only useful fields for the report, for example:
- breach name/id
- breach date
- exposed data fields
- record count when available
- source/reference URL when available
- provider risk/password field when available

DO NOT
- Store the email in a database.
- Log full provider responses.
- Invent missing breach details.
- Tell the user that "no breach found" means the email was never compromised. Phrase it as "no matching breach found in the checked source".

ATTRIBUTION
Include an unobtrusive "Breach data powered by XposedOrNot" attribution in the report/footer when required by the provider's current terms.

TESTING
Create a provider mock mode or small mock fixture so the UI can be demonstrated even when the external API is unavailable.
```

## Expected result

A working breach lookup service with safe parsing, clear error handling, and a provider-neutral internal data format.
