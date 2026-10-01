# 04 — Flask Backend Prompt

## Goal
Create a clean Python backend that safely receives the email and orchestrates the breach lookup and AI analysis.

## Copy-paste prompt for Antigravity

```text
Implement the Python backend for EchoRisk AI using Flask.

BACKEND REQUIREMENTS
- Flask application
- JSON API endpoint: POST `/api/scan`
- Input: {"email": "..."}
- Validate the email server-side
- Normalize/lowercase the email before lookup
- Use environment variables for all secrets
- Add clear exception handling
- Return consistent JSON responses
- Never return stack traces to the browser in production mode

SUGGESTED FILES
- app.py
- services/breach_service.py
- services/ai_service.py
- services/report_service.py
- utils/validators.py
- .env.example
- requirements.txt

NORMALIZED INTERNAL DATA
Create a consistent Python structure such as:
{
  "email": "masked-or-session-only-value",
  "breach_count": 0,
  "breaches": [],
  "exposed_data_types": [],
  "has_password_exposure": false,
  "source": "XposedOrNot",
  "status": "success"
}

IMPORTANT PRIVACY RULE
Do not write scanned emails or sensitive API responses into application logs.
Do not save the scan to a database in version 1.

API FLOW
1. Receive email.
2. Validate email.
3. Call breach service.
4. Normalize provider response.
5. Send only necessary verified facts to AI service.
6. Build final response.
7. Return JSON to frontend.

ERROR RESPONSE FORMAT
Use a consistent shape:
{
  "status": "error",
  "message": "Human-readable safe message",
  "code": "SOME_ERROR_CODE"
}

DEVELOPMENT EXPERIENCE
- Add a health route `/health`.
- Add comments explaining important security decisions.
- Keep the backend beginner-friendly and easy to explain in a viva.
- Do not introduce microservices, Docker, message queues, Redis, or databases unless truly needed.

Create `.env.example` with placeholder variable names only.
```

## Expected result

A small Flask backend with clean service separation and safe configuration handling.
