# Security Policy — EchoRisk AI

EchoRisk AI is an email data-breach tracking and digital-exposure assessment platform. It may process email addresses, breach intelligence returned by third-party services, risk assessments, and security recommendations. Security controls must be implemented in the application and infrastructure; this document alone does not protect the website.

## Supported Versions

Security fixes should be applied to the latest deployed version. Older deployments may not receive security updates.

| Version | Supported |
| --- | --- |
| Latest release / production deployment | Yes |
| Older releases | Best effort; upgrade recommended |

## Reporting a Vulnerability

Please do not publish exploitable vulnerability details, credentials, personal data, or proof-of-concept attacks in public issues.

Report suspected vulnerabilities privately to the project maintainer using the repository's **Private vulnerability reporting** feature (GitHub: **Security → Advisories → Report a vulnerability**) if enabled. If private reporting is not enabled, contact the maintainer through a verified private channel listed in the repository profile.

Include:
- A concise description and potential impact.
- Steps to reproduce in a test environment.
- Affected version, endpoint, or component.
- Redacted screenshots or logs, if useful.

Do not access, modify, download, or disclose other people's data. Do not perform denial-of-service tests, phishing, social engineering, or tests against systems you do not own or have permission to assess. Please allow the maintainer reasonable time to investigate and fix the issue before public disclosure.

## Security Requirements for the Website

Use this checklist when implementing and reviewing EchoRisk AI. Mark an item complete only after it has been implemented and tested.

### 1. Secrets and configuration
- [x] Keep Anthropic/Claude API keys, XposedOrNot credentials (if used), database credentials, signing keys, and session secrets on the server in environment variables or a managed secret store.
- [x] Never place secrets in frontend JavaScript, mobile/browser bundles, source control, screenshots, logs, or public configuration files.
- [x] Add `.env`, `.env.*` (except a deliberately safe example file), private key files, and local secret files to `.gitignore`.
- [x] Provide a `.env.example` containing placeholder values only.
- [x] Rotate any secret that has been committed, exposed, or shared. Removing it from the latest commit is not enough.

### 2. Email addresses and privacy
- [x] Collect only the data required to perform a breach lookup and explain the purpose, retention period, and third-party services in the privacy notice.
- [x] Use HTTPS for every page and API request; redirect HTTP to HTTPS in production deployment.
- [x] Do not put email addresses, API keys, breach details, or full risk reports in URL query strings, analytics events, or error messages.
- [x] Redact or omit email addresses and sensitive breach details from application logs (`mask_email` displays `u***r@domain.com`). Restrict log access.
- [x] Avoid storing lookup history unless it is necessary and clearly disclosed. Zero permanent storage of scanned emails or search history on backend disks/databases.
- [x] Do not reveal whether another user has an account or saved report through different error messages or response timing.

### 3. Input validation and API security
- [x] Validate and normalize email addresses on the server (`backend/input_validator.py`); set reasonable maximum lengths (254 chars total, 64 user) and reject malformed input.
- [x] Use parameterized database queries or a safe ORM (Zero SQL database used in V1, eliminating SQL injection surface).
- [x] Enforce request-size limits (`MAX_CONTENT_LENGTH = 1MB`), timeouts (requests timeout=6s/8s), and strict content types (`request.is_json`).
- [x] Apply rate limits to breach lookups (thread-safe sliding window rate limiter: 30 requests/minute per client IP with HTTP 429 response).
- [x] Add abuse monitoring and temporary throttling for repeated failures. Avoid permanent IP blocks that can be abused against other users.
- [x] Return generic public error messages; keep diagnostic details in protected server logs.
- [x] If the site uses cookies for sessions, set `Secure`, `HttpOnly`, and an appropriate `SameSite` value (Zero tracking cookies used in V1).

### 4. Authentication and authorization (if accounts exist)
- [x] *Architectural Decision:* User accounts and credentials are intentionally omitted in V1 to maintain a zero-retention, zero-credential-database security model.

### 5. XposedOrNot and other external services
- [x] Call breach-intelligence providers from the backend where possible; do not expose provider credentials in the browser.
- [x] Set connection/read timeouts, validate response schemas, handle provider errors safely, and limit retries.
- [x] Treat all third-party responses as untrusted data. Escape output before rendering it (`escapeHtml()` in JS, Jinja2 auto-escaping in templates).
- [x] Request only the data needed. Review each provider's terms, privacy practices, and retention policy.
- [x] Do not imply that a missing result proves an account is safe; explain that results depend on the provider's coverage and freshness.

### 6. Anthropic/Claude and AI-generated output
- [x] Keep the Anthropic API key server-side and restrict its permissions and usage where the provider supports it.
- [x] Send only the minimum information needed for an assessment. Email addresses are strictly omitted from the Claude payload; only verified breach facts and categories are transmitted.
- [x] Treat breach records, user input, and retrieved content as untrusted input; they must not be allowed to override system instructions or trigger tools.
- [x] Do not let model output execute as code, SQL, shell commands, or HTML. Validate structured output against a JSON schema and escape text in the UI.
- [x] Put limits on input size, output tokens (max 600 tokens), request frequency, and spending; handle provider failures gracefully with the deterministic rule-based security engine fallback.
- [x] Clearly distinguish verified provider data from AI-generated interpretation. Do not present AI risk scores as guarantees or definitive proof of compromise.

### 7. Browser security headers
Configure and test suitable HTTP response headers at the application or hosting layer:
- [x] Content-Security-Policy (CSP) restricting scripts to 'self' and trusted CDN, fonts to Google Fonts, and API connections to 'self' and XposedOrNot.
- [x] Strict-Transport-Security (HSTS) after HTTPS is correctly configured across the intended domain.
- [x] `X-Content-Type-Options: nosniff`.
- [x] `Referrer-Policy: strict-origin-when-cross-origin`.
- [x] A restrictive `Permissions-Policy: camera=(), microphone=(), geolocation=()`.
- [x] Clickjacking protection using CSP `frame-ancestors 'none'` and legacy `X-Frame-Options: DENY`.

### 8. Cross-origin access, uploads, and output rendering
- [x] Configure CORS with explicit restrictions.
- [x] File uploads are completely disabled in V1.
- [x] Escape user-controlled and third-party text for its output context. Avoid raw unescaped rendering for untrusted content.
- [x] Prevent open redirects with strict local route handling.

### 9. Database, deployment, and dependencies
- [x] Encrypt traffic in transit (HTTPS) and use zero server-side credential databases.
- [x] Use separate development and production credentials and environments via `.env`.
- [x] Keep runtime, framework, dependencies, and deployment platform patched and minimal.
- [x] Enable dependency and secret scanning in the repository and review security alerts.
- [x] Zero sensitive data stored to back up or leak.
- [x] Disable debug mode and verbose stack traces in production (`FLASK_ENV=production`).
- [x] Limit administrative access, protect CI/CD secrets, and review changes before deployment.

### 10. Monitoring and incident response
- [x] Log security-relevant events without logging passwords, tokens, API keys, or raw personal data (masked emails only).
- [x] Alert on unusual lookup volume and throttle excessive requests via sliding-window rate limiter.
- [x] Prepare a response process to contain incidents, rotate credentials, patch issues, and preserve operational logs.
- [x] Periodically test rate limits, input validation, and provider failure fallbacks.

## Recommended Security Tests Before Release

- Test invalid, oversized, and malformed email input.
- Confirm unauthenticated users cannot access private reports or admin endpoints.
- Confirm one user cannot access another user's reports by changing an identifier.
- Test XSS handling using harmless test strings in all user- and provider-controlled fields.
- Verify SQL queries are parameterized and rate limits work.
- Confirm API keys are absent from frontend bundles, source maps, repository history, and browser network responses.
- Check security headers, HTTPS configuration, dependency alerts, and production error handling.
- Test provider timeouts, malformed responses, and AI service failures.

Run security tests only against systems you own or are explicitly authorized to test.

## Scope

This policy covers the EchoRisk AI website, its backend/API, deployment configuration, and project-managed integrations. Vulnerabilities in third-party services should be reported to their respective providers. This policy is not a guarantee that the site is secure or that every listed control is currently implemented.

## Policy Maintenance

Review this file whenever authentication, data storage, API integrations, hosting, or the threat model changes. Keep the reporting instructions accurate and ensure someone monitors the configured reporting channel.
