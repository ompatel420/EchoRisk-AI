# EchoRisk AI — Viva & Technical Q&A Defense Guide

This guide is designed for classroom defense, academic vivas, project presentations, and code walkthroughs. It breaks down the core architecture, security choices, and technical trade-offs of **EchoRisk AI**.

---

## 1. Project Concept & Core Value

### Q: What is EchoRisk AI?
**A:** EchoRisk AI is a privacy-first cybersecurity web application that audits digital exposure for personal email addresses. It discovers if an email has appeared in verified data breaches, translates complex breach records into an explainable risk evaluation using Claude AI (with deterministic fallback), and provides users with actionable defensive countermeasures.

### Q: What real-world cybersecurity threat does EchoRisk AI address?
**A:** Credential stuffing, password spraying, and spear-phishing. When online services suffer database compromises, attackers correlate leaked credentials across platforms. EchoRisk AI helps users discover their exposed data vectors before adversaries exploit them.

---

## 2. Technical Stack & Architecture Decisions

### Q: Why Python & Flask instead of Django or FastAPI?
**A:**
1. **Lightweight Simplicity:** Flask provides a clean microframework without unnecessary ORM or boilerplate overhead.
2. **Speed & Clarity:** The application focuses on API orchestration (XposedOrNot + Anthropic), making Flask's request/response lifecycle straightforward and easy to explain.
3. **No Heavy Database Dependency:** Since the architecture follows a zero-retention model, an heavyweight database framework like Django was unnecessary.

### Q: Why Vanilla HTML, CSS, and Modern JavaScript instead of React, Next.js, or Vue?
**A:**
1. **Zero Framework Bloat:** Fast initial render without massive `node_modules` bundles or compile steps.
2. **Standard Web APIs:** Uses standard DOM manipulation, Fetch API, and CSS custom properties (variables) for theme consistency.
3. **Auditability:** Clean separation of concerns with minimal dependencies simplifies security auditing during academic review.

---

## 3. Data Collection, Privacy & Security

### Q: Does EchoRisk AI collect or store unnecessary user data?
**A:** **No.** EchoRisk AI implements a strict **Zero Permanent Data Retention** policy:
- **Scanned Emails:** Evaluated purely in volatile server memory during the lifecycle of the HTTP request. Never written to a database, SQLite file, or disk storage.
- **Console / Server Logs:** Application logs only record masked email addresses (`u***r@domain.com`), preventing accidental exposure in server stdout or log aggregators.
- **AI Processing Privacy:** The raw email address is **never transmitted to Anthropic / Claude AI**. Claude receives only anonymized breach metadata (breach count, names, dates, leaked data categories).
- **Password Exposure Checker:** The user's plaintext password never leaves the browser. The frontend hashes the password using Keccak-512 and transmits only the first 10 hex characters (k-Anonymity model) to XposedOrNot.
- **Notify Me Feature:** Kept strictly zero-storage. No emails or alert subscriptions are stored or cached on the server or in the browser.
- **No Trackers:** Zero Google Analytics, zero advertising pixels, zero third-party telemetry scripts.

### Q: Why is there no user registration / login system in Version 1?
**A:** An intentional architectural decision:
1. Storing user accounts requires managing password hashes, session tokens, and a relational database.
2. A breach checker storing user credentials would create a high-value honeypot for attackers.
3. Requiring login creates unnecessary friction and data collection for everyday users who simply want to audit their exposure.

---

## 4. Threat Intelligence & External APIs

### Q: How is XposedOrNot integrated into EchoRisk AI?
**A:**
- The backend communicates directly with the official XposedOrNot REST API (`https://api.xposedornot.com/v1/check-email/<email>`).
- If an email has records in known breaches, XposedOrNot returns verified incident names.
- EchoRisk AI cross-references this in real-time against verified breach incident details (breach date, records leaked, exposed data types, company domain) with zero persistent caching.

### Q: Why is the breach lookup performed before AI reasoning?
**A:** To eliminate **AI hallucination**. Large Language Models should never guess whether an email was breached or invent imaginary security breaches. By performing a deterministic database lookup first, EchoRisk AI grounds the AI strictly on confirmed, real-world facts.

### Q: What is the purpose of Anthropic Claude in this project?
**A:** Claude acts as an explainable risk analyst. It reads verified breach facts and interprets what they mean for a normal human:
- Evaluates the severity of exposed data (e.g. passwords vs. simple usernames).
- Calculates an objective risk index (0–100).
- Generates clear, prioritized defensive steps (e.g. password resets, MFA, session revocation).

### Q: What happens if the Claude API key is missing or the service is down?
**A:** EchoRisk AI has a built-in **Deterministic Rule-Based Security Engine** (`_generate_fallback_assessment()` in `ai_service.py`). If the API key is empty or the network call fails, the fallback engine immediately calculates risk scores and defensive steps using cybersecurity heuristics. The viva demonstration never breaks!

### Q: What happens when an email has no breach records?
**A:** The application returns a clean report:
- Status: "No Known Breaches Found"
- Risk Score: 10 / 100 (Low)
- Key Findings: Absence of compromised credentials in checked databases.
- Defensive Advice: Proactive cybersecurity hygiene (unique passwords, 2FA, phishing awareness).

---

## 5. Security Hardening & Defenses Implemented

### Q: What security controls are implemented on the server?
**A:**
1. **HTTP Security Headers:**
   - `Content-Security-Policy` (CSP) restricts script, style, font, and connect origins.
   - `X-Content-Type-Options: nosniff` blocks MIME confusion attacks.
   - `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` prevent clickjacking.
   - `Referrer-Policy: strict-origin-when-cross-origin` protects user referrer privacy.
   - `Permissions-Policy: camera=(), microphone=(), geolocation=()` restricts device capabilities.
2. **Payload Size Guard:** `MAX_CONTENT_LENGTH = 1MB` to prevent denial-of-service memory exhaustion.
3. **Sliding Window Rate Limiter:** In-memory rate limiting throttles requests to 30 lookups per minute per IP, preventing automated scraping and brute force.
4. **Input Normalization & RFC Validation:** Strict server-side regex, username/domain length constraints, domain typo suggestions (Levenshtein distance), and DNS checks.
5. **Output Escaping:** Strict HTML escaping on both client and server to prevent Cross-Site Scripting (XSS).
