# EchoRisk AI — Email Data Breach & Cyber Risk Tracker

> A modern, privacy-first cybersecurity web application that checks whether an email address or password has been compromised in known data breaches, explains exposure risks using Claude AI (with an intelligent deterministic rule-based fallback), and delivers actionable defensive countermeasures.

![EchoRisk AI Banner](frontend/static/assets/hero-illustration.svg)

---

## 1. Project Overview

**EchoRisk AI** is an academic cybersecurity demonstration platform designed to protect users against credential stuffing, password spraying, and spear-phishing attacks. Everyday online accounts are frequently compromised in third-party database breaches.

EchoRisk AI provides an instant, transparent risk assessment:
- **Verified Breach Intelligence:** Cross-referenced in real-time from the official **XposedOrNot** threat database.
- **Explainable AI Risk Evaluation:** Grounded reasoning powered by **Claude AI** (Anthropic) that evaluates exposure vectors without hallucinations.
- **Deterministic Cybersecurity Engine:** A zero-dependency fallback engine that guarantees 100% viva and offline reliability if an AI API key is not supplied.
- **k-Anonymity Password Exposure Checker:** Client-side Keccak-512 hashing tests password exposures without ever transmitting plaintext credentials.
- **Zero Permanent Data Retention:** Strict ephemeral, in-memory processing with no email database or raw credential logging.

---

## 2. Data Collection & Privacy Audit (Does It Collect Unnecessary Data?)

A core tenet of EchoRisk AI is **minimal data collection and zero retention**:

| Data Type | Collected? | Stored on Server? | Transmitted to 3rd Parties? | Protection Mechanism |
|---|---|---|---|---|
| **Scanned Email Addresses** | Yes (in memory only) | **NO** (Zero DB, zero disk files) | Yes (sent via HTTPS to XposedOrNot API for lookup) | Evaluated strictly in volatile memory during the request lifecycle. Masked in logs (`u***r@domain.com`). **Never sent to Claude AI**. |
| **Passwords** | No (hashed locally) | **NO** (Never received by server) | Partial hash only (first 10 hex characters of Keccak-512) | Plaintext passwords **never leave your browser**. Evaluated using a k-Anonymity query against XposedOrNot. |
| **Search / Lookup History** | No | **NO** | No | No search history or audit records are recorded on disk or in a database. |
| **User Accounts / Profiles** | No | **NO** | No | No registration, login, or session cookies are used in Version 1 to prevent honeypot vulnerabilities. |
| **Notification Subscriptions** | Optional (Simulation) | **NO** | No | Strict Zero-Storage: No notification emails are stored in browser localStorage or cached on server. |
| **Telemetry / Tracking Pixels** | **NO** | **NO** | No | Zero Google Analytics, zero advertising pixels, zero device fingerprinting, and zero tracking cookies. |

---

## 3. Key Features

- **Instant Email Exposure Scan:** Check any email against millions of cataloged breach records.
- **Password Exposure Auditor:** Test password strength and check if hashes have leaked online using client-side Keccak-512 k-Anonymity.
- **Interactive Threat Report:**
  - Visual status pill and masked target display (`u***r@domain.com`).
  - Threat index gauge (0–100) and color-coded risk level badge (*Low*, *Moderate*, *High*, *Critical*).
  - Password exposure indicator (identifies credential leaks vs. metadata leaks).
  - Detailed breach cards with logo, domain, incident date, affected record count, and exposure description.
  - Actionable defensive checklist (MFA enrollment, password rotation, session audits).
- **Executive PDF / Print Export:** Clean, formatted print styles for generating offline cybersecurity audit reports.
- **Dual Evaluation Engines:** Automatically selects Claude AI if an `ANTHROPIC_API_KEY` is present; seamlessly switches to the built-in deterministic heuristic engine otherwise.
- **Offline Demo / Viva Mode:** Includes pre-configured demo chips (`compromised@example.com` and `safe@example.com`) for classroom presentation.
- **Incident Dossiers:** Dedicated detail pages (`/breach/<id>`) detailing specific high-profile historical compromises (Adobe, LinkedIn, Canva, etc.).

---

## 4. Security Controls & Hardening

EchoRisk AI incorporates rigorous application security standards documented in [SECURITY.md](SECURITY.md):

1. **HTTP Security Response Headers:**
   - `Content-Security-Policy`: Restricts scripts, styles, fonts, images, and API connections to verified origins.
   - `X-Content-Type-Options: nosniff`: Prevents MIME-type confusion attacks.
   - `X-Frame-Options: DENY` & CSP `frame-ancestors 'none'`: Comprehensive clickjacking defense.
   - `Referrer-Policy: strict-origin-when-cross-origin`: Shields request metadata.
   - `Permissions-Policy`: Disables camera, microphone, and geolocation.
2. **In-Memory Rate Limiting:**
   - Thread-safe sliding window rate limiter throttles requests on `/api/scan` to **30 requests per minute per IP**, returning HTTP 429 with a `Retry-After` header.
3. **Request Body Size Guard:**
   - Enforces a 1 MB limit via Flask `MAX_CONTENT_LENGTH`, mitigating denial-of-service memory exhaustion attacks with a clean HTTP 413 error.
4. **Input Sanitization & Normalization:**
   - Server-side RFC validation, length checks (254 chars max), domain typo auto-correction (Levenshtein distance), and fail-open DNS checks.
5. **Output Escaping:**
   - All dynamic content is escaped using `escapeHtml()` in JavaScript and auto-escaping in Jinja2 templates, mitigating Cross-Site Scripting (XSS).

---

## 5. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **Backend** | Python 3.9+ / Flask | Lightweight API orchestration, rate limiting, and routing |
| **Frontend** | Vanilla HTML5, CSS3, Modern ES6+ | Clean, fast client with zero heavy framework overhead |
| **Breach Intelligence** | XposedOrNot REST API | Real-time verified breach verification |
| **AI Risk Reasoning** | Anthropic Claude API (`claude-3-5-sonnet-20241022`) | Objective exposure interpretation over verified facts |
| **Local Cryptography** | Keccak-512 (SHA-3) via `js-sha3` | Client-side password hashing for k-Anonymity queries |
| **Configuration** | `python-dotenv` | Environment separation (`.env` / `.env.example`) |
| **Styling & Assets** | Custom CSS & Scalable SVGs | Purple & white cybersecurity design system |

---

## 6. Project Structure

```
Echorisk-AI/
├── .env.example                     # Sanitized environment template for configuration
├── .gitignore                       # Prevents secret leakage (.env, __pycache__, logs)
├── 01_PROJECT_PLAN.md               # Architecture planning document
├── 02_UI_DESIGN.md                  # Design specifications
├── 03_FRONTEND.md                   # Frontend specifications
├── 04_FLASK_BACKEND.md              # Backend specifications
├── 05_BREACH_API.md                 # Threat API integration notes
├── 06_CLAUDE_AI_AND_REPORT.md       # AI risk prompt & schema guidelines
├── 07_TESTING_AND_FINAL_POLISH.md   # Final testing and viva requirements
├── PROJECT_IMPLEMENTATION_NOTES.md  # Detailed implementation notes
├── README.md                        # Project documentation (this file)
├── SECURITY.md                      # Security policy, checklist & threat model
├── VIVA_NOTES.md                    # Academic viva & technical Q&A defense guide
├── requirements.txt                 # Pinned Python package dependencies
├── app.py                           # Root application entrypoint
├── run.bat                          # One-click Windows launch script
├── backend/
│   ├── __init__.py
│   ├── app.py                       # Flask server, rate limiter, security headers
│   ├── services/
│   │   ├── __init__.py
│   │   ├── breach_service.py        # XposedOrNot API client & catalog cache
│   │   ├── ai_service.py            # Claude AI client & deterministic fallback engine
│   │   └── report_service.py        # Report normalization and aggregation
│   └── utils/
│       ├── __init__.py
│       └── validators.py            # RFC validation, Levenshtein typo detection, masking
└── frontend/
    ├── templates/
    │   ├── index.html               # Main scanner landing page & interactive report
    │   └── breach_detail.html       # Individual incident dossier template
    └── static/
        ├── css/
        │   └── style.css            # Complete design system
        ├── js/
        │   └── app.js               # Client controller, k-Anonymity hasher, UI logic
        └── assets/
            ├── logo.png             # Application logo (PNG)
            ├── logo.svg             # Application logo (SVG)
            └── hero-illustration.svg# Shield & radar cybersecurity graphic
```

---

## 7. Setup & Installation Guide

### Prerequisites
- **Python 3.9+** installed on your system.

### Step 1: Clone or Open Repository
```bash
cd "d:\Users\Om Patel\Projects\Antigravity\Echorisk-AI"
```

### Step 2: Virtual Environment Setup
```bash
# On Windows:
python -m venv venv
.\venv\Scripts\activate

# On macOS/Linux:
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create your local `.env` from the provided example template:
```bash
# Windows:
copy .env.example .env

# macOS/Linux:
cp .env.example .env
```
Open `.env` to configure your settings:
```ini
FLASK_APP=app.py
FLASK_ENV=development
FLASK_PORT=5000
SECRET_KEY=change-this-in-production

# Optional: Add your Anthropic key or leave blank for the built-in deterministic engine
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022

# Threat intelligence settings
XPOSEDORNOT_API_URL=https://api.xposedornot.com/v1
MOCK_MODE=false
```

### Step 5: Start the Web Application
```bash
# Direct Python execution:
python app.py

# Or on Windows using the batch script:
.\run.bat
```
Visit the local server in your browser:
```
http://localhost:5000
```

---

## 8. Verification & Security Testing

You can verify the backend endpoints and security defenses using Python:

```bash
# 1. Verify health status and HTTP security headers
python -c "from backend.app import app; c = app.test_client(); r = c.get('/health'); print('Health:', r.status_code, r.json); print('CSP:', r.headers.get('Content-Security-Policy'))"

# 2. Test input validation (empty and invalid emails)
python -c "from backend.app import app; c = app.test_client(); print('Empty:', c.post('/api/scan', json={'email': ''}).status_code); print('Invalid:', c.post('/api/scan', json={'email': 'bad'}).status_code)"

# 3. Test rate limiting (30 requests threshold)
python -c "from backend.app import app; c = app.test_client(); [c.post('/api/scan', json={'email': 'safe@example.com'}) for _ in range(30)]; print('Rate limited:', c.post('/api/scan', json={'email': 'safe@example.com'}).status_code)"

# 4. Test request payload size guard (1 MB limit)
python -c "from backend.app import app; c = app.test_client(); print('Payload guard:', c.post('/api/scan', json={'email': 'a' * 1050000}).status_code)"
```

---

## 9. Academic Defense & Viva Notes

Comprehensive questions and answers addressing architecture, why Flask was chosen, threat modeling, AI prompting safety, and edge-case handling are available in [VIVA_NOTES.md](VIVA_NOTES.md).

---

## 10. License & Attributions

- Developed as an educational cybersecurity demonstration and college viva project.
- Breach threat intelligence powered by the public threat database at [XposedOrNot](https://xposedornot.com).
