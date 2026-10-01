# EchoRisk AI — Email Data Breach Tracker

> A modern, privacy-first cybersecurity web application that checks whether an email address has been compromised in known data breaches, explains the exposure risk using Claude AI, and delivers practical defensive recommendations.

![EchoRisk AI Banner](frontend/static/assets/hero-illustration.svg)

---

## 1. Project Overview
**EchoRisk AI** was built as a clean, college-level cybersecurity demonstration project. Everyday users often have their passwords, identities, and email addresses leaked in third-party database breaches without their knowledge. Attackers exploit these leaks to execute credential-stuffing and spear-phishing attacks.

EchoRisk AI solves this problem by allowing users to check an email address in one click, receiving:
- **Verified Breach Facts:** Cross-referenced in real-time from the official **XposedOrNot** threat database.
- **Explainable AI Risk Evaluation:** Grounded reasoning powered by **Claude AI** (Anthropic) that evaluates exposure vectors without hallucinations.
- **Defensive Countermeasures:** Actionable, prioritized steps (MFA, password resets, session management) to safeguard compromised accounts.
- **Zero Permanent Data Retention:** Emails are never saved to a database or written into server logs.

---

## 2. Key Features

- **One-Click Instant Scan:** Enter an email address and scan against millions of verified breach records.
- **Reference UI Match:** Clean white-and-purple aesthetic (`#6D28D9` / `#7C3AED`) matching modern cybersecurity industry standards.
- **Triple Feature Cards:** 
  1. *Breach Detection* (cross-referenced against verified databases).
  2. *Risk Assessment* (objective threat score and metrics).
  3. *Security Guidance* (actionable defensive countermeasures).
- **Interactive Scan Report:**
  - Dynamic radar animation during database search.
  - Overall status banner and masked email display (`u***r@domain.com`).
  - Threat index gauge (0–100) and color-coded risk badge (Low, Moderate, High, Critical).
  - Password exposure alert indicating whether credentials or hashes were leaked.
  - Detailed breach cards with company name, domain, breach date, records leaked, and source link.
  - Prioritized defensive action checklist.
- **Robust Deterministic Fallback:** If the Anthropic Claude API key is absent or unreachable, an intelligent rule-based cybersecurity engine immediately evaluates the verified breach facts, ensuring 100% viva reliability.
- **Demo / Viva Mode:** Pre-loaded one-click test chips (`compromised@example.com` and `safe@example.com`) for seamless offline or classroom demonstrations.
- **Notify Me Alert Subscription:** Interactive modal for users to register interest in automated breach monitoring.
- **Accessible & Responsive:** Full keyboard navigation, semantic HTML5, aria attributes, and mobile-friendly responsive layout.

---

## 3. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend** | Python 3.9+ / Flask | Lightweight, clean web server & API orchestration |
| **Frontend** | HTML5, Vanilla CSS3, Modern JS | Clean client with zero heavy framework bloat |
| **Breach Intelligence** | XposedOrNot REST API | Real-time verified breach lookups |
| **AI Reasoning** | Anthropic Claude API (`claude-3-5-sonnet-20241022`) | Defensive risk analysis on verified breach facts |
| **Security & Config** | `python-dotenv` | Encapsulation of credentials in `.env` |
| **Styling & Assets** | Pure CSS & Custom SVGs | Custom-tailored purple & white design system |

---

## 4. Folder Structure

```
Echorisk-AI/
├── 01_PROJECT_PLAN.md
├── 02_UI_DESIGN.md
├── 03_FRONTEND.md
├── 04_FLASK_BACKEND.md
├── 05_BREACH_API.md
├── 06_CLAUDE_AI_AND_REPORT.md
├── 07_TESTING_AND_FINAL_POLISH.md
├── PROJECT_IMPLEMENTATION_NOTES.md
├── README.md
├── VIVA_NOTES.md
├── requirements.txt
├── .gitignore
├── .env
├── app.py
├── run.bat
├── backend/
│   ├── __init__.py
│   ├── app.py
│   ├── requirements.txt
│   ├── services/
│   │   ├── __init__.py
│   │   ├── breach_service.py
│   │   ├── ai_service.py
│   │   └── report_service.py
│   └── utils/
│       ├── __init__.py
│       └── validators.py
└── frontend/
    ├── templates/
    │   ├── index.html
    │   └── breach_detail.html
    └── static/
        ├── css/
        │   └── style.css
        ├── js/
        │   └── app.js
        └── assets/
            ├── logo.png
            ├── logo.svg
            └── hero-illustration.svg
```

---

## 5. Setup & Installation Guide

### Prerequisites
- Python 3.9 or higher installed on your computer.
- Git (optional).

### Step 1: Clone or Navigate to Project Directory
```bash
cd d:\Users\Om Patel\Projects\Antigravity\Echorisk-AI
```

### Step 2: Create and Activate Virtual Environment (Recommended)
```bash
# On Windows:
python -m venv venv
.\venv\Scripts\activate

# On macOS/Linux:
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Open `.env` in any text editor and adjust variables if desired:
- `ANTHROPIC_API_KEY`: *(Optional)* Insert your Anthropic API key to enable Claude 3 reasoning. If left empty, EchoRisk AI automatically uses its built-in rule-based deterministic security engine!
- `MOCK_MODE`: Set to `false` for live XposedOrNot queries, or `true` for simulated offline presentation mode.
- `FLASK_PORT`: Default is `5000`.

### Step 5: Run the Flask Web Application
```bash
python app.py
```
Open your web browser and visit:
```
http://localhost:5000
```

---

## 6. How the Data Flow Works

```
[ User enters email ]
         │
         ▼
[ Client-side Validation ] (RFC format check, whitespace normalization)
         │
         ▼
[ POST /api/scan ] ──────> [ backend/utils/validators.py ] (Server-side validation & masking)
                                  │
                                  ▼
                     [ backend/services/breach_service.py ]
                                  │
                     (Query XposedOrNot REST API)
                                  │
                                  ▼
                     [ Normalize Breach Facts ]
                     (Counts, breach titles, exposed types, password flag)
                                  │
                                  ▼
                      [ backend/services/ai_service.py ]
                     (Send strictly verified facts to Claude AI / Fallback)
                                  │
                                  ▼
                    [ backend/services/report_service.py ]
                     (Combine facts, risk score & defensive actions)
                                  │
                                  ▼
[ Return 200 OK JSON ] ──> [ Browser Dynamic Report UI ]
```

---

## 7. Privacy & Security Principles

1. **Zero Permanent Data Retention:** The application does not store scanned email addresses in any database, cache, or disk storage.
2. **Zero Sensitive Logging:** Server console logs print only masked email identifiers (`u***r@example.com`) to prevent accidental credential leakage in operational logs.
3. **No Direct Frontend API Exposure:** API keys and external third-party requests are handled solely by the Python backend. The client browser communicates only with `/api/scan`.
4. **Non-Hallucinatory AI Prompting:** Claude AI is supplied solely with confirmed breach facts. It is explicitly instructed never to invent breaches, guess passwords, or generate offensive attack tactics.

---

## 8. Known Limitations & Future Roadmap

- **Phone Number Checking:** The initial version is dedicated strictly to email breach checking. Future iterations can add phone number checking once standardized lookup APIs are integrated.
- **Dark Web Monitoring Daemon:** Currently, scans are on-demand. Automated recurring alert notifications are captured via the "Notify Me" interface for future cron/worker queue integration.
- **Provider Coverage:** Results reflect incidents cataloged by XposedOrNot; unpublicized or private corporate breaches may not appear.

---

## 9. License & Attribution
- Educational college project developed for cyber awareness and academic viva presentation.
- Breach threat intelligence powered by [XposedOrNot](https://xposedornot.com).
