# EchoRisk AI — Viva & Oral Examination Notes

This guide provides concise, technically sound answers to potential questions asked by professors and examiners during project demonstrations and viva examinations.

---

### 1. What is EchoRisk AI?
**Answer:**  
EchoRisk AI is a privacy-first cybersecurity web application designed to help users identify whether their email credentials have been compromised in verified third-party data breaches. It bridges the gap between raw, cryptic database dumps and non-technical users by pairing real-time breach threat intelligence (from XposedOrNot) with defensive AI reasoning (via Anthropic Claude) to evaluate exposure severity and prescribe prioritized remediation steps.

---

### 2. Why was Flask chosen for the backend?
**Answer:**  
- **Micro-framework efficiency:** Flask is lightweight, unopinionated, and avoids heavy ORM or boilerplate bloat (unlike Django), which is ideal for a service-oriented API gateway.
- **Python ecosystem:** Python natively integrates with modern AI SDKs (Anthropic, OpenAI) and HTTP libraries (`requests`), allowing clean modular service abstraction.
- **Maintainability & Viva Explainability:** The codebase is transparent and simple enough to walk through line-by-line during an academic examination without complex configuration files or hidden magic.

---

### 3. Why Vanilla HTML5, CSS3, and JavaScript instead of React or Angular?
**Answer:**  
- **Zero Build Step & Fast Performance:** Vanilla web technologies run natively in any browser with zero node compile steps, webpack bundling, or dependency vulnerabilities.
- **Lightweight Footprint:** The application loads instantly with minimal memory overhead.
- **Clean DOM Manipulation:** Dynamic asynchronous UI updates are handled cleanly using the native `fetch()` API and DOM manipulation without the overhead of a virtual DOM.

---

### 4. How is XposedOrNot used in the application?
**Answer:**  
XposedOrNot is an open, community-supported breach threat intelligence repository. Our backend queries its REST API (`/v1/check-email/{email}`) over HTTPS. When an email matches breach records, our `breach_service.py` extracts the breach titles, cross-references breach metadata (affected domains, dates, breach descriptions, leaked fields), and normalizes the payload into a consistent internal JSON schema.

---

### 5. Why is Claude AI used?
**Answer:**  
Raw breach data is often confusing for everyday users (e.g., they may not know what "salted SHA1 hashes" or "credential stuffing" mean). Claude AI acts as an objective, defensive cybersecurity advisor. It analyzes the specific combination of leaked fields (e.g., passwords vs. plain emails vs. IP addresses) and generates:
1. An easy-to-understand risk summary.
2. An objective threat index.
3. Prioritized defensive steps (e.g., updating specific passwords, enabling Authenticator-based 2FA, session revocation).

---

### 6. Why is the breach lookup performed BEFORE AI reasoning?
**Answer (Critical viva concept):**  
**To eliminate Large Language Model (LLM) hallucinations.** LLMs cannot and should not be used as authoritative databases because they generate probabilistic text and would invent fake breaches, dates, or leaked passwords.  
By querying XposedOrNot first, we obtain **100% verified ground truth facts**. We then pass only these verified facts to Claude with strict system prompts prohibiting extrapolation, ensuring the AI's role is strictly **defensive reasoning and translation**, never data generation.

---

### 7. What happens when there is no breach found?
**Answer:**  
When XposedOrNot returns a 404 or empty breach list:
- The backend normalizes this into a clean zero-breach object (`breach_count: 0`, `risk_level: "Low"`).
- The frontend renders a positive status banner ("No Known Breaches Found").
- The report carefully explains that while no records appeared in the checked database, users should still practice good cyber hygiene (unique passwords, MFA), rather than claiming absolute immunity.

---

### 8. What happens when an external API fails or the internet is offline?
**Answer:**  
EchoRisk AI implements defense-in-depth error handling:
- **Claude API Failure / Missing Key:** The application automatically switches to a built-in **Deterministic Rule-Based Security Engine** (`backend/services/ai_service.py`). It calculates risk level and generates defensive recommendations using verified rule logic, ensuring the user still receives a complete report.
- **XposedOrNot Network Failure / Rate Limit:** The server catches `requests.exceptions.RequestException` and returns a clean HTTP 503 with a user-friendly error message, rather than crashing or exposing a stack trace.
- **Viva Demo Mode (`MOCK_MODE`):** For offline viva presentations, a single flag in `.env` provides instant, realistic simulation data for test accounts (`compromised@example.com` and `safe@example.com`).

---

### 9. Why are API keys kept in `.env` rather than frontend JavaScript?
**Answer:**  
- **Credential Protection:** Frontend JavaScript runs in the user's browser, meaning anyone could inspect network traffic or view page source to steal secret API keys.
- **Rate-limit & Billing Abuse:** Exposing Anthropic keys client-side could lead to quota exhaustion or unauthorized financial charges.
- **Twelve-Factor App Methodology:** Secrets and environment-dependent configurations are kept isolated on the server in `.env` and excluded from source control via `.gitignore`.

---

### 10. Why is there no user registration or login in Version 1?
**Answer:**  
- **Privacy by Design:** Users checking if their personal data has been leaked are often hesitant to create an account, enter a password, or leave personal traces on a new website.
- **Zero Attack Surface:** By not implementing user databases or session tables, EchoRisk AI does not store sensitive email credentials on disk, meaning the application itself cannot become the target of a credential breach!
- **Viva Focus:** Keeps the project focused on core cybersecurity principles without distracting administrative overhead.

---

### 11. How does the hero illustration animation work and what technologies are used?
**Answer:**  
The hero illustration is built using **Pure Vector SVG (XML) and CSS3 Keyframe Animations** with **zero external animation libraries** (no Lottie, GSAP, or heavy GIF/video files), keeping it under 6 KB in size.

It operates on a **two-layer animation architecture**:
1. **Internal SVG Component Animations (`<defs><style>` inside `hero-illustration.svg`):**
   - **Sparkle Rays (`@keyframes raySparkle`):** Three radiance lines above the shield pulse from scale `0.92` to `1.12` with staggered delays (`0s`, `0.6s`, `1.2s`) to create an authentic shimmer.
   - **Floating Energy Dots (`@keyframes dotBlink`):** Ambient particles drift vertically (`translateY(-3px)`) and fade in/out with staggered delays.
   - **Organic Breathing Aura (`@keyframes auraFlow`):** The soft pastel background cloud smoothly scales (`scale(0.96 -> 1.03)`) and shifts position on an infinite 5-second alternating loop.
   - **Shield Gleam (`@keyframes shieldGleam`):** Dynamically pulses the drop-shadow intensity around the purple security badge.
2. **External Floating Levitation (`style.css`):**
   - **3D Continuous Float (`@keyframes heroLevitate`):** The entire `.hero-illustration-img` glides vertically (`translateY(-15px)`) and subtly rotates (`0.8deg`) on a `cubic-bezier(0.45, 0.05, 0.55, 0.95)` easing curve. Its shadow darkens and expands as it rises, creating realistic elevation depth.
   - **Interactive Hover (`:hover`):** Pauses the animation loop and lifts the illustration (`translateY(-18px) scale(1.04)`) with an expanded purple aura glow.

**Technical Advantages for Viva:**
- **GPU Hardware Accelerated:** Animates only `transform`, `opacity`, and `filter: drop-shadow`, which run directly on the browser's GPU compositor thread for a locked **60+ FPS with zero CPU layout reflows**.
- **Resolution-Independent:** Sharp and crisp at any display resolution (mobile, Retina, 4K).
- **Instant Load:** Requires 0ms JavaScript execution time because it renders natively via browser CSS.
