# 01 — Project Planning Prompt

## Goal
Create the foundation and implementation plan for EchoRisk AI before writing the full UI and backend.

## Copy-paste prompt for Antigravity

```text
You are the lead developer for my college project called "EchoRisk AI — Email Data Breach Tracker".

Read this planning file completely before doing anything.

PROJECT PURPOSE
Build a simple, professional cybersecurity website where a user enters an email address and gets a clear report showing whether that email appears in known data breaches. The first version must be easy for a college student to understand, demonstrate, and explain in a viva.

TECH STACK
- Python backend using Flask
- HTML5
- CSS3
- Vanilla JavaScript
- XposedOrNot API for breach lookup
- Claude API for AI-generated risk explanation and security recommendations
- .env for API secrets
- No permanent user account system
- No scan-history database in version 1

IMPORTANT PRODUCT RULES
1. Keep the website simple and professional.
2. Use a white/light background with purple as the main accent color.
3. Do not make the UI visually complicated.
4. Do not add unnecessary animations, dashboards, charts, authentication, payment features, or social-login features.
5. The user should be able to scan an email from the home page in one obvious action.
6. Do not store the user's scanned email or breach report permanently by default.
7. API keys must never appear in frontend JavaScript.
8. The backend must call external APIs; the browser must call my Flask backend instead of directly exposing provider secrets.
9. Design the code so phone checking can be added later, but keep email checking as the main working feature.

REFERENCE UI DIRECTION
Use the reference style I provided:
- clean white/light background
- dark navy text
- purple gradient for primary buttons and highlights
- simple navigation
- large headline
- email input + Check Now button
- three simple feature cards
- generous whitespace
- rounded corners
- subtle shadows
- small shield/security illustration

CREATE NOW
1. Analyze the requirements.
2. Propose the exact folder structure.
3. Define Flask routes and responsibilities.
4. Define frontend pages/components.
5. Define the data flow from email input to final report.
6. Define the environment variables required.
7. Define a small JSON structure for normalized breach results.
8. Define error states and empty states.
9. Define a simple implementation order.

Do not write the complete application yet.
Create or update a developer-readable implementation plan in `PROJECT_IMPLEMENTATION_NOTES.md` and explain what will be built in each stage.
Keep all decisions practical for a college project and avoid unnecessary architecture.
```

## Expected result

Antigravity should create a concrete implementation plan and project structure without overengineering the project.
