# 02 — UI Design Prompt

## Goal
Build the clean purple-and-white frontend that matches the supplied reference style.

## Copy-paste prompt for Antigravity

```text
Now build the EchoRisk AI frontend based on the project plan and the reference UI style.

STYLE
Create a simple, professional, modern cybersecurity website. Do not make it look like a complex admin dashboard.

COLOR SYSTEM
- Primary purple: #6D28D9 or a close professional purple
- Secondary purple: #8B5CF6
- Light purple background accents: #F3E8FF / #F5F3FF
- Main text: dark navy #111827
- Secondary text: #667085
- White cards: #FFFFFF
- Borders: very light gray/lavender

LAYOUT
Top navigation:
- EchoRisk AI logo/wordmark on the left
- Home
- How It Works
- About
- Notify Me button on the right

Hero:
- Small security label such as "Your Digital Safety Matters"
- Main heading: "Check if Your Email Has Been Exposed"
- Make "Exposed" purple
- Short explanatory paragraph
- One email input
- One purple "Check Now" button
- Small privacy note under the form
- Simple shield + email illustration on the right

Feature section:
Create only 3 cards:
1. Breach Detection — check against trusted breach sources
2. Risk Assessment — understand the exposure level
3. Security Guidance — get practical next steps

How It Works section:
Use exactly 3 simple steps:
1. Enter your email
2. Check known breaches
3. View your security report

Footer:
- EchoRisk AI
- Short description
- Basic navigation links
- Simple privacy note

UI RULES
- Keep lots of whitespace.
- Use consistent 12–18px border radius.
- Use subtle shadows only.
- Avoid excessive gradients.
- Avoid glassmorphism.
- Avoid excessive icons.
- Avoid large graphs on the landing page.
- Make the main CTA visually obvious.
- Make the form responsive.
- On mobile, stack the hero into one column.

FUNCTIONAL FRONTEND
- Add client-side email validation.
- Show a loading state while scanning.
- Show a clear error message if the request fails.
- The form should call the Flask backend endpoint `/api/scan` using fetch().
- Keep API/provider logic out of frontend JavaScript.

FILES
Create clean reusable files such as:
- templates/index.html
- static/css/style.css
- static/js/app.js
- static/assets/...

Do not add a frontend framework. Use plain HTML, CSS, and JavaScript.
```

## Expected result

A simple responsive landing page matching the supplied screenshot style, but built from clean HTML/CSS/JS.
