# 03 — Frontend Functionality Prompt

## Goal
Connect the landing page to the Flask backend and create the user-facing scan/report screens.

## Copy-paste prompt for Antigravity

```text
Continue the EchoRisk AI project. Do not redesign the existing UI. Keep the current simple purple-and-white visual style.

IMPLEMENT FRONTEND BEHAVIOR
1. The home page has an email input and "Check Now" button.
2. Validate that the input looks like a valid email.
3. On submit, disable the button and show a small loading indicator.
4. Send POST JSON to `/api/scan`:
   { "email": "user@example.com" }
5. Expect normalized JSON from the Flask backend.
6. Render a clean report section without reloading the page.
7. Provide a "Scan Another Email" action.
8. Preserve the landing page design.

REPORT UI
Show only useful information:
- Scan status: No known breaches found / Breaches found
- Total number of breaches
- Risk level
- Short risk summary
- Exposed data categories
- Breach list with name, date, exposed data and source/reference when available
- Recommended actions

REPORT DESIGN
- Use a simple summary card at the top.
- Use a small purple risk indicator, but do not use misleading precision.
- Use tags/chips for exposed data types.
- Use expandable or compact breach cards if the list is long.
- Keep the page readable for a college demo.

ERROR STATES
Handle:
- invalid email
- empty input
- API timeout
- provider failure
- Claude failure
- unexpected server response

SECURITY UX
- Never render a user's raw API key.
- Do not expose provider response objects directly to the browser if unnecessary.
- Escape/safely insert text into the DOM.

ACCESSIBILITY
- Use labels for form controls.
- Use buttons for actions.
- Add visible focus states.
- Maintain good color contrast.
- Use semantic HTML.

Do not add authentication or persistent user profiles.
```

## Expected result

The website should now feel like a real working product: the user enters an email, clicks one button, waits, and gets a readable report.
