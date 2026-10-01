# 07 — Testing, Security and Final Polish Prompt

## Goal
Make the college project stable, understandable, and ready for demonstration.

## Copy-paste prompt for Antigravity

```text
Finish the EchoRisk AI project without changing the overall visual design.

FINAL CHECKLIST
1. Run the Flask app locally.
2. Verify `/health`.
3. Verify the home page loads.
4. Test valid email input.
5. Test empty input.
6. Test invalid email input.
7. Test no-breach response.
8. Test breach-found response.
9. Test provider timeout/failure.
10. Test Claude failure with fallback report.
11. Test a long breach list.
12. Test mobile width and desktop width.
13. Verify keyboard navigation and visible focus states.
14. Verify no API keys appear in HTML, JS, Git-tracked files, or screenshots.
15. Verify `.env` is in `.gitignore`.
16. Verify `.env.example` contains placeholder names only.
17. Verify emails and provider responses are not being written to logs.
18. Check that user-facing wording is clear and not alarmist.
19. Check that the report does not expose unnecessary personal information.
20. Add XposedOrNot attribution where required by current provider terms.

CODE QUALITY
- Remove duplicate code.
- Keep functions small.
- Add simple comments only where helpful.
- Use meaningful names.
- Keep the project easy to explain in a college viva.

README
Create or update `README.md` with:
- project overview
- features
- technology stack
- folder structure
- how to install dependencies
- how to configure `.env`
- how to run Flask
- how the data flow works
- privacy notes
- API/provider notes
- known limitations

VIVA SECTION
Also create `VIVA_NOTES.md` containing:
- What is EchoRisk AI?
- Why Flask?
- Why HTML/CSS/JavaScript?
- How XposedOrNot is used?
- Why is Claude used?
- Why is the breach lookup performed before AI reasoning?
- What happens when there is no breach?
- What happens when an API fails?
- Why are API keys kept in `.env`?
- Why is there no login in version 1?

Do not introduce new product features at this stage. Focus on correctness, polish and demo readiness.
```

## Expected result

A polished, demonstrable, privacy-conscious college project with documentation and viva notes.
