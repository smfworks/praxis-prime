# COPPA pack

Starter policy. Not legal advice and not a verifiable parental-consent system.

Dial: `coppa`. Default: off.

Detectors match "under 13" and ages below 13 ("age 8", "7 years old"). "13 years old" and older ages do not match.

Enforce mode:

- routes only to providers flagged `local`
- denies browser, MCP, `web_fetch`, and Telegram egress
- treats a memory write as needing approval, which the store redacts instead of keeping the raw text
- uses a 30-day technical retention window

Citations recorded on the pack: 15 U.S.C. §§ 6501–6506 and 16 CFR Part 312.
