# North Carolina pack

Starter policy for the Identity Theft Protection Act, N.C.G.S. §§ 75-60 to 75-66. Not legal advice. Confirm with North Carolina counsel before relying on it.

Dial: `state_nc`. Default: off.

This pack encodes the technical controls from the verified Article 2A summary in ARCHITECTURE §17.2:

- Social Security numbers use the structural filter (not 000, 666, or 9xx). Enforce blocks them on shell, browser, MCP, `web_fetch`, and Telegram.
- Personal information also includes a card number that passes Luhn, an account number next to a checking or savings cue, a driver's-license label, and an email or phone next to a capitalized personal name.
- Redaction keeps the last four digits. A stricter dial that masks the same span wins.
- Disposal uses a 365-day technical retention window. The statute requires reasonable destruction and a policy. It does not set that number of days.
- `praxis-prime breach record --pack state_nc` stores a local incident row and a draft notice. The draft lists the starter § 75-65 fields, including FTC and NC Attorney General contacts. It is not sent. The 30-day clock is an internal SLA. § 75-65 says "without unreasonable delay" and does not fix 30 days. More than 1,000 persons adds a reminder about nationwide consumer reporting agencies.

Professional overlays (legal ethics, medical-board notes, education, homeschool, forensic) are not rules in this pack. SOURCE-NOTES §11 marks several of those rows as secondary or unverified.

§§ 75-63 and 75-63.1 (security freezes) are informational only.
