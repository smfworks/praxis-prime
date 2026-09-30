# HIPAA pack

Starter policy. Not legal advice, a BAA, or a certification.

Dial: `hipaa`. Default: off.

The detectors follow the categories in 45 CFR 164.514(b)(2): names tied to a patient-name label, street addresses near a patient or PHI cue, dates of birth, phone and fax, email, Social Security numbers, medical record numbers, health-plan beneficiary numbers, account numbers, certificate or license numbers, vehicle identifiers, device identifiers, URLs, IP addresses, biometric phrases, and National Provider Identifiers.

Weak identifiers require a nearby cue so a bare email or phone number is not treated as PHI. SSN checks reject area 000, 666, and 900–999, group 00, and serial 0000. NPI uses the CMS Luhn check with the 80840 prefix.

Enforce mode:

- routes prompts to providers flagged `local` or `baa`
- blocks the call when none of those providers is in the chain
- denies PHI on `browser`, `mcp__` tools, `web_fetch`, and Telegram
- masks PHI in tool output and memory

The retention window is 2190 days, the six-year documentation figure in 45 CFR 164.530(j), used here as a technical window.

Citations recorded on the pack: 45 CFR 164.514(b)(2), 164.502(b), 164.530(j), and 164.404.
