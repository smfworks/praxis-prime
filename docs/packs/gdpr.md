# GDPR pack

Starter policy. Not legal advice and not a lawful-basis determination.

Dial: `gdpr`. Default: off.

Detectors match special-category phrases such as "health data", "genetic data", "biometric data", "racial or ethnic origin", "political opinion", "religious belief", "trade union", and "sexual orientation". The word "health" alone does not match.

Enforce mode routes those prompts to providers flagged `local` or `eu_region`. `zero_retention` is recorded on providers but this pack does not treat it as enough for a Chapter V transfer. Telegram egress is denied. Memory is masked. The technical retention window is 30 days, carried forward from the existing memory default.

`praxis-prime gdpr export --subject` and `praxis-prime gdpr erase --subject` copy or delete local rows whose text contains the subject. The export includes the pack's lawful-basis reminder. The owner still has to choose and record a basis.

Citations recorded on the pack: Regulation (EU) 2016/679, Article 9, Articles 15 and 17, and Chapter V.
