# Mental/Behavioral Health Pack — Knowledge Base

**Not legal or clinical advice.** Verify every jurisdiction fact with your state board and counsel. Praxis does not diagnose, determine treatment, establish a therapeutic relationship, or decide that a duty to warn applies.

This knowledge base is ingested into the `pack:behavioral_health` RAG namespace on pack activation. It grounds Praxis's clinical-documentation and compliance outputs across the 13 states the pack covers: FL, GA, SC, TN, VA, WV, MD, PA, OH, NJ, NY, CT, MA.

## 1. The 13-state mental/behavioral health quick reference

| State | Board | Duty to warn | SCR window (child) | Minor MH consent age | Retention (adult/minor) | Data-security |
|---|---|---|---|---|---|---|
| FL | FL Board of CSW/MFT/MHC | mandatory duty (notify law enforcement; victim warning is permissive) | 24h | 13 | 5yr / 7yr | breach-notification |
| GA | GA Composite Board (Counselors/SW/MFT) | case-law only (unverified on the court site) | 24h | 13 | 5yr / 7yr | breach-notification |
| SC | SC Board of SW Examiners (LLR) | case-law only | 24h | 14 | 5yr / 7yr | breach-notification |
| TN | TN Health Related Boards (SW) | mandatory duty | 24h | 13 | 7yr / 7yr | breach-notification |
| VA | VA Board of Counseling (DHP) | mandatory duty | 24h | 14 | 6yr / 3yr | breach-notification |
| WV | WV Board of SW Examiners | permissive disclosure | 24h | 14 | 5yr / 7yr | breach-notification |
| MD | MD Board of SW / Professional Counselors | mandatory duty | 24h | 14 | 5yr / 7yr | breach-notification |
| PA | PA State Board of SW/MFT/PC | case-law only | 24h | 14 | 7yr / 21 | breach-notification |
| OH | OH Counselor/SW/MFT Board | mandatory duty | 24h | 14 | 5yr / 7yr | breach-notification |
| NJ | NJ Board of SW Examiners / MFT | mandatory duty | 24h | 14 | 6yr / 21 | breach-notification |
| NY | NYSED Office of the Professions (SW/MHP) | mandatory duty (SAFE Act report, not a victim warning) | 24h | 14 | 6yr / 21+ | **SHIELD obligation** |
| CT | CT DPH (SW/Counseling/MFT) | permissive disclosure | 24h | 14 | 6yr / 21 | breach-notification |
| MA | MA Board of SW / Allied MH | mandatory duty | 24h | 14 | 7yr / 21+ | **WISP mandate (201 CMR 17.00)** |

Note: CA (outside the 13-state registry) is the canonical Tarasoff-codified jurisdiction (Cal. Civ. Code §43.92); the gate module carries a CA profile for the duty-to-warn eval. The national duty table, including trigger, discharge, professions, source URL, and the 2026-09-30 check date, is in section 10. Rows marked unverified are not guesses filled in with a citation.

## 2. Governance line (non-negotiable)

- **Never write to the clinical record autonomously.** Treatment-plan and progress-note drafts route for clinician attestation (`treatment_planning_attestation` / `psychotherapy_notes_governance`).
- **Never draft psychotherapy notes.** Psychotherapy notes are the clinician's private process notes; Praxis may draft progress notes only (45 CFR §164.508).
- **Never diagnose, determine treatment, or establish a therapeutic relationship.** Praxis is a documentation and compliance assistant, not a clinician.
- **Never contact a victim, law enforcement, or a hospital autonomously.** Duty-to-warn/protect protective action is SEND-held for clinician approval; the clinician — not Praxis — decides whether the duty applies.
- **Never file a mandated report as the reporter of record.** Praxis drafts the scaffold; the clinician files with the SCR (SEND-held).
- **PHI = minimum necessary.** HIPAA purpose-of-use + accounting-of-disclosures + breach workflow (reuses the medical vertical's HIPAA governance).
- **42 CFR Part 2 for SUD records.** Specific written consent for most disclosures; general HIPAA TPO consent does NOT cover Part 2 records; re-disclosure prohibition notice must accompany every permitted Part 2 disclosure; law enforcement / bare subpoena need a qualifying court order.
- **Minor consent for MH:** apply the state's age floor to record access; parent access to self-consented confidential MH encounters requires the minor's authorization.

## 3. Duty to warn / protect (Tarasoff-line)

1. **Credible serious threat of physical violence against a reasonably identifiable victim** triggers a duty analysis.
2. State standard, from the researched table: mandatory duty, permissive disclosure, case-law only, or no duty or none found. California remains the codified Tarasoff statute (Cal. Civ. Code §43.92). A permissive statute allows disclosure and does not, by itself, require it.
3. Praxis surfaces the standard + citation and routes protective action (warn victim / notify law enforcement / hospitalize) to the clinician — SEND-held.
4. Known history of violence + stated intent to act elevate the finding to critical.
5. Suicidal crisis (separate) triggers a safety-plan scaffold, not a duty-to-warn report; civil-commitment standard surfaced from the state profile.

## 4. Mandated reporting

- All licensed MH professionals are mandated reporters in all 13 states.
- Child abuse: file with the state SCR within 24h (36h CA) of disclosure.
- Praxis drafts the report scaffold; the clinician is the reporter of record; filing is SEND-held.
- Dependent-adult and elder abuse follow the same workflow with the appropriate recipient (APS).

## 5. 42 CFR Part 2 (SUD records)

- Applies to federally assisted SUD treatment programs in every state.
- Specific written consent required for most disclosures (recipient, purpose, amount, expiration).
- General HIPAA TPO consent does NOT authorize Part 2 disclosures.
- Re-disclosure prohibition: the recipient may not re-disclose without new specific authorization; the notice MUST accompany every permitted disclosure.
- Law enforcement / bare subpoena: require a qualifying Part 2 court order (§2.65), not just consent.

## 6. Psychotherapy notes (45 CFR §164.508)

- Psychotherapy notes = the clinician's private, process-oriented notes documenting the content of a counseling session, kept separate from the rest of the record.
- Specific authorization required for any use or disclosure beyond the clinician's own treatment use.
- Praxis NEVER drafts psychotherapy notes — only progress notes.
- Patient-access carve-out: 45 CFR §164.528 limits the patient's right to inspect psychotherapy notes (specific authorization required to disclose).
- A payer cannot demand psychotherapy notes without specific authorization.

## 7. Minor consent for MH

- State age floors: FL=13, GA=13, SC=14, TN=13, VA=14, WV=14, MD=14, PA=14, OH=14, NJ=14, NY=14, CT=14, MA=14 (outpatient MH; some cap sessions or require parent notification after N sessions).
- Self-consented confidential MH encounters: parent portal/record-release access denied without the minor's authorization.
- Minor self-access and provider treatment access remain allowed.
- Psychotherapy notes need their own specific authorization regardless of the minor-consent gate.

## 8. Records retention + patient access

- Adult retention: 5–7 years from last visit (state-specific).
- Minor: often until age 21 or N years after last visit, whichever longer.
- Patient access deadlines: NY/MA = 10 days; FL/VA = 15; NJ = 7; MD = 21; others HIPAA 30-day floor.
- Psychotherapy notes carry the patient-access carve-out (45 CFR §164.528).
- Part 2 SUD records carry the re-disclosure prohibition indefinitely — retention does not extinguish Part 2 protections.
- Legal hold blocks disposal. Praxis never deletes autonomously (DESTRUCTIVE, dual approval).

## 9. Civil commitment (decision-support only)

- Praxis surfaces the state's civil-commitment standard (danger to self/others, gravely disabled, inability to care for self) when a patient is in acute crisis.
- Praxis never initiates an involuntary hold autonomously — clinician + facility action, SEND-held.
- Standards: FL Baker Act, GA, SC, TN, VA, WV, MD, PA (clear and present danger), OH, NJ, NY (likelihood of serious harm), CT, MA (likelihood of serious harm), CA LPS §5150.

## 10. Duty to warn / protect — 50 states and the District of Columbia

**Not legal or clinical advice. Verify with your state board and counsel.** Checked 2026-09-30.

### Sources and methodology

Each row was checked on 2026-09-30 against a primary source: the official state code or session laws, or an official court opinion. Secondary summaries were used only to find a citation, then the official page was opened. A row with `verified: false` means the official text could not be opened, the search did not cover every relevant license chapter, or the sources conflict. Those rows record what was actually read. They do not invent a citation.

Classifications:

- **mandatory duty** — a statute or binding opinion requires protective action when the trigger is met. An immunity statute that imposes a duty in the exception (no liability unless a communicated threat is followed by a failure to take the listed steps) is a mandatory duty.
- **permissive disclosure** — confidentiality may be breached to warn or protect, and no binding duty was verified.
- **case-law only** — the duty comes from a judicial opinion; no duty statute was verified.
- **no duty or none found** — no duty statute or binding duty opinion was verified. That is an absence of a finding on this check, not a holding that no duty exists.

The machine-readable table is `hybridagent_praxis_mbh.modules.duty_to_warn_registry`. Practice profiles (board, minor consent, retention) remain the 13-state registry plus California.

| State | Classification | Verified | Citation |
|---|---|---|---|
| AL | no duty or none found | no | Ala. Code §34-26-2 (psychologist privilege; no duty language verified) |
| AK | permissive disclosure | yes | AS 08.86.200(a)(3); AS 08.29.200(a)(1); AS 08.63.200(a)(5); AS 08.95.900(a)(6) |
| AZ | mandatory duty | yes | A.R.S. §36-517.02 |
| AR | mandatory duty | yes | Ark. Code Ann. §§20-45-201 and 20-45-202 (Act 1212 of 2013) |
| CA | mandatory duty | yes | Cal. Civ. Code §43.92; Tarasoff v. Regents of Univ. of Cal., 17 Cal.3d 425 (1976) |
| CO | mandatory duty | yes | C.R.S. §13-21-117 |
| CT | permissive disclosure | yes | Conn. Gen. Stat. §52-146f(2) (2026 supplement) |
| DE | mandatory duty | yes | 16 Del. C. §§5401–5402 |
| DC | permissive disclosure | yes | D.C. Code §7-1203.03 |
| FL | mandatory duty | yes | Fla. Stat. §§456.059, 490.0147(2), 491.0147(2) (2026) |
| GA | case-law only | no | Bradley Center, Inc. v. Wessner, 250 Ga. 199, 296 S.E.2d 693 (1982) |
| HI | permissive disclosure | yes | Haw. Rev. Stat. §626-1, Rule 504.1(d)(6); Haw. Rev. Stat. §453D-13(2) |
| ID | mandatory duty | yes | Idaho Code §§6-1901 to 6-1904 |
| IL | mandatory duty | yes | 405 ILCS 5/6-103(b), (c) |
| IN | mandatory duty | yes | Ind. Code §§34-30-16-1 and 34-30-16-2 |
| IA | mandatory duty | yes | Iowa Code §228.7A (2026) |
| KS | permissive disclosure | yes | K.S.A. 65-5603(a)(6) |
| KY | mandatory duty | yes | KRS 202A.400 |
| LA | mandatory duty | yes | La. R.S. 9:2800.2 |
| ME | mandatory duty | yes | 32 M.R.S. §§2600-F, 3300-I, 3820, 6207-C, 7007, and 13867 |
| MD | mandatory duty | yes | Md. Code, Cts. & Jud. Proc. §5-609 |
| MA | mandatory duty | yes | M.G.L. c. 123, §36B |
| MI | mandatory duty | yes | MCL 330.1946 |
| MN | mandatory duty | yes | Minn. Stat. §§148.975, 148E.240 subd. 6, 148B.391, 148B.593, and 148F.13 subd. 2 |
| MS | permissive disclosure | yes | Miss. Code Ann. §41-21-97(1)(e) (2023 S.B. 2797, Laws 2023, ch. 337) |
| MO | case-law only | yes | Bradley v. Ray, 904 S.W.2d 302 (Mo. App. 1995) |
| MT | mandatory duty | yes | MCA 27-1-1102 |
| NE | mandatory duty | yes | Neb. Rev. Stat. §§38-2137 and 38-3132 |
| NV | mandatory duty | yes | NRS 629.550 |
| NH | mandatory duty | yes | RSA 329:31, RSA 329-B:29, and RSA 330-A:35 |
| NJ | mandatory duty | yes | N.J.S.A. 2A:62A-16 (P.L. 2018, c.34; P.L. 2019, c.59) |
| NM | permissive disclosure | yes | NMSA 1978, §§43-1-19(B)(2) and 32A-6A-24(D)(2) (2024 S.B. 230) |
| NY | mandatory duty | yes | N.Y. Mental Hyg. Law §9.46 |
| NC | permissive disclosure | yes | N.C.G.S. §122C-55(d) |
| ND | mandatory duty | yes | N.D.C.C. §43-53-11(2)–(4) |
| OH | mandatory duty | yes | Ohio Rev. Code §2305.51 (eff. Apr. 9, 2025) |
| OK | case-law only | yes | Wofford v. Eastern State Hospital, 1990 OK 77, 795 P.2d 516, as stated in later Oklahoma Supreme Court opinions on OSCN |
| OR | permissive disclosure | yes | ORS 179.505(12) (2025); ORS 40.252 (2025) |
| PA | case-law only | yes | Emerich v. Philadelphia Center for Human Development, Inc., 554 Pa. 209, 720 A.2d 1032 (1998) |
| RI | permissive disclosure | no | R.I. Gen. Laws §5-39.1-4(a)(2) |
| SC | case-law only | yes | Bishop v. South Carolina Dep't of Mental Health, 331 S.C. 79, 502 S.E.2d 78 (1998), as stated in Doe v. Marion, 373 S.C. 390, 645 S.E.2d 245 (2007) |
| SD | mandatory duty | yes | SDCL 36-32-77 (licensed professional counselors); SDCL 36-33-55 (licensed marriage and family therapists) |
| TN | mandatory duty | yes | Tenn. Code Ann. §33-3-206 (2024 Tenn. Pub. Ch. 783); discharge also §33-3-207 (2024 Tenn. Pub. Ch. 761) |
| TX | permissive disclosure | yes | Tex. Health & Safety Code §§611.002(b-1), 611.004(a)(2), 611.004(a-1) |
| UT | mandatory duty | yes | Utah Code §§78B-3-501 and 78B-3-502 |
| VT | mandatory duty | yes | 18 V.S.A. §1882 (2017, No. 51, §2), incorporating Peck v. Counseling Service of Addison County, Inc., 146 Vt. 61 (1985) |
| VA | mandatory duty | yes | Va. Code §54.1-2400.1 |
| WA | mandatory duty | yes | RCW 71.05.120(3) |
| WV | permissive disclosure | yes | W. Va. Code §27-3-1(b)(5) |
| WI | case-law only | yes | Schuster v. Altenberg, 144 Wis. 2d 223, 424 N.W.2d 159 (1988), as quoted in Milwaukee Deputy Sheriff's Ass'n v. City of Wauwatosa, 2010 WI App 95 |
| WY | permissive disclosure | yes | W.S. 33-38-113(a)(iv) (2023 Wyo. Sess. Laws, Enrolled Act No. 39); W.S. 33-27-123(a)(iv) (2022 Wyo. Sess. Laws, Enrolled Act No. 18) |

Trigger, discharge, covered professions, source URL, check date, and any unverified note are on each `DutyToWarnEntry` in the registry. Do not treat an unverified row as settled law.
