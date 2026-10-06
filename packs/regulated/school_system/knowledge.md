# School System Pack — Knowledge Base

This knowledge base is ingested into the `pack:school_system` RAG namespace on pack activation. It grounds Praxis for **institutional** K-12 / district use across: FL, GA, SC, TN, VA, WV, MD, PA, OH, NJ, NY, CT, MA.

**Not the homeschool pack.** Homeschool is parent-educator autonomous. School system is **enforced** for licensed staff and LEA roles.

## 1. 13-state education quick reference

| State | Privacy / operator | AI signal | SPED note | Standout |
|---|---|---|---|---|
| FL | §1002.22/222 + **§1006.1494 SOPIPA** | §1002.321(3) closed AI + parent AI logs | §1003.57 + IDEA | 90-day operator delete; biometric ban |
| GA | §20-2-661–667 (verify) | Limited | IDEA | Operator-style privacy |
| SC | §59-1-490 data governance | Limited | IDEA | FERPA floor + DOE data rules |
| TN | Data Accessibility + SOPIPA (verify) | Limited | IDEA | Operator-style privacy |
| VA | **§22.1-289.01** school service providers | §22.1-70.2 AI-generated content in internet safety | §22.1-214/215 | Student PII breach §22.1-287.02 |
| WV | **§18-2-5h** | Affective computing **banned** | Policy 2419 | Vendor privacy clauses + penalties |
| MD | **Educ. §4-131** (2015) | MSDE AI guidance track | IDEA | SOPIPA-style operators |
| PA | FERPA + Ch. 12 records | No statewide AI statute verified | **22 Pa. Code Ch. 14** | Dense SPED procedure structure |
| OH | **§§3319.325–.327** | **§3301.24 AI policy by 2026-07-01** | OAC 3301-51 | 90-day return/destroy; district property |
| NJ | SOPPA-type (verify) | Limited | N.J.A.C. 6A:14 | Re-verify primary text |
| NY | **Ed Law §2-d + Part 121 ceiling** | Local + 2-d | Part 200 / Art. 89 | DPO, NIST, Bill of Rights, 7-day vendor breach, APPR in scope |
| CT | **CGS 10-234aa–dd** | Limited | BSE | Contracts **void** if missing clauses |
| MA | **603 CMR 23** + c.93H | **DESE AI Guidance** (human oversight) | 603 CMR 28 | Transcript **60 years**; temp ≤7 |

## 2. Governance line (non-negotiable)

- **Draft, don't decide FAPE/eligibility/placement/manifestation.** IEP team decides.
- **Never post final grades without educator attestation.**
- **Never SEND academic parent messages without staff approval.**
- **Never auto-file mandated reports** — remind only; human is reporter of record.
- **Never train foundation models on identifiable student PII** by default.
- **Never collect biometrics (FL) or affective computing (WV)** for school purposes.
- **Directory info is not free-for-all** — FERPA opt-outs apply.

## 3. FERPA + operator privacy

- Data classes: directory, education_record, special_education, staff_appr, behavioral.
- Prohibited purposes: commercial, targeted_advertising, model_training on PII.
- NY 2-d: written DPA, encryption at rest/in transit, Parents' Bill of Rights, NIST CSF, vendor→LEA breach ≤7 calendar days.
- CT: Model TOS clauses; board owns student data; Hub pledge ≠ compliance.
- FL/OH: operator deletion ≤90 days after student exit (on district notice) unless parent consents to retain.

## 4. Special education guardrails

- Track referral → eval → eligibility → IEP → annual → reeval against state timeline (typically 60 days).
- Goals/present levels without baseline data → mass-IEP risk flag.
- Transition planning at EducationProfile.transition_planning_age (often 14–16).
- Related services and accommodation **drafts** OK; placement/FAPE finalization blocked.

## 5. Educator attestation

| Artifact | Who may attest |
|---|---|
| grade_post | teacher_of_record, admin |
| iep_adoption / amendment | case_manager, admin |
| parent_academic_message | teacher, case_manager, admin, counselor |
| discipline_letter | admin |
| records_release | registrar, admin |
| mandatory_report_draft | draft only — never execute |

## 6. Parent portal triage

- Academic / SPED-sensitive / mixed / unknown → draft for staff (SEND held).
- Pure logistics + exact allowlisted template → may auto-reply.
- Free-form logistics → hold for staff.

## 7. Academic integrity

- Student-facing complete answers on graded/homework work → blocked.
- Teacher-facing lesson plans and formative scaffolds → allowed.
- OH districts: confirm AI tool is approved under the required AI policy.

## 8. Staff certification

- `credential_for(..., profession="teacher")` loads PD hours/cycle from EducationProfile when encoded (e.g. FL 120 pts / 5 years).
- Other states may show `no_requirement` for PD hours until hours are encoded; certification authority still tracked in notes.

## 9. What this pack does not do

- Replace SIS/LMS.
- Make high-stakes educational decisions.
- Act as student surveillance / emotion AI.
- Absorb the parent-homeschool pack.
