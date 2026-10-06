# Law Firm Pack — Knowledge Base

This knowledge base is ingested into the `pack:law_firm` RAG namespace on pack activation. It grounds Praxis's legal-research and matter-management outputs across the 13 states the pack covers: FL, GA, SC, TN, VA, WV, MD, PA, OH, NJ, NY, CT, MA.

## 1. The 13-state quick reference

| State | Bar / Governing Rules | CLE | Ad-filing? | Data-security tier | IOLTA | UPL statute |
|---|---|---|---|---|---|---|
| FL | The Florida Bar (integrated); FL Rules of Prof. Conduct | 33/3yr (5 ethics) | **Yes** (The Florida Bar) | breach-notification | required | Ch. 454 |
| GA | State Bar of GA (integrated); GA Rules of Prof. Conduct | 12/yr (1 ethics) | No | breach-notification | required | O.C.G.A. §15-19-9 |
| SC | SC Bar (unified); SC Rules of Prof. Conduct | 14/yr (2 ethics) | No | breach-notification | required | §40-5-310 |
| TN | TN Bar Assn (voluntary); Board of Professional Responsibility | 15/yr (1 ethics) | No | breach-notification | required | T.C.A. §23-3-603 |
| VA | VA State Bar (integrated); VA Rules of Prof. Conduct | 12/yr (2 ethics) | No | breach-notification | required | §54.1-3904 |
| WV | WV State Bar (integrated); WV Rules of Prof. Conduct | 24/2yr (3 ethics) | No | breach-notification | required | WVC §30-2-4 |
| MD | MD State Bar (voluntary); Attorney Grievance Commission | required (verify hours) | No | breach-notification | required | §10-601 |
| PA | PA Bar Assn (voluntary); Disciplinary Board of PA | 12/yr (1 ethics) | No | breach-notification | required | 42 Pa.C.S. §2521 |
| OH | OH State Bar (voluntary); Office of Disciplinary Counsel | 24/2yr (2.5 ethics/yr) | No | breach-notification | required | ORC §4705 |
| NJ | NJ State Bar (voluntary); Office of Attorney Ethics | 24/2yr (4 ethics) | No | breach-notification | required | N.J.S.A. 2C:21-21 |
| NY | NYSBA (voluntary); 22 NYCRR Part 1200 | 24/2yr (4 ethics, 1 cyber) | **Yes** (Appellate Division — strictest in nation) | **SHIELD obligation** | required | Judiciary Law §478 |
| CT | CT Bar (voluntary); Statewide Grievance Committee | 12/yr (2 ethics) | No | breach-notification | required | §51-88 |
| MA | MBA (voluntary); Board of Bar Overseers | **None** (no mandatory CLE) | No | **WISP mandate** (201 CMR 17.00) | required | c. 221 §41 |

All 13 states prohibit non-lawyer ownership of law firms (no MDP). All 13 require attorney supervision of non-lawyer staff (Rule 5.3 equivalent). All 13 require IOLTA.

## 2. Attorney-advertising filing (NY + FL only)

**NY — 22 NYCRR Part 1200, Rules 7.1-7.5 (strictest in the nation):**
- Solicitation materials must be filed with the Attorney Advertising Registration Unit of the Appellate Division.
- "Attorney Advertising" label required on envelopes and the first page of written solicitation.
- Mandatory disclaimer: "Prior results do not guarantee a similar outcome."
- Restrictions on testimonials, portrayals of judges, fictitious names.
- Website-specific rules apply.

**FL — Florida Rules of Prof. Conduct, Rules 4-7.1 to 4-7.5:**
- Filing required with The Florida Bar.
- Content and format restrictions; disclaimers required.

**The other 11 states (GA, SC, TN, VA, WV, MD, PA, OH, NJ, CT, MA): no filing required.**

When the matter's jurisdiction is NY or FL, the `advertising_filing` module's `validate_before_send` gate activates automatically. Missing label = critical. Missing disclaimers = critical. Draft status (not yet filed) = high. Filed without a filing number = high. Rejected = critical. The SEND approval cannot proceed with critical/high findings.

## 3. Data-security tiers

**MA 201 CMR 17.00 — WISP mandate (the strictest):**
- Written Information Security Program (WISP) required.
- Encryption of personal information at rest and in transit.
- Employee security training, current.
- Breach-notification procedure documented.
- The Praxis controls that evidence this: data classification, egress allowlist, redaction gate, sandbox isolation, audit trail.
- Citation: 201 CMR 17.00 §17.03-17.04; M.G.L. c. 93H §3.

**NY SHIELD Act — affirmative security obligation:**
- Reasonable administrative, technical, and physical safeguards for private information of NY residents.
- Accepts documented safeguards (e.g., data classification + encryption + breach procedure) in lieu of a WISP document.
- Breach notification: GBL §899-aa (30-day deadline).
- Safeguards duty: GBL §899-bb.

**The other 11 states — breach-notification only:**
- No proactive security standard; breach notification required on a breach.
- Minimal attestation: a documented breach-notification procedure.

The `security_attestation` module's `attest(state, controls)` returns a per-jurisdiction `SecurityAttestation` with findings + pass/fail. MA demands the full WISP+encryption+training set; NY demands reasonable safeguards; the rest demand only a breach procedure.

## 4. Privilege-basis reference (for privilege logs)

| Basis | When to use |
|---|---|
| attorney_client | Direct attorney-client communication for legal advice (RPC 1.6 confidentiality / attorney-client privilege). |
| work_product | Material prepared in anticipation of litigation (work-product doctrine). |
| attorney_work_product | Hickman v. Taylor / state-equivalent attorney work-product. |
| joint_defense | Shared under a joint defense / common interest agreement. |
| common_interest | Common interest privilege. |
| other | Other privilege — specify in the basis detail. |

The `discovery_templates` module's `PrivilegeLog` produces the standard discovery format with one row per withheld document: Bates number, date, author, recipients, document type, description, privilege basis, basis detail, redaction note.

## 5. Expert-witness disclosure (Rule 26(a)(2) / state equivalent)

The federal Rule 26(a)(2)(B) disclosure requires six sections:
1. **Qualifications** — education, licenses, experience.
2. **Subject matter of testimony** — what the expert will address.
3. **Basis for opinion** — the facts/data considered.
4. **Compensation** — billing rate / arrangement.
5. **Prior testimony list** — cases, courts, years, roles (last four years).
6. **Exhibits / authored documents** — the artifact ids.

State variants are largely the same. The `discovery_templates` module's `render_expert_disclosure` surfaces the jurisdiction's governing rules from the 13-state registry and adapts the format.

## 6. The UPL guardrail

Praxis does **not** provide legal advice, form an attorney-client relationship, or guarantee outcomes. Every client-facing output routes as a draft for attorney review and approval before sending. The unauthorized practice of law is criminally enforceable in every US jurisdiction. The governance broker enforces this: SEND-class outputs are held for attorney approval (dual approval with DESTRUCTIVE). Praxis is a tool used BY licensed attorneys, never a legal-service provider.

## 7. Trust accounting guardrail

Praxis is a knowledge and work platform, not accounting software. IOLTA / client trust accounts are out of scope. Do not use Praxis for trust accounting. The tool allowlist excludes any trust-ledger tool. All 13 states require IOLTA; Praxis never touches client trust funds.

## 8. Legal-hold workflow

When a litigation hold duty arises on a matter:
1. **Issue** a matter-wide hold with scope, reason, custodian, and issued_by.
2. Route to the custodian for **acknowledge** (they confirm preservation).
3. Surface the hold on the matter dashboard; block any deletion proposal for in-scope records.
4. On **release**, record released_by + release_reason with audit.

The `legal_hold` module's `LegalHoldLedger` enforces the state machine: issued → acknowledged → released (or withdrawn before ack). `matter_under_hold(matter_id)` is the query downstream disposition paths call to block deletion under hold.

## 9. CE/PDH credential tracking

12 of 13 states require CLE for attorneys (MA is the only exception). All 13 require PDH for PEs (relevant when a law firm retains engineering experts). The `credentials` module:
- Tracks per-attorney credentials with per-state requirements sourced from the 13-state registry.
- `compliance_status` returns current / expiring_soon / expired / ce_deficient / no_requirement.
- For MA attorneys: `no_requirement` (no mandatory CLE) — a valid state, not a gap.
- `CredentialLedger.renew` resets or carries hours into a new cycle.