# US state packs

Starter policy for the 13 state dials already in the catalog. Not legal advice. Several Praxis source profiles were marked established knowledge rather than a primary-source reading. These packs cite the public statute names and keep the day count as an internal SLA (`sla_is_legal_deadline = false`).

Each dial defaults to off. Enforce mode detects a structural SSN and an email next to a personal name (`US_PII`), asks before browser, MCP, `web_fetch`, or Telegram egress, redacts with the last four digits, and can store a breach record.

| Dial | State | Citations recorded on the pack |
|---|---|---|
| `state_ct` | Connecticut | Conn. Gen. Stat. § 36a-701b; Connecticut Data Privacy Act, Public Act 22-15 |
| `state_fl` | Florida | Fla. Stat. § 501.171 |
| `state_ga` | Georgia | O.C.G.A. §§ 10-1-910 to 10-1-915 |
| `state_ma` | Massachusetts | M.G.L. c. 93H; 201 CMR 17.00 |
| `state_md` | Maryland | Md. Code, Commercial Law §§ 14-3501 to 14-3508 |
| `state_nj` | New Jersey | N.J.S.A. 56:8-161 to 56:8-166 |
| `state_ny` | New York | N.Y. Gen. Bus. Law §§ 899-aa and 899-bb |
| `state_oh` | Ohio | Ohio Rev. Code § 1349.19 |
| `state_pa` | Pennsylvania | 73 P.S. §§ 2301–2329 |
| `state_sc` | South Carolina | S.C. Code Ann. § 39-1-90 |
| `state_tn` | Tennessee | Tenn. Code Ann. § 47-18-2107 |
| `state_va` | Virginia | Va. Code § 18.2-186.6; Va. Code §§ 59.1-575 to 59.1-585 |
| `state_wv` | West Virginia | W. Va. Code §§ 46A-2A-101 to 46A-2A-105 |

`praxis-prime breach record --pack state_ny` (or any of these ids) stores the same kind of local draft as the North Carolina command. Nothing is sent.
