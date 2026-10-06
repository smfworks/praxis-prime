# Compliance dials

Starter policy for a local agent. It is not legal advice, a certification, a business associate agreement, or a completed data-subject response. Confirm controls with counsel before you rely on them.

Dials default to **off**. A fresh config does not detect, redact, route, or block anything beyond the baseline approval spine. The spine (send, spend, share, destructive) stays on. No dial can turn it off.

## Modes

| Position | Behavior |
|---|---|
| `off` | The dial adds nothing. |
| `monitor` | Detectors may match. The audit log records a warning. The action still runs. |
| `enforce` | The strictest matching rule wins: block, require approval, redact, pin providers, or deny egress. Retention windows apply on the memory sweep. |

Dials compose by intersection. A hook, skill, MCP server, or Decision Engine answer cannot loosen an enforce result. Only the owner config (`[dials]` in `config.toml`) changes a position. A change after the first recorded snapshot is an audit event of kind `dial_change`.

## One engine

`praxis_prime.policy.PolicyEngine` evaluates, in order, the baseline spine and then the active packs:

| Surface | Hook |
|---|---|
| User text and routine prompts | H1 |
| Model prompt, and the provider pin | H2 |
| Tools, including `browser`, `web_fetch`, and `mcp__…` | H3 |
| Tool output and model text | H4 |
| Owner-bound Telegram delivery | H5 |
| Session persist and memory redact | H6 |
| Retention sweep | H7 |

Pack rules name the hooks they apply to. A hit on a hook the rule does not list is audited and does not block.

Decision Engine tier 0 reads the same detectors. It may add a data class. It cannot clear one.

## Packs

Bundled TOML lives in `packs/compliance` and is shipped inside the wheel. The same pack id in `~/.config/praxis-prime/packs` or `<project>/.prime/packs` replaces the bundled file. Each pack carries detectors, rules, a retention window, required audit events, and legal citations in its metadata.

| Pack | Dial | What enforce does |
|---|---|---|
| HIPAA | `hipaa` | 18 safe-harbor-style identifiers. PHI routes only to providers flagged `local` or `baa`. External tools and Telegram are denied. Memory and tool output are masked. |
| FERPA | `ferpa` | Education-record phrases and student ids. Egress asks. Memory is masked. |
| COPPA | `coppa` | Under-13 signals. Local models only. Third-party egress denied. Memory writes require approval, which the store treats as redaction. Short retention. |
| GDPR | `gdpr` | Special-category phrases. Providers must be `local` or `eu_region`. `zero_retention` alone is not a transfer basis in this pack. Export and erase commands. Lawful-basis reminder. |
| 13 states | `state_ct` … `state_wv` | SSN and named email. Send asks. Breach records. The 30-day figure is an internal SLA, not a statement of each statute's deadline. |
| North Carolina | `state_nc` | N.C.G.S. §§ 75-60 to 75-66 as technical controls: SSN egress block, last-four redaction, breach draft, disposal window. |
| PCI | `pci` | Luhn-valid card numbers. Egress denied. Last four kept in redaction. |
| SOC 2, EU AI Act, CCPA/CPRA, NIST AI RMF, ISO/IEC 42001 | matching dial ids | Metadata only. CCPA access and delete use the GDPR export and erase commands. |

Per-pack notes are in [docs/packs](packs/).

Provider flags are `local`, `baa`, `eu_region`, and `zero_retention`, under `[models.providers.<name>]`. Ollama is local. An OpenAI-compatible base URL on `127.0.0.1`, `localhost`, or `::1` is local. Other providers are not, until the owner sets a flag. Flags are claims the owner records. The pack does not verify a BAA or a region.

If enforce needs a flagged provider and none is in the chain, the model call is blocked and the reason names the data class and the missing flags.

## Commands

```bash
praxis-prime compliance status
praxis-prime compliance packs
praxis-prime compliance test "patient MRN AB12345"
praxis-prime compliance explain 12
praxis-prime compliance report --since 2026-01-01T00:00:00+00:00
praxis-prime compliance report --format html
praxis-prime gdpr export --subject ada@example.com
praxis-prime gdpr erase --subject ada@example.com
praxis-prime breach record --pack state_nc --summary "laptop lost" --affected 12
praxis-prime breach list
```

`compliance test` prints matches even when the dial is off, and labels those as inactive. It does not change config.

`gdpr export` prints memory rows and transcript messages that contain the subject. `gdpr erase` deletes those rows and writes a retention audit event with a hash of the subject, not the subject. The lawful-basis note from the GDPR pack is included in the export. It does not choose a basis.

`breach record` stores a local row and a notice draft. It does not send anything. North Carolina drafts list the starter § 75-65 fields, including FTC and NC Attorney General contacts. More than 1,000 persons adds a consumer-reporting-agency reminder. The 30-day SLA in the NC pack is a policy choice. The statute says "without unreasonable delay" and does not set that number.

`compliance report` summarizes detections, blocks, approvals, and retention actions already in the audit log.

## Memory and retention

Enforce redacts on memory write using the pack's style. HIPAA masks. North Carolina keeps the last four digits unless a stricter dial also matches, in which case the mask wins. Monitor does not add a new redaction path beyond the redaction mode already configured (`secrets` or `pii`). HIPAA, FERPA, and GDPR monitor still use those existing patterns.

The retention sweep deletes rows whose `expires_at` has passed. Enforce dials contribute their pack window. The shortest window wins. Profile and semantic rows expire only when an enforce dial sets one. A sweep that removes rows while an enforce dial is on writes a `retention` audit event.

## Vertical packs

The six public MIT packs (homeschool, education, forensic, legal, medical, behavioral health) ship as data under `packs/regulated/` and in the wheel. `praxis-prime packs install <name>` copies that bundled data. It does not clone git, and it does not turn a dial on. Hard-coded model pins are removed from the vendored `pack.json` and still ignored if a later pack includes one. Dashboard JavaScript and pack Python are not in the tree and are not loaded. See [PACKS-LEGACY.md](PACKS-LEGACY.md).

`packs/compliance/*.toml` ships inside the wheel. A file with the same pack id in `~/.config/praxis-prime/packs` or `<project>/.prime/packs` replaces the bundled pack. North Carolina professional overlays that SOURCE-NOTES §11 marks S or U are not encoded as rules.

## Audit

Compliance findings are kind `compliance`. Payloads list the dial, data class, rule id, hook, and decision. They do not store the matched identifier. Mode changes are kind `dial_change`. Breach rows also append kind `breach`.
