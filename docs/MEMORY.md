# Memory

Tier 1 is the session transcript already stored in `prime.db`. This milestone adds three more tiers in the same file. There is no separate vector database.

ARCHITECTURE §10 numbers these differently: episodic as tier 2, semantic facts (including a profile) as tier 3, and procedural skills as tier 4. Skills stay files (ARCHITECTURE §9). The numbers below are the ones this milestone stores and prints.

| Tier | Kind | What is stored | How it is used |
|---|---|---|---|
| 2 | `profile` | Short durable facts | Copied into every prompt, newest first, capped |
| 3 | `episodic` | One dated summary per session and scope | Written when a turn finishes. Search rank decays with age |
| 4 | `semantic` | Notes you ask to remember | BM25, plus a local embedding when one is configured |

The default caps are 20 profile facts and 4000 characters (`memory.profile_cap`, `memory.profile_chars`). Episodic rank uses a 14-day half-life (`memory.episodic_half_life_days`). The same normalized text in the same tier and scope is one row: a repeat bumps `updated_at` and does not insert a second copy.

## Scopes

`global`, `project` (stored as `project:<resolved path>`), and `channel` (stored as `channel:<name>`). A chat turn searches global, the current project, and the channel when the turn has one. Telegram sets the channel to `telegram`.

## Tools and CLI

The agent can call `remember`, `forget`, and `recall`. `remember` writes `profile` or `semantic`. Episodic rows are written by the loop, not by that tool.

```bash
praxis-prime memory list
praxis-prime memory list --tier profile --scope global
praxis-prime memory search "deployed api"
praxis-prime memory forget mem_0123abcd
praxis-prime memory forget --match oolong --scope global
praxis-prime memory forget --before 2026-01-01T00:00:00+00:00
praxis-prime memory export
```

`forget` deletes matching rows. It does not rewrite the audit log.

## Embeddings

`models.embed` defaults to `local:bge-small`. That name is not downloaded, and recall uses BM25, which needs no model. Set `models.embed` to `ollama:<model>` to store vectors from Ollama's `/api/embed`. If that call fails, the row is still saved and search stays on BM25. Vectors live in the `embedding_json` column.

## Redaction and dials

`memory.redact` defaults to `secrets`. Tokens, passwords, `sk-` keys, GitHub tokens, AWS access-key ids, bearer values, and private-key blocks are replaced with `[redacted]` before a write. `pii` also strips emails, US Social Security numbers, long card numbers, and phone numbers. `off` stores the text as given, unless a dial below adds a rule.

HIPAA, FERPA, and GDPR still default to `off`. While a dial is `off` it adds no pattern and no retention window. `monitor` or `enforce` turns on the PII patterns. HIPAA adds medical-record-number shapes. FERPA adds a student-id shape. `enforce` also sets a retention window. The shortest window wins:

| Dial | Enforce window |
|---|---|
| GDPR | 30 days |
| FERPA | 365 days |
| HIPAA | 2190 days |

Episodic rows also expire after `memory.episodic_ttl_days` (default 90) even when every dial is off. Profile and semantic rows do not expire unless an enforce dial sets a window. `monitor` redacts and does not shorten that window. The scheduler deletes expired rows on each tick. These windows are technical defaults from ARCHITECTURE §17, not legal advice.

A write that is only `[redacted]` after the pass is refused.
