# Local Decision Engine

Praxis Prime decides on this machine. The engine is a tiered cascade with a calibrated confidence, an explain trace, and a hash-chained audit row. It does **not** call TypeSafe AI, Jev, or any other hosted decision service. Jev's public request shape is only a reference (ARCHITECTURE §7).

The approval pre-screener is **off** by default. Compliance dials stay **off** by default. The baseline approval spine is not a dial and the engine cannot turn it off.

## Cascade

Each question stops at the first tier whose calibrated confidence clears `min_confidence` (default 0.80), unless policy says that tier may not decide alone. Safety purposes (`risk_triage`, `injection`, `approval_screen`, `data_class`) are not settled by Tier 1.

| Tier | What runs | When it stops the cascade |
|---|---|---|
| 0 | Deterministic rules: allow/deny lists, counts, ISO dates, and dial detectors | Confidence is 1 (or 0.95 on an allow-list hit) |
| 1 | Pluggable classifiers. The built-in one is a keyword overlap baseline. No model is loaded | A clear keyword margin, about 0.86 or higher |
| 2 | One local judge through the model router. No default spec; set `models.tier2` in setup | The judge's calibrated top label clears the threshold |
| 3 | A jury of 3–5 role lenses. Default roles: skeptic, safety, domain. Also available: cost, user-advocate, scout, strategist, forecaster | Agreement is high and pooled confidence clears the threshold |
| 4 | A larger model when `models.tier4` is set, then a human if `escalate_to_human` is true. There is no default spec | The model is confident, or a human answered |

Jury votes are collected one after another in this build. Aggregation is `confidence-weighted` (default) or `majority`. Disagreement is the mean pairwise Jensen–Shannon divergence. Above `disagreement_js` (default 0.15), or on a tie, the jury does not decide and Tier 4 runs when `max_tier` allows it.

Numbers, dates, and counts are answered in code at Tier 0. Judge text inside the state is fenced as untrusted data. Judges have no tools.

Low confidence, disagreement, or an exhausted budget returns the best answer so far with `escalate: true`.

## API

Both routes use the same handler and the gateway bearer token. `GET /health` stays open. These do not.

- `POST /v1/decide`
- `POST /v1/systemone`

```json
{
  "model": "prime-decide-default",
  "state": {"message": "The invoice refund failed"},
  "questions": {
    "department": {
      "type": "choice",
      "instructions": "Which team should handle this?",
      "criteria": {"billing": "invoices and refunds", "technical": "outages"}
    }
  },
  "x_prime": {"max_tier": 2, "min_confidence": 0.8, "purpose": "inbox_triage"}
}
```

Question types are `choice` (2–255 options), `score` (2–10 levels), and `noul` (yes/no; `yesno` is accepted too). The response carries the label, probabilities, the tier that decided (`x_prime.tiers`), per-judge ballots, cost and latency, and an explain trace. For yes/no, the wire field is `noul` (probability of yes). Confidence for every question is under `x_prime.confidence`.

In-process entry point: `praxis_prime.decide.decide()`.

## CLI

```bash
praxis-prime decide "Is this urgent?"
praxis-prime decide "Which team?" --options billing,technical,sales --max-tier 2 --explain
praxis-prime decide feedback dec_0123abcd --correct
praxis-prime decide feedback dec_0123abcd --label billing
praxis-prime decide report
```

`--explain` prints the tier trace. `feedback` records whether a logged outcome was right. `report` prints ECE, MCE, and Brier score, and fits a calibrator once four or more labeled outcomes exist.

The agent loop can call the `decide` tool. It is read-only. It does not approve or perform the action the question describes.

## Config

`praxis-prime config` writes this under `[decide]`. Relevant keys:

| Key | Default | Meaning |
|---|---|---|
| `prescreen` | `false` | Approval pre-screener |
| `max_tier` | `4` | Highest tier the cascade may run |
| `min_confidence` | `0.80` | Early-exit threshold |
| `disagreement_js` | `0.15` | Jury disagreement that forces escalation |
| `aggregation` | `confidence-weighted` | or `majority` |
| `jury_size` | `3` | Clamped to 3–5 |
| `escalate_to_human` | `false` | Tier 4 may block on the approval queue |
| `models.tier2` | empty | Single judge. An example is `ollama:qwen3:8b`; that string is not the default |
| `models.tier4` | empty | Escalation model. An example is `ollama:qwen3:32b`; that string is not the default |
| `judges.models` | empty | Assigned round-robin to jury roles when you set them |
| `judges.personas` | skeptic, safety, domain, cost, user-advocate | First `jury_size` roles sit |
| `budgets.max_usd` | `0.05` | Cost cap. Local calls cost `usd_per_call` (default 0) |
| `budgets.max_calls` | `8` | Model-call cap |
| `lists.allow` / `lists.deny` | empty | Tier 0 phrases |
| `calibration.method` | `auto` | `temperature`, `platt`, `isotonic`, or `auto` |

`latency_budget_ms.default` (800) stops model tiers once the question has used that much time. Rules and the keyword classifier still run.

## Approvals

Leave `decide.prescreen` false unless you want an extra look at tool calls. While it is false, approvals behave exactly as they do without the engine.

While it is true:

- A clearly unsafe command (`curl … \| sh`, `wget … \| sh`, `rm -rf /`, `mkfs`, `dd of=/dev/…`) is auto-denied.
- The engine may attach "recommends approve" or "recommends deny" and a confidence to the approval reason.
- It never turns an ask into an allow.
- It never auto-approves git push, a force operation, a delete of a tracked file, or a write outside the task worktree. Those stay on the approval queue, including Telegram when the daemon is paired.

`escalate_to_human` is also false by default, so a low-confidence decision returns `escalate: true` instead of blocking. Set it true on the daemon when Tier 4 should open an approval card. That card uses the same queue as every other approval, so Telegram buttons work. A text reply still cannot approve.

## Dials

Tier 0 dial rules run only when that dial is `monitor` or `enforce`. They are technical filters, not legal conclusions.

| Dial | Detector |
|---|---|
| `pci` | Luhn-valid card number, when the question is about PCI or card data |
| `hipaa` | SSN-shaped identifier, when the question is about PHI |
| `state_nc` | SSN-shaped identifier, when the question is about NC_PII |

With every dial off, those detectors do not fire.

## Calibration and audit

Every decision is appended to the SHA-256 audit chain (`kind` `decision`) with the tier, label, confidence, votes, and a hash of the state. The raw state is not stored. `praxis-prime` audit verification covers these rows the same way it covers tool calls.

Predicted labels are logged in `decide/labels.db` under the data directory. Feedback marks them correct or not. Calibrators are JSON files in `decide/calibrators/`. The default is the identity (temperature 1). `decide report` fits temperature scaling, Platt scaling, or isotonic regression in pure Python. `auto` uses Platt for binary labels and isotonic once there are at least 1000 binary labels; otherwise temperature scaling.

## Deferred

ONNX classifiers, logprob calibration from the model server, a logarithmic opinion pool, parallel jury calls, distillation, the nightly recalibration timer, and the eval suites named in ARCHITECTURE §7.6 (`injection`, `data_class`, `intent`, `numbers_dates`, and the rest). Pydantic models are not a dependency yet; the dataclasses in `praxis_prime.decide.schema` and `protocol/decide.schema.json` are the contract.
