"""Typed Decision Engine request and response.

The wire shape follows the public request/response outline in ARCHITECTURE
§7.3 (choice, score, and yes/no). This is Praxis Prime's own schema. It does
not import or call a TypeSafe SDK.

Pydantic models are deferred. These dataclasses are the pre-alpha stand-in,
and ``protocol/decide.schema.json`` is the exported JSON Schema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


class DecideError(ValueError):
    """The request is not a decision the engine can run."""


@dataclass(frozen=True, slots=True)
class Question:
    """One typed question. ``noul`` is the yes/no wire name."""

    type: str
    instructions: str
    options: tuple[str, ...]
    criteria: dict[str, str]


@dataclass(frozen=True, slots=True)
class RequestLimits:
    """Per-call overrides from ``x_prime``. Unset fields fall back to config."""

    purpose: str = ""
    data_class: str = ""
    max_tier: int | None = None
    min_confidence: float | None = None
    latency_budget_ms: int | None = None
    explain: bool = True


@dataclass(frozen=True, slots=True)
class DecideRequest:
    model: str
    state_text: str
    questions: dict[str, Question]
    limits: RequestLimits = field(default_factory=RequestLimits)


@dataclass(frozen=True, slots=True)
class JudgeVote:
    role: str
    model: str
    label: str
    confidence: float
    rationale: str
    probabilities: dict[str, float]


@dataclass(slots=True)
class QuestionAnswer:
    """One question's result. ``confidence`` is P(chosen label) after calibration."""

    question_id: str
    type: str
    label: str
    confidence: float
    tier: int
    probabilities: dict[str, float]
    raw_probabilities: dict[str, float]
    votes: list[JudgeVote]
    disagreement: float | None
    rationale: str
    trace: list[str]
    latency_ms: float
    cost_usd: float
    input_tokens: int
    output_tokens: int
    escalate: bool
    calibrator: str


@dataclass(slots=True)
class DecisionResponse:
    model: str
    decision_id: str
    answers: dict[str, QuestionAnswer]
    latency_ms: float
    cost_usd: float
    escalate: bool
    audit_hash: str | None = None
    audit_seq: int | None = None

    def to_wire(self) -> dict[str, Any]:
        """JSON body for ``POST /v1/decide`` and ``POST /v1/systemone``."""
        answers: dict[str, Any] = {}
        tiers: dict[str, str] = {}
        raw: dict[str, Any] = {}
        calibrators: dict[str, str] = {}
        jury: dict[str, Any] = {}
        explain: dict[str, list[str]] = {}
        confidences: dict[str, float] = {}
        input_tokens = 0
        output_tokens = 0
        for key, answer in self.answers.items():
            answers[key] = _wire_answer(answer)
            tiers[key] = f"T{answer.tier}"
            raw[key] = answer.raw_probabilities
            calibrators[key] = answer.calibrator
            confidences[key] = round(answer.confidence, 4)
            explain[key] = list(answer.trace)
            input_tokens += answer.input_tokens
            output_tokens += answer.output_tokens
            if answer.votes:
                counts: dict[str, int] = {}
                for vote in answer.votes:
                    counts[vote.label] = counts.get(vote.label, 0) + 1
                jury[key] = {
                    "judges": len(answer.votes),
                    "js_divergence": answer.disagreement,
                    "votes": counts,
                    "ballots": [
                        {
                            "role": vote.role,
                            "model": vote.model,
                            "label": vote.label,
                            "confidence": round(vote.confidence, 4),
                            "rationale": vote.rationale,
                        }
                        for vote in answer.votes
                    ],
                }
        return {
            "model": self.model,
            "decision_id": self.decision_id,
            "answers": answers,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
            "x_prime": {
                "decision_id": self.decision_id,
                "audit_seq": self.audit_seq,
                "audit_hash": self.audit_hash,
                "tiers": tiers,
                "confidence": confidences,
                "raw_probabilities": raw,
                "calibrator": calibrators,
                "jury": jury,
                "escalate": self.escalate,
                "latency_ms": round(self.latency_ms, 3),
                "cost_usd": round(self.cost_usd, 6),
                "explain": explain,
            },
        }


def parse_request(payload: DecideRequest | dict[str, Any]) -> DecideRequest:
    if isinstance(payload, DecideRequest):
        return payload
    if not isinstance(payload, dict):
        raise DecideError("decide body must be an object")
    questions_raw = payload.get("questions")
    if not isinstance(questions_raw, dict) or not questions_raw:
        raise DecideError("questions must be a non-empty object")
    questions: dict[str, Question] = {}
    for key, value in questions_raw.items():
        if not isinstance(value, dict):
            raise DecideError(f"question {key} must be an object")
        questions[str(key)] = _parse_question(str(key), value)
    extension = payload.get("x_prime")
    if extension is None:
        extension = {}
    if not isinstance(extension, dict):
        raise DecideError("x_prime must be an object")
    return DecideRequest(
        model=str(payload.get("model") or "prime-decide-default"),
        state_text=_render_state(payload.get("state")),
        questions=questions,
        limits=_parse_limits(extension),
    )


def simple_request(
    question: str,
    *,
    options: list[str] | None = None,
    state: str = "",
    max_tier: int | None = None,
) -> DecideRequest:
    """Build a one-question request for the CLI and the ``decide`` tool."""
    text = question.strip()
    if not text:
        raise DecideError("question is empty")
    cleaned = [item.strip() for item in (options or []) if item.strip()]
    if cleaned:
        body: dict[str, Any] = {
            "type": "choice",
            "instructions": text,
            "criteria": {item: item for item in cleaned},
        }
    else:
        body = {
            "type": "noul",
            "instructions": text,
            "criteria": {"true": "Yes", "false": "No"},
        }
    extra: dict[str, Any] = {}
    if max_tier is not None:
        extra["max_tier"] = max_tier
    return parse_request(
        {
            "model": "prime-decide-default",
            "state": state.strip() or text,
            "questions": {"q": body},
            "x_prime": extra,
        }
    )


def _parse_question(key: str, raw: dict[str, Any]) -> Question:
    qtype = str(raw.get("type") or "noul").lower()
    if qtype in {"yesno", "yes_no", "bool", "boolean"}:
        qtype = "noul"
    instructions = _flatten(raw.get("instructions"))
    criteria = raw.get("criteria")
    if qtype == "noul":
        described = _criteria_map(criteria)
        return Question(
            type="noul",
            instructions=instructions,
            options=("true", "false"),
            criteria={
                "true": described.get("true", "Yes"),
                "false": described.get("false", "No"),
            },
        )
    if qtype == "choice":
        options, described = _options(criteria)
        if not 2 <= len(options) <= 255:
            raise DecideError(f"question {key} needs 2 to 255 choice options")
        return Question(
            type="choice",
            instructions=instructions,
            options=tuple(options),
            criteria=described,
        )
    if qtype == "score":
        options, described = _options(criteria)
        if not 2 <= len(options) <= 10:
            raise DecideError(f"question {key} needs 2 to 10 score levels")
        return Question(
            type="score",
            instructions=instructions,
            options=tuple(options),
            criteria=described,
        )
    raise DecideError(f"question {key} has unknown type {qtype!r}")


def _options(criteria: object) -> tuple[list[str], dict[str, str]]:
    if isinstance(criteria, dict):
        options = [str(key) for key in criteria]
        described = {str(key): _flatten(value) or str(key) for key, value in criteria.items()}
        return options, described
    if isinstance(criteria, list):
        options = [str(item) for item in criteria]
        return options, {item: item for item in options}
    if isinstance(criteria, str):
        options = [part.strip() for part in criteria.split(",") if part.strip()]
        return options, {item: item for item in options}
    return [], {}


def _criteria_map(criteria: object) -> dict[str, str]:
    if isinstance(criteria, dict):
        return {str(key).lower(): _flatten(value) for key, value in criteria.items()}
    return {}


def _parse_limits(raw: dict[str, Any]) -> RequestLimits:
    return RequestLimits(
        purpose=str(raw.get("purpose") or ""),
        data_class=str(raw.get("data_class") or ""),
        max_tier=_tier(raw.get("max_tier")),
        min_confidence=_float(raw.get("min_confidence")),
        latency_budget_ms=_int(raw.get("latency_budget_ms")),
        explain=bool(raw.get("explain", True)),
    )


def _tier(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().upper()
    if text.startswith("T") and text[1:].isdigit():
        return int(text[1:])
    if text.isdigit():
        return int(text)
    raise DecideError(f"max_tier {value!r} is not a tier")


def _float(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise DecideError("min_confidence must be a number") from exc


def _int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise DecideError("latency_budget_ms must be an integer") from exc


def _render_state(state: object) -> str:
    if state is None:
        return ""
    if isinstance(state, str):
        return state
    return json.dumps(state, sort_keys=True, default=str)


def _flatten(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "; ".join(_flatten(item) for item in value)
    if isinstance(value, dict):
        return "; ".join(f"{key}: {_flatten(item)}" for key, item in value.items())
    return str(value)


def _wire_answer(answer: QuestionAnswer) -> dict[str, Any]:
    probs = {key: round(value, 4) for key, value in answer.probabilities.items()}
    if answer.type == "noul":
        return {"type": "noul", "noul": round(probs.get("true", 0.0), 4)}
    if answer.type == "score":
        levels = list(answer.probabilities)
        legend = {str(index): level for index, level in enumerate(levels)}
        score = 0.0
        for index, level in enumerate(levels):
            score += index * answer.probabilities.get(level, 0.0)
        return {
            "type": "score",
            "score": round(score, 4),
            "legend": legend,
            "probabilities": {
                str(index): round(answer.probabilities[level], 4)
                for index, level in enumerate(levels)
            },
            "confidence": round(answer.confidence, 4),
        }
    return {
        "type": "choice",
        "choice": answer.label,
        "probabilities": probs,
        "confidence": round(answer.confidence, 4),
    }
