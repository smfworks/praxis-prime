"""``decide`` tool for the agent loop.

The tool asks the local Decision Engine. It does not perform the action the
question is about, and it does not call a hosted decision service.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from praxis_prime.decide.engine import DecisionEngine
from praxis_prime.decide.schema import DecideError, simple_request
from praxis_prime.tools.registry import Risk, Tool, ToolContext, ToolRegistry

_OBJECT = {"type": "object", "additionalProperties": False}


def make_decide_tool(engine: DecisionEngine) -> Tool:
    def execute(arguments: Mapping[str, object], context: ToolContext) -> str:
        del context
        question = arguments.get("question")
        if not isinstance(question, str) or not question.strip():
            raise ValueError("decide requires a question")
        options = _options(arguments.get("options"))
        state = arguments.get("state")
        state_text = state if isinstance(state, str) else ""
        max_tier = arguments.get("max_tier")
        tier = int(max_tier) if isinstance(max_tier, int) else None
        try:
            request = simple_request(question, options=options, state=state_text, max_tier=tier)
            response = engine.decide(request)
        except DecideError as exc:
            raise ValueError(str(exc)) from exc
        answer = response.answers["q"]
        body = {
            "decision_id": response.decision_id,
            "label": answer.label,
            "confidence": round(answer.confidence, 4),
            "tier": answer.tier,
            "escalate": answer.escalate,
            "rationale": answer.rationale,
            "trace": answer.trace,
        }
        return json.dumps(body, sort_keys=True)

    return Tool(
        name="decide",
        description=(
            "Ask the local Decision Engine a yes/no or multiple-choice question. "
            "Runs on this machine. Does not call a hosted decision service and "
            "does not approve actions."
        ),
        parameters={
            **_OBJECT,
            "properties": {
                "question": {"type": "string", "description": "The question to decide."},
                "options": {
                    "type": "string",
                    "description": "Comma-separated choices. Omit for yes/no.",
                },
                "state": {
                    "type": "string",
                    "description": "Untrusted text the decision is about.",
                },
                "max_tier": {
                    "type": "integer",
                    "description": "Highest cascade tier to run, from 0 to 4.",
                },
            },
            "required": ["question"],
        },
        risk=Risk.READ,
        execute=execute,
    )


def install_decide_tool(registry: ToolRegistry, engine: DecisionEngine) -> None:
    if registry.get("decide") is not None:
        return
    registry.register(make_decide_tool(engine))


def _options(value: object) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []
