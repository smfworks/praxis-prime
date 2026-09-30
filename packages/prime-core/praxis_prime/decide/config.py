"""Decision Engine settings from ``config.toml``.

Defaults match ARCHITECTURE §25, with the approval pre-screener off.
Judge model names are router specs (``ollama:qwen3:8b``). Nothing here is a
hosted Jev model name.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from praxis_prime.paths import config_dir

_AGGREGATIONS = {"majority", "confidence-weighted"}
_SAFETY_PURPOSES = frozenset({"risk_triage", "injection", "approval_screen", "data_class"})


@dataclass(frozen=True, slots=True)
class DecideConfig:
    enabled: bool = True
    prescreen: bool = False
    profile: str = "gpu-8g"
    max_tier: int = 4
    min_confidence: float = 0.8
    disagreement_js: float = 0.15
    aggregation: str = "confidence-weighted"
    jury_size: int = 3
    tier2_model: str = "ollama:qwen3:8b"
    tier4_model: str = "ollama:qwen3:32b"
    judge_models: tuple[str, ...] = ("ollama:qwen3:8b", "ollama:qwen3:1.7b")
    personas: tuple[str, ...] = (
        "skeptic",
        "safety",
        "domain",
        "cost",
        "user-advocate",
    )
    latency_budget_ms: int = 800
    max_usd: float = 0.05
    max_calls: int = 8
    usd_per_call: float = 0.0
    calibration_method: str = "auto"
    deny: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    escalate_to_human: bool = False
    backend: str = "ollama"

    @staticmethod
    def from_table(table: Mapping[str, object] | None) -> DecideConfig:
        if not table:
            return DecideConfig()
        return _from_mapping(table)

    def jury_roles(self) -> tuple[str, ...]:
        size = min(5, max(3, self.jury_size))
        roles = self.personas or ("skeptic", "safety", "user-advocate")
        if len(roles) >= size:
            return roles[:size]
        padded: list[str] = list(roles)
        while len(padded) < size:
            padded.append(roles[len(padded) % len(roles)])
        return tuple(padded)

    def model_for_role(self, index: int) -> str:
        models = self.judge_models or (self.tier2_model,)
        return models[index % len(models)]


def load_decide_config(
    config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> DecideConfig:
    path = config_path
    if path is None and env is not None:
        path = config_dir(env) / "config.toml"
    table: dict[str, object] = {}
    if path is not None and path.is_file():
        loaded = tomllib.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            raw = loaded.get("decide")
            if isinstance(raw, dict):
                table = raw
    return DecideConfig.from_table(table)


def _from_mapping(table: Mapping[str, object]) -> DecideConfig:
    models = _dict(table.get("models"))
    judges = _dict(table.get("judges"))
    budgets = _dict(table.get("budgets"))
    calibration = _dict(table.get("calibration"))
    lists = _dict(table.get("lists"))
    latency = table.get("latency_budget_ms")
    latency_ms = 800
    if isinstance(latency, dict):
        latency_ms = _as_int(latency.get("default"), 800)
    elif latency is not None:
        latency_ms = _as_int(latency, 800)
    aggregation = str(table.get("aggregation") or "confidence-weighted")
    if aggregation not in _AGGREGATIONS:
        aggregation = "confidence-weighted"
    personas = _strings(judges.get("personas")) or _strings(judges.get("roles"))
    judge_models = _strings(judges.get("models"))
    return DecideConfig(
        enabled=_as_bool(table.get("enabled"), True),
        prescreen=_as_bool(table.get("prescreen"), False),
        profile=str(table.get("profile") or "gpu-8g"),
        max_tier=min(4, max(0, _as_int(table.get("max_tier"), 4))),
        min_confidence=_clamp(_as_float(table.get("min_confidence"), 0.8), 0.0, 1.0),
        disagreement_js=_clamp(_as_float(table.get("disagreement_js"), 0.15), 0.0, 1.0),
        aggregation=aggregation,
        jury_size=min(5, max(3, _as_int(table.get("jury_size"), 3))),
        tier2_model=str(models.get("tier2") or "ollama:qwen3:8b"),
        tier4_model=str(models.get("tier4") or "ollama:qwen3:32b"),
        judge_models=tuple(judge_models) or ("ollama:qwen3:8b", "ollama:qwen3:1.7b"),
        personas=tuple(personas)
        or ("skeptic", "safety", "domain", "cost", "user-advocate"),
        latency_budget_ms=max(0, latency_ms),
        max_usd=max(0.0, _as_float(budgets.get("max_usd"), 0.05)),
        max_calls=max(0, _as_int(budgets.get("max_calls"), 8)),
        usd_per_call=max(0.0, _as_float(budgets.get("usd_per_call"), 0.0)),
        calibration_method=str(calibration.get("method") or "auto"),
        deny=tuple(_strings(lists.get("deny"))),
        allow=tuple(_strings(lists.get("allow"))),
        escalate_to_human=_as_bool(table.get("escalate_to_human"), False),
        backend=str(judges.get("backend") or "ollama"),
    )


def safety_purpose(purpose: str) -> bool:
    return purpose in _SAFETY_PURPOSES


def _dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _as_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _clamp(value: float, low: float, high: float) -> float:
    return min(high, max(low, value))

