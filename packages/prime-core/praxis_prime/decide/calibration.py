"""Local probability calibration.

Temperature scaling (multi-class), Platt scaling, and isotonic regression
are pure Python. No NumPy. Fitted calibrators live under
``decide/calibrators/`` in the data directory (ARCHITECTURE §7.6).

The default calibrator is the identity (temperature 1). A fit replaces it
only after labeled outcomes exist.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ReliabilityBin:
    lower: float
    upper: float
    count: int
    confidence: float
    accuracy: float


@dataclass(frozen=True, slots=True)
class ReliabilityReport:
    count: int
    ece: float
    mce: float
    brier: float
    bins: tuple[ReliabilityBin, ...]
    method: str
    version: str

    def format(self) -> str:
        if self.count == 0:
            return "Reliability report: no labeled outcomes yet.\n"
        lines = [
            f"Reliability report ({self.count} labeled outcomes)",
            f"calibrator: {self.version} ({self.method})",
            f"ECE {self.ece:.4f}   MCE {self.mce:.4f}   Brier {self.brier:.4f}",
            "bin        n   confidence   accuracy",
        ]
        for item in self.bins:
            if item.count == 0:
                continue
            lines.append(
                f"{item.lower:.1f}-{item.upper:.1f}  {item.count:4d}"
                f"   {item.confidence:.3f}        {item.accuracy:.3f}"
            )
        return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class Calibrator:
    method: str = "temperature"
    version: str = "identity@v0"
    temperature: float = 1.0
    platt_a: float = 0.0
    platt_b: float = 0.0
    isotonic: tuple[tuple[float, float], ...] = ()

    def apply(self, probabilities: dict[str, float]) -> dict[str, float]:
        if not probabilities:
            return {}
        if self.method == "platt" and len(probabilities) == 2:
            return _apply_platt(probabilities, self.platt_a, self.platt_b)
        if self.method == "isotonic" and self.isotonic and len(probabilities) == 2:
            return _apply_isotonic(probabilities, self.isotonic)
        if self.method == "temperature" and abs(self.temperature - 1.0) > 1e-6:
            return scale_temperature(probabilities, self.temperature)
        return dict(probabilities)

    def to_json(self) -> dict[str, object]:
        return {
            "method": self.method,
            "version": self.version,
            "temperature": self.temperature,
            "platt_a": self.platt_a,
            "platt_b": self.platt_b,
            "isotonic": [[score, value] for score, value in self.isotonic],
        }

    @staticmethod
    def from_json(raw: dict[str, object]) -> Calibrator:
        points = raw.get("isotonic")
        isotonic: list[tuple[float, float]] = []
        if isinstance(points, list):
            for item in points:
                if isinstance(item, list) and len(item) == 2:
                    isotonic.append((float(item[0]), float(item[1])))
        return Calibrator(
            method=str(raw.get("method") or "temperature"),
            version=str(raw.get("version") or "identity@v0"),
            temperature=float(raw.get("temperature") or 1.0),
            platt_a=float(raw.get("platt_a") or 0.0),
            platt_b=float(raw.get("platt_b") or 0.0),
            isotonic=tuple(isotonic),
        )


class CalibratorStore:
    """One JSON file, ``default.json``, for the pre-alpha single template."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.path = self.directory / "default.json"

    def load(self) -> Calibrator:
        if not self.path.is_file():
            return Calibrator()
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return Calibrator()
        if not isinstance(loaded, dict):
            return Calibrator()
        return Calibrator.from_json(loaded)

    def save(self, calibrator: Calibrator) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(calibrator.to_json(), indent=2, sort_keys=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(payload + "\n", encoding="utf-8")
        temporary.replace(self.path)


def scale_temperature(probabilities: dict[str, float], temperature: float) -> dict[str, float]:
    """Soften or sharpen a distribution. ``temperature`` > 1 lowers confidence."""
    temp = temperature if temperature > 1e-3 else 1e-3
    powered = {
        key: math.exp(math.log(max(value, 1e-12)) / temp) for key, value in probabilities.items()
    }
    total = sum(powered.values()) or 1.0
    return {key: value / total for key, value in powered.items()}


def fit_temperature(rows: list[tuple[dict[str, float], str]]) -> float:
    """Grid-search the temperature that minimizes mean negative log likelihood."""
    if not rows:
        return 1.0

    def nll(temperature: float) -> float:
        total = 0.0
        for probabilities, label in rows:
            scaled = scale_temperature(probabilities, temperature)
            total -= math.log(max(scaled.get(label, 1e-12), 1e-12))
        return total / len(rows)

    best_t = 1.0
    best = nll(1.0)
    temperature = 0.05
    while temperature <= 5.0:
        loss = nll(temperature)
        if loss < best:
            best = loss
            best_t = temperature
        temperature *= 1.15
    return best_t


def fit_platt(scores: list[float], labels: list[float]) -> tuple[float, float]:
    """Fit ``P(y=1) = sigmoid(a * score + b)`` with gradient descent."""
    if not scores:
        return -1.0, 0.0
    a = -1.0
    b = 0.0
    rate = 0.2
    count = len(scores)
    for _ in range(500):
        grad_a = 0.0
        grad_b = 0.0
        for score, label in zip(scores, labels, strict=True):
            linear = max(-30.0, min(30.0, a * score + b))
            predicted = 1.0 / (1.0 + math.exp(-linear))
            error = predicted - label
            grad_a += error * score
            grad_b += error
        a -= rate * grad_a / count
        b -= rate * grad_b / count
    return a, b


def apply_platt_score(score: float, a: float, b: float) -> float:
    linear = max(-30.0, min(30.0, a * score + b))
    return 1.0 / (1.0 + math.exp(-linear))


def fit_isotonic(pairs: list[tuple[float, float]]) -> tuple[tuple[float, float], ...]:
    """Pool-adjacent-violators. Each step is ``(min score in the block, probability)``."""
    ordered = sorted(pairs, key=lambda item: item[0])
    blocks: list[list[float]] = []
    for score, label in ordered:
        blocks.append([score, label, 1.0])
        while len(blocks) >= 2 and _mean(blocks[-2]) > _mean(blocks[-1]):
            right = blocks.pop()
            left = blocks.pop()
            blocks.append([left[0], left[1] + right[1], left[2] + right[2]])
    return tuple((block[0], block[1] / block[2]) for block in blocks)


def apply_isotonic_score(score: float, steps: tuple[tuple[float, float], ...]) -> float:
    if not steps:
        return min(1.0, max(0.0, score))
    chosen = steps[0][1]
    for edge, value in steps:
        if score + 1e-12 >= edge:
            chosen = value
        else:
            break
    return min(1.0, max(0.0, chosen))


def reliability(
    pairs: list[tuple[float, bool]],
    *,
    bins: int = 10,
    method: str = "temperature",
    version: str = "identity@v0",
) -> ReliabilityReport:
    """Expected calibration error, max calibration error, and Brier score."""
    width = 1.0 / bins
    counts = [0] * bins
    conf_sum = [0.0] * bins
    correct_sum = [0.0] * bins
    for confidence, correct in pairs:
        clipped = min(1.0, max(0.0, confidence))
        index = min(bins - 1, int(clipped * bins)) if clipped < 1 else bins - 1
        counts[index] += 1
        conf_sum[index] += clipped
        correct_sum[index] += 1.0 if correct else 0.0
    total = len(pairs)
    ece = 0.0
    mce = 0.0
    rows: list[ReliabilityBin] = []
    for index in range(bins):
        count = counts[index]
        avg_conf = conf_sum[index] / count if count else 0.0
        accuracy = correct_sum[index] / count if count else 0.0
        if count and total:
            gap = abs(accuracy - avg_conf)
            ece += (count / total) * gap
            mce = max(mce, gap)
        rows.append(
            ReliabilityBin(
                lower=index * width,
                upper=(index + 1) * width,
                count=count,
                confidence=avg_conf,
                accuracy=accuracy,
            )
        )
    if total == 0:
        brier = 0.0
    else:
        brier = sum((confidence - (1.0 if correct else 0.0)) ** 2 for confidence, correct in pairs)
        brier /= total
    return ReliabilityReport(
        count=total,
        ece=ece,
        mce=mce,
        brier=brier,
        bins=tuple(rows),
        method=method,
        version=version,
    )


def choose_method(configured: str, *, binary: bool, count: int) -> str:
    if configured in {"temperature", "platt", "isotonic"}:
        return configured
    if binary and count >= 1000:
        return "isotonic"
    if binary:
        return "platt"
    return "temperature"


def _mean(block: list[float]) -> float:
    return block[1] / block[2]


def _apply_platt(probabilities: dict[str, float], a: float, b: float) -> dict[str, float]:
    positive = _positive_key(probabilities)
    negative = next(key for key in probabilities if key != positive)
    calibrated = apply_platt_score(probabilities[positive], a, b)
    return {positive: calibrated, negative: 1.0 - calibrated}


def _apply_isotonic(
    probabilities: dict[str, float],
    steps: tuple[tuple[float, float], ...],
) -> dict[str, float]:
    positive = _positive_key(probabilities)
    negative = next(key for key in probabilities if key != positive)
    calibrated = apply_isotonic_score(probabilities[positive], steps)
    return {positive: calibrated, negative: 1.0 - calibrated}


def _positive_key(probabilities: dict[str, float]) -> str:
    if "true" in probabilities:
        return "true"
    return next(iter(probabilities))
