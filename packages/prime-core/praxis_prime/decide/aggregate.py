"""Jury aggregation and disagreement.

``majority`` picks the label with the most votes. A tie does not decide.
``confidence-weighted`` mixes the judges' distributions in proportion to
each judge's confidence. Disagreement is the mean pairwise Jensen-Shannon
divergence. A logarithmic opinion pool is later work (ARCHITECTURE §7.4).
"""

from __future__ import annotations

import math
from collections import Counter

from praxis_prime.decide.schema import JudgeVote


def aggregate(
    votes: list[JudgeVote],
    options: tuple[str, ...],
    method: str,
) -> tuple[str, dict[str, float], float, bool]:
    """Return label, pooled probabilities, JS divergence, and whether the jury tied."""
    if not votes:
        uniform = {option: 1.0 / len(options) for option in options} if options else {}
        return "", uniform, 1.0, True
    distributions = [_smooth(vote.probabilities, options) for vote in votes]
    divergence = _mean_js(distributions)
    if method == "majority":
        counts = Counter(vote.label for vote in votes)
        winner_count = max(counts.values())
        leaders = [label for label, count in counts.items() if count == winner_count]
        tied = len(leaders) != 1
        probabilities = _mix(distributions, options, weights=None)
        label = leaders[0] if not tied else max(probabilities, key=probabilities.get)
        if tied:
            divergence = max(divergence, 1.0)
        return label, probabilities, divergence, tied
    weights = [max(vote.confidence, 1e-6) for vote in votes]
    probabilities = _mix(distributions, options, weights=weights)
    label = max(probabilities, key=probabilities.get)
    return label, probabilities, divergence, False


def label_distribution(
    label: str,
    confidence: float,
    options: tuple[str, ...],
) -> dict[str, float]:
    """Put ``confidence`` on ``label`` when that keeps it the mode."""
    names = list(options) or [label]
    if label not in names:
        names.append(label)
    others = [name for name in names if name != label]
    if not others:
        return {label: 1.0}
    floor = 1.0 / len(names)
    peak = min(1.0, max(confidence, floor))
    if peak <= floor:
        peak = min(0.99, floor + 0.01)
    rest = (1.0 - peak) / len(others)
    return {label: peak, **{name: rest for name in others}}


def _mix(
    distributions: list[dict[str, float]],
    options: tuple[str, ...],
    *,
    weights: list[float] | None,
) -> dict[str, float]:
    names = list(options)
    for dist in distributions:
        for key in dist:
            if key not in names:
                names.append(key)
    totals = dict.fromkeys(names, 0.0)
    weight_sum = 0.0
    for index, dist in enumerate(distributions):
        weight = 1.0 if weights is None else weights[index]
        weight_sum += weight
        for name in names:
            totals[name] += weight * dist.get(name, 0.0)
    if weight_sum <= 0:
        share = 1.0 / len(names) if names else 0.0
        return dict.fromkeys(names, share)
    return {name: value / weight_sum for name, value in totals.items()}


def _smooth(probabilities: dict[str, float], options: tuple[str, ...]) -> dict[str, float]:
    names = list(options) or list(probabilities)
    for key in probabilities:
        if key not in names:
            names.append(key)
    floored = {name: max(probabilities.get(name, 0.0), 1e-6) for name in names}
    total = sum(floored.values()) or 1.0
    return {name: value / total for name, value in floored.items()}


def _mean_js(distributions: list[dict[str, float]]) -> float:
    if len(distributions) < 2:
        return 0.0
    total = 0.0
    pairs = 0
    for index, left in enumerate(distributions):
        for right in distributions[index + 1 :]:
            total += _js(left, right)
            pairs += 1
    if pairs == 0:
        return 0.0
    return total / pairs


def _js(left: dict[str, float], right: dict[str, float]) -> float:
    keys = set(left) | set(right)
    mixture = {key: 0.5 * (left.get(key, 1e-12) + right.get(key, 1e-12)) for key in keys}
    return 0.5 * _kl(left, mixture) + 0.5 * _kl(right, mixture)


def _kl(source: dict[str, float], target: dict[str, float]) -> float:
    total = 0.0
    for key, value in source.items():
        if value <= 0:
            continue
        total += value * math.log(value / max(target.get(key, 1e-12), 1e-12))
    return total
