"""Tier 1 classifiers.

The interface is pluggable. The built-in baseline scores option text against
the state with keyword overlap. It does not load a model. A later ONNX head
can implement the same method (ARCHITECTURE §7.4).
"""

from __future__ import annotations

import re
from typing import Protocol

from praxis_prime.decide.schema import Question

_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    {
        "this",
        "that",
        "with",
        "from",
        "your",
        "have",
        "will",
        "what",
        "when",
        "where",
        "which",
        "about",
        "into",
        "they",
        "them",
        "than",
        "then",
        "only",
        "does",
        "should",
        "would",
        "could",
        "there",
        "their",
        "true",
        "false",
    }
)


class Classifier(Protocol):
    name: str

    def classify(self, state: str, question: Question) -> tuple[str, float] | None:
        """Return ``(label, confidence)`` or None to abstain."""


class KeywordClassifier:
    """Overlap between each option's criteria and the state."""

    name = "keyword"

    def classify(self, state: str, question: Question) -> tuple[str, float] | None:
        if question.type == "noul":
            return None
        text = state.lower()
        scores = {
            option: _hits(question.criteria.get(option, option), text)
            for option in question.options
        }
        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        if not ranked or ranked[0][1] <= 0:
            return None
        best, hits = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0
        if hits >= 2 and hits >= second + 1:
            confidence = 0.92 if hits >= 3 else 0.86
            return best, confidence
        if hits >= 1 and hits > second:
            return best, 0.55
        return best, 0.4


def _hits(description: str, text: str) -> int:
    words = [
        word
        for word in _WORD.findall(description.lower())
        if len(word) >= 4 and word not in _STOP
    ]
    if not words:
        return 0
    return sum(1 for word in words if _present(word, text))


def _present(word: str, text: str) -> bool:
    if word in text:
        return True
    if word.endswith("s") and word[:-1] in text:
        return True
    return f"{word}s" in text
