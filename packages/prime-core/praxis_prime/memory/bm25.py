"""Okapi BM25 over a small in-memory corpus.

No extra dependency. This is the recall path when no embedding model is
configured, and the tie-break beside vectors when one is.
"""

from __future__ import annotations

import math
import re

_TOKEN = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def bm25_scores(
    query: str,
    documents: list[str],
    *,
    k1: float = 1.5,
    b: float = 0.75,
) -> list[float]:
    docs = [tokenize(doc) for doc in documents]
    terms = tokenize(query)
    if not terms or not docs:
        return [0.0] * len(documents)
    count = len(docs)
    avgdl = sum(len(doc) for doc in docs) / count or 1.0
    df: dict[str, int] = {}
    for doc in docs:
        for term in set(doc):
            df[term] = df.get(term, 0) + 1
    scores: list[float] = []
    for doc in docs:
        tf: dict[str, int] = {}
        for term in doc:
            tf[term] = tf.get(term, 0) + 1
        length = len(doc) or 1
        score = 0.0
        for term in terms:
            freq = tf.get(term, 0)
            if freq == 0:
                continue
            seen = df.get(term, 0)
            idf = math.log(1.0 + (count - seen + 0.5) / (seen + 0.5))
            denom = freq + k1 * (1.0 - b + b * length / avgdl)
            score += idf * (freq * (k1 + 1.0)) / denom
        scores.append(score)
    return scores


def cosine(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    dot = 0.0
    left_norm = 0.0
    right_norm = 0.0
    for a, b in zip(left, right, strict=True):
        dot += a * b
        left_norm += a * a
        right_norm += b * b
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / math.sqrt(left_norm * right_norm)
