"""Local embedding client.

The default config names ``local:bge-small``, which this process does not
download. Recall then uses BM25. An ``ollama:<model>`` embed spec calls
Ollama's ``/api/embed`` and returns None on any failure so a down server
never blocks a memory write.
"""

from __future__ import annotations

import json
from typing import Protocol
from urllib.request import Request, urlopen

from praxis_prime.router.http import normalize_base


class Embedder(Protocol):
    def embed(self, text: str) -> list[float] | None:
        """Return one vector, or None when no model is available."""


class NullEmbedder:
    """BM25-only recall. Used in tests and when embed is not an Ollama spec."""

    def embed(self, text: str) -> list[float] | None:
        del text
        return None


class OllamaEmbedder:
    def __init__(self, host: str, model: str, *, timeout: float = 2.0) -> None:
        self.host = host
        self.model = model
        self.timeout = timeout

    def embed(self, text: str) -> list[float] | None:
        if not self.model or not text.strip():
            return None
        url = normalize_base(self.host or "http://127.0.0.1:11434") + "/api/embed"
        body = json.dumps({"model": self.model, "input": text}).encode("utf-8")
        request = Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        vectors = payload.get("embeddings")
        if isinstance(vectors, list) and vectors and isinstance(vectors[0], list):
            try:
                return [float(item) for item in vectors[0]]
            except (TypeError, ValueError):
                return None
        single = payload.get("embedding")
        if isinstance(single, list):
            try:
                return [float(item) for item in single]
            except (TypeError, ValueError):
                return None
        return None


def embedder_for(spec: str, host: str) -> Embedder:
    if spec.startswith("ollama:"):
        model = spec.split(":", 1)[1].strip()
        if model:
            return OllamaEmbedder(host, model)
    return NullEmbedder()
