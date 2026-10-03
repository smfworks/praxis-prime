"""Shipped SPA assets and the opt-in stub model."""

from __future__ import annotations

import json
import re
from pathlib import Path

from praxis_prime.router.stub import providers_from_env
from praxis_prime.router.types import ChatRequest

_INLINE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.IGNORECASE)
# React's production bundle names these. They are error text and XML namespaces,
# not requests. A CDN, font host, or analytics host is still rejected.
_LOCAL_ONLY = (
    "https://react.dev/errors/",
    "http://www.w3.org/",
)
_FORBIDDEN = (
    "fonts.googleapis",
    "fonts.gstatic",
    "cdn.jsdelivr",
    "unpkg.com",
    "cdnjs.cloudflare",
    "googletagmanager",
    "google-analytics",
)


def test_shipped_spa_is_local_and_has_no_inline_script():
    root = Path(__file__).resolve().parents[1] / "ui" / "dist"
    html_path = root / "index.html"
    assert html_path.is_file()
    html = html_path.read_text(encoding="utf-8")
    assert 'src="/assets/' in html
    assert _INLINE.search(html) is None
    saw_script = False
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".html", ".js", ".css"}:
            continue
        text = path.read_text(encoding="utf-8")
        for host in _FORBIDDEN:
            assert host not in text
        assert "unsafe-inline" not in text
        assert "unsafe-eval" not in text
        stripped = text
        for prefix in _LOCAL_ONLY:
            stripped = stripped.replace(prefix, "")
        assert "http://" not in stripped
        assert "https://" not in stripped
        if path.suffix.lower() == ".js":
            saw_script = True
    assert saw_script


def test_stub_replies_stay_off_unless_the_env_is_set(tmp_path: Path):
    assert providers_from_env({}) is None
    path = tmp_path / "replies.json"
    path.write_text(
        json.dumps(
            {
                "replies": [
                    {
                        "content": "Looking.",
                        "toolCalls": [
                            {"id": "c1", "name": "shell", "arguments": {"command": "rm -f note"}}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    providers = providers_from_env({"PRAXIS_PRIME_STUB_REPLIES": str(path)})
    assert providers is not None
    provider = providers["ollama"]
    events = list(provider.iter_stream(ChatRequest(model="ollama:qwen3:32b", messages=())))
    assert [type(event).__name__ for event in events] == ["TextDelta", "AssistantFinal"]
    assert getattr(events[0], "text", "") == "Looking."
