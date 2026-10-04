"""Ask a model for a theme package, then let the validator judge it.

The default path is offline. A caller passes a ``complete(prompt)`` model.
The live path, ``router_complete``, uses the configured router and is not
called unless a test opts in. Model text is untrusted: files are written
only under the destination directory, and ``theme lint`` is the only check.

Addendum A §1.1.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from praxis_prime.statfile import StatKind, lstat_kind
from praxis_prime.themes.archive import MAX_FILE_BYTES
from praxis_prime.themes.errors import ThemeError
from praxis_prime.themes.validate import validate_dir

MAX_ROUNDS = 3
_MAX_REPLY = 1_000_000
_TOP = frozenset(
    {
        "theme.toml",
        "THEME.md",
        "LICENSE",
        "LICENSE.txt",
        "theme.css",
        "NOTICE",
        "OFL.txt",
    }
)


class ThemeModel(Protocol):
    def complete(self, prompt: str) -> str:
        """Return the next package. The prompt includes lint errors after a failure."""


@dataclass(frozen=True, slots=True)
class RoundResult:
    ok: bool
    rounds: int
    theme_id: str
    message: str


def default_guide() -> str:
    """The authoring guide from this repository checkout."""
    path = Path(__file__).resolve().parents[4] / "docs" / "THEME-AUTHORING.md"
    return path.read_text(encoding="utf-8")


def author_prompt(guide: str, brief: str) -> str:
    return (
        f"{guide.rstrip()}\n\n"
        f"Brief: {brief.strip()}\n\n"
        "Reply with one JSON object and nothing else. Keys are package-relative "
        "paths. Values are the file text. Include theme.toml, THEME.md, and LICENSE. "
        "Do not use an id that starts with smf. Do not include a remote URL.\n"
    )


def run_roundtrip(
    model: ThemeModel,
    brief: str,
    dest: Path,
    *,
    guide: str | None = None,
    rounds: int = MAX_ROUNDS,
) -> RoundResult:
    """Write the model's package under ``dest`` and lint it, with a few fix-up rounds."""
    if rounds < 1 or rounds > MAX_ROUNDS:
        raise ValueError(f"rounds must be from 1 to {MAX_ROUNDS}")
    _require_dir(dest)
    text = guide if guide is not None else default_guide()
    prompt = author_prompt(text, brief)
    last = "the model did not return a package"
    for attempt in range(1, rounds + 1):
        raw = model.complete(prompt)
        try:
            files = parse_package(raw)
            _replace(dest, files)
            package = validate_dir(dest)
        except (ThemeError, ValueError, OSError, UnicodeError) as exc:
            last = exc.to_json() if isinstance(exc, ThemeError) else str(exc)
            if not isinstance(last, str):
                last = json.dumps(last)
            prompt = f"{prompt}\nLint errors:\n{last}\n"
            continue
        return RoundResult(True, attempt, package.theme_id, "")
    return RoundResult(False, rounds, "", last if isinstance(last, str) else json.dumps(last))


def parse_package(raw: str) -> dict[str, str]:
    """JSON path to text. Rejects absolute paths, ``..``, and unknown names."""
    if len(raw) > _MAX_REPLY:
        raise ValueError("model output is too large")
    try:
        loaded = json.loads(_json_object(raw))
    except json.JSONDecodeError as exc:
        raise ValueError(f"model output is not JSON ({exc})") from exc
    if not isinstance(loaded, dict) or not loaded:
        raise ValueError("model output must be a JSON object of files")
    files: dict[str, str] = {}
    for key, value in loaded.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("each file must be a string path and a string body")
        relative = _safe_relative(key)
        if len(value.encode("utf-8")) > MAX_FILE_BYTES:
            raise ValueError(f"{relative} is larger than the per-file cap")
        files[relative] = value
    return files


def router_complete(prompt: str) -> str:
    """One completion from the configured provider chain.

    Called only by the opt-in live test. This module does not store a key
    or a provider URL.
    """
    from praxis_prime.router.factory import build_router
    from praxis_prime.router.settings import load_settings
    from praxis_prime.router.types import AssistantFinal, ChatMessage, ChatRequest, TextDelta

    router = build_router(load_settings())
    request = ChatRequest(
        model="",
        messages=(ChatMessage(role="user", content=prompt),),
    )
    parts: list[str] = []
    final = ""
    for event in router.iter_stream(request):
        if isinstance(event, TextDelta):
            parts.append(event.text)
        elif isinstance(event, AssistantFinal):
            final = event.content
    text = final or "".join(parts)
    if not text.strip():
        raise RuntimeError("the router returned an empty theme")
    return text


class RouterModel:
    """ThemeModel adapter for ``router_complete``."""

    def complete(self, prompt: str) -> str:
        return router_complete(prompt)


def _json_object(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("model output has no JSON object")
    return text[start : end + 1]


def _safe_relative(key: str) -> str:
    if not key or key.startswith(("/", "\\")) or "\\" in key or "\x00" in key:
        raise ValueError(f"refusing path {key!r}")
    parts = tuple(part for part in key.split("/") if part not in {"", "."})
    if not parts or ".." in parts:
        raise ValueError(f"refusing path {key!r}")
    relative = "/".join(parts)
    if relative in _TOP:
        return relative
    if relative.startswith("assets/fonts/") and _one_segment(relative, "assets/fonts/"):
        return relative
    if relative.startswith("assets/ornaments/") and _one_segment(relative, "assets/ornaments/"):
        return relative
    raise ValueError(f"refusing path {key!r}")


def _one_segment(relative: str, prefix: str) -> bool:
    name = relative[len(prefix) :]
    if not name or "/" in name or name in {".", ".."}:
        return False
    return all(char.isalnum() or char in "._-" for char in name)


def _require_dir(dest: Path) -> None:
    kind = lstat_kind(dest)
    if kind is StatKind.MISSING:
        dest.mkdir(parents=True)
        return
    if kind is not StatKind.DIR:
        raise ValueError("package directory must be a real directory")


def _replace(dest: Path, files: dict[str, str]) -> None:
    _clear(dest)
    root = dest.resolve()
    for relative, text in files.items():
        path = (dest / relative).resolve()
        if path != root and root not in path.parents:
            raise ValueError(f"refusing to write {relative}")
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_new(path, text)


def _clear(dest: Path) -> None:
    for name in _TOP:
        _unlink(dest / name)
    assets = dest / "assets"
    if lstat_kind(assets) is StatKind.DIR:
        shutil.rmtree(assets)
    elif lstat_kind(assets) is StatKind.SYMLINK:
        assets.unlink()


def _unlink(path: Path) -> None:
    kind = lstat_kind(path)
    if kind is StatKind.MISSING:
        return
    if kind is StatKind.DIR:
        shutil.rmtree(path)
        return
    path.unlink()


def _write_new(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
