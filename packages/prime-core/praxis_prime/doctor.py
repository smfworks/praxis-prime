"""Environment checks for ``praxis-prime doctor``.

Reports Python, Ubuntu vs Arch vs Omarchy, Wayland vs X11, and whether Ollama
answers on loopback. A missing display or a stopped Ollama is a warning.
Python older than 3.12 is a failure.

TODO: ARCHITECTURE §28.1 (portals, uinput, PipeWire) once those adapters exist.
"""

from __future__ import annotations

import os
import shutil
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_OLLAMA_BASE = "http://127.0.0.1:11434"
_OLLAMA_PROBE_PATH = "/api/tags"
_PROBE_TIMEOUT_SECONDS = 1.5

Which = Callable[[str], str | None]
PathExists = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str

    def format(self) -> str:
        return f"[{self.status:>4}] {self.name}: {self.detail}"


def format_report(checks: Sequence[Check]) -> str:
    lines = ["praxis-prime doctor", *(check.format() for check in checks)]
    return "\n".join(lines) + "\n"


def report_exit_code(checks: Sequence[Check]) -> int:
    if any(check.status == "fail" for check in checks):
        return 1
    return 0


def collect_checks(
    *,
    version_info: tuple[int, int, int],
    os_release_text: str | None,
    env: Mapping[str, str],
    which: Which,
    path_exists: PathExists,
    ollama_reachable: bool,
    ollama_base: str = DEFAULT_OLLAMA_BASE,
    bwrap_present: bool = False,
    playwright_present: bool = False,
) -> list[Check]:
    return [
        check_python(version_info),
        check_os(os_release_text, env, which, path_exists),
        check_session(env),
        check_ollama(ollama_reachable, ollama_base),
        check_sandbox(bwrap_present),
        check_browser(playwright_present),
    ]


def check_python(version_info: tuple[int, int, int]) -> Check:
    version = ".".join(str(part) for part in version_info[:3])
    if version_info >= (3, 12):
        return Check("Python", "ok", version)
    return Check("Python", "fail", f"{version} (3.12 or newer is required)")


def check_os(
    os_release_text: str | None,
    env: Mapping[str, str],
    which: Which,
    path_exists: PathExists,
) -> Check:
    parsed = parse_os_release(os_release_text or "")
    family, detail = classify_os(parsed, env, which, path_exists)
    if family in {"ubuntu", "arch", "omarchy"}:
        return Check("OS", "ok", f"{family} ({detail})")
    if family == "unknown":
        return Check("OS", "warn", detail)
    return Check("OS", "warn", f"{family} ({detail})")


def check_session(env: Mapping[str, str]) -> Check:
    kind, detail = classify_session(env)
    status = "ok" if kind in {"wayland", "x11"} else "warn"
    return Check("Session", status, detail)


def check_sandbox(bwrap_present: bool) -> Check:
    if bwrap_present:
        return Check(
            "Sandbox",
            "ok",
            "bubblewrap is on PATH. Stdio MCP servers use it.",
        )
    return Check(
        "Sandbox",
        "warn",
        "bubblewrap is not on PATH. Stdio MCP servers run with an env allowlist only.",
    )


def check_browser(playwright_present: bool) -> Check:
    if playwright_present:
        return Check(
            "Browser",
            "ok",
            "Playwright is installed. Chromium is a separate download; "
            "without it the browser tool uses web_fetch.",
        )
    return Check(
        "Browser",
        "warn",
        "Playwright is not installed. The browser tool falls back to web_fetch. "
        "Install with pip install 'praxis-prime[browser]'.",
    )


def check_ollama(reachable: bool, base_url: str) -> Check:
    if reachable:
        return Check("Ollama", "ok", f"reachable at {base_url}")
    return Check("Ollama", "warn", f"not reachable at {base_url}")


def classify_os(
    os_release: Mapping[str, str],
    env: Mapping[str, str],
    which: Which,
    path_exists: PathExists,
) -> tuple[str, str]:
    """Return ``(family, detail)``.

    ``family`` is ``ubuntu``, ``arch``, ``omarchy``, ``other``, or ``unknown``.
    Omarchy is reported on its own, including when the underlying id is Arch.
    """
    pretty = os_release.get("PRETTY_NAME") or os_release.get("ID") or "unknown"
    if _is_omarchy(os_release, env, which, path_exists):
        return "omarchy", f"Omarchy on {pretty}"
    os_id = os_release.get("ID", "").lower()
    like = _tokens(os_release.get("ID_LIKE", ""))
    if os_id == "ubuntu" or "ubuntu" in like:
        return "ubuntu", pretty
    if os_id in {"arch", "archlinux"} or "arch" in like or "archlinux" in like:
        return "arch", pretty
    if not os_release:
        return "unknown", "os-release not found"
    return "other", pretty


def classify_session(env: Mapping[str, str]) -> tuple[str, str]:
    """Return ``(kind, detail)`` where kind is wayland, x11, or unknown.

    Wayland wins when both Wayland and X11 variables are set, because XWayland
    still publishes ``DISPLAY``.
    """
    session = env.get("XDG_SESSION_TYPE", "").strip().lower()
    if env.get("WAYLAND_DISPLAY") or session == "wayland":
        return "wayland", "Wayland"
    if session == "x11" or env.get("DISPLAY"):
        return "x11", "X11"
    return "unknown", "headless (WAYLAND_DISPLAY and DISPLAY are unset)"


def parse_os_release(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = _unquote(value.strip())
    return parsed


def probe_ollama(
    base_url: str = DEFAULT_OLLAMA_BASE,
    timeout: float = _PROBE_TIMEOUT_SECONDS,
) -> bool:
    """Return true when Ollama's tags endpoint answers on loopback."""
    url = base_url.rstrip("/") + _OLLAMA_PROBE_PATH
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def run_system_doctor() -> list[Check]:
    from praxis_prime.browser.driver import playwright_available

    return collect_checks(
        version_info=(sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
        os_release_text=_read_text(Path("/etc/os-release")),
        env=_system_env(),
        which=shutil.which,
        path_exists=lambda candidate: Path(candidate).exists(),
        ollama_reachable=probe_ollama(),
        bwrap_present=shutil.which("bwrap") is not None,
        playwright_present=playwright_available(),
    )


def _system_env() -> Mapping[str, str]:
    return os.environ


def _is_omarchy(
    os_release: Mapping[str, str],
    env: Mapping[str, str],
    which: Which,
    path_exists: PathExists,
) -> bool:
    names = _tokens(os_release.get("ID", ""))
    names |= _tokens(os_release.get("ID_LIKE", ""))
    names |= _tokens(os_release.get("VARIANT_ID", ""))
    if "omarchy" in names:
        return True
    if which("omarchy"):
        return True
    home = env.get("HOME")
    if home and path_exists(str(Path(home) / ".config" / "omarchy")):
        return True
    return path_exists("/usr/bin/omarchy")


def _tokens(value: str) -> set[str]:
    return {part.strip().lower() for part in value.replace(",", " ").split() if part.strip()}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None
