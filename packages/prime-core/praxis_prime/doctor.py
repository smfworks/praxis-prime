"""Environment checks for ``praxis-prime doctor``.

Reports Python, Ubuntu vs Arch vs Omarchy, Wayland vs X11, the configured
model provider, and local servers that answered a read-only probe. A missing
display is a warning. A missing provider is a warning. Detected local servers
are information only and are not selected. Python older than 3.12 is a failure.

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
    provider_spec: str = "",
    provider_ready: bool = False,
    local_servers: Sequence[str] | None = None,
) -> list[Check]:
    detected = list(local_servers or ())
    if ollama_reachable and not any(item.startswith("ollama ") for item in detected):
        detected.append(f"ollama at {ollama_base}")
    return [
        check_python(version_info),
        check_os(os_release_text, env, which, path_exists),
        check_session(env),
        check_provider(provider_spec, provider_ready),
        check_local_servers(detected),
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
    """Kept for callers that probe Ollama on its own. Doctor does not select it."""
    if reachable:
        return Check("Ollama", "ok", f"reachable at {base_url}")
    return Check("Ollama", "warn", f"not reachable at {base_url}")


def check_provider(spec: str, ready: bool) -> Check:
    chosen = spec.strip()
    if not chosen:
        return Check(
            "Provider",
            "warn",
            "no provider configured. Run `praxis-prime setup` or open the web UI.",
        )
    if ready:
        return Check("Provider", "ok", f"configured {chosen}")
    return Check(
        "Provider",
        "warn",
        f"{chosen} is chosen but not verified. Run `praxis-prime setup`.",
    )


def check_local_servers(servers: Sequence[str]) -> Check:
    if not servers:
        return Check("Local servers", "info", "none detected (information only; not selected)")
    listed = ", ".join(servers)
    return Check("Local servers", "info", f"detected (information only; not selected): {listed}")


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


def _detected_local_servers() -> list[str]:
    """Names of local servers that answered. Detection never selects one."""
    try:
        from praxis_prime.onboarding.detect import detect

        found = detect(timeout=0.8)
    except (OSError, ValueError):
        return []
    servers = found.get("servers")
    if not isinstance(servers, list):
        return []
    names: list[str] = []
    for item in servers:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider", "")).strip()
        base = str(item.get("baseUrl", "")).strip()
        if provider and base:
            names.append(f"{provider} at {base}")
        elif provider:
            names.append(provider)
    return names


def run_system_doctor() -> list[Check]:
    from praxis_prime.browser.driver import playwright_available
    from praxis_prime.router.settings import load_settings

    settings = load_settings()
    ready = bool(settings.model_spec) and settings.model_spec in settings.verified_specs
    return collect_checks(
        version_info=(sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
        os_release_text=_read_text(Path("/etc/os-release")),
        env=_system_env(),
        which=shutil.which,
        path_exists=lambda candidate: Path(candidate).exists(),
        ollama_reachable=probe_ollama(timeout=0.8),
        bwrap_present=shutil.which("bwrap") is not None,
        playwright_present=playwright_available(),
        provider_spec=settings.model_spec,
        provider_ready=ready,
        local_servers=_detected_local_servers(),
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
