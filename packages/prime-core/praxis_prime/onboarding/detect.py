"""Read-only discovery. Nothing here downloads, installs, pulls, or starts a server."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from praxis_prime.onboarding.probe import FetchResult, ProbeError
from praxis_prime.onboarding.probe import fetch as default_fetch
from praxis_prime.onboarding.registry import key_env_names, local_servers

# Derived from the provider registry. The tuples stay equal to the historical ones.
LOCAL_SERVERS: tuple[tuple[str, str, str, str], ...] = local_servers()
KEY_ENV_NAMES: tuple[str, ...] = key_env_names()

Fetcher = Callable[..., FetchResult]
Runner = Callable[[Sequence[str]], str]
DETECT_TIMEOUT = 0.8


def detect(
    env: Mapping[str, str] | None = None,
    *,
    fetcher: Fetcher | None = None,
    runner: Runner | None = None,
    timeout: float = DETECT_TIMEOUT,
) -> dict[str, object]:
    """Local servers, key *names*, and GPU facts. Values of keys are omitted."""
    source = os.environ if env is None else env
    fetch = fetcher or default_fetch
    present = [name for name in KEY_ENV_NAMES if source.get(name, "").strip()]
    return {
        "servers": _servers(fetch, timeout),
        "envKeys": present,
        "hardware": detect_hardware(runner),
    }


def _servers(fetch: Fetcher, timeout: float) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    for provider, base, models_path, props_path in LOCAL_SERVERS:
        try:
            result = fetch("GET", base + models_path, timeout=timeout, limit=256 * 1024)
        except (ProbeError, OSError, TimeoutError, ValueError):
            continue
        if result.status < 200 or result.status >= 300:
            continue
        models, context = _parse_models(result.body)
        if props_path and context is None:
            context = _props_context(fetch, base + props_path, timeout)
        found.append(
            {
                "provider": provider,
                "baseUrl": base,
                "models": models,
                "contextLength": context,
            }
        )
    return found


def _props_context(fetch: Fetcher, url: str, timeout: float) -> int | None:
    try:
        result = fetch("GET", url, timeout=timeout, limit=256 * 1024)
    except (ProbeError, OSError, TimeoutError, ValueError):
        return None
    if result.status < 200 or result.status >= 300:
        return None
    try:
        payload = json.loads(result.body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return _context_number(payload) or _context_number(payload.get("default_generation_settings"))


def _parse_models(body: bytes) -> tuple[list[str], int | None]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return [], None
    if not isinstance(payload, dict):
        return [], None
    names: list[str] = []
    context: int | None = None
    models = payload.get("models")
    if isinstance(models, list):
        for item in models:
            if isinstance(item, dict):
                name = item.get("name") or item.get("model")
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
                if context is None:
                    context = _context_number(item)
    data = payload.get("data")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                name = item.get("id")
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
                if context is None:
                    context = _context_number(item)
    if context is None:
        context = _context_number(payload)
    return names, context


def _context_number(value: object) -> int | None:
    if not isinstance(value, dict):
        return None
    for key in ("max_model_len", "context_length", "n_ctx", "context_window"):
        raw = value.get(key)
        if isinstance(raw, bool):
            continue
        if isinstance(raw, int) and raw > 0:
            return raw
        if isinstance(raw, float) and raw > 0:
            return int(raw)
    return None


def detect_hardware(runner: Runner | None = None) -> list[dict[str, str]]:
    """GPU names and driver versions from read-only sources. Information only."""
    run = runner or _run_command
    found: list[dict[str, str]] = []
    nvidia = run(["nvidia-smi", "--query-gpu=name,driver_version", "--format=csv,noheader"])
    for line in nvidia.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) >= 2 and parts[0] and parts[1]:
            found.append({"vendor": "nvidia", "name": parts[0], "driver": parts[1]})
    if not any(item["vendor"] == "nvidia" for item in found):
        version = _read_text(Path("/proc/driver/nvidia/version"))
        if version:
            driver = version.splitlines()[0][:120]
            found.append({"vendor": "nvidia", "name": "NVIDIA", "driver": driver})
    rocm = run(["rocm-smi", "--showdriverversion"])
    for line in rocm.splitlines():
        if "driver" in line.lower() and ":" in line:
            driver = line.split(":", 1)[1].strip()[:120]
            found.append({"vendor": "amd", "name": "AMD", "driver": driver})
    found.extend(_drm_cards())
    if not found:
        lspci = run(["lspci", "-nn"])
        for line in lspci.splitlines():
            lower = line.lower()
            if "vga" not in lower and "3d controller" not in lower and "display" not in lower:
                continue
            if "nvidia" in lower:
                vendor = "nvidia"
            elif "amd" in lower or "ati" in lower:
                vendor = "amd"
            else:
                vendor = ""
            if vendor:
                found.append({"vendor": vendor, "name": line.strip()[:160], "driver": ""})
    return found


def _drm_cards() -> list[dict[str, str]]:
    root = Path("/sys/class/drm")
    if not root.is_dir():
        return []
    cards: list[dict[str, str]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return []
    for entry in entries:
        name = entry.name
        if not name.startswith("card") or "-" in name:
            continue
        vendor_path = entry / "device" / "vendor"
        try:
            vendor_id = vendor_path.read_text(encoding="utf-8").strip().lower()
        except OSError:
            continue
        vendor = {"0x10de": "nvidia", "0x1002": "amd"}.get(vendor_id, "")
        if not vendor:
            continue
        if any(item["vendor"] == vendor for item in cards):
            continue
        cards.append({"vendor": vendor, "name": name, "driver": ""})
    return cards


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _run_command(argv: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            timeout=1.5,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout or ""
