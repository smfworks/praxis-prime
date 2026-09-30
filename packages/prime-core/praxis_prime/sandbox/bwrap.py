"""Bubblewrap launcher for shell commands.

bubblewrap is LGPL-2.0+ and is invoked as a system binary. It is not linked
into this process. ``--unshare-all`` drops the network namespace. If the
binary is missing, callers must not run the command on the host unless a
person has approved that command.

A failed sandbox does not fall back to an unsandboxed run.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path


class SandboxError(RuntimeError):
    """The sandbox could not run the command. The host shell was not used."""


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def build_bwrap_argv(command: str, cwd: Path) -> list[str]:
    """Return a bwrap command that runs ``command`` with network unshared."""
    work = cwd.resolve()
    argv = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/workspace",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "TERM",
        "xterm-256color",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--bind",
        str(work),
        "/workspace",
        "--chdir",
        "/workspace",
    ]
    for optional in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
        if Path(optional).exists():
            argv.extend(["--ro-bind", optional, optional])
    argv.extend(["--", "bash", "-lc", command])
    return argv


def run_bwrap(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
) -> str:
    """Run ``command`` inside bubblewrap. Never falls back to the host."""
    if not bwrap_available():
        raise SandboxError(
            "bubblewrap is not available; the command was not run on the host"
        )
    argv = build_bwrap_argv(command, cwd)
    source = os.environ if env is None else env
    try:
        return run_process(
            argv,
            cwd=cwd,
            cancelled=cancelled,
            timeout=timeout,
            env=scrub_env(source),
        )
    except OSError as exc:
        raise SandboxError(
            f"bubblewrap failed to start ({exc}); the command was not run on the host"
        ) from exc


def run_host_shell(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
) -> str:
    """Run a command on the host. Callers must already have an approval."""
    source = os.environ if env is None else env
    return run_process(
        ["bash", "-lc", command],
        cwd=cwd,
        cancelled=cancelled,
        timeout=timeout,
        env=scrub_env(source),
    )


def scrub_env(source: Mapping[str, str]) -> dict[str, str]:
    """Drop credential-shaped variables before a shell starts."""
    blocked_prefixes = (
        "OPENAI_",
        "ANTHROPIC_",
        "XAI_",
        "PRAXIS_PRIME_",
        "AWS_",
        "AZURE_",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NPM_TOKEN",
    )
    cleaned: dict[str, str] = {}
    for key, value in source.items():
        upper = key.upper()
        if upper.startswith(blocked_prefixes):
            continue
        if any(part in upper for part in ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "APIKEY")):
            continue
        cleaned[key] = value
    return cleaned


def run_process(
    argv: list[str],
    *,
    cwd: Path,
    cancelled: Callable[[], bool],
    timeout: float,
    env: dict[str, str] | None,
) -> str:
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    waited = 0.0
    try:
        while True:
            if cancelled():
                _kill(proc)
                raise SandboxError("command cancelled")
            try:
                stdout, stderr = proc.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                waited += 0.2
                if waited >= timeout:
                    _kill(proc)
                    raise SandboxError(f"command timed out after {timeout:.0f}s") from None
        return _combine(stdout, stderr, proc.returncode)
    finally:
        if proc.poll() is None:
            _kill(proc)


def _kill(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()


def _combine(stdout: str, stderr: str, code: int | None) -> str:
    parts: list[str] = []
    if stdout:
        parts.append(stdout.rstrip("\n"))
    if stderr:
        parts.append(stderr.rstrip("\n"))
    if code not in (0, None):
        parts.append(f"(exit {code})")
    return "\n".join(parts) if parts else "(no output)"
