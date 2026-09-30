"""Bubblewrap launcher for shell commands.

bubblewrap is LGPL-2.0+ and is invoked as a system binary. It is not linked
into this process. ``--unshare-all`` drops the network namespace. The
workspace is mounted read-only unless the caller has an approved write scope.
That scope is one directory: a task worktree or the approved command's
cwd. It is never ``$HOME`` and never the main checkout when one is named.
Bash is started with ``--noprofile --norc`` so a login alias cannot rewrite
an allowlisted command.

If the binary is missing, callers must not run the command on the host unless
a person has approved that command. A failed sandbox does not fall back to an
unsandboxed run.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path


class SandboxError(RuntimeError):
    """The sandbox could not run the command. The host shell was not used."""


@dataclass(frozen=True, slots=True)
class CommandStatus:
    """Exit code plus combined output. ``code`` is the process status."""

    code: int
    output: str


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def writable_scope_ok(
    cwd: Path,
    scope: Path | None,
    main_checkout: Path | None = None,
) -> bool:
    """True when ``cwd`` is the one directory this write may mount."""
    if scope is None:
        return False
    try:
        resolved = cwd.resolve()
        allowed = scope.resolve()
        home = Path.home().resolve()
    except OSError:
        return False
    if resolved != allowed:
        return False
    if resolved == home or _contains(resolved, home):
        return False
    if main_checkout is not None:
        try:
            if resolved == main_checkout.resolve():
                return False
        except OSError:
            return False
    return True


def build_bwrap_argv(
    command: str,
    cwd: Path,
    *,
    ro_binds: list[tuple[str, str]] | None = None,
    writable: bool = False,
    scope: Path | None = None,
    main_checkout: Path | None = None,
) -> list[str]:
    """Return a bwrap command that runs ``command`` with network unshared.

    The workspace mount is ``--ro-bind`` unless ``writable`` is set and
    ``scope`` is exactly ``cwd``, and that directory is not ``$HOME`` or
    ``main_checkout``.
    """
    work = cwd.resolve()
    mount = "--ro-bind"
    if writable:
        if not writable_scope_ok(work, scope, main_checkout):
            raise SandboxError(
                "refusing read-write bind outside the approved worktree; "
                "the command was not run"
            )
        mount = "--bind"
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
        mount,
        str(work),
        "/workspace",
        "--chdir",
        "/workspace",
    ]
    for optional in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
        if Path(optional).exists():
            argv.extend(["--ro-bind", optional, optional])
    for src, dest in ro_binds or []:
        if Path(src).exists():
            argv.extend(["--ro-bind", src, dest])
    argv.extend(["--", "bash", "--noprofile", "--norc", "-c", command])
    return argv


def run_bwrap(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
    writable: bool = False,
    scope: Path | None = None,
    main_checkout: Path | None = None,
) -> str:
    """Run ``command`` inside bubblewrap. Never falls back to the host."""
    if not bwrap_available():
        raise SandboxError(
            "bubblewrap is not available; the command was not run on the host"
        )
    argv = build_bwrap_argv(
        command,
        cwd,
        writable=writable,
        scope=scope,
        main_checkout=main_checkout,
    )
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


def run_bwrap_status(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
    stdin: str = "",
    writable: bool = False,
    scope: Path | None = None,
    main_checkout: Path | None = None,
) -> CommandStatus:
    """Run ``command`` inside bubblewrap and return its exit code."""
    if not bwrap_available():
        raise SandboxError(
            "bubblewrap is not available; the command was not run on the host"
        )
    argv = build_bwrap_argv(
        command,
        cwd,
        writable=writable,
        scope=scope,
        main_checkout=main_checkout,
    )
    source = os.environ if env is None else env
    try:
        return run_captured(
            argv,
            cwd=cwd,
            cancelled=cancelled,
            timeout=timeout,
            env=scrub_env(source),
            stdin=stdin,
        )
    except OSError as exc:
        raise SandboxError(
            f"bubblewrap failed to start ({exc}); the command was not run on the host"
        ) from exc


def run_host_status(
    command: str,
    cwd: Path,
    cancelled: Callable[[], bool],
    *,
    timeout: float = 30,
    env: Mapping[str, str] | None = None,
    stdin: str = "",
) -> CommandStatus:
    """Run a command on the host and return its exit code.

    Callers that use this for a shell tool must already have an approval.
    Project hooks use it only when bubblewrap is missing, and only with a
    scrubbed environment.
    """
    source = os.environ if env is None else env
    return run_captured(
        ["bash", "--noprofile", "--norc", "-c", command],
        cwd=cwd,
        cancelled=cancelled,
        timeout=timeout,
        env=scrub_env(source),
        stdin=stdin,
    )


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
        ["bash", "--noprofile", "--norc", "-c", command],
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
    blocked_names = {"BASH_ENV", "ENV", "SHELLOPTS"}
    cleaned: dict[str, str] = {}
    for key, value in source.items():
        upper = key.upper()
        if upper in blocked_names or upper.startswith("BASH_FUNC_"):
            continue
        if upper.startswith(blocked_prefixes):
            continue
        if any(part in upper for part in ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "APIKEY")):
            continue
        cleaned[key] = value
    return cleaned


def run_captured(
    argv: list[str],
    *,
    cwd: Path,
    cancelled: Callable[[], bool],
    timeout: float,
    env: dict[str, str] | None,
    stdin: str = "",
) -> CommandStatus:
    """Run ``argv`` and return the exit code. Does not fall back to another command."""
    if cancelled():
        raise SandboxError("command cancelled")
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    waited = 0.0
    try:
        if proc.stdin is not None:
            try:
                proc.stdin.write(stdin)
                proc.stdin.close()
            except BrokenPipeError:
                pass
            # communicate() refuses a stdin handle that is already closed.
            proc.stdin = None
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
        code = proc.returncode if proc.returncode is not None else 1
        output = _combine(stdout, stderr, None)
        return CommandStatus(code=code, output=output)
    finally:
        if proc.poll() is None:
            _kill(proc)


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


def _contains(parent: Path, child: Path) -> bool:
    """True when ``child`` is strictly inside ``parent``."""
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return parent != child


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
