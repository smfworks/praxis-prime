"""Launch a stdio MCP server with an env allowlist.

bubblewrap is used when ``bwrap`` is on PATH and the server asks for it.
The parent environment is never passed through. Only the allowlist, plus
values the user wrote on that server, are visible to the child.

The server's working directory is mounted read-only. A read-write bind is
added only for an explicit per-server directory that a person approved,
and that directory is never ``$HOME`` and never the main checkout. The
mount decision is written to the audit log.

A failed bubblewrap start does not fall back to the host. A missing
``bwrap`` binary runs the command with the same allowlist and no extra
variables. ARCHITECTURE §13.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from praxis_prime.sandbox.bwrap import bwrap_available, writable_scope_ok

_PYTHON = ("python", "python3")


def child_environment(
    spec_command: str,
    allow: tuple[str, ...],
    explicit: Mapping[str, str],
    parent: Mapping[str, str],
) -> dict[str, str]:
    """Build the child environment. ``parent`` is filtered by ``allow`` first."""
    env: dict[str, str] = {}
    for key in allow:
        value = parent.get(key)
        if value:
            env[key] = value
    for key, value in explicit.items():
        if "\n" in value or "\x00" in value:
            raise ValueError(f"refusing env {key}: values cannot contain newlines")
        env[key] = value
    if "PATH" not in env:
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    if _is_python(spec_command) and "PYTHONUNBUFFERED" not in env:
        env["PYTHONUNBUFFERED"] = "1"
    return env


@dataclass(frozen=True, slots=True)
class McpMount:
    """How the server's filesystem is mounted. ``mode`` is ``ro`` or ``rw``."""

    mode: str
    decision: str
    scope: str


def mcp_mount_decision(
    cwd: Path,
    write_scope: Path | None,
    *,
    write_approved: bool,
    main_checkout: Path | None,
) -> McpMount:
    """Read-only cwd unless ``write_scope`` was approved and is a legal directory.

    A missing scope is the default and is allowed. A scope that was asked
    for and refused, or that is ``$HOME`` or the main checkout, stays
    read-only and is recorded as a denial.
    """
    if write_scope is None:
        return McpMount("ro", "allow", "")
    try:
        scope = write_scope.resolve()
        work = cwd.resolve()
    except OSError:
        return McpMount("ro", "deny", str(write_scope))
    legal = (
        write_approved
        and scope.is_dir()
        and writable_scope_ok(scope, scope, main_checkout)
    )
    if not legal:
        return McpMount("ro", "deny", str(scope))
    chosen = work if scope == work else scope
    return McpMount("rw", "allow", str(chosen))


def audit_mcp_mount(
    audit: Any,
    *,
    server: str,
    mount: McpMount,
    main_checkout: Path | None,
) -> None:
    """Record the mount decision the way shell records ``shell_mount``."""
    if audit is None or not hasattr(audit, "append"):
        return
    summary = f"{mount.mode} {mount.decision} {server}"
    audit.append(
        session_id=None,
        kind="mcp_mount",
        summary=summary[:300],
        payload={
            "server": server,
            "mount": mount.mode,
            "decision": mount.decision,
            "write_scope": mount.scope,
            "main_checkout": "" if main_checkout is None else str(main_checkout),
        },
    )


def build_mcp_bwrap_argv(
    command: str,
    args: tuple[str, ...] | list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    network: str,
    write_scope: Path | None = None,
    write_approved: bool = False,
    main_checkout: Path | None = None,
) -> list[str]:
    """Return a bwrap command that runs the server with ``--clearenv``.

    The working directory is ``--ro-bind``. ``write_scope`` is ``--bind``
    only when ``write_approved`` is set and the directory is not ``$HOME``
    or ``main_checkout``.
    """
    argv = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]
    if network == "on":
        argv.append("--share-net")
    for key, value in env.items():
        argv.extend(["--setenv", key, value])
    argv.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
    work = cwd.resolve()
    mount = mcp_mount_decision(
        work,
        write_scope,
        write_approved=write_approved,
        main_checkout=main_checkout,
    )
    bound: list[Path] = []
    for optional in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
        path = Path(optional)
        if path.exists():
            argv.extend(["--ro-bind", optional, optional])
            bound.append(path)
    if work.exists():
        flag = "--bind" if mount.mode == "rw" and mount.scope == str(work) else "--ro-bind"
        argv.extend([flag, str(work), str(work)])
        bound.append(work)
    if mount.mode == "rw" and mount.scope and mount.scope != str(work):
        # A parent --ro-bind (the cwd, or /usr) does not make this directory
        # writable. Mount it afterwards so the read-write bind sits on top.
        scope = Path(mount.scope)
        if scope.exists():
            argv.extend(["--bind", str(scope), str(scope)])
            bound.append(scope)
    for candidate in _bind_candidates(command, args):
        if _covered(candidate, bound):
            continue
        argv.extend(["--ro-bind", str(candidate), str(candidate)])
        bound.append(candidate)
    argv.extend(["--chdir", str(work), "--", command, *args])
    return argv


def popen_stdio(
    command: str,
    args: tuple[str, ...],
    *,
    cwd: Path,
    allow: tuple[str, ...],
    explicit: Mapping[str, str],
    parent: Mapping[str, str],
    sandbox: str,
    network: str,
    write_scope: Path | None = None,
    write_approved: bool = False,
    main_checkout: Path | None = None,
    audit: Any = None,
    server: str = "",
) -> subprocess.Popen[bytes]:
    """Start the server. The returned process speaks MCP on stdin and stdout."""
    env = child_environment(command, allow, explicit, parent)
    work = cwd.resolve()
    work.mkdir(parents=True, exist_ok=True)
    mount = mcp_mount_decision(
        work,
        write_scope,
        write_approved=write_approved,
        main_checkout=main_checkout,
    )
    audit_mcp_mount(audit, server=server, mount=mount, main_checkout=main_checkout)
    use_bwrap = sandbox != "off" and bwrap_available()
    if use_bwrap:
        argv = build_mcp_bwrap_argv(
            command,
            args,
            cwd=work,
            env=env,
            network=network,
            write_scope=write_scope,
            write_approved=write_approved,
            main_checkout=main_checkout,
        )
    else:
        argv = [command, *args]
    try:
        return subprocess.Popen(
            argv,
            cwd=work,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeError(f"could not start MCP server: {exc}") from exc


def _bind_candidates(command: str, args: tuple[str, ...] | list[str]) -> list[Path]:
    found: list[Path] = []
    venv = _venv_root(Path(command))
    if venv is not None:
        found.append(venv.resolve())
    found.extend(_interpreter_dirs(Path(command)))
    for raw in (command, *args):
        path = Path(raw)
        if not path.exists():
            continue
        resolved = path.resolve()
        found.append(resolved)
        # The child execs ``raw``. Mounting only the resolved target leaves a
        # symlink such as ``.../bin/python`` missing inside the sandbox.
        if path.is_absolute() and resolved != path:
            found.append(path)
    return found


def _interpreter_dirs(executable: Path) -> list[Path]:
    """``bin`` and ``lib`` for an interpreter that does not live under ``/usr``.

    ``actions/setup-python`` installs a ``python`` symlink next to the real
    binary. The dynamic linker also needs the sibling ``lib`` directory.
    """
    if not executable.exists():
        return []
    parent = executable.resolve().parent
    if parent.name != "bin":
        return []
    root = parent.parent
    dirs: list[Path] = []
    for name in ("bin", "lib", "lib64"):
        candidate = root / name
        if candidate.is_dir():
            dirs.append(candidate)
    return dirs


def _covered(path: Path, prefixes: list[Path]) -> bool:
    """True when ``path`` itself, not its symlink target, is already mounted.

    Resolving a venv ``bin/python`` lands on the system interpreter under
    ``/usr``. That must not drop the symlink the child actually execs.
    """
    probe = path if path.is_symlink() else path.resolve()
    for prefix in prefixes:
        base = prefix if prefix.is_symlink() else prefix.resolve()
        try:
            probe.relative_to(base)
        except ValueError:
            continue
        return True
    return False


def _venv_root(executable: Path) -> Path | None:
    """Return the venv root. ``pyvenv.cfg`` lives next to ``bin``, not inside it."""
    if not executable.exists():
        return None
    checked: list[Path] = []
    for parent in (executable.parent, *executable.resolve().parents):
        checked.append(parent)
        if parent.name == "bin":
            checked.append(parent.parent)
    seen: set[Path] = set()
    for parent in checked:
        if parent in seen:
            continue
        seen.add(parent)
        if (parent / "pyvenv.cfg").is_file():
            return parent
    return None


def _is_python(command: str) -> bool:
    name = Path(command).name
    return name in _PYTHON or name.startswith("python3.")
