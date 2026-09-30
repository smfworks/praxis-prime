"""Launch a stdio MCP server with an env allowlist.

bubblewrap is used when ``bwrap`` is on PATH and the server asks for it.
The parent environment is never passed through. Only the allowlist, plus
values the user wrote on that server, are visible to the child.

A failed bubblewrap start does not fall back to the host. A missing
``bwrap`` binary runs the command with the same allowlist and no extra
variables. ARCHITECTURE §13.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.sandbox.bwrap import bwrap_available

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


def build_mcp_bwrap_argv(
    command: str,
    args: tuple[str, ...] | list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    network: str,
) -> list[str]:
    """Return a bwrap command that runs the server with ``--clearenv``."""
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
    bound: list[Path] = []
    for optional in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
        path = Path(optional)
        if path.exists():
            argv.extend(["--ro-bind", optional, optional])
            bound.append(path)
    if work.exists():
        argv.extend(["--bind", str(work), str(work)])
        bound.append(work)
    for candidate in _bind_candidates(command, args):
        if _covered(candidate, bound):
            continue
        flag = "--ro-bind"
        argv.extend([flag, str(candidate), str(candidate)])
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
) -> subprocess.Popen[bytes]:
    """Start the server. The returned process speaks MCP on stdin and stdout."""
    env = child_environment(command, allow, explicit, parent)
    work = cwd.resolve()
    work.mkdir(parents=True, exist_ok=True)
    use_bwrap = sandbox != "off" and bwrap_available()
    if use_bwrap:
        argv = build_mcp_bwrap_argv(command, args, cwd=work, env=env, network=network)
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
    for prefix in prefixes:
        try:
            path.resolve().relative_to(prefix.resolve())
        except ValueError:
            continue
        return True
    return False


def _venv_root(executable: Path) -> Path | None:
    if not executable.exists():
        return None
    for parent in (executable.parent, *executable.resolve().parents):
        if (parent / "pyvenv.cfg").is_file():
            return parent
    return None


def _is_python(command: str) -> bool:
    name = Path(command).name
    return name in _PYTHON or name.startswith("python3.")
