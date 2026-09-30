"""Install the systemd --user unit.

The same unit works on Ubuntu and on Arch/Omarchy. ``service install``
rewrites ExecStart to the ``praxis-primed`` found on PATH so a distro
package (``/usr/bin``) and a pip install (``~/.local/bin`` or a venv) both
start. Linger is not enabled.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from praxis_prime.paths import cache_dir, data_dir, state_dir

UNIT_NAME = "praxis-prime.service"
_PACKAGED_EXEC = "/usr/bin/praxis-primed"


def render_user_unit(exec_start: str) -> str:
    """Unit text. ``exec_start`` is the daemon command without ``--config``."""
    return (
        "# systemd --user unit for Ubuntu 22.04+ and Arch/Omarchy.\n"
        "# Installed by `praxis-prime service install`.\n"
        "# ARCHITECTURE §26. Linger is not enabled.\n"
        "[Unit]\n"
        "Description=Praxis Prime agent daemon\n"
        "Documentation=https://github.com/smfworks/praxis-prime\n"
        "After=network-online.target graphical-session.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_start} --config %h/.config/praxis-prime/config.toml\n"
        "Restart=on-failure\n"
        "RestartSec=3\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "ProtectSystem=strict\n"
        "UMask=0077\n"
        "ReadWritePaths=%h/.local/share/praxis-prime %h/.local/state/praxis-prime "
        "%h/.cache/praxis-prime %t/praxis-prime\n"
        "RuntimeDirectory=praxis-prime\n"
        "StateDirectory=praxis-prime\n"
        "CacheDirectory=praxis-prime\n"
        "WorkingDirectory=%h\n"
        "Environment=PRAXIS_PRIME_LOG=info\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        "Environment=PYTHONDONTWRITEBYTECODE=1\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def packaged_unit_text() -> str:
    return render_user_unit(_PACKAGED_EXEC)


def systemd_user_dir(env: Mapping[str, str] | None = None) -> Path:
    environ = os.environ if env is None else env
    config_home = environ.get("XDG_CONFIG_HOME")
    if not config_home:
        home = environ.get("HOME") or str(Path.home())
        config_home = str(Path(home) / ".config")
    return Path(config_home) / "systemd" / "user"


def unit_path(env: Mapping[str, str] | None = None) -> Path:
    return systemd_user_dir(env) / UNIT_NAME


def daemon_exec() -> list[str]:
    found = shutil.which("praxis-primed")
    if found:
        return [found]
    return [sys.executable, "-m", "praxis_prime.daemon"]


def install(env: Mapping[str, str] | None = None) -> int:
    """Write the user unit, reload, and enable it."""
    command = _exec_start(daemon_exec())
    path = unit_path(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_user_unit(command), encoding="utf-8")
    _ensure_state_dirs(env)
    print(f"praxis-prime service: wrote {path}")
    reload = _systemctl(["daemon-reload"])
    if reload != 0:
        return reload
    enabled = _systemctl(["enable", "--now", UNIT_NAME])
    if enabled == 0:
        print("praxis-prime service: enabled praxis-prime.service")
    return enabled


def uninstall(env: Mapping[str, str] | None = None) -> int:
    """Disable the user unit and remove the file this command wrote."""
    _systemctl(["disable", "--now", UNIT_NAME], check=False)
    path = unit_path(env)
    path.unlink(missing_ok=True)
    print(f"praxis-prime service: removed {path}")
    return _systemctl(["daemon-reload"], check=False)


def _exec_start(argv: list[str]) -> str:
    parts = [shlex.quote(part) if any(char.isspace() for char in part) else part for part in argv]
    return " ".join(parts)


def _ensure_state_dirs(env: Mapping[str, str] | None) -> None:
    for directory in (data_dir(env), state_dir(env), cache_dir(env)):
        directory.mkdir(parents=True, exist_ok=True)


def _systemctl(args: list[str], *, check: bool = True) -> int:
    try:
        completed = subprocess.run(
            ["systemctl", "--user", *args],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print(
            "praxis-prime service: systemctl not found. The unit file was updated, "
            "but systemd did not enable it.",
            file=sys.stderr,
        )
        return 1 if check else 0
    if completed.returncode != 0 and check:
        if completed.stderr:
            sys.stderr.write(completed.stderr)
        if completed.stdout:
            sys.stderr.write(completed.stdout)
        return completed.returncode
    return 0 if not check else completed.returncode
