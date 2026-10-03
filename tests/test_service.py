"""systemd --user unit text and install/uninstall with a fake systemctl."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from praxis_prime.service import install, packaged_unit_text, render_worker_slice, uninstall


def test_packaged_unit_matches_the_file_and_stays_loopback():
    path = Path("packaging/systemd/praxis-prime.service")
    text = path.read_text(encoding="utf-8")
    assert text == packaged_unit_text()
    assert "%h" in text
    assert "WantedBy=default.target" in text
    assert "NoNewPrivileges=yes" in text
    assert "ProtectSystem=strict" in text
    assert "/usr/bin/praxis-primed" in text
    assert "0.0.0.0" not in text
    assert "apt" not in text
    assert "pacman" not in text
    assert "Requires=graphical-session.target" not in text
    assert "PRAXIS_PRIME_WORKER_SLICE=on" in text
    slice_file = Path("packaging/systemd/praxis-prime-workers.slice")
    assert slice_file.read_text(encoding="utf-8") == render_worker_slice()
    assert "MemoryMax=512M" in slice_file.read_text(encoding="utf-8")


def test_install_and_uninstall_use_the_local_binary(tmp_path: Path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    daemon = bin_dir / "praxis-primed"
    daemon.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    daemon.chmod(0o755)
    log = tmp_path / "systemctl.log"
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + _sh(log) + "\nexit 0\n",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    assert install() == 0
    unit_path = tmp_path / "config" / "systemd" / "user" / "praxis-prime.service"
    text = unit_path.read_text(encoding="utf-8")
    assert str(daemon) in text
    assert "WantedBy=default.target" in text
    assert "NoNewPrivileges=yes" in text
    recorded = log.read_text(encoding="utf-8")
    assert "--user daemon-reload" in recorded
    assert "--user enable --now praxis-prime.service" in recorded
    assert "PRAXIS_PRIME_WORKER_SLICE=on" in text
    slice_unit = tmp_path / "config" / "systemd" / "user" / "praxis-prime-workers.slice"
    assert "MemoryMax=512M" in slice_unit.read_text(encoding="utf-8")
    assert (tmp_path / "data" / "praxis-prime").is_dir()
    assert (tmp_path / "state" / "praxis-prime").is_dir()

    assert uninstall() == 0
    assert not unit_path.exists()
    assert not slice_unit.exists()
    recorded = log.read_text(encoding="utf-8")
    assert "disable --now praxis-prime.service" in recorded
    assert stat.S_ISREG(daemon.stat().st_mode)


def _sh(path: Path) -> str:
    return "'" + str(path).replace("'", "'\\''") + "'"
