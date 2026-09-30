"""CLI entry points: version, doctor, config, and the daemon bind rule."""

import importlib
import importlib.util
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from praxis_prime import __version__
from praxis_prime.cli import main
from praxis_prime.daemon import main as daemon_main

_SUBMODULES = (
    "praxis_prime.loop",
    "praxis_prime.router",
    "praxis_prime.policy",
    "praxis_prime.approvals",
    "praxis_prime.memory",
    "praxis_prime.scheduler",
    "praxis_prime.governance",
    "praxis_prime.decide",
    "praxis_prime.swarm",
    "praxis_prime.audit",
    "praxis_prime.gateway",
    "praxis_prime.sandbox",
    "praxis_prime.coding",
    "praxis_prime.tools",
    "praxis_prime.mcp",
    "praxis_prime.skills",
    "praxis_prime.migrate",
)


def test_version_flag(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"praxis-prime {__version__}"


def test_module_version():
    env = os.environ.copy()
    env["PYTHONPATH"] = _core_path() + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-m", "praxis_prime", "--version"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == f"praxis-prime {__version__}"


def test_missing_command_prints_help(capsys):
    assert main([]) == 2
    assert "doctor" in capsys.readouterr().out


def test_doctor_reports_the_four_checks(capsys):
    code = main(["doctor"])
    assert code == 0
    output = capsys.readouterr().out
    for name in ("Python", "OS", "Session", "Ollama"):
        assert name in output


def test_config_command_writes_dials_off(tmp_path, capsys):
    code = main(["config", "--config-dir", str(tmp_path)])
    assert code == 0
    assert "all off" in capsys.readouterr().out
    parsed = tomllib.loads((tmp_path / "config.toml").read_text(encoding="utf-8"))
    assert set(parsed["dials"].values()) == {"off"}
    profile = tomllib.loads((tmp_path / "policy" / "profile.toml").read_text(encoding="utf-8"))
    assert profile["profile"]["dials"] == []


def test_daemon_version_and_refuses_a_public_bind(capsys):
    assert daemon_main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out
    assert daemon_main(["--listen", "0.0.0.0:18790"]) == 2
    message = capsys.readouterr().err
    assert "loopback" in message


def test_console_scripts_when_installed():
    # Do not resolve(): the venv python is often a symlink into /usr/bin.
    bindir = Path(sys.executable).absolute().parent
    scripts = {
        "praxis-prime": f"praxis-prime {__version__}",
        "pprime": f"praxis-prime {__version__}",
        "praxis-primed": f"praxis-primed {__version__}",
    }
    missing = [name for name in scripts if not (bindir / name).exists()]
    if missing:
        message = f"console scripts missing: {', '.join(missing)}"
        if _running_in_ci():
            raise AssertionError(message)
        pytest.skip(message)
    for name, expected in scripts.items():
        completed = subprocess.run(
            [str(bindir / name), "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0
        assert completed.stdout.strip() == expected


def test_kernel_submodules_import():
    for name in _SUBMODULES:
        module = importlib.import_module(name)
        assert module.__doc__


def test_nc_pack_stub_is_off():
    path = Path("packs/jurisdictions/nc.py")
    spec = importlib.util.spec_from_file_location("nc_pack_stub", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.PACK_ID == "state:NC"
    assert module.DEFAULT_POSITION == "off"


def _core_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "packages" / "prime-core")


def _running_in_ci() -> bool:
    return bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
