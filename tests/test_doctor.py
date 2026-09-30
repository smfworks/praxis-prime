"""OS, session, and Ollama checks."""

from praxis_prime.doctor import (
    check_browser,
    check_ollama,
    check_python,
    check_sandbox,
    classify_os,
    classify_session,
    collect_checks,
    parse_os_release,
    report_exit_code,
)

UBUNTU = """\
NAME="Ubuntu"
VERSION="24.04.4 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04.4 LTS"
"""

ARCH = """\
NAME="Arch Linux"
ID=arch
PRETTY_NAME="Arch Linux"
"""


def _no_which(_name: str) -> str | None:
    return None


def _no_path(_candidate: str) -> bool:
    return False


def test_parse_os_release_strips_quotes_and_comments():
    parsed = parse_os_release("# comment\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04\"\n\n")
    assert parsed["ID"] == "ubuntu"
    assert parsed["PRETTY_NAME"] == "Ubuntu 24.04"


def test_classifies_ubuntu_arch_and_omarchy():
    empty: dict[str, str] = {}
    ubuntu = parse_os_release(UBUNTU)
    arch = parse_os_release(ARCH)
    assert classify_os(ubuntu, empty, _no_which, _no_path)[0] == "ubuntu"
    assert classify_os(arch, empty, _no_which, _no_path)[0] == "arch"

    def omarchy_which(name: str) -> str | None:
        if name == "omarchy":
            return "/usr/bin/omarchy"
        return None

    family, detail = classify_os(arch, empty, omarchy_which, _no_path)
    assert family == "omarchy"
    assert "Omarchy" in detail

    mint = parse_os_release("ID=linuxmint\nID_LIKE=ubuntu\nPRETTY_NAME=\"Linux Mint\"\n")
    assert classify_os(mint, empty, _no_which, _no_path)[0] == "ubuntu"

    debian = parse_os_release("ID=debian\nPRETTY_NAME=\"Debian GNU/Linux\"\n")
    assert classify_os(debian, empty, _no_which, _no_path)[0] == "other"
    assert classify_os({}, empty, _no_which, _no_path)[0] == "unknown"


def test_omarchy_config_dir_counts():
    arch = parse_os_release(ARCH)

    def exists(candidate: str) -> bool:
        return candidate.endswith("/.config/omarchy")

    family, _detail = classify_os(arch, {"HOME": "/home/user"}, _no_which, exists)
    assert family == "omarchy"


def test_session_prefers_wayland_over_x11():
    assert classify_session({"WAYLAND_DISPLAY": "wayland-1", "DISPLAY": ":0"})[0] == "wayland"
    assert classify_session({"XDG_SESSION_TYPE": "wayland"})[0] == "wayland"
    assert classify_session({"DISPLAY": ":1"})[0] == "x11"
    assert classify_session({"XDG_SESSION_TYPE": "x11"})[0] == "x11"
    kind, detail = classify_session({})
    assert kind == "unknown"
    assert "WAYLAND_DISPLAY" in detail
    assert "DISPLAY" in detail


def test_missing_browser_and_sandbox_are_warnings():
    assert check_sandbox(True).status == "ok"
    assert check_sandbox(False).status == "warn"
    assert "web_fetch" in check_browser(False).detail
    assert check_browser(True).status == "ok"
    checks = collect_checks(
        version_info=(3, 12, 0),
        os_release_text=UBUNTU,
        env={},
        which=_no_which,
        path_exists=_no_path,
        ollama_reachable=True,
        bwrap_present=False,
        playwright_present=False,
    )
    assert report_exit_code(checks) == 0


def test_python_requirement_and_ollama_status():
    assert check_python((3, 12, 3)).status == "ok"
    assert check_python((3, 13, 0)).status == "ok"
    assert check_python((3, 11, 9)).status == "fail"
    assert check_ollama(True, "http://127.0.0.1:11434").status == "ok"
    assert check_ollama(False, "http://127.0.0.1:11434").status == "warn"


def test_only_python_failure_sets_the_exit_code():
    checks = collect_checks(
        version_info=(3, 11, 0),
        os_release_text=UBUNTU,
        env={},
        which=_no_which,
        path_exists=_no_path,
        ollama_reachable=False,
    )
    assert [check.name for check in checks] == [
        "Python",
        "OS",
        "Session",
        "Ollama",
        "Sandbox",
        "Browser",
    ]
    assert report_exit_code(checks) == 1

    healthy = collect_checks(
        version_info=(3, 12, 3),
        os_release_text=UBUNTU,
        env={},
        which=_no_which,
        path_exists=_no_path,
        ollama_reachable=False,
    )
    assert report_exit_code(healthy) == 0
    assert {check.status for check in healthy if check.name == "OS"} == {"ok"}
