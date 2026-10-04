"""``praxis-prime setup``: scripted installs, a re-run, and the local setup URL."""

from __future__ import annotations

import io
import json
from argparse import Namespace
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

from praxis_prime.onboarding.cli import setup_command
from praxis_prime.onboarding.probe import FetchResult
from praxis_prime.onboarding.record import read_record
from praxis_prime.onboarding.token import ensure_first_run_token, read_first_run_token
from praxis_prime.router.settings import load_settings


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _fetch(method: str, url: str, **kwargs: object) -> FetchResult:
    del method
    if url.endswith("/v1/models") or url.endswith("/api/tags"):
        body = {"data": [{"id": "local-model", "max_model_len": 32768}]}
        return FetchResult(200, json.dumps(body).encode("utf-8"))
    raw = kwargs.get("body") or b"{}"
    payload = json.loads(raw if isinstance(raw, (bytes, str)) else b"{}")
    tools = isinstance(payload, dict) and "tools" in payload
    if "/v1/messages" in url:
        block = {"type": "tool_use", "name": "ping"} if tools else {"type": "text", "text": "ready"}
        return FetchResult(200, json.dumps({"content": [block]}).encode())
    if tools:
        message: dict[str, object] = {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "c1"}],
        }
    else:
        message = {"role": "assistant", "content": "ready"}
    return FetchResult(200, json.dumps({"choices": [{"message": message}]}).encode())


def _env(tmp_path: Path) -> dict[str, str]:
    for name in ("config", "data", "runtime", "state"):
        (tmp_path / name).mkdir()
    return {
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_RUNTIME_DIR": str(tmp_path / "runtime"),
        "XDG_STATE_HOME": str(tmp_path / "state"),
    }


def _args(tmp_path: Path, **overrides: object) -> Namespace:
    values: dict[str, object] = {
        "non_interactive": False,
        "section": None,
        "web": False,
        "provider": "",
        "model": "",
        "utility_model": "",
        "vision_model": "",
        "judge_model": "",
        "base_url": "",
        "tls_fingerprint": "",
        "lane": None,
        "api_key_env": "",
        "api_key_stdin": False,
        "owner": "",
        "owner_password_stdin": False,
        "replace": False,
        "skip_test": False,
        "config_dir": str(tmp_path / "config" / "praxis-prime"),
        "data_dir": str(tmp_path / "data" / "praxis-prime"),
    }
    values.update(overrides)
    return Namespace(**values)


def _run(
    tmp_path: Path,
    args: Namespace,
    stdin: str,
    env: dict[str, str] | None = None,
    *,
    tty: bool = False,
    prompts: list[str] | None = None,
) -> tuple[int, str]:
    source = _Tty(stdin) if tty else io.StringIO(stdin)
    out = io.StringIO()
    recorded = prompts if prompts is not None else []

    def fake_getpass(prompt: str = "", stream: io.TextIOBase | None = None) -> str:
        recorded.append(prompt)
        if stream is not None:
            stream.write(prompt)
            stream.flush()
        line = source.readline()
        if line == "":
            raise EOFError
        return line.rstrip("\n")

    patch = mock.patch("getpass.getpass", fake_getpass) if tty else nullcontext()
    with patch:
        code = setup_command(
            args,
            stdin=source,
            stdout=out,
            env=env if env is not None else _env(tmp_path),
            fetcher=_fetch,
        )
    return code, out.getvalue()


def test_non_tty_refuses_to_prompt(tmp_path: Path):
    code, text = _run(tmp_path, _args(tmp_path), "")
    assert code == 2
    assert "--non-interactive" in text


def test_skip_test_cannot_mark_ready(tmp_path: Path):
    env = _env(tmp_path)
    code, text = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            skip_test=True,
            provider="llamacpp",
            model="local-model",
        ),
        "",
        env,
    )
    assert code == 2
    assert "cannot mark the provider ready" in text
    assert not (tmp_path / "config" / "praxis-prime" / "config.toml").exists()


def test_scripted_setup_marks_ready_only_after_the_test(tmp_path: Path):
    env = _env(tmp_path)
    code, text = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            provider="llamacpp",
            model="local-model",
            base_url="http://127.0.0.1:9",
        ),
        "",
        env,
    )
    assert code == 0
    assert "Inference ready" in text
    settings = load_settings({}, config_path=tmp_path / "config" / "praxis-prime" / "config.toml")
    assert settings.model_spec == "llamacpp:local-model"
    record = read_record(tmp_path / "config" / "praxis-prime")
    assert record["ready"] is True
    again, message = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            provider="openai",
            model="gpt-4o",
            api_key_env="PRAXIS_PRIME_OPENAI_API_KEY",
        ),
        "",
        {**env, "PRAXIS_PRIME_OPENAI_API_KEY": "sk-from-env"},
    )
    assert again == 2
    assert "already configured" in message
    assert "sk-from-env" not in message
    kept = load_settings({}, config_path=tmp_path / "config" / "praxis-prime" / "config.toml")
    assert kept.model_spec == "llamacpp:local-model"


def test_api_key_env_is_stored_and_not_printed(tmp_path: Path):
    env = _env(tmp_path)
    env["PRAXIS_PRIME_OPENAI_API_KEY"] = "sk-from-env"
    code, text = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            provider="openai",
            model="gpt-4o",
            api_key_env="PRAXIS_PRIME_OPENAI_API_KEY",
        ),
        "",
        env,
    )
    assert code == 0
    assert "sk-from-env" not in text
    secret = (tmp_path / "config" / "praxis-prime" / "secrets.env").read_text(encoding="utf-8")
    config = (tmp_path / "config" / "praxis-prime" / "config.toml").read_text(encoding="utf-8")
    assert "sk-from-env" in secret
    assert "sk-from-env" not in config


def test_explicit_skip_is_not_ready(tmp_path: Path):
    env = _env(tmp_path)
    code, text = _run(
        tmp_path,
        _args(tmp_path, non_interactive=True, provider="skip"),
        "",
        env,
    )
    assert code == 0
    assert "not configured" in text
    record = read_record(tmp_path / "config" / "praxis-prime")
    assert record.get("ready") is False


def test_web_url_keeps_the_token_in_the_fragment(tmp_path: Path):
    env = _env(tmp_path)
    info = tmp_path / "runtime" / "praxis-prime"
    info.mkdir()
    (info / "gateway.json").write_text(json.dumps({"port": 18790}), encoding="utf-8")
    code, text = _run(tmp_path, _args(tmp_path, web=True), "", env)
    assert code == 0
    token = read_first_run_token(tmp_path / "config" / "praxis-prime")
    assert f"http://127.0.0.1:18790/#setup={token}" in text
    assert "?setup=" not in text
    assert token not in text.split("#", 1)[0]


def test_interactive_wizard_shows_current_values_and_creates_an_owner(tmp_path: Path):
    env = _env(tmp_path)
    config = tmp_path / "config" / "praxis-prime"
    ensure_first_run_token(config)
    script = "\n".join(
        [
            "ada",
            "correct-horse",
            "1",
            "llamacpp",
            "local-model",
            "http://127.0.0.1:9",
            "",
            "",
            "",
            "",
            "",
            "n",
            "n",
            "",
        ]
    )
    prompts: list[str] = []
    code, text = _run(tmp_path, _args(tmp_path), script, env, tty=True, prompts=prompts)
    assert code == 0, text
    assert "(unset)" in text
    assert "nothing is preselected" in text
    assert "created owner ada" in text
    assert "Inference ready" in text
    assert "Owner password: " in prompts
    assert "API key (blank to keep the stored key): " in prompts
    assert "correct-horse" not in text
    assert read_first_run_token(config) == ""
    settings = load_settings({}, config_path=config / "config.toml")
    assert settings.model_spec == "llamacpp:local-model"
