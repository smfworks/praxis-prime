"""Provider locality: address class, setup record, and compliance routing."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from praxis_prime.compliance.providers import ProviderFlags, filter_chain, flags_from_config
from praxis_prime.locality import classify_address, classify_host, host_of, locality
from praxis_prime.onboarding.probe import FetchResult, ProbeError
from praxis_prime.onboarding.record import read_record
from praxis_prime.onboarding.registry import _lane_host, flow_lane_for, lane_for
from praxis_prime.onboarding.service import (
    OnboardingService,
    Selection,
    _locality,
    _recorded_place,
)
from praxis_prime.policy.engine import HookPoint, PolicyContext, PolicyEngine
from praxis_prime.router.settings import load_settings
from praxis_prime.router.types import ModelRef
from test_onboarding_cli import _args, _env, _run

_PHI = "Patient MRN AB12345"


@pytest.mark.parametrize(
    ("url", "host", "kind"),
    [
        ("http://[::1]:8000", "::1", "local"),
        ("http://127.0.0.5", "127.0.0.5", "local"),
        ("http://0.0.0.0:11434", "0.0.0.0", "local"),
        ("http://[::]:11434", "::", "local"),
        ("http://192.168.1.50", "192.168.1.50", "lan"),
        ("http://10.1.2.3", "10.1.2.3", "lan"),
        ("http://172.16.0.1", "172.16.0.1", "lan"),
        ("http://100.64.1.1", "100.64.1.1", "lan"),
        ("http://[fd00::5]", "fd00::5", "lan"),
        ("http://172.32.0.1", "172.32.0.1", "cloud"),
        ("http://100.128.0.1", "100.128.0.1", "cloud"),
        ("http://203.0.113.10", "203.0.113.10", "cloud"),
        ("http://8.8.8.8", "8.8.8.8", "cloud"),
        ("http://192.0.2.1", "192.0.2.1", "cloud"),
        ("http://198.51.100.1", "198.51.100.1", "cloud"),
        ("http://198.18.0.1", "198.18.0.1", "cloud"),
        ("http://[2001:db8::1]", "2001:db8::1", "cloud"),
        ("http://[2606:4700::1111]", "2606:4700::1111", "cloud"),
        ("http://169.254.169.254", "169.254.169.254", "cloud"),
        ("http://[fe80::1]", "fe80::1", "cloud"),
        ("http://[::ffff:192.168.1.5]", "::ffff:192.168.1.5", "lan"),
        ("http://[::ffff:8.8.8.8]", "::ffff:8.8.8.8", "cloud"),
        ("http://[2002:c0a8:0101::1]", "2002:c0a8:0101::1", "cloud"),
    ],
)
def test_address_table(url: str, host: str, kind: str):
    assert host_of(url) == host
    assert locality(url) == kind
    assert classify_address(host) == kind


def test_localhost_names_do_not_resolve():
    def boom(host: str) -> list[str]:
        raise AssertionError(host)

    assert host_of("localhost") == "localhost"
    assert host_of("foo.localhost") == "foo.localhost"
    assert classify_host("localhost", resolver=boom) == "local"
    assert classify_host("Foo.LocalHost.", resolver=boom) == "local"
    assert locality("localhost", resolver=boom) == "local"
    assert locality("foo.localhost", resolver=boom) == "local"
    assert locality("http://api.localhost:11434", resolver=boom) == "local"
    assert locality("", resolver=boom) == "cloud"
    assert classify_host("   ", resolver=boom) == "cloud"


def test_translators_and_link_local_fail_closed():
    assert classify_address("::ffff:192.168.1.5") == "lan"
    assert classify_address("::ffff:8.8.8.8") == "cloud"
    assert classify_address("2002:c0a8:0101::1") == "cloud"
    assert classify_address("64:ff9b::8.8.8.8") == "cloud"
    assert classify_address("::8.8.8.8") == "cloud"
    assert classify_address("::1") == "local"
    assert classify_address("::") == "local"
    assert classify_address("fe80::1%eth0") == "cloud"
    assert host_of("http://[fe80::1%eth0]:11434") == "fe80::1"
    assert classify_address("224.0.0.1") == "cloud"
    assert classify_address("255.255.255.255") == "cloud"


def test_names_take_the_most_remote_address():
    def resolve(host: str) -> list[str]:
        return {
            "public.example": ["203.0.113.10"],
            "lan.example": ["192.168.1.5"],
            "loop.example": ["127.0.0.1", "::1"],
            "mixed.example": ["192.168.1.5", "203.0.113.9"],
            "both.example": ["127.0.0.1", "10.1.2.3"],
            "bad.example": ["not-an-ip"],
        }[host]

    assert classify_host("public.example", resolver=resolve) == "cloud"
    assert classify_host("lan.example", resolver=resolve) == "lan"
    assert classify_host("loop.example", resolver=resolve) == "local"
    assert classify_host("mixed.example", resolver=resolve) == "cloud"
    assert classify_host("both.example", resolver=resolve) == "lan"
    assert classify_host("bad.example", resolver=resolve) == "cloud"

    def broken(host: str) -> list[str]:
        raise OSError(host)

    assert classify_host("down.example", resolver=broken) == "cloud"
    assert classify_host("empty.example", resolver=lambda host: []) == "cloud"

    def odd(host: str) -> list[str]:
        raise RuntimeError(host)

    assert classify_host("odd.example", resolver=odd) == "cloud"


def test_a_hung_resolver_is_cloud():
    def hang(host: str) -> list[str]:
        time.sleep(2)
        return ["127.0.0.1"]

    assert classify_host("slow.example", resolver=hang, timeout=0.05) == "cloud"


def test_lane_helpers_agree_on_the_issue_rows(monkeypatch: pytest.MonkeyPatch):
    def resolve(host: str) -> list[str]:
        assert host == "api.example.com"
        return ["203.0.113.10"]

    monkeypatch.setattr("praxis_prime.locality.resolve_host", resolve)
    rows = (
        ("ollama", "http://[::1]:8000", "::1", "local"),
        ("vllm", "http://[fd00::5]:8000", "fd00::5", "lan"),
        ("network", "http://203.0.113.10:8080", "203.0.113.10", "cloud"),
        ("ollama", "http://api.example.com:11434", "api.example.com", "cloud"),
    )
    for provider, base, host, kind in rows:
        assert _lane_host(base) == host
        assert lane_for(provider, base) == kind
        assert _locality("lan", base) == kind
        assert _recorded_place(provider, base) == (kind, kind)
    assert _locality("cloud", "http://[::1]:8000") == "cloud"
    assert lane_for("ollama", "http://127.0.0.5:11434") == "local"
    assert flow_lane_for("ollama", "http://127.0.0.5:11434") == "lan"
    assert flow_lane_for("ollama", "http://203.0.113.10:11434") == "lan"
    assert lane_for("ollama", "") == "local"


def test_cloud_providers_do_not_resolve(monkeypatch: pytest.MonkeyPatch):
    def boom(host: str) -> list[str]:
        raise AssertionError(host)

    monkeypatch.setattr("praxis_prime.locality.resolve_host", boom)
    assert lane_for("openai", "https://api.example.com/v1") == "cloud"
    assert lane_for("anthropic", "https://api.example.com") == "cloud"
    assert lane_for("xai", "https://api.example.com") == "cloud"
    assert lane_for("openai-compatible-cloud", "https://api.example.com/v1") == "cloud"
    assert flags_from_config("openai", base_url="https://api.example.com").local is False
    assert flags_from_config("xai", base_url="https://api.example.com").local is False
    assert flags_from_config("anthropic", base_url="https://api.example.com").local is False
    assert _locality("cloud", "http://api.example.com") == "cloud"
    assert _recorded_place("openai", "http://api.example.com") == ("cloud", "cloud")
    assert _recorded_place("openai-compatible-cloud", "http://127.0.0.1:9") == ("cloud", "cloud")


def test_flags_follow_the_address(monkeypatch: pytest.MonkeyPatch):
    def resolve(host: str) -> list[str]:
        table = {
            "ollama.example.com": ["203.0.113.10"],
            "gpu.lan": ["192.168.1.5"],
            "public.example": ["8.8.8.8"],
        }
        if host not in table:
            raise AssertionError(host)
        return table[host]

    monkeypatch.setattr("praxis_prime.locality.resolve_host", resolve)
    assert flags_from_config("ollama", base_url="https://ollama.example.com").local is False
    assert flags_from_config("ollama", base_url="http://203.0.113.10:11434").local is False
    loopback = flags_from_config("ollama", base_url="http://127.0.0.1:11434")
    assert loopback.local is True
    assert loopback == ProviderFlags(local=True)
    assert loopback.as_dict() == {
        "local": True,
        "baa": False,
        "eu_region": False,
        "zero_retention": False,
    }
    assert flags_from_config("ollama", base_url="http://192.168.1.5:11434").local is False
    trusted = flags_from_config(
        "ollama",
        base_url="http://192.168.1.5:11434",
        trusted_hosts=("192.168.1.5",),
    )
    assert trusted.local is True
    named = flags_from_config(
        "ollama",
        base_url="http://gpu.lan:11434",
        trusted_hosts=("GPU.LAN",),
    )
    assert named.local is True
    listed_public = flags_from_config(
        "ollama",
        base_url="http://public.example:11434",
        trusted_hosts=("public.example",),
    )
    assert listed_public.local is False
    explicit = flags_from_config(
        "ollama",
        {"local": True},
        base_url="https://ollama.example.com",
    )
    assert explicit.local is True
    assert explicit.local_explicit is True
    assert flags_from_config("llamacpp", base_url="http://127.0.0.1:8080").local is True
    assert flags_from_config("vllm", base_url="http://8.8.8.8:8000").local is False
    assert flags_from_config("ollama", base_url="").local is False
    assert flags_from_config("openai").local is False
    assert flags_from_config("xai", base_url="https://api.x.ai/v1").local is False


def test_filter_chain_drops_a_rebound_name(monkeypatch: pytest.MonkeyPatch):
    answers = iter([["127.0.0.1"], ["203.0.113.9"]])

    def resolve(host: str) -> list[str]:
        assert host == "ollama.lab"
        return next(answers)

    monkeypatch.setattr("praxis_prime.locality.resolve_host", resolve)
    flags = flags_from_config("ollama", base_url="http://ollama.lab:11434")
    assert flags.local is True
    kept = filter_chain(
        [ModelRef("ollama", "qwen")],
        [("local", "baa")],
        {"ollama": flags},
    )
    assert kept == []
    sticky = flags_from_config(
        "ollama",
        {"local": True},
        base_url="http://ollama.lab:11434",
    )
    again = filter_chain([ModelRef("ollama", "qwen")], [("local",)], {"ollama": sticky})
    assert [item.provider for item in again] == ["ollama"]


def test_filter_chain_does_not_recheck_an_ip_literal(monkeypatch: pytest.MonkeyPatch):
    def boom(host: str) -> list[str]:
        raise AssertionError(host)

    monkeypatch.setattr("praxis_prime.locality.resolve_host", boom)
    flags = flags_from_config("ollama", base_url="http://127.0.0.1:11434")
    kept = filter_chain([ModelRef("ollama", "qwen")], [("local",)], {"ollama": flags})
    assert [item.provider for item in kept] == ["ollama"]


def _write_config(
    path: Path,
    host: str,
    *,
    trusted: tuple[str, ...] = (),
    local: bool | None = None,
) -> None:
    lines = [
        "[dials]",
        'hipaa = "enforce"',
        "",
        "[models]",
        'primary = "ollama:qwen"',
    ]
    if trusted:
        rendered = ", ".join(json.dumps(item) for item in trusted)
        lines.append(f"trusted_inference_hosts = [{rendered}]")
    lines.extend(["", "[models.providers.ollama]", f"host = {json.dumps(host)}"])
    if local is not None:
        lines.append("local = true" if local else "local = false")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _hipaa_chain(
    tmp_path: Path,
    host: str,
    *,
    trusted: tuple[str, ...] = (),
    env: dict[str, str] | None = None,
) -> tuple[list[ModelRef], str, PolicyEngine]:
    root = tmp_path / "cfg"
    root.mkdir()
    _write_config(root / "config.toml", host, trusted=trusted)
    settings = load_settings(env if env is not None else {}, config_path=root / "config.toml")
    engine = PolicyEngine(settings.dials, provider_flags=settings.provider_flags)
    verdict = engine.evaluate(PolicyContext(hook=HookPoint.H2_PRE_MODEL, tool="model", text=_PHI))
    assert ("local", "baa") in verdict.route_groups
    chain, message = engine.constrain_chain(
        [ModelRef("openai", "gpt"), ModelRef("ollama", "qwen")],
        verdict,
    )
    return chain, message, engine


@pytest.mark.parametrize(
    ("host", "trusted", "kept"),
    [
        ("http://203.0.113.10:11434", (), False),
        ("http://127.0.0.1:11434", (), True),
        ("http://192.168.1.5:11434", ("192.168.1.5",), True),
        ("http://192.168.1.5:11434", (), False),
    ],
)
def test_hipaa_enforce_follows_ollama_locality(
    tmp_path: Path,
    host: str,
    trusted: tuple[str, ...],
    kept: bool,
):
    chain, message, _engine = _hipaa_chain(tmp_path, host, trusted=trusted)
    providers = [item.provider for item in chain]
    if kept:
        assert message == ""
        assert providers == ["ollama"]
    else:
        assert providers == []
        assert message.startswith("Blocked by compliance enforce")


def test_env_ollama_host_on_a_public_address_is_blocked(tmp_path: Path):
    chain, message, engine = _hipaa_chain(
        tmp_path,
        "http://127.0.0.1:11434",
        env={"PRAXIS_PRIME_OLLAMA_HOST": "http://8.8.8.8:11434"},
    )
    assert engine.provider_flags["ollama"].local is False
    assert chain == []
    assert message.startswith("Blocked by compliance enforce")


def test_rebinding_after_load_blocks_the_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    answers = iter([["127.0.0.1"], ["203.0.113.9"]])

    def resolve(host: str) -> list[str]:
        assert host == "ollama.lab"
        return next(answers)

    monkeypatch.setattr("praxis_prime.locality.resolve_host", resolve)
    _chain, message, engine = _hipaa_chain(tmp_path, "http://ollama.lab:11434")
    assert engine.provider_flags["ollama"].local is True
    assert message.startswith("Blocked by compliance enforce")


def test_explicit_local_survives_a_public_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    def resolve(host: str) -> list[str]:
        raise AssertionError(host)

    monkeypatch.setattr("praxis_prime.locality.resolve_host", resolve)
    root = tmp_path / "cfg"
    root.mkdir()
    _write_config(root / "config.toml", "http://ollama.lab:11434", local=True)
    settings = load_settings({}, config_path=root / "config.toml")
    assert settings.provider_flags["ollama"].local is True
    engine = PolicyEngine(settings.dials, provider_flags=settings.provider_flags)
    verdict = engine.evaluate(PolicyContext(hook=HookPoint.H2_PRE_MODEL, tool="model", text=_PHI))
    chain, message = engine.constrain_chain([ModelRef("ollama", "qwen")], verdict)
    assert message == ""
    assert [item.provider for item in chain] == ["ollama"]


def test_trusted_inference_hosts_are_normalized(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text(
        "\n".join(
            [
                "[models]",
                "trusted_inference_hosts = [",
                '  " GPU.LAN.",',
                '  "",',
                '  "[FD00::5]",',
                '  "fe80::1%eth0",',
                '  "192.168.1.5",',
                '  "192.168.1.5",',
                '  "Host.Example.",',
                "  7,",
                "]",
                "",
                "[models.providers.ollama]",
                'host = "http://127.0.0.1:11434"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    settings = load_settings({}, config_path=path)
    assert settings.trusted_inference_hosts == (
        "gpu.lan",
        "fd00::5",
        "fe80::1",
        "192.168.1.5",
        "host.example",
    )
    other = tmp_path / "string.toml"
    other.write_text('[models]\ntrusted_inference_hosts = "gpu.lan"\n', encoding="utf-8")
    assert load_settings({}, config_path=other).trusted_inference_hosts == ()


def _fetch(method: str, url: str, **kwargs: object) -> FetchResult:
    del method
    if "down.example" in url:
        raise ProbeError("down")
    if url.endswith("/v1/models") or url.endswith("/api/tags"):
        body = {"data": [{"id": "local-model", "max_model_len": 32768}]}
        return FetchResult(200, json.dumps(body).encode("utf-8"))
    raw = kwargs.get("body") or b"{}"
    payload = json.loads(raw if isinstance(raw, (bytes, str)) else b"{}")
    tools = isinstance(payload, dict) and "tools" in payload
    if tools:
        message: dict[str, object] = {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "c1"}],
        }
    else:
        message = {"role": "assistant", "content": "ready"}
    return FetchResult(200, json.dumps({"choices": [{"message": message}]}).encode())


def _service(tmp_path: Path) -> OnboardingService:
    return OnboardingService(config_dir=tmp_path, data_dir=tmp_path / "data", fetcher=_fetch)


def test_probe_models_reports_locality(tmp_path: Path):
    service = _service(tmp_path)
    lan = service.probe_models("network", "http://192.168.1.50:8000")
    assert lan["locality"] == "lan"
    assert lan["loopback"] is False
    local = service.probe_models("ollama", "http://[::1]:11434")
    assert local["locality"] == "local"
    assert local["loopback"] is True
    public = service.probe_models("network", "http://203.0.113.10:8000")
    assert public["ok"] is True
    assert public["locality"] == "cloud"
    unspecified = service.probe_models("ollama", "http://0.0.0.0:11434")
    assert unspecified["locality"] == "local"
    assert unspecified["loopback"] is False
    assert unspecified["network"] is True
    named = service.probe_models("ollama", "http://foo.localhost:11434")
    assert named["locality"] == "local"
    assert named["loopback"] is True
    failed = service.probe_models("network", "http://down.example:9")
    assert failed["ok"] is False
    assert failed["locality"] == "cloud"


def test_save_records_the_address_class(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def resolve(host: str) -> list[str]:
        assert host == "public.example"
        return ["203.0.113.9"]

    monkeypatch.setattr("praxis_prime.locality.resolve_host", resolve)

    public = tmp_path / "public"
    public.mkdir()
    saved = _service(public).save(
        Selection(
            lane="local",
            provider="ollama",
            model="qwen",
            base_url="http://public.example:11434",
        )
    )
    assert saved["ok"] is True
    assert saved["locality"] == "cloud"
    assert all("leave this network" not in str(item) for item in saved["warnings"])
    record = read_record(public)
    assert record["lane"] == "cloud"
    assert record["locality"] == "cloud"
    assert not (public / "secrets.env").exists()

    blank = tmp_path / "blank"
    blank.mkdir()
    opened = _service(blank).save(
        Selection(
            lane="",
            provider="network",
            model="local-model",
            base_url="http://203.0.113.10:8000",
        )
    )
    assert opened["locality"] == "cloud"
    assert read_record(blank)["lane"] == "cloud"
    assert read_record(blank)["locality"] == "cloud"

    lan = tmp_path / "lan"
    lan.mkdir()
    moved = _service(lan).save(
        Selection(
            lane="local",
            provider="network",
            model="local-model",
            base_url="http://192.168.1.50:8000",
        )
    )
    assert moved["locality"] == "lan"
    assert read_record(lan)["lane"] == "lan"
    assert read_record(lan)["locality"] == "lan"

    loop = tmp_path / "loop"
    loop.mkdir()
    home = _service(loop).save(
        Selection(
            lane="lan",
            provider="llamacpp",
            model="local-model",
            base_url="http://[::1]:8080",
        )
    )
    assert home["locality"] == "local"
    assert read_record(loop)["lane"] == "local"
    assert read_record(loop)["locality"] == "local"


def test_cli_warns_for_a_public_local_server_and_still_saves(tmp_path: Path):
    env = _env(tmp_path)
    code, text = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            provider="ollama",
            model="qwen",
            base_url="http://203.0.113.10:11434",
        ),
        "",
        env,
    )
    assert code == 0, text
    assert (
        "warning: 203.0.113.10 is not on this machine or a private network; "
        "prompts will leave this network."
    ) in text
    record = read_record(tmp_path / "config" / "praxis-prime")
    assert record["lane"] == "cloud"
    assert record["locality"] == "cloud"

    quiet, quiet_text = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            provider="ollama",
            model="qwen",
            base_url="http://192.168.1.50:11434",
            replace=True,
        ),
        "",
        env,
    )
    assert quiet == 0, quiet_text
    assert "leave this network" not in quiet_text
    assert read_record(tmp_path / "config" / "praxis-prime")["lane"] == "lan"


def test_cli_cloud_lane_keeps_the_old_save_rules(tmp_path: Path):
    env = _env(tmp_path)
    refused, text = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            provider="ollama",
            model="qwen",
            base_url="http://203.0.113.10:11434",
            lane="cloud",
        ),
        "",
        env,
    )
    assert refused == 2
    assert "not a cloud preset" in text
    needs_key, message = _run(
        tmp_path,
        _args(
            tmp_path,
            non_interactive=True,
            provider="openai-compatible",
            model="local-model",
            base_url="http://203.0.113.10:8000",
            lane="cloud",
        ),
        "",
        env,
    )
    assert needs_key == 2
    assert "needs an API key" in message
