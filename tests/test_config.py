"""Default config writes XDG files with every dial off."""

import tomllib

from praxis_prime.config import (
    default_config_document,
    default_profile_document,
    render_config_toml,
    render_profile_toml,
    write_default_config,
)
from praxis_prime.policy.dials import dial_ids


def test_rendered_config_round_trips_and_dials_are_off():
    parsed = tomllib.loads(render_config_toml())
    assert parsed == default_config_document()
    assert set(parsed["dials"]) == set(dial_ids())
    assert set(parsed["dials"].values()) == {"off"}
    assert parsed["core"]["mode"] == "ask"
    assert parsed["jarvis"]["enabled"] is False
    assert parsed["sandbox"]["network"] == "off"
    assert parsed["sandbox"]["default_tier"] == "bwrap"
    assert parsed["mcp"]["serve"] is False
    assert parsed["browser"]["profile"] == "disposable"
    assert str(parsed["gateway"]["listen"]).startswith("127.0.0.1:")
    assert str(parsed["models"]["primary"]).startswith("ollama:")
    assert parsed["tools"]["read_roots"] == []
    assert parsed["tools"]["read_allow"] == []
    assert parsed["tools"]["fetch_allow"] == []


def test_profile_starts_with_no_active_dials():
    parsed = tomllib.loads(render_profile_toml())
    assert parsed == default_profile_document()
    assert parsed["profile"]["dials"] == []
    assert parsed["profile"]["mode"] == "ask"


def test_write_is_idempotent_until_force(tmp_path):
    first = write_default_config(tmp_path)
    assert first.wrote is True
    original = first.config_path.read_text(encoding="utf-8")
    first.config_path.write_text(original + "# touched\n", encoding="utf-8")

    second = write_default_config(tmp_path)
    assert second.wrote is False
    assert first.config_path.read_text(encoding="utf-8").endswith("# touched\n")

    forced = write_default_config(tmp_path, force=True)
    assert forced.wrote is True
    rewritten = tomllib.loads(forced.config_path.read_text(encoding="utf-8"))
    assert set(rewritten["dials"].values()) == {"off"}
    profile = tomllib.loads(forced.profile_path.read_text(encoding="utf-8"))
    assert profile["profile"]["dials"] == []
