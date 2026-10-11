"""Secret shapes from issue #83. Secrets mode, dials off."""

from __future__ import annotations

from praxis_prime.memory.redact import redact_text
from praxis_prime.policy.dials import default_positions


def _kept(text: str, mode: str) -> str:
    return redact_text(text, mode=mode, dials=default_positions())


def test_redacts_a_bare_xai_key() -> None:
    secret = "xai-" + ("A" * 80)
    text = f"prefix {secret} xai-shortkey explain the xai docs"
    assert secret in _kept(text, "off")
    kept = _kept(text, "secrets")
    assert secret not in kept
    assert "[redacted]" in kept
    assert "xai-shortkey" in kept
    assert "explain the xai docs" in kept


def test_redacts_a_github_fine_grained_pat() -> None:
    secret = "github_pat_" + ("A" * 22) + "_" + ("b" * 59)
    text = f"prefix {secret} github_path github_pat_example"
    assert secret in _kept(text, "off")
    kept = _kept(text, "secrets")
    assert secret not in kept
    assert "[redacted]" in kept
    assert "github_path" in kept
    assert "github_pat_example" in kept


def test_redacts_a_bare_jwt() -> None:
    header = "eyJ" + ("H" * 12)
    token = f"{header}.{('P' * 12)}.{('S' * 12)}"
    padded = token + "="
    text = " ".join(
        [
            token,
            padded,
            f"authorization: Bearer {padded}",
            f"Bearer {token}",
            "eyJ",
            "eyJhbGciOiJIUzI1NiJ9",
            "not.a.jwt",
            "Bearer of bad news",
        ]
    )
    untouched = _kept(text, "off")
    assert token in untouched
    assert padded in untouched
    kept = _kept(text, "secrets")
    assert token not in kept
    assert padded not in kept
    assert "[redacted]" in kept
    assert "eyJ" in kept.split()
    assert "eyJhbGciOiJIUzI1NiJ9" in kept
    assert "not.a.jwt" in kept
    assert "Bearer of bad news" in kept
    assert "Bearer [redacted]" in kept


def test_redacts_an_underscore_glued_sk_secret() -> None:
    secret = "_sk-" + ("A" * 16)
    ask = "ask-" + ("B" * 12)
    bare = "sk-" + ("C" * 16)
    text = f"prefix {secret} {ask} sk-short {bare}"
    untouched = _kept(text, "off")
    assert secret in untouched
    assert bare in untouched
    kept = _kept(text, "secrets")
    assert secret not in kept
    assert bare not in kept
    assert "[redacted]" in kept
    assert ask in kept
    assert "sk-short" in kept
