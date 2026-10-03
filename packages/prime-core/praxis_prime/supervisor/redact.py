"""Remove infrastructure secrets from a worker or upstream payload.

The replacement does not shorten the rest of the text. Error strings that
need a short log line use ``scrub_secrets`` instead.
"""

from __future__ import annotations


def redact(text: str, secrets: list[str]) -> str:
    cleaned = text
    for secret in secrets:
        if secret:
            cleaned = cleaned.replace(secret, "[redacted]")
    return cleaned


def redact_value(value: object, secrets: list[str]) -> object:
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, dict):
        return {str(key): redact_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
    return value
