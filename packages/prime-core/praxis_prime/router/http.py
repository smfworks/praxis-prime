"""Small blocking HTTP helper for model providers. Standard library only."""

from __future__ import annotations

from collections.abc import Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from praxis_prime.router.types import ProviderUnreachable, scrub_secrets


def open_lines(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    timeout: float,
    secrets: list[str],
    provider: str,
) -> Iterator[str]:
    """POST ``body`` and yield decoded lines. Connection failures are unreachable."""
    request = Request(url, data=body, headers=headers, method="POST")
    try:
        response = urlopen(request, timeout=timeout)  # noqa: S310
    except HTTPError as exc:
        detail = scrub_secrets(exc.read(2000).decode("utf-8", errors="replace"), secrets)
        raise ProviderUnreachable(
            provider,
            f"HTTP {exc.code} from {url}. {detail}".strip(),
        ) from exc
    except URLError as exc:
        raise ProviderUnreachable(provider, f"could not reach {url} ({exc.reason})") from exc
    except OSError as exc:
        raise ProviderUnreachable(provider, f"could not reach {url} ({exc})") from exc

    def lines() -> Iterator[str]:
        try:
            for raw in response:
                yield raw.decode("utf-8", errors="replace")
        finally:
            response.close()

    return lines()


def normalize_base(url: str) -> str:
    text = url.strip().rstrip("/")
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    return text
