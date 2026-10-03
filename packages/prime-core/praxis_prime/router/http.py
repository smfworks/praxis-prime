"""Small blocking HTTP helper for model providers. Standard library only."""

from __future__ import annotations

import time
from collections.abc import Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request

from praxis_prime.router.types import ProviderUnreachable, scrub_secrets
from praxis_prime.supervisor.redact import redact
from praxis_prime.upstream import RedirectRefused, build_opener, iter_bounded

_OPENER = build_opener()


def open_lines(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    timeout: float,
    secrets: list[str],
    provider: str,
    deadline: float | None = None,
) -> Iterator[str]:
    """POST ``body`` and yield decoded lines. Redirects and oversized bodies are refused."""
    request = Request(url, data=body, headers=headers, method="POST")
    limit = timeout if deadline is None else deadline
    try:
        response = _OPENER.open(request, timeout=timeout)  # noqa: S310
    except RedirectRefused as exc:
        raise ProviderUnreachable(provider, "redirect refused") from exc
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
    ends = time.monotonic() + limit

    def lines() -> Iterator[str]:
        try:
            for raw in iter_bounded(response, deadline=ends):
                yield redact(raw.decode("utf-8", errors="replace"), secrets)
        except TimeoutError as exc:
            raise ProviderUnreachable(provider, "upstream deadline exceeded") from exc
        except ValueError as exc:
            raise ProviderUnreachable(provider, "upstream body exceeds 4MB") from exc
        except OSError as exc:
            raise ProviderUnreachable(provider, f"upstream read failed ({exc})") from exc
        finally:
            try:
                response.close()
            except OSError:
                pass

    return lines()


def normalize_base(url: str) -> str:
    text = url.strip().rstrip("/")
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    return text
