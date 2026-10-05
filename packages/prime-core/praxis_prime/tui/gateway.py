"""TUI facade over the loopback gateway.

Frames go through :class:`GatewayClient`. Theme and setup reads are HTTP
``GET`` on ``127.0.0.1`` with the same bearer token. Nothing here opens
``prime.db`` or the Omarchy theme file.

One chat holds the socket. A decision for the approval that chat is waiting
on is handed to the chat decider, which sends ``approvals.decide`` once.
A decision for a different id waits until the turn returns. An empty answer
is not a decision.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from http.client import HTTPConnection
from typing import Protocol
from urllib.parse import parse_qsl, urlencode

from praxis_prime.gateway.client import (
    Decider,
    Endpoint,
    EventHandler,
    GatewayClient,
    GatewayError,
)

DECISIONS = frozenset({"allow_once", "allow_session", "deny"})
MAX_BODY = 1_000_000
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_ALLOWED = frozenset(
    {
        "/v1/themes/active",
        "/v1/onboarding/status",
        "/v1/profiles",
        "/v1/approvals",
    }
)
_CSS_PATH = re.compile(r"^/themes/([a-z0-9][a-z0-9.-]{0,63})/([0-9a-f]{64})\.css$")
_PROFILE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")

NOT_RUNNING = (
    "praxis-primed is not running.\n"
    "Start it with `praxis-prime daemon start`.\n"
    "If no provider is chosen yet, run `praxis-prime setup` "
    "or open the web wizard at http://127.0.0.1:18790/.\n"
)


class FramePort(Protocol):
    """The slice of the operator socket the TUI uses."""

    def list_approvals(self, profile: str = "") -> list[dict[str, object]]: ...

    def decide(
        self,
        approval_id: str,
        decision: str,
        profile: str = "",
    ) -> dict[str, object]: ...

    def chat(
        self,
        text: str,
        *,
        session_id: str | None = None,
        on_event: EventHandler | None = None,
        decider: Decider | None = None,
        timeout: float | None = None,
        profile: str | None = None,
    ) -> dict[str, object]: ...

    def close(self) -> None: ...


class HttpPort(Protocol):
    """Loopback GETs. Implementations must not follow redirects."""

    def get_json(self, path: str) -> dict[str, object]: ...

    def get_text(self, path: str) -> str: ...


@dataclass(frozen=True, slots=True)
class Readiness:
    """Whether chat can start, and the sentence to show when it cannot."""

    ready: bool
    message: str


class GatewayFrames:
    """:class:`FramePort` backed by a connected :class:`GatewayClient`."""

    def __init__(self, client: GatewayClient) -> None:
        self._client = client

    def list_approvals(self, profile: str = "") -> list[dict[str, object]]:
        return self._client.list_approvals(profile)

    def decide(
        self,
        approval_id: str,
        decision: str,
        profile: str = "",
    ) -> dict[str, object]:
        return self._client.decide(approval_id, decision, profile)

    def chat(
        self,
        text: str,
        *,
        session_id: str | None = None,
        on_event: EventHandler | None = None,
        decider: Decider | None = None,
        timeout: float | None = None,
        profile: str | None = None,
    ) -> dict[str, object]:
        return self._client.chat(
            text,
            session_id=session_id,
            on_event=on_event,
            decider=decider,
            timeout=timeout,
            profile=profile,
        )

    def close(self) -> None:
        self._client.close()


class LoopbackHttp:
    """HTTP on ``127.0.0.1`` only. Redirects are refused. Bodies are capped."""

    def __init__(self, host: str, port: int, token: str) -> None:
        if host != "127.0.0.1":
            raise GatewayError("TUI HTTP stays on 127.0.0.1")
        if not token:
            raise GatewayError("missing gateway token")
        self.host = host
        self.port = port
        self._token = token

    def get_json(self, path: str) -> dict[str, object]:
        body = self._get(path)
        try:
            loaded = json.loads(body)
        except json.JSONDecodeError as exc:
            raise GatewayError("gateway returned invalid JSON") from exc
        if not isinstance(loaded, dict):
            raise GatewayError("gateway returned a non-object")
        return loaded

    def get_text(self, path: str) -> str:
        return self._get(path).decode("utf-8", errors="replace")

    def _get(self, path: str) -> bytes:
        _check_path(path)
        conn = HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request(
                "GET",
                path,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Host": "127.0.0.1",
                    "Accept": "application/json, text/css;q=0.9, */*;q=0.1",
                    "Connection": "close",
                },
            )
            response = conn.getresponse()
            status = response.status
            if status in _REDIRECTS:
                raise GatewayError(f"gateway redirect refused ({status})")
            if status != 200:
                raise GatewayError(f"gateway HTTP {status}")
            announced = response.getheader("Content-Length")
            if announced is not None:
                try:
                    size = int(announced)
                except ValueError as exc:
                    raise GatewayError("bad content length") from exc
                if size > MAX_BODY:
                    raise GatewayError("gateway response is too large")
            chunks: list[bytes] = []
            remaining = MAX_BODY + 1
            while remaining > 0:
                block = response.read(min(65536, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            body = b"".join(chunks)
            if len(body) > MAX_BODY:
                raise GatewayError("gateway response is too large")
            return body
        finally:
            conn.close()


class TuiGateway:
    """One operator connection. Chat and decisions share one lock."""

    def __init__(
        self,
        frames: FramePort,
        http: HttpPort,
        *,
        profile: str = "",
        port: int = 18790,
    ) -> None:
        self.frames = frames
        self.http = http
        self.profile = profile
        self.port = port
        self._lock = threading.Lock()
        self._in_chat = False
        self._queued: dict[str, str] = {}
        self._wait_hook: Callable[[], None] | None = None

    @classmethod
    def connect(cls, endpoint: Endpoint, *, profile: str = "") -> TuiGateway:
        client = GatewayClient.connect(endpoint, client="tui")
        http = LoopbackHttp(endpoint.host, endpoint.port, endpoint.token)
        return cls(GatewayFrames(client), http, profile=profile, port=endpoint.port)

    def close(self) -> None:
        self.frames.close()

    def set_wait_hook(self, hook: Callable[[], None] | None) -> None:
        """Called on the chat thread while an approval is pending.

        Plain mode uses this to read ``/approve`` lines without a second
        socket request.
        """
        self._wait_hook = hook

    @property
    def in_chat(self) -> bool:
        with self._lock:
            return self._in_chat

    def list_approvals(self) -> list[dict[str, object]]:
        """Pending cards. Raises while a turn holds the socket."""
        with self._lock:
            if self._in_chat:
                raise GatewayError("chat in progress")
            return self.frames.list_approvals(self.profile)

    def decide(self, approval_id: str, decision: str) -> str:
        """Queue or send one decision. Returns ``queued`` or ``sent``.

        ``decision`` must be ``allow_once``, ``allow_session``, or ``deny``.
        The socket call is serialized with ``list_approvals``. A decision
        during a turn is queued for that turn's decider instead.
        """
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision {decision!r}")
        if not approval_id or not str(approval_id).strip():
            raise ValueError("approval id is empty")
        approval_id = str(approval_id).strip()
        with self._lock:
            if self._in_chat:
                self._queued[approval_id] = decision
                return "queued"
            self.frames.decide(approval_id, decision, self.profile)
            return "sent"

    def chat(
        self,
        text: str,
        *,
        session_id: str | None,
        on_event: EventHandler | None,
        profile: str | None = None,
    ) -> dict[str, object]:
        """One turn. The decider never invents an approval answer."""
        with self._lock:
            if self._in_chat:
                raise GatewayError("chat in progress")
            self._in_chat = True
        try:
            return self.frames.chat(
                text,
                session_id=session_id or None,
                on_event=on_event,
                decider=self._decider,
                profile=profile if profile is not None else (self.profile or None),
            )
        finally:
            with self._lock:
                leftover = list(self._queued.items())
                self._queued.clear()
                try:
                    for approval_id, decision in leftover:
                        self.frames.decide(approval_id, decision, self.profile)
                finally:
                    self._in_chat = False

    def readiness(self) -> Readiness:
        """Chat gate from ``GET /v1/onboarding/status``.

        A failed request does not invent a setup error and does not block chat.
        """
        try:
            status = self.http.get_json("/v1/onboarding/status")
        except GatewayError:
            return Readiness(True, "")
        return readiness_from(status, self.port)

    def _decider(self, pending: dict[str, object]) -> str | None:
        hook = self._wait_hook
        if hook is not None:
            hook()
        approval_id = str(pending.get("id", ""))
        with self._lock:
            return self._queued.pop(approval_id, None)


def readiness_from(status: dict[str, object], port: int) -> Readiness:
    """Map the onboarding status document onto a banner sentence."""
    if status.get("inferenceReady") is not False:
        return Readiness(True, "")
    missing: list[str] = []
    raw = status.get("missing")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                missing.append(str(item.get("id", "")))
    provider = str(status.get("provider") or "").strip()
    wizard = f"http://127.0.0.1:{port}/"
    if "provider not verified" in missing:
        name = provider or "The provider"
        return Readiness(
            False,
            f"{name} has not passed the setup test. "
            f"Run `praxis-prime setup` or open the web wizard at {wizard}.",
        )
    return Readiness(
        False,
        "No model provider is configured. "
        f"Run `praxis-prime setup` or open the web wizard at {wizard}.",
    )


def resolve_profile(http: HttpPort, requested: str) -> str:
    """``--profile``, else ``default``, else the only profile, else empty."""
    if requested:
        return requested
    try:
        body = http.get_json("/v1/profiles")
    except GatewayError:
        return ""
    items = body.get("profiles")
    ids: list[str] = []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                ids.append(item["id"])
    if "default" in ids:
        return "default"
    if len(ids) == 1:
        return ids[0]
    return ""


def active_theme_path(profile: str) -> str:
    if not profile:
        return "/v1/themes/active"
    return "/v1/themes/active?" + urlencode({"profile": profile})


def _check_path(path: str) -> None:
    if not path.startswith("/") or path.startswith("//") or "\\" in path or ".." in path:
        raise GatewayError("refusing a gateway path the TUI does not use")
    bare, _, query = path.partition("?")
    if bare not in _ALLOWED and _CSS_PATH.fullmatch(bare) is None:
        raise GatewayError("refusing a gateway path the TUI does not use")
    if not query:
        return
    pairs = parse_qsl(query, keep_blank_values=False)
    if bare != "/v1/themes/active" or len(pairs) != 1 or pairs[0][0] != "profile":
        raise GatewayError("refusing a gateway query")
    if _PROFILE.fullmatch(pairs[0][1]) is None:
        raise GatewayError("refusing a gateway query")
