"""Gateway facade and loopback HTTP used by the TUI. No daemon and no model."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from praxis_prime.gateway.client import Endpoint, GatewayClient, GatewayError
from praxis_prime.tui.gateway import (
    DECISIONS,
    LoopbackHttp,
    Readiness,
    TuiGateway,
    active_theme_path,
    readiness_from,
    resolve_profile,
)


class FakeFrames:
    """In-process frame port. ``chat_impl`` stands in for one model turn."""

    def __init__(self) -> None:
        self.decisions: list[tuple[str, str, str]] = []
        self.chats: list[dict[str, object]] = []
        self.approvals: list[dict[str, object]] = []
        self.closed = False
        self.chat_impl = None

    def list_approvals(self, profile: str = "") -> list[dict[str, object]]:
        return [dict(item) for item in self.approvals]

    def decide(self, approval_id: str, decision: str, profile: str = "") -> dict[str, object]:
        self.decisions.append((approval_id, decision, profile))
        return {"ok": True, "state": decision}

    def chat(
        self,
        text: str,
        *,
        session_id: str | None = None,
        on_event=None,
        decider=None,
        timeout: float | None = None,
        profile: str | None = None,
    ) -> dict[str, object]:
        self.chats.append({"text": text, "session_id": session_id, "profile": profile})
        if self.chat_impl is not None:
            return self.chat_impl(text, session_id, on_event, decider, timeout, profile)
        if on_event is not None:
            on_event({"kind": "text", "text": "ok"})
        return {
            "type": "result",
            "ok": True,
            "payload": {"sessionId": session_id or "sess-1", "text": "ok"},
        }

    def close(self) -> None:
        self.closed = True


class FakeHttp:
    def __init__(self, status: dict[str, object] | None = None, *, fail: bool = False) -> None:
        self.status = status or {"inferenceReady": True, "missing": [], "provider": "ollama:qwen"}
        self.fail = fail
        self.profiles: list[dict[str, str]] = [{"id": "default"}]
        self.paths: list[str] = []

    def get_json(self, path: str) -> dict[str, object]:
        self.paths.append(path)
        if self.fail:
            raise GatewayError("down")
        bare = path.split("?", 1)[0]
        if bare == "/v1/onboarding/status":
            return dict(self.status)
        if bare == "/v1/profiles":
            return {"ok": True, "profiles": list(self.profiles)}
        if bare == "/v1/themes/active":
            return {"ok": True, "id": "smf.praxis", "mode": "dark", "css": ""}
        raise GatewayError(path)

    def get_text(self, path: str) -> str:
        self.paths.append(path)
        if self.fail:
            raise GatewayError("down")
        return ""


def _gateway(**kwargs: object) -> tuple[TuiGateway, FakeFrames, FakeHttp]:
    frames = FakeFrames()
    http = kwargs.pop("http", None)
    if http is None:
        http = FakeHttp()
    profile = str(kwargs.pop("profile", "default"))
    port = int(kwargs.pop("port", 18790))  # type: ignore[arg-type]
    return TuiGateway(frames, http, profile=profile, port=port), frames, http  # type: ignore[arg-type]


def test_decisions_are_the_three_gateway_strings() -> None:
    assert DECISIONS == frozenset({"allow_once", "allow_session", "deny"})


@pytest.mark.parametrize("decision", ["yes", "y", "allow", ""])
def test_unknown_decision_is_not_sent(decision: str) -> None:
    gateway, frames, _http = _gateway()
    with pytest.raises(ValueError):
        gateway.decide("ap1", decision)
    assert frames.decisions == []


def test_empty_approval_id_is_not_sent() -> None:
    gateway, frames, _http = _gateway()
    with pytest.raises(ValueError):
        gateway.decide("  ", "deny")
    assert frames.decisions == []


def test_idle_decide_reaches_the_frames_once() -> None:
    gateway, frames, _http = _gateway()
    assert gateway.decide("ap1", "allow_once") == "sent"
    assert gateway.decide("ap1", "allow_session") == "sent"
    assert gateway.decide("ap2", "deny") == "sent"
    assert frames.decisions == [
        ("ap1", "allow_once", "default"),
        ("ap1", "allow_session", "default"),
        ("ap2", "deny", "default"),
    ]


def test_chat_forwards_events_and_does_not_auto_decide() -> None:
    gateway, frames, _http = _gateway()
    seen: list[dict[str, object]] = []

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, timeout, profile
        on_event({"kind": "text", "text": "Hello"})
        on_event({"kind": "approval", "approval": {"id": "ap"}})
        for _ in range(3):
            assert decider({"id": "ap"}) is None
        return {"type": "result", "ok": True, "payload": {"sessionId": "s1", "text": "Hello"}}

    frames.chat_impl = script
    result = gateway.chat("hi", session_id=None, on_event=seen.append, profile="default")
    assert result["payload"]["sessionId"] == "s1"
    assert [item["kind"] for item in seen] == ["text", "approval"]
    assert frames.decisions == []
    assert frames.chats[0]["session_id"] is None
    assert frames.chats[0]["profile"] == "default"


def test_decision_during_chat_is_sent_once() -> None:
    gateway, frames, _http = _gateway()
    started = threading.Event()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, timeout
        started.set()
        card = {"id": "ap9"}
        on_event({"kind": "approval", "approval": card})
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            decision = decider(card)
            if decision:
                frames.decide("ap9", decision, profile or "")
                break
            time.sleep(0.01)
        else:
            raise AssertionError("decider was not offered the queued decision")
        return {"type": "result", "ok": True, "payload": {"sessionId": "s", "text": "done"}}

    frames.chat_impl = script
    errors: list[BaseException] = []

    def run() -> None:
        try:
            gateway.chat("hi", session_id=None, on_event=lambda _payload: None, profile="default")
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert started.wait(2)
    with pytest.raises(GatewayError, match="chat in progress"):
        gateway.list_approvals()
    assert gateway.decide("ap9", "deny") == "queued"
    thread.join(3)
    assert not thread.is_alive()
    assert errors == []
    assert frames.decisions == [("ap9", "deny", "default")]


def test_other_approval_waits_until_the_turn_ends() -> None:
    gateway, frames, _http = _gateway()
    started = threading.Event()

    def script(text, session_id, on_event, decider, timeout, profile):
        del text, session_id, timeout, profile
        started.set()
        card = {"id": "ap-now"}
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            decision = decider(card)
            if decision:
                frames.decide("ap-now", decision, "default")
                break
            time.sleep(0.01)
        else:
            raise AssertionError("missing decision")
        return {"type": "result", "ok": True, "payload": {"sessionId": "s", "text": "done"}}

    frames.chat_impl = script

    def run() -> None:
        gateway.chat("hi", session_id="s", on_event=None, profile="default")

    thread = threading.Thread(target=run)
    thread.start()
    assert started.wait(2)
    gateway.decide("ap-later", "allow_once")
    gateway.decide("ap-now", "deny")
    thread.join(3)
    assert ("ap-now", "deny", "default") in frames.decisions
    assert ("ap-later", "allow_once", "default") in frames.decisions
    assert frames.decisions[-1] == ("ap-later", "allow_once", "default")


def test_provider_missing_message() -> None:
    ready = readiness_from(
        {"inferenceReady": False, "missing": [{"id": "no provider chosen"}], "provider": ""},
        18790,
    )
    assert ready == Readiness(
        False,
        "No model provider is configured. "
        "Run `praxis-prime setup` or open the web wizard at http://127.0.0.1:18790/.",
    )


def test_provider_not_verified_names_the_provider() -> None:
    ready = readiness_from(
        {
            "inferenceReady": False,
            "missing": [{"id": "provider not verified"}],
            "provider": "ollama:qwen",
        },
        18791,
    )
    assert ready.ready is False
    assert ready.message.startswith("ollama:qwen has not passed the setup test.")
    assert "http://127.0.0.1:18791/" in ready.message


def test_failed_status_does_not_invent_a_setup_error() -> None:
    http = FakeHttp(fail=True)
    gateway, _frames, _http = _gateway(http=http)
    assert gateway.readiness() == Readiness(True, "")


def test_status_without_inference_flag_does_not_block() -> None:
    assert readiness_from({"setupRequired": False}, 18790).ready is True


def test_resolve_profile_prefers_default_then_the_only_one() -> None:
    http = FakeHttp()
    http.profiles = [{"id": "alpha"}, {"id": "default"}]
    assert resolve_profile(http, "") == "default"
    assert resolve_profile(http, "alpha") == "alpha"
    http.profiles = [{"id": "solo"}]
    assert resolve_profile(http, "") == "solo"
    http.profiles = [{"id": "alpha"}, {"id": "beta"}]
    assert resolve_profile(http, "") == ""
    http.fail = True
    assert resolve_profile(http, "") == ""


def test_active_theme_path_rejects_nothing_but_a_profile_query() -> None:
    assert active_theme_path("") == "/v1/themes/active"
    assert active_theme_path("default") == "/v1/themes/active?profile=default"


def test_loopback_http_refuses_other_hosts() -> None:
    with pytest.raises(GatewayError, match="127.0.0.1"):
        LoopbackHttp("10.0.0.1", 80, "token-token")
    with pytest.raises(GatewayError, match="token"):
        LoopbackHttp("127.0.0.1", 80, "")


def test_loopback_http_bearer_and_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    del monkeypatch
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib name
            seen["authorization"] = self.headers.get("Authorization", "")
            seen["host"] = self.headers.get("Host", "")
            seen["path"] = self.path
            if self.path == "/v1/themes/active":
                body = json.dumps({"ok": True, "id": "smf.praxis"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/v1/onboarding/status":
                self.send_response(302)
                self.send_header("Location", "http://example.com/away")
                self.end_headers()
                return
            if self.path.startswith("/themes/") and self.path.endswith(".css"):
                body = b"/* theme */"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            del fmt, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        http = LoopbackHttp("127.0.0.1", port, "secret-token")
        body = http.get_json("/v1/themes/active")
        assert body["id"] == "smf.praxis"
        assert seen["authorization"] == "Bearer secret-token"
        assert seen["host"] == "127.0.0.1"
        css_path = "/themes/smf.praxis/" + ("ab" * 32) + ".css"
        assert http.get_text(css_path) == "/* theme */"
        with pytest.raises(GatewayError, match="redirect"):
            http.get_json("/v1/onboarding/status")
        with pytest.raises(GatewayError, match="path"):
            http.get_text("//evil.example/x")
        with pytest.raises(GatewayError, match="path"):
            http.get_json("/v1/themes/active/../../etc/passwd")
        with pytest.raises(GatewayError, match="query"):
            http.get_json("/v1/onboarding/status?token=nope")
    finally:
        server.shutdown()
        server.server_close()


def test_connect_client_name_is_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint = Endpoint("127.0.0.1", 9, "token-value")
    seen: dict[str, object] = {}

    def connect(ep: Endpoint, **kwargs: object) -> GatewayClient:
        seen["endpoint"] = ep
        seen["client"] = kwargs.get("client")
        raise GatewayError("stopped")

    monkeypatch.setattr(GatewayClient, "connect", staticmethod(connect))
    with pytest.raises(GatewayError, match="stopped"):
        TuiGateway.connect(endpoint)
    assert seen["client"] == "tui"
    assert seen["endpoint"] == endpoint
