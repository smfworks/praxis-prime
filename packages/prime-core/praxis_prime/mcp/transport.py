"""MCP transports: stdio, streamable HTTP, and legacy SSE.

stdio messages are newline-delimited JSON. A ``Content-Length`` header is
still accepted on read. Streamable HTTP POSTs JSON and accepts a JSON body
or an SSE response. If that POST is rejected and the mode is ``auto``, the
client opens the legacy SSE stream and posts to the endpoint event.

ARCHITECTURE §8.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urljoin

from praxis_prime.mcp.protocol import PROTOCOL_VERSION, McpError, dumps_message, parse_message

_FALLBACK_STATUS = {404, 405, 406, 501}


class _SseFallback(Exception):
    """Streamable HTTP is not this server. Try the legacy SSE transport."""


class StdioTransport:
    """One MCP server process. A reader thread demuxes responses by id."""

    def __init__(self, proc: subprocess.Popen[bytes], *, timeout: float = 30) -> None:
        self.proc = proc
        self.timeout = timeout
        self.stderr_tail = ""
        self._next_id = 0
        self._responses: dict[Any, dict[str, Any]] = {}
        self._cond = threading.Condition()
        self._write_lock = threading.Lock()
        self._closed = False
        self._reader = threading.Thread(target=self._read_stdout, name="mcp-stdio", daemon=True)
        self._errors = threading.Thread(target=self._read_stderr, name="mcp-stderr", daemon=True)
        self._reader.start()
        self._errors.start()

    def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        notify: bool = False,
    ) -> dict[str, Any] | None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": dict(params or {})}
        if notify:
            self.send(message)
            return None
        self._next_id += 1
        req_id = self._next_id
        message["id"] = req_id
        self.send(message)
        deadline = time.monotonic() + self.timeout
        with self._cond:
            while req_id not in self._responses:
                if self._closed or self.proc.poll() is not None:
                    code = self.proc.returncode
                    detail = self.stderr_tail.strip()[:300]
                    raise McpError(f"MCP server exited ({code}). {detail}".strip())
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise McpError(f"timed out waiting for {method}")
                self._cond.wait(remaining)
            return self._responses.pop(req_id)

    def send(self, message: Mapping[str, Any]) -> None:
        if self.proc.stdin is None:
            raise McpError("MCP server stdin is closed")
        data = dumps_message(message)
        with self._write_lock:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except BrokenPipeError as exc:
                raise McpError("MCP server closed stdin") from exc

    def close(self) -> None:
        self._closed = True
        if self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        with self._cond:
            self._cond.notify_all()

    def _read_stdout(self) -> None:
        stdout = self.proc.stdout
        if stdout is None:
            return
        while not self._closed:
            line = stdout.readline()
            if not line:
                break
            if line.lower().startswith(b"content-length:"):
                message = _read_framed(stdout, line)
            else:
                message = parse_message(line)
            if not message:
                continue
            if _is_server_request(message):
                self._answer_server(message)
                continue
            if "id" in message:
                with self._cond:
                    self._responses[message["id"]] = message
                    self._cond.notify_all()
        with self._cond:
            self._cond.notify_all()

    def _answer_server(self, message: Mapping[str, Any]) -> None:
        if message.get("method") == "roots/list":
            result: dict[str, Any] = {"roots": []}
            self.send({"jsonrpc": "2.0", "id": message.get("id"), "result": result})
            return
        self.send(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32601, "message": "unsupported"},
            }
        )

    def _read_stderr(self) -> None:
        stderr = self.proc.stderr
        if stderr is None:
            return
        chunks: list[str] = []
        for line in iter(stderr.readline, b""):
            chunks.append(line.decode("utf-8", errors="replace"))
            if sum(len(part) for part in chunks) > 4000:
                chunks = chunks[-8:]
        self.stderr_tail = "".join(chunks)[-1000:]


class HttpTransport:
    """Streamable HTTP, with a legacy SSE fallback when ``mode`` is ``auto``."""

    def __init__(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        *,
        mode: str = "auto",
        timeout: float = 30,
    ) -> None:
        self.url = url
        self.mode = mode
        self.timeout = timeout
        self.session_id = ""
        self._headers = dict(headers or {})
        self._next_id = 0
        self._sse_post: str | None = None
        self._inbox: queue.Queue[dict[str, Any]] = queue.Queue()
        self._endpoint: queue.Queue[tuple[str, str]] = queue.Queue()
        self._early: dict[Any, dict[str, Any]] = {}
        self._closed = False
        self._http_ok = False

    def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        notify: bool = False,
    ) -> dict[str, Any] | None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": dict(params or {})}
        req_id: int | None = None
        if not notify:
            self._next_id += 1
            req_id = self._next_id
            message["id"] = req_id
        if self.mode == "sse" or self._sse_post is not None:
            return self._sse_roundtrip(message, req_id)
        try:
            return self._http_roundtrip(message, req_id)
        except _SseFallback:
            if self.mode == "http":
                raise McpError("server rejected streamable HTTP") from None
            self.mode = "sse"
            return self._sse_roundtrip(message, req_id)

    def close(self) -> None:
        self._closed = True

    def _http_roundtrip(
        self,
        message: Mapping[str, Any],
        req_id: int | None,
    ) -> dict[str, Any] | None:
        data = json.dumps(message).encode()
        request = urllib.request.Request(
            self.url,
            data=data,
            headers=self._post_headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                self._http_ok = True
                return _read_http_body(response, req_id, self)
        except urllib.error.HTTPError as exc:
            if (
                not self._http_ok
                and self.mode == "auto"
                and exc.code in _FALLBACK_STATUS
            ):
                raise _SseFallback from exc
            raise McpError(f"HTTP {exc.code} from MCP server") from exc
        except urllib.error.URLError as exc:
            raise McpError(f"could not reach MCP server: {exc.reason}") from exc

    def _sse_roundtrip(
        self,
        message: Mapping[str, Any],
        req_id: int | None,
    ) -> dict[str, Any] | None:
        self._ensure_sse()
        if not self._sse_post:
            raise McpError("SSE endpoint is missing")
        data = json.dumps(message).encode()
        request = urllib.request.Request(
            self._sse_post,
            data=data,
            headers=self._post_headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read(4096)
        except urllib.error.HTTPError as exc:
            if exc.code not in {200, 202, 204}:
                raise McpError(f"HTTP {exc.code} posting to the SSE endpoint") from exc
        except urllib.error.URLError as exc:
            raise McpError(f"could not reach MCP SSE endpoint: {exc.reason}") from exc
        if req_id is None:
            return None
        return self._wait_sse(req_id)

    def _ensure_sse(self) -> None:
        if self._sse_post:
            return
        thread = threading.Thread(target=self._sse_loop, name="mcp-sse", daemon=True)
        thread.start()
        try:
            status, payload = self._endpoint.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise McpError("SSE server did not send an endpoint event") from exc
        if status != "ok" or not payload:
            raise McpError("SSE server did not send an endpoint event")
        self._sse_post = urljoin(self.url, payload)

    def _sse_loop(self) -> None:
        headers = dict(self._headers)
        headers["Accept"] = "text/event-stream"
        headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
        request = urllib.request.Request(self.url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                _consume_sse(response, self._endpoint, self._inbox, lambda: self._closed)
        except Exception:
            if not self._closed:
                self._endpoint.put(("err", ""))

    def _wait_sse(self, req_id: int) -> dict[str, Any]:
        if req_id in self._early:
            return self._early.pop(req_id)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                message = self._inbox.get(timeout=0.2)
            except queue.Empty:
                continue
            if message.get("id") == req_id:
                return message
            if "id" in message:
                self._early[message["id"]] = message
        raise McpError("timed out waiting for an SSE response")

    def _post_headers(self) -> dict[str, str]:
        headers = dict(self._headers)
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/event-stream"
        headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers


def _is_server_request(message: Mapping[str, Any]) -> bool:
    return (
        "method" in message
        and "id" in message
        and "result" not in message
        and "error" not in message
    )


def _read_framed(stdout: Any, first: bytes) -> dict[str, Any] | None:
    try:
        length = int(first.split(b":", 1)[1].strip())
    except ValueError:
        return None
    while True:
        extra = stdout.readline()
        if extra in {b"\n", b"\r\n", b""}:
            break
    body = stdout.read(length)
    return parse_message(body)


def _read_http_body(
    response: Any, req_id: int | None, transport: HttpTransport
) -> dict[str, Any] | None:
    session = response.headers.get("Mcp-Session-Id")
    if session:
        transport.session_id = str(session)
    ctype = response.headers.get("Content-Type", "")
    if "text/event-stream" in ctype:
        inbox: queue.Queue[dict[str, Any]] = queue.Queue()
        endpoint: queue.Queue[tuple[str, str]] = queue.Queue()
        _consume_sse(response, endpoint, inbox, lambda: False, stop_after=1)
        if req_id is None:
            return None
        try:
            return inbox.get_nowait()
        except queue.Empty as exc:
            raise McpError("streamable HTTP SSE response had no message") from exc
    raw = response.read(2_000_000)
    if not raw:
        return None
    return parse_message(raw)


def _consume_sse(
    response: Any,
    endpoint: queue.Queue[tuple[str, str]],
    inbox: queue.Queue[dict[str, Any]],
    closed: Callable[[], bool],
    *,
    stop_after: int = 0,
) -> None:
    event = "message"
    data: list[str] = []
    seen = 0
    while not closed():
        line = response.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        if text == "":
            if _dispatch_sse(event, "\n".join(data), endpoint, inbox):
                seen += 1
                if stop_after and seen >= stop_after:
                    return
            event = "message"
            data = []
            continue
        if text.startswith(":"):
            continue
        if text.startswith("event:"):
            event = text.split(":", 1)[1].strip() or "message"
        elif text.startswith("data:"):
            data.append(text.split(":", 1)[1].lstrip(" "))
    if data:
        _dispatch_sse(event, "\n".join(data), endpoint, inbox)


def _dispatch_sse(
    event: str,
    data: str,
    endpoint: queue.Queue[tuple[str, str]],
    inbox: queue.Queue[dict[str, Any]],
) -> bool:
    if not data:
        return False
    if event == "endpoint":
        endpoint.put(("ok", data.strip()))
        return False
    message = parse_message(data)
    if message is None:
        return False
    inbox.put(message)
    return True
