"""Minimal WebSocket (RFC 6455) for the loopback gateway.

Clients mask frames. The server does not. This is original code for the
Praxis Prime gateway, not a copy of another project's socket stack.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
import threading

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_PAYLOAD = 1_048_576


class WebSocketError(Exception):
    """The peer closed or sent a frame this stack will not accept."""


class ByteBuffer:
    """A socket plus bytes already read past an HTTP header."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.data = bytearray()

    def read_exact(self, count: int) -> bytes:
        while len(self.data) < count:
            chunk = self.sock.recv(max(4096, count - len(self.data)))
            if not chunk:
                raise ConnectionError("connection closed")
            self.data.extend(chunk)
        out = bytes(self.data[:count])
        del self.data[:count]
        return out

    def read_until(self, marker: bytes, limit: int) -> bytes:
        while marker not in self.data:
            if len(self.data) > limit:
                raise ValueError("header too large")
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed")
            self.data.extend(chunk)
        index = self.data.index(marker) + len(marker)
        out = bytes(self.data[:index])
        del self.data[:index]
        return out


def accept_key(sec_key: str) -> str:
    digest = hashlib.sha1((sec_key + _GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def encode_frame(opcode: int, payload: bytes, *, mask: bool) -> bytes:
    if len(payload) > _MAX_PAYLOAD:
        raise WebSocketError("frame too large")
    first = 0x80 | (opcode & 0x0F)
    mask_bit = 0x80 if mask else 0
    length = len(payload)
    if length < 126:
        header = bytes((first, mask_bit | length))
    elif length < 65536:
        header = bytes((first, mask_bit | 126)) + struct.pack("!H", length)
    else:
        header = bytes((first, mask_bit | 127)) + struct.pack("!Q", length)
    if not mask:
        return header + payload
    key = os.urandom(4)
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return header + key + masked


class WebSocketConnection:
    """One accepted or dialed WebSocket. ``client=True`` masks outgoing frames."""

    def __init__(self, sock: socket.socket, buffer: ByteBuffer, *, client: bool) -> None:
        self.sock = sock
        self.buffer = buffer
        self.client = client
        self._send_lock = threading.Lock()

    def send_text(self, text: str) -> None:
        self.send_frame(0x1, text.encode("utf-8"))

    def send_close(self) -> None:
        try:
            self.send_frame(0x8, b"")
        except OSError:
            return

    def send_frame(self, opcode: int, payload: bytes) -> None:
        frame = encode_frame(opcode, payload, mask=self.client)
        with self._send_lock:
            self.sock.sendall(frame)

    def recv_text(self) -> str | None:
        """Return one text message, or None when the peer closes."""
        fragments: list[bytes] = []
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode == 0x8:
                try:
                    self.send_frame(0x8, b"")
                except OSError:
                    pass
                return None
            if opcode == 0x9:
                self.send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in {0x1, 0x0}:
                fragments.append(payload)
                if sum(len(part) for part in fragments) > _MAX_PAYLOAD:
                    raise WebSocketError("message too large")
                if fin:
                    return b"".join(fragments).decode("utf-8", errors="replace")
                continue
            raise WebSocketError(f"unsupported opcode {opcode}")

    def close(self) -> None:
        self.send_close()
        try:
            self.sock.close()
        except OSError:
            return

    def _read_frame(self) -> tuple[bool, int, bytes]:
        header = self.buffer.read_exact(2)
        fin = bool(header[0] & 0x80)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.buffer.read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.buffer.read_exact(8))[0]
        if length > _MAX_PAYLOAD:
            raise WebSocketError("frame too large")
        if self.client and masked:
            raise WebSocketError("server frame was masked")
        if not self.client and not masked:
            raise WebSocketError("client frame was not masked")
        mask_key = self.buffer.read_exact(4) if masked else b""
        payload = self.buffer.read_exact(length) if length else b""
        if masked:
            payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        return fin, opcode, payload


def client_handshake(
    sock: socket.socket,
    *,
    host: str,
    port: int,
    token: str,
    path: str = "/ws",
) -> ByteBuffer:
    """Perform the opening handshake. Returns a buffer positioned after it."""
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if token:
        lines.append(f"Authorization: Bearer {token}")
    request = "\r\n".join(lines) + "\r\n\r\n"
    sock.sendall(request.encode("ascii"))
    buffer = ByteBuffer(sock)
    raw = buffer.read_until(b"\r\n\r\n", limit=16384)
    head = raw.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    if " 101 " not in head:
        raise WebSocketError(f"websocket upgrade failed: {head}")
    headers = _headers(raw)
    expected = accept_key(key)
    if headers.get("sec-websocket-accept", "") != expected:
        raise WebSocketError("websocket accept key did not match")
    return buffer


def server_upgrade_response(sec_key: str) -> bytes:
    accept = accept_key(sec_key)
    text = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    return text.encode("ascii")


def _headers(raw: bytes) -> dict[str, str]:
    text = raw.decode("iso-8859-1", errors="replace")
    headers: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return headers
