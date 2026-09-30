"""Streamable HTTP and the legacy SSE fallback, against a local server."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from praxis_prime.audit.log import AuditLog
from praxis_prime.mcp.client import McpClient
from praxis_prime.mcp.config import ServerSpec
from praxis_prime.state import StateDB

TOKEN = "test-token"


def test_streamable_http_sends_bearer_and_audits_without_the_token(tmp_path):
    seen: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            seen["authorization"] = self.headers.get("Authorization", "")
            seen["protocol"] = self.headers.get("MCP-Protocol-Version", "")
            seen["accept"] = self.headers.get("Accept", "")
            response = _rpc(body)
            if response is None:
                self.send_response(202)
                self.end_headers()
                return
            payload = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "sess-1")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    db = StateDB(tmp_path / "prime.db")
    spec = ServerSpec(
        name="remote",
        transport="http",
        url=f"http://127.0.0.1:{port}/mcp",
        token_env="PRAXIS_PRIME_MCP_TEST_TOKEN",
        trust="untrusted",
    )
    client = McpClient(
        spec,
        cwd=tmp_path,
        audit=AuditLog(db),
        parent_env={"PRAXIS_PRIME_MCP_TEST_TOKEN": TOKEN, "PATH": "/usr/bin"},
    )
    try:
        client.connect()
        assert [tool.name for tool in client.tools] == ["echo"]
        assert client.call_tool("echo", {"text": "hi"}) == "hi"
        assert seen["authorization"] == f"Bearer {TOKEN}"
        assert seen["protocol"] == "2025-03-26"
        assert "application/json" in seen["accept"]
        assert "text/event-stream" in seen["accept"]
    finally:
        client.close()
        server.shutdown()
    payload = "\n".join(
        row["payload_json"]
        for row in db.conn.execute("SELECT payload_json FROM audit_events").fetchall()
    )
    assert TOKEN not in payload
    assert "tools/call" in payload
    db.close()


def test_sse_fallback_when_post_is_rejected(tmp_path):
    import queue

    events: queue.Queue[dict[str, object] | None] = queue.Queue()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            if self.path.startswith("/message"):
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                response = _rpc(body)
                if response is not None:
                    events.put(response)
                self.send_response(202)
                self.end_headers()
                return
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            endpoint = f"http://127.0.0.1:{port}/message"
            self.wfile.write(f"event: endpoint\ndata: {endpoint}\n\n".encode())
            self.wfile.flush()
            while True:
                item = events.get()
                if item is None:
                    break
                payload = json.dumps(item)
                self.wfile.write(f"event: message\ndata: {payload}\n\n".encode())
                self.wfile.flush()

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    spec = ServerSpec(
        name="legacy",
        transport="auto",
        url=f"http://127.0.0.1:{port}/sse",
        trust="untrusted",
    )
    client = McpClient(spec, cwd=tmp_path, parent_env={"PATH": "/usr/bin"})
    try:
        client.connect()
        assert client.call_tool("echo", {"text": "sse"}) == "sse"
    finally:
        events.put(None)
        client.close()
        server.shutdown()


def _rpc(body: dict[str, object]) -> dict[str, object] | None:
    method = str(body.get("method", ""))
    req_id = body.get("id")
    if method.startswith("notifications/"):
        return None
    if method == "initialize":
        result = {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "http-fake", "version": "0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "echo",
                    "description": "Echo",
                    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                    "annotations": {"readOnlyHint": True},
                }
            ]
        }
    elif method == "tools/call":
        params = body.get("params") if isinstance(body.get("params"), dict) else {}
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        result = {
            "content": [{"type": "text", "text": str(arguments.get("text", ""))}],
            "isError": False,
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": "method not found"},
        }
    return {"jsonrpc": "2.0", "id": req_id, "result": result}
