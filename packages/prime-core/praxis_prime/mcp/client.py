"""MCP client session: initialize, discover, and call.

Every JSON-RPC request is appended to the audit log when one is provided.
Tool results are plain text here. The agent loop fences them as untrusted
data before they reach the model.

Full OAuth 2.1 (dynamic registration, PKCE, refresh) is not implemented.
HTTP servers use a bearer token from ``token_env`` or a header written by
the user. See docs/MCP.md.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from praxis_prime import __version__
from praxis_prime.approvals.gate import ApprovalDecision, ApprovalRequest
from praxis_prime.audit.log import AuditLog
from praxis_prime.mcp.auth import resolve_headers
from praxis_prime.mcp.config import ServerSpec
from praxis_prime.mcp.protocol import (
    PROTOCOL_FALLBACK,
    PROTOCOL_VERSION,
    McpError,
    prompt_text,
    redact_mapping,
    resource_text,
    tool_result_text,
)
from praxis_prime.mcp.sandbox import mcp_mount_decision, popen_stdio
from praxis_prime.mcp.transport import HttpTransport, StdioTransport
from praxis_prime.sandbox.bwrap import bwrap_available, writable_scope_ok
from praxis_prime.tools.registry import Risk

_PAGE_LIMIT = 20


@dataclass(frozen=True, slots=True)
class McpToolInfo:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]


@dataclass(frozen=True, slots=True)
class McpResourceInfo:
    uri: str
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class McpPromptInfo:
    name: str
    description: str


class McpClient:
    """A connected MCP server. Construct it and call ``connect``."""

    def __init__(
        self,
        spec: ServerSpec,
        *,
        cwd: Path,
        audit: AuditLog | None = None,
        parent_env: Mapping[str, str] | None = None,
        timeout: float = 30,
        gate: Any = None,
        main_checkout: Path | None = None,
    ) -> None:
        self.spec = spec
        self.cwd = cwd
        self.audit = audit
        self.parent_env = os.environ if parent_env is None else parent_env
        self.timeout = timeout
        self.gate = gate
        self.main_checkout = main_checkout
        self.protocol = ""
        self.server_info: dict[str, Any] = {}
        self.tools: list[McpToolInfo] = []
        self.resources: list[McpResourceInfo] = []
        self.prompts: list[McpPromptInfo] = []
        self._transport: StdioTransport | HttpTransport | None = None

    def connect(self) -> None:
        self._transport = _open_transport(self)
        try:
            self._initialize()
            self.tools = [_tool(item) for item in self._list("tools/list", "tools")]
            self.resources = [_resource(item) for item in self._list("resources/list", "resources")]
            self.prompts = [_prompt(item) for item in self._list("prompts/list", "prompts")]
        except Exception:
            self.close()
            raise

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object],
        *,
        session_id: str | None = None,
    ) -> str:
        result = self._rpc(
            "tools/call",
            {"name": name, "arguments": dict(arguments)},
            session_id=session_id,
            audit_extra={"tool": name, "arguments": redact_mapping(arguments)},
        )
        return tool_result_text(result)

    def read_resource(self, uri: str, *, session_id: str | None = None) -> str:
        result = self._rpc(
            "resources/read",
            {"uri": uri},
            session_id=session_id,
            audit_extra={"uri": uri[:180]},
        )
        return resource_text(result)

    def get_prompt(
        self,
        name: str,
        arguments: Mapping[str, object] | None = None,
        *,
        session_id: str | None = None,
    ) -> str:
        params: dict[str, object] = {"name": name}
        if arguments:
            params["arguments"] = {str(key): str(value) for key, value in arguments.items()}
        result = self._rpc(
            "prompts/get",
            params,
            session_id=session_id,
            audit_extra={"prompt": name},
        )
        return prompt_text(result)

    def close(self) -> None:
        transport = self._transport
        self._transport = None
        if transport is not None:
            transport.close()

    def _initialize(self) -> None:
        params = _initialize_params(PROTOCOL_VERSION)
        try:
            result = self._rpc("initialize", params, audit_extra={"phase": "initialize"})
        except McpError:
            params = _initialize_params(PROTOCOL_FALLBACK)
            result = self._rpc("initialize", params, audit_extra={"phase": "initialize"})
        self.protocol = str(result.get("protocolVersion", ""))
        info = result.get("serverInfo")
        self.server_info = info if isinstance(info, dict) else {}
        transport = self._require()
        transport.request("notifications/initialized", {}, notify=True)

    def _list(self, method: str, key: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor = ""
        for _ in range(_PAGE_LIMIT):
            params: dict[str, object] = {}
            if cursor:
                params["cursor"] = cursor
            try:
                result = self._rpc(method, params, audit_extra={"count_key": key})
            except McpError as exc:
                if _missing_method(exc):
                    return items
                raise
            batch = result.get(key)
            if isinstance(batch, list):
                items.extend(item for item in batch if isinstance(item, dict))
            nxt = result.get("nextCursor")
            if not isinstance(nxt, str) or not nxt:
                break
            cursor = nxt
        return items

    def _rpc(
        self,
        method: str,
        params: Mapping[str, object],
        *,
        session_id: str | None = None,
        audit_extra: Mapping[str, object] | None = None,
    ) -> dict[str, Any]:
        transport = self._require()
        ok = True
        try:
            message = transport.request(method, params)
        except McpError:
            ok = False
            self._audit(method, ok=False, session_id=session_id, extra=audit_extra)
            raise
        if message is None:
            self._audit(method, ok=False, session_id=session_id, extra=audit_extra)
            raise McpError(f"{method} returned no result")
        if "error" in message:
            self._audit(method, ok=False, session_id=session_id, extra=audit_extra)
            raise McpError(_error_text(message.get("error")))
        result = message.get("result")
        self._audit(method, ok=ok, session_id=session_id, extra=audit_extra)
        if isinstance(result, dict):
            return result
        return {}

    def _audit(
        self,
        method: str,
        *,
        ok: bool,
        session_id: str | None,
        extra: Mapping[str, object] | None,
    ) -> None:
        if self.audit is None:
            return
        payload: dict[str, object] = {
            "server": self.spec.name,
            "method": method,
            "transport": self.spec.transport,
            "ok": ok,
        }
        if extra:
            for key, value in extra.items():
                if key == "arguments" and isinstance(value, dict):
                    payload[key] = value
                else:
                    payload[key] = (
                        value if isinstance(value, (str, int, bool)) else str(value)[:180]
                    )
        self.audit.append(
            session_id=session_id,
            kind="mcp",
            summary=f"{self.spec.name} {method} {'ok' if ok else 'error'}",
            payload=payload,
        )

    def _require(self) -> StdioTransport | HttpTransport:
        if self._transport is None:
            raise McpError(f"MCP server {self.spec.name} is not connected")
        return self._transport


def _open_transport(client: McpClient) -> StdioTransport | HttpTransport:
    spec = client.spec
    if spec.transport == "stdio":
        scope, approved = _stdio_write(client)
        proc = popen_stdio(
            spec.command,
            spec.args,
            cwd=client.cwd,
            allow=spec.allowlist(),
            explicit=spec.env_map(),
            parent=client.parent_env,
            sandbox=spec.sandbox,
            network=spec.network,
            write_scope=scope,
            write_approved=approved,
            main_checkout=client.main_checkout,
            audit=client.audit,
            server=spec.name,
            host_approved=_host_launch_approved(client),
        )
        return StdioTransport(proc, timeout=client.timeout)
    headers = resolve_headers(spec.headers, spec.token_env, client.parent_env)
    mode = "sse" if spec.transport == "sse" else ("http" if spec.transport == "http" else "auto")
    return HttpTransport(spec.url, headers, mode=mode, timeout=client.timeout)


def _stdio_write(client: McpClient) -> tuple[Path | None, bool]:
    """Return the configured scope and whether this launch may mount it read-write.

    No scope means the working directory stays read-only and nobody is asked.
    ``$HOME``, the main checkout, and any directory that is or contains an
    account-data root are not asked: they cannot be a write scope. Any other
    directory is mounted read-write only after the approval gate allows it.
    When the sandbox is off or bubblewrap is missing, nothing is mounted, so
    a write scope is not asked. The host start is decided separately.
    """
    if client.spec.sandbox == "off" or not bwrap_available():
        return None, False
    raw = client.spec.write_scope.strip()
    if not raw:
        return None, False
    scope = Path(raw)
    if not scope.is_absolute():
        scope = Path(client.cwd) / scope
    try:
        resolved = scope.resolve()
    except OSError:
        return scope, False
    if not writable_scope_ok(resolved, resolved, client.main_checkout):
        return resolved, False
    preview = mcp_mount_decision(
        Path(client.cwd),
        resolved,
        write_approved=True,
        main_checkout=client.main_checkout,
    )
    if preview.decision != "allow":
        return resolved, False
    gate = client.gate
    if gate is None or not hasattr(gate, "authorize"):
        return resolved, False
    decision = gate.authorize(
        ApprovalRequest(
            tool=f"mcp:{client.spec.name}",
            risk=Risk.DESTRUCTIVE,
            reason="MCP server write scope",
            summary=f"read-write bind {resolved}",
            arguments={"server": client.spec.name, "write_scope": str(resolved)},
            grant_key=f"mcp-write:{client.spec.name}:{resolved}",
            sandboxed=client.spec.sandbox != "off",
            mount="rw",
        )
    )
    approved = decision in {ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION}
    return resolved, approved


def _host_launch_approved(client: McpClient) -> bool:
    """True when this stdio server may start on the host.

    Account data fails closed and is not asked, including for a trusted
    server. A trusted server with ``sandbox = "off"`` is an explicit host
    choice and starts with no gate when no account data exists. That is
    the product's own ``mcp serve`` path. An untrusted server still needs
    an approval, and a missing bubblewrap is not treated as ``sandbox = "off"``.
    """
    if client.spec.transport != "stdio":
        return False
    if client.spec.sandbox != "off" and bwrap_available():
        return False
    from praxis_prime.policy.boundary import account_data_present

    if account_data_present():
        return False
    if client.spec.trust == "trusted" and client.spec.sandbox == "off":
        return True
    gate = client.gate
    if gate is None or not hasattr(gate, "authorize"):
        return False
    decision = gate.authorize(
        ApprovalRequest(
            tool=f"mcp:{client.spec.name}",
            risk=Risk.DESTRUCTIVE,
            reason="MCP server would run on the host",
            summary=f"host start {client.spec.name}",
            arguments={"server": client.spec.name},
            grant_key=f"mcp-host:{client.spec.name}",
            sandboxed=False,
            mount="host",
        )
    )
    return decision in {ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION}


def _initialize_params(version: str) -> dict[str, object]:
    return {
        "protocolVersion": version,
        "capabilities": {"roots": {"listChanged": False}},
        "clientInfo": {"name": "praxis-prime", "version": __version__},
    }


def _tool(item: Mapping[str, Any]) -> McpToolInfo:
    schema = item.get("inputSchema")
    annotations = item.get("annotations")
    return McpToolInfo(
        name=str(item.get("name", "")),
        description=str(item.get("description", "")),
        input_schema=schema if isinstance(schema, dict) else {"type": "object", "properties": {}},
        annotations=annotations if isinstance(annotations, dict) else {},
    )


def _resource(item: Mapping[str, Any]) -> McpResourceInfo:
    return McpResourceInfo(
        uri=str(item.get("uri", "")),
        name=str(item.get("name", "")),
        description=str(item.get("description", "")),
    )


def _prompt(item: Mapping[str, Any]) -> McpPromptInfo:
    return McpPromptInfo(
        name=str(item.get("name", "")),
        description=str(item.get("description", "")),
    )


def _error_text(error: object) -> str:
    if isinstance(error, dict):
        message = str(error.get("message", "MCP error"))
        code = error.get("code")
        return f"{message} ({code})" if code is not None else message
    return "MCP error"


def _missing_method(exc: McpError) -> bool:
    text = str(exc).lower()
    return "-32601" in text or "not found" in text or "method" in text and "unsupported" in text
