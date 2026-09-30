"""``praxis-prime mcp`` commands.

``serve`` is the only way to expose Praxis Prime as an MCP server. It is
not started by the daemon.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from praxis_prime.approvals.gate import ApprovalDecision
from praxis_prime.audit.log import AuditLog
from praxis_prime.config import resolve_config_dir
from praxis_prime.mcp.config import (
    McpConfigError,
    ServerSpec,
    add_project_server,
    add_server,
    load_servers,
    remove_project_server,
    remove_server,
    validate_name,
)
from praxis_prime.mcp.risk import map_tool_risk
from praxis_prime.profiles.home import resolve_runtime_layout
from praxis_prime.state import StateDB


def add_mcp_parser(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = commands.add_parser("mcp", help="List, check, or serve MCP servers.")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--config-dir", help="Config directory. Defaults to the XDG path.")
    shared.add_argument("--data-dir", help="Directory that contains prime.db.")
    shared.add_argument(
        "--project-dir",
        help="Project root for .prime/mcp.json. Defaults to the current directory.",
    )
    sub = parser.add_subparsers(dest="mcp_command")
    sub.add_parser("list", parents=[shared], help="Show configured servers. Does not connect.")
    add = sub.add_parser("add", parents=[shared], help="Save a server in config.toml.")
    add.add_argument("name")
    add.add_argument("--command", dest="server_command", help="Stdio executable.")
    add.add_argument("--arg", action="append", default=[], help="Argument for the stdio command.")
    add.add_argument("--url", help="Streamable HTTP or SSE URL.")
    add.add_argument("--transport", choices=["stdio", "http", "sse", "auto"])
    add.add_argument("--trust", choices=["trusted", "untrusted"], default="untrusted")
    add.add_argument("--sandbox", choices=["bwrap", "off"], default="bwrap")
    add.add_argument("--network", choices=["off", "on"], default="off")
    add.add_argument(
        "--token-env",
        default="",
        help="Environment or secrets.env variable that holds the bearer token.",
    )
    add.add_argument("--env-allow", action="append", default=[], help="Parent env var to pass.")
    add.add_argument(
        "--env",
        action="append",
        default=[],
        help="Explicit KEY=VALUE for the server process. Do not put secrets here.",
    )
    add.add_argument(
        "--risk",
        action="append",
        default=[],
        help="Per-tool risk, for example write_note=DRAFT.",
    )
    add.add_argument(
        "--project",
        action="store_true",
        help="Write .prime/mcp.json instead of config.toml.",
    )
    remove = sub.add_parser("remove", parents=[shared], help="Remove a saved server.")
    remove.add_argument("name")
    remove.add_argument("--project", action="store_true", help="Remove from .prime/mcp.json.")
    test = sub.add_parser("test", parents=[shared], help="Connect and list capabilities.")
    test.add_argument("name")
    tools = sub.add_parser("tools", parents=[shared], help="List tools for one server.")
    tools.add_argument("name")
    sub.add_parser(
        "serve",
        parents=[shared],
        help="Expose decide, recall, and skills_list on stdio. Off unless you run this.",
    )


def mcp_command(args: argparse.Namespace) -> int:
    try:
        return _dispatch(args)
    except McpConfigError as exc:
        print(f"praxis-prime mcp: {exc}", file=sys.stderr)
        return 2


def _dispatch(args: argparse.Namespace) -> int:
    command = args.mcp_command
    if command == "list":
        return _list(args)
    if command == "add":
        return _add(args)
    if command == "remove":
        return _remove(args)
    if command == "test":
        return _test(args)
    if command == "tools":
        return _tools(args)
    if command == "serve":
        return _serve(args)
    print("praxis-prime mcp: choose list, add, remove, test, tools, or serve", file=sys.stderr)
    return 2


def _list(args: argparse.Namespace) -> int:
    specs = load_servers(_config_path(args), _project_root(args), include_disabled=True)
    if not specs:
        print("No MCP servers configured.")
        return 0
    for spec in specs:
        where = spec.url or spec.command
        state = "enabled" if spec.enabled else "disabled"
        print(
            f"{spec.name}\t{spec.transport}\t{spec.trust}\t{spec.source}\t{state}\t{where}"
        )
    return 0


def _add(args: argparse.Namespace) -> int:
    name = validate_name(args.name)
    env_pairs = tuple(_split_pair(item, "--env") for item in args.env)
    risks = tuple(_split_pair(item, "--risk") for item in args.risk)
    transport = args.transport
    if transport is None:
        transport = (
            "stdio" if args.server_command and not args.url else ("auto" if args.url else "")
        )
    spec = ServerSpec(
        name=name,
        transport=transport or "stdio",
        command=args.server_command or "",
        args=tuple(args.arg),
        env=env_pairs,
        env_allow=tuple(args.env_allow) if args.env_allow else None,
        url=args.url or "",
        token_env=args.token_env,
        trust=args.trust,
        sandbox=args.sandbox,
        network=args.network,
        tool_risks=risks,
        source="project" if args.project else "config",
    )
    if spec.transport == "stdio" and not spec.command:
        raise McpConfigError("stdio server needs --command")
    if spec.transport in {"http", "sse", "auto"} and not spec.url:
        raise McpConfigError("HTTP server needs --url")
    if args.project:
        path = add_project_server(_project_root(args), spec)
    else:
        path = add_server(_config_dir(args), spec)
    print(f"saved {name} in {path}")
    return 0


def _remove(args: argparse.Namespace) -> int:
    name = validate_name(args.name)
    if args.project:
        removed = remove_project_server(_project_root(args), name)
    else:
        removed = remove_server(_config_dir(args), name)
    if not removed:
        print(f"praxis-prime mcp: no server named {name}", file=sys.stderr)
        return 2
    print(f"removed {name}")
    return 0


def _test(args: argparse.Namespace) -> int:
    spec = _require(args, args.name)
    client, db = _connect(args, spec)
    try:
        info = client.server_info.get("name", spec.name)
        version = client.server_info.get("version", "")
        print(f"server: {info} {version}".rstrip())
        print(f"protocol: {client.protocol}")
        print(f"transport: {spec.transport}")
        print(f"trust: {spec.trust}")
        print(f"tools: {len(client.tools)}")
        print(f"resources: {len(client.resources)}")
        print(f"prompts: {len(client.prompts)}")
        return 0
    finally:
        client.close()
        db.close()


def _tools(args: argparse.Namespace) -> int:
    spec = _require(args, args.name)
    client, db = _connect(args, spec)
    try:
        if not client.tools:
            print("tools: none")
        else:
            print("tools:")
            for info in client.tools:
                decision = map_tool_risk(
                    info.name,
                    info.annotations,
                    trust=spec.trust,
                    override=spec.risk_map().get(info.name, ""),
                    sandboxed=spec.transport == "stdio" and spec.sandbox != "off",
                )
                ask = " ask" if decision.force_approval else ""
                print(
                    f"  mcp__{spec.name}__{info.name}  "
                    f"{decision.risk.value}{ask}  {info.description}"
                )
        if client.resources:
            print("resources:")
            for resource in client.resources:
                print(f"  {resource.uri}  {resource.name}  {resource.description}")
        if client.prompts:
            print("prompts:")
            for prompt in client.prompts:
                print(f"  {prompt.name}  {prompt.description}")
        return 0
    finally:
        client.close()
        db.close()


def _serve(args: argparse.Namespace) -> int:
    from praxis_prime.mcp.server import run_stdio_server
    from praxis_prime.runtime import build_runtime

    config_dir = _config_dir(args) if args.config_dir else None
    data_dir = Path(args.data_dir) if args.data_dir else None
    config_path = (config_dir / "config.toml") if config_dir else None
    data_path = (data_dir / "prime.db") if data_dir else None
    runtime = build_runtime(
        config_path=config_path,
        data_path=data_path,
        cwd=_project_root(args),
        approver=lambda _request: ApprovalDecision.DENY,
    )
    try:
        run_stdio_server(runtime)
    finally:
        runtime.close()
    return 0


def _connect(args: argparse.Namespace, spec: ServerSpec) -> tuple[object, StateDB]:
    from praxis_prime.mcp.client import McpClient

    path = _db_path(args)
    db = StateDB(path)
    client = McpClient(
        spec,
        cwd=_project_root(args),
        audit=AuditLog(db),
        parent_env=os.environ,
    )
    try:
        client.connect()
    except Exception as exc:
        client.close()
        db.close()
        print(f"praxis-prime mcp: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    return client, db


def _require(args: argparse.Namespace, name: str) -> ServerSpec:
    validate_name(name)
    for spec in load_servers(_config_path(args), _project_root(args), include_disabled=True):
        if spec.name == name:
            if not spec.enabled:
                raise McpConfigError(f"{name} is disabled")
            return spec
    raise McpConfigError(f"no server named {name}")


def _config_dir(args: argparse.Namespace) -> Path:
    return resolve_config_dir(args.config_dir)


def _config_path(args: argparse.Namespace) -> Path:
    return _config_dir(args) / "config.toml"


def _project_root(args: argparse.Namespace) -> Path:
    raw = getattr(args, "project_dir", None)
    if raw:
        return Path(raw)
    return Path.cwd()


def _db_path(args: argparse.Namespace) -> Path:
    data_file = Path(args.data_dir) / "prime.db" if args.data_dir else None
    return resolve_runtime_layout(None, data_file=data_file, profile=None).db_path


def _split_pair(item: str, flag: str) -> tuple[str, str]:
    if "=" not in item:
        raise McpConfigError(f"{flag} expects KEY=VALUE")
    key, value = item.split("=", 1)
    if not key.strip():
        raise McpConfigError(f"{flag} expects KEY=VALUE")
    return key.strip(), value
