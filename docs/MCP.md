# MCP client and optional server

Praxis Prime can call tools on Model Context Protocol servers, and it can expose a small safe subset of itself to other agents. The client is a stdlib implementation of the public protocol (stdio, streamable HTTP, and the older SSE transport). The official `mcp` Python SDK is not a dependency. `mcp.serve` stays false in the default config. The daemon does not start an MCP server.

Tool results, resource bodies, and prompt text are untrusted data. The agent loop wraps them in `<<<UNTRUSTED` fences. Instructions inside that text are not followed. Every MCP request and response is appended to the hash-chained audit log (`kind` `mcp`). Tokens and secret-like argument values are redacted. Full tool output is not stored in the audit row.

## Configure a server

User servers live in `config.toml` under `[mcp.servers.<name>]`. A project file `.prime/mcp.json` uses the same `mcpServers` object shape as Claude Code and Cursor. When both define the same name, the project file wins.

```toml
[mcp]
enabled = true
serve = false
lazy_threshold = 8
env_allow = ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM"]

[mcp.servers.notes]
command = "python3"
args = [".prime/notes_server.py"]
trust = "untrusted"
sandbox = "bwrap"
network = "off"
```

```json
{
  "mcpServers": {
    "notes": {
      "command": "python3",
      "args": [".prime/notes_server.py"],
      "trust": "untrusted"
    }
  }
}
```

Server names are letters, digits, `_`, and `-`, at most 41 characters, and must not contain `__`.

| Field | Meaning |
|---|---|
| `command`, `args` | Stdio executable and arguments |
| `url` | Streamable HTTP endpoint. `transport` `sse` forces the legacy GET stream |
| `transport` or `type` | `stdio`, `http`, `sse`, or `auto` (HTTP, then SSE if the POST is rejected) |
| `trust` | `untrusted` (default) or `trusted` |
| `sandbox` | `bwrap` (default) or `off` |
| `network` | `off` (default) or `on`. `on` adds `--share-net` inside bubblewrap |
| `env` | Explicit `KEY=VALUE` pairs. Do not put secrets here |
| `env_allow` | Extra parent environment names to pass. Replaces the global list for this server |
| `headers` | HTTP headers. `${VAR}` and `${env:VAR}` are filled from the environment or `secrets.env` |
| `token_env` | Variable name whose value is sent as `Authorization: Bearer`. The value is not written to config |
| `tools` or `toolRisks` | Map of remote tool name to a risk class (`READ`, `DRAFT`, `SEND`, `DESTRUCTIVE`, `SPEND`, `SHARE`) |

`praxis-prime mcp add` writes `config.toml`. `--project` writes `.prime/mcp.json` instead. It will not store an `Authorization` header. Put bearer tokens in the environment or `secrets.env` and name the variable with `--token-env`.

```bash
praxis-prime mcp add notes --command python3 --arg .prime/notes_server.py
praxis-prime mcp list
praxis-prime mcp test notes
praxis-prime mcp tools notes
praxis-prime mcp remove notes
```

`--config-dir` and `--project-dir` point those commands at a directory other than the XDG config and the current working directory.

## How tools reach the agent

Discovered tools are registered as `mcp__<server>__<tool>`. Characters outside `[A-Za-z0-9_-]` in the remote name become `_`.

The prompt does not receive the whole catalog. While no server has been connected, the preamble only names the configured servers. `mcp_find_tools` connects and searches tools, resources, and prompts. When a server has more tools than `mcp.lazy_threshold` (default 8), only the matching names are revealed to the model. A direct call still resolves a hidden tool. `mcp_read_resource` and `mcp_get_prompt` read the other two surfaces.

Resources and prompts that a server does not implement are treated as empty. Pagination follows `nextCursor`.

## Trust and approvals

Each server has a trust level. The approval hook uses the existing risk classes. The mapping is:

| Signal | Risk | Asks? |
|---|---|---|
| `destructiveHint` | `DESTRUCTIVE` | yes. An override cannot lower this |
| `readOnlyHint` | `READ` | no, even when the name looks like a write |
| `openWorldHint` | `SEND` | yes |
| Write-like name, untrusted, no read-only hint | `DRAFT` | yes |
| No annotation and not write-like | `SEND` | yes (ARCHITECTURE §8) |
| Trusted server, explicit `DRAFT` override on a write-like name | `DRAFT` | no |

Write-like names match `write`, `create`, `update`, `delete`, `remove`, `edit`, `send`, `post`, `put`, `exec`, `shell`, `purchase`, `pay`, `submit`, `upload`, `mkdir`, `drop`, and `insert`. Session grants for `mcp__` tools are hashed per summary, so allowing one call does not allow every tool on that server.

## Stdio sandbox and environment

When `bwrap` is on `PATH` and `sandbox` is `bwrap`, the child runs under bubblewrap with a cleared environment. Only the allowlist is passed: `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, and `TERM`, plus any names in the server's `env_allow`, plus the explicit `env` map. `HOME` is not passed unless you name it. Python commands also get `PYTHONUNBUFFERED=1`. Network stays off unless `network = "on"`.

If bubblewrap is missing, the same allowlist is used and the process is not wrapped. `praxis-prime doctor` warns in that case. A failed bubblewrap start is not retried on the host.

## HTTP auth

`token_env` and `${VAR}` headers read the environment or `secrets.env` (ARCHITECTURE §25). The token is not logged. Full OAuth 2.1 (PKCE, dynamic client registration, refresh) is not implemented.

## Serving Praxis Prime

```bash
praxis-prime mcp serve
```

This speaks MCP on stdio and is off unless you run it. Other agents can add it as a stdio server. The tools are:

| Tool | What it does |
|---|---|
| `decide` | Local Decision Engine. Same cascade as `praxis-prime decide`. Does not call a hosted service |
| `recall` | Search memory |
| `skills_list` | Names and descriptions of discovered skills. Bodies are not returned |

Those calls are audited. The server does not expose shell, browser, or arbitrary MCP passthrough.
