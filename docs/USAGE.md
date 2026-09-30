# Using Praxis Prime

This milestone runs the agent loop in a loopback daemon and in the terminal, plus a local Decision Engine, saved routines, memory tiers, and skills. Compliance dials still default to off. The approval pre-screener is off until you set `decide.prescreen`. The TUI and web UI are not in this build.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Chat and one-shot ask

```bash
praxis-prime chat
praxis-prime ask "what is in this directory?"
```

`ask` writes the answer to stdout and the tool timeline to stderr.

If `praxis-primed` is already healthy, `chat` and `ask` attach to it and print `attached to praxis-primed` on stderr. Otherwise they run the loop in this process. `--local` always stays in this process, which is also what `--config-dir` and `--data-dir` do.

Attached `ask` waits for an approval (the terminal, `praxis-prime approvals`, or Telegram) instead of denying immediately. In-process `ask` still denies when stdin is not a terminal.

Inside `chat`:

| Input | Effect |
|---|---|
| `/help` | Show commands |
| `/model` | Show the active model and the fallback chain |
| `/model ollama:qwen3:8b` | Use that model for the rest of the session |
| `/clear` | Start a new session (drops in-session approvals) |
| `/quit` | Leave |
| Ctrl-C | Cancel the current turn and return to the prompt |
| Ctrl-D | Leave |

`--session <id>` resumes a stored transcript. `--model` overrides the config for that process.

## Approvals

Reading, listing, and sandboxed non-destructive commands can run on their own. These always ask:

- sending
- spending
- sharing access
- deleting or overwriting

The prompt is:

- `y` allow this once
- `n` deny
- `a` allow this exact shell command, or this tool and risk, for the rest of the session

`ask` uses the same prompt when stdin is a terminal and the loop is in this process. Otherwise an in-process `ask` denies the action and continues. A denied tool does not run. An approval that is still pending when its TTL ends (default 15 minutes, `gateway.approval_ttl_seconds` or `PRAXIS_PRIME_APPROVAL_TTL`) is denied. Shutting the daemon down denies anything still waiting.

When a daemon is running, decide from another terminal:

```bash
praxis-prime approvals list
praxis-prime approvals approve ap_0123abcd
praxis-prime approvals approve ap_0123abcd --session
praxis-prime approvals deny ap_0123abcd
```

`approve` is once. `--session` allows that same action for the rest of the session that asked. A text message, including "yes" or `/approve`, is not a decision.

`shell` uses bubblewrap when `bwrap` is installed. The sandbox has no network, and the workspace is mounted read-only unless a write was approved for that directory. Only `ls`, `cat` (and `head` / `tail`) of concrete workspace paths, `git status`, `git diff` of existing non-secret files or `--stat` / `--name-only` / `--name-status`, and `git log` without `-p` skip approval. `pytest --collect-only` asks, because collection imports the repo's `conftest.py`. A directory or `.` beside a file asks unless the diff is one of those summary flags. A pathspec that starts with `:` is allowlisted only when it names an existing non-secret file. Before a content diff is auto-approved, `git --name-only -z` must list only those files. The sandbox home is an empty directory. Repo git config is an allowlist: auto-approval requires every key in the worktree config, `config.worktree`, a linked worktree's common dir, and any included file to be `core.repositoryformatversion=0`, `core.filemode`, `core.bare`, `core.logallrefupdates`, `core.ignorecase`, `core.precomposeunicode`, `core.symlinks`, `remote.<name>.url`, `remote.<name>.fetch`, `branch.<name>.remote`, `branch.<name>.merge`, `user.name`, `user.email`, or `init.defaultBranch`. Any other key asks, as does an unreadable or oversized config, a `.gitmodules` file, or a `modules` directory. `git status` does not ask on a `HEAD` `filter=` alone, because a filter or driver defined in config already asks. Globs, `rev:path`, and patch output of the whole tree ask. Anything else asks, including deletes, redirects, and interpreters. If bubblewrap is missing, or it fails to start, the command is not silently run on the host: every unsandboxed command needs approval, and a failed sandbox is reported as a failure.

## Models

The default spec is `ollama:qwen3:32b`. Ollama's native chat API is `http://127.0.0.1:11434`. Override it with `PRAXIS_PRIME_OLLAMA_HOST` or `OLLAMA_HOST`.

Other specs:

| Spec | Provider |
|---|---|
| `ollama:<model>` | Local Ollama |
| `openai-compatible:<model>`, `vllm:<model>`, `llamacpp:<model>` | A server that speaks `/v1/chat/completions` |
| `openai:<model>` | OpenAI |
| `anthropic:<model>` | Anthropic Messages API |
| `xai:<model>` | xAI (OpenAI-compatible) |

Set the base URL for llama.cpp or vLLM with `PRAXIS_PRIME_OPENAI_COMPATIBLE_BASE_URL`. A model name for that server can be `PRAXIS_PRIME_OPENAI_COMPATIBLE_MODEL` (default `local`).

Keys, only in the environment:

- `PRAXIS_PRIME_OPENAI_API_KEY` or `OPENAI_API_KEY`
- `PRAXIS_PRIME_ANTHROPIC_API_KEY` or `ANTHROPIC_API_KEY`
- `PRAXIS_PRIME_XAI_API_KEY` or `XAI_API_KEY`

`praxis-prime config` never writes those values. If the selected provider is down or has no key, the router tries the next entry. A non-local primary falls back to Ollama. A configured OpenAI-compatible base URL is added to the chain. Paid providers are not called unless the spec or `PRAXIS_PRIME_FALLBACK_MODELS` names them.

`PRAXIS_PRIME_MODEL` overrides `models.primary` in the config file. `PRAXIS_PRIME_MAX_ITERATIONS` caps a turn (default 200).

## What the loop guarantees

- The system prompt is a fixed string for the process. The workspace path is a user message, so the prompt can stay cache-stable.
- Each tool call is checked before it runs. Dial hooks are skipped while every dial is off. A dial hook cannot turn an approval into a silent allow.
- Tool output is wrapped in `<<<UNTRUSTED` fences. Text inside a fence is data. The fence markers are escaped so a page cannot close the fence early.
- Sessions, messages, and audit rows are in `prime.db` under the XDG data directory. The audit rows are a SHA-256 chain of tool calls and approvals. Arguments that look like secrets are redacted. Full prompts are not stored in the audit log.

## Daemon

`praxis-primed` hosts the kernel and the gateway on `127.0.0.1:18790`. It refuses any other bind address. HTTP `GET /health` is open. `GET /status` and the approval routes need the bearer token. The token is created at `$XDG_RUNTIME_DIR/praxis-prime/gateway.token` (mode 0600) and is not written to `config.toml` or `gateway.json`. Logs are JSON lines at `$XDG_STATE_HOME/praxis-prime/daemon.log` (or `~/.local/state/praxis-prime/daemon.log`).

```bash
praxis-prime daemon start
praxis-prime daemon status
praxis-prime daemon logs
praxis-prime daemon stop
```

`start` runs `praxis-primed` in the background. `stop` sends SIGTERM and denies pending approvals. Clients speak one protocol: a WebSocket on `/ws` whose first frame is `connect`.

## systemd user service

The same unit works on Ubuntu 22.04+ and on Arch/Omarchy. It does not enable linger, and it does not use distro package managers.

```bash
praxis-prime service install
systemctl --user status praxis-prime.service
praxis-prime service uninstall
```

`install` writes `$XDG_CONFIG_HOME/systemd/user/praxis-prime.service` (or `~/.config/systemd/user/praxis-prime.service`), points `ExecStart` at the `praxis-primed` on `PATH`, reloads the user daemon, and enables the unit. The packaged file in `packaging/systemd/praxis-prime.service` uses `/usr/bin/praxis-primed`. Log in to a user session so `systemd --user` is running. On a machine that should keep the daemon after logout, linger is a separate `loginctl enable-linger` decision; this command does not make it.

## Telegram

Create a bot with [@BotFather](https://t.me/BotFather): `/newbot`, then copy the token. Put it in the environment or in a secrets file. Do not put it in `config.toml`, and do not commit it.

```bash
export PRAXIS_PRIME_TELEGRAM_BOT_TOKEN='paste-from-botfather'
# or
install -m 600 /dev/null "$HOME/.config/praxis-prime/secrets.env"
echo 'PRAXIS_PRIME_TELEGRAM_BOT_TOKEN=paste-from-botfather' >> "$HOME/.config/praxis-prime/secrets.env"
```

`PRAXIS_PRIME_SECRETS_FILE` overrides that path. Start the daemon after the token is set (`daemon start`, or `service install` with the variable in the user environment). Then, on the machine that runs the daemon:

```bash
praxis-prime telegram pair
```

That prints a one-time code. In Telegram, open the bot and send `/pair CODE` within 10 minutes. Only that chat becomes the owner. Other chats are told they are not allowed and are not sent to the model.

Owner messages are untrusted input to the agent. When a tool needs approval, the bot sends a card (action, risk, why) with buttons: Approve, Deny, Always this session. A text reply cannot approve, including `/approve`, "approve", and "always this session". If nobody decides before the TTL, the action is denied.

## Coding mode

`praxis-prime code` runs a repo-aware coding task. It has to be launched inside a git repository (or with `--repo`). The task runs on a new branch named `prime/<slug>` in a git worktree under the XDG data directory (`$XDG_DATA_HOME/praxis-prime/worktrees/`, or `~/.local/share/praxis-prime/worktrees/`). The checkout you started in is not modified until you accept.

```bash
praxis-prime code "add a failing test for the empty cart"
```

Inside `chat`, `/code <task>` does the same thing in this process, including when chat is attached to the daemon. Coding mode does not go through the daemon: the worktree is on this machine.

At the end you get a diff and three choices:

| Choice | Effect |
|---|---|
| accept | Commit on the task branch, if needed, and merge it into the current branch. Nothing is pushed. |
| discard | Delete the worktree and the task branch. |
| keep | Commit on the task branch, if needed, remove the worktree, and leave the branch. Nothing is merged or pushed. |

`--accept`, `--discard`, and `--keep` skip the prompt. With no flag and no terminal, the branch is kept and the checkout is left alone.

`git push`, force operations (`git push --force`, `git push -f`, `git reset --hard`, and similar), and deletes of tracked files always ask, including in `full` mode. Writes outside the task worktree, and writes to instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `.prime/`), also ask. Edits inside the worktree do not.

New tools, on the same approval hook as the rest of the agent:

| Tool | Risk |
|---|---|
| `grep`, `glob` | READ. `grep` uses `rg` when it is on `PATH`. |
| `write_file`, `edit_file` | DRAFT inside the worktree. `edit_file` replaces one exact `old_string`. If that text is missing or matches more than once, the file is not modified. |
| `run_command`, `run_tests` | Same sandbox as `shell`. `run_tests` reads a `test:` line in `AGENTS.md` or `CLAUDE.md`, otherwise a manifest (`pytest`, `npm test`, `make test`, `cargo test`, `go test`). |

### Instruction files

Instructions are read from the checkout you launched in, then appended into the first user message. The system prompt stays fixed. Later text wins. The merged size is capped at 32 KiB and the CLI reports when it truncates.

Precedence, lowest first:

1. Global files in the config directory: `AGENTS.override.md` if it exists, otherwise `AGENTS.md`, then `CLAUDE.md`.
2. Each directory from the git root down to the working directory. In each directory:
   - `AGENTS.override.md`, or `AGENTS.md` when there is no override
   - `CLAUDE.md`, then `.claude/rules/**/*.md`
   - `.cursor/rules/*.mdc` and `*.md`. `alwaysApply: true` rules are included as always-on text. Other rules keep their `globs` and `description` and apply only when those files are in play.
   - `.github/copilot-instructions.md`
   - `.prime/rules/**/*.md`, then `.prime/environment.toml` and `.prime/config.toml`

A directory closer to the working directory outranks the repo root. An override file replaces `AGENTS.md` in that same directory only.

The prompt also gets a short file tree and a keyword search for files that overlap the task. Coding mode does not build an embedding index of the repo. Semantic memory is a separate store; see [MEMORY.md](MEMORY.md).

### Hooks

Project hooks live in `.prime/hooks.toml`. `.prime/hooks` is also read when it is a TOML file or a directory of `*.toml` files. `.claude/settings.json` and `.cursor/hooks.json` are read when they use command hooks.

```toml
[[hook]]
event = "PreToolUse"          # or PostToolUse, or Stop
matcher = "write_file|edit_file"
command = "python3 .prime/hooks/guard.py"
```

`PreToolUse` runs before the tool. Exit code 2 blocks it. Any other non-zero exit blocks too. Exit 0 allows, and a JSON line `{"decision": "deny", "reason": "..."}` or `"ask"` can still tighten that. A hook cannot turn a policy denial into an allow. `Stop` is the on-finish hook.

Hooks run inside bubblewrap when `bwrap` is installed (no network). Without bubblewrap they run with a scrubbed environment. HTTP and MCP hook handlers are not implemented.

## Decision Engine

The engine runs locally. It does not call a hosted decision service. See [DECISION-ENGINE.md](DECISION-ENGINE.md).

```bash
praxis-prime decide "Is this urgent?"
praxis-prime decide "Which team?" --options billing,technical --max-tier 2 --explain
praxis-prime decide feedback dec_0123abcd --correct
praxis-prime decide report
```

`POST /v1/decide` and `POST /v1/systemone` are the same handler. Both need the gateway bearer token.

`decide.prescreen` defaults to false. Turn it on only if you want the engine to auto-deny clearly unsafe commands or to attach an approve/deny recommendation. It will not auto-approve git push, force operations, deletes of tracked files, or writes outside the task worktree. Those still wait on the approval queue, including Telegram.

Every decision is appended to the hash-chained audit log. Dial rules stay quiet while every dial is off.

## Routines

`praxis-primed` runs saved prompts. See [ROUTINES.md](ROUTINES.md).

```bash
praxis-prime routines add --name morning --prompt "Draft the brief." --cron "0 8 * * *"
praxis-prime routines list
praxis-prime routines history
```

Triggers are cron (including `@every`), an interval, a file watch, or `POST /v1/routines/<id>/fire` with the gateway bearer token. The minimum gap is one minute. A missed run is skipped or caught up once (`--missed skip` or `--missed once`). Always-ask actions inside a daemon run wait on the approval queue and on Telegram when the bot is paired. If nobody answers before the TTL, the action is denied. `routines run` from the CLI denies those actions immediately.

## Compliance

Dials stay off until you set one to `monitor` or `enforce` in `config.toml`. Off leaves chat, tools, memory, and model routing as they are. See [COMPLIANCE.md](COMPLIANCE.md). Packs are starter policy, not legal advice.

```bash
praxis-prime compliance status
praxis-prime compliance packs
praxis-prime compliance test "patient MRN AB12345"
praxis-prime compliance report
praxis-prime gdpr export --subject ada@example.com
praxis-prime gdpr erase --subject ada@example.com
praxis-prime breach record --pack state_nc --summary "laptop lost" --affected 3
praxis-prime breach list
```

`monitor` writes an audit warning and does not block. `enforce` may block, ask, redact, or send a protected prompt only to a provider you flagged `local`, `baa`, or `eu_region`. If none of those providers is configured, the model call stops with an explanation. A skill, hook, MCP server, or Decision Engine answer cannot turn enforce off.

Provider flags live under `[models.providers.<name>]` as `local`, `baa`, `eu_region`, and `zero_retention`. Ollama is local without a flag.

## Memory

Profile facts are copied into the prompt. Past sessions become a short episodic summary. `recall` searches with BM25 unless `models.embed` is an Ollama model. See [MEMORY.md](MEMORY.md).

```bash
praxis-prime memory list
praxis-prime memory search "project notes"
praxis-prime memory export
```

Secrets are redacted before a write. HIPAA, FERPA, and GDPR still default to off, and an off dial adds no extra rule.

## Skills

`SKILL.md` folders are discovered from the project, the config directory, `~/.agents/skills`, and the bundled examples. The prompt lists names and descriptions. The body loads when the agent calls `use_skill`. See [SKILLS.md](SKILLS.md).

```bash
praxis-prime skills list
praxis-prime skills show morning-brief
praxis-prime skills install ./some-skill
```

A git URL is cloned only after you confirm it, and only with `git clone --depth 1`. Install does not run scripts.

## MCP

The client connects to stdio and streamable HTTP servers (SSE when the HTTP POST is rejected). Project config is `.prime/mcp.json` with a `mcpServers` object. Tools are named `mcp__<server>__<tool>` and loaded lazily so a large catalog stays out of the prompt. Untrusted write-like tools ask. Stdio children get an env allowlist and bubblewrap when `bwrap` is installed. Every call is audited. Tool output is untrusted. See [MCP.md](MCP.md).

```bash
praxis-prime mcp add notes --command python3 --arg .prime/notes_server.py
praxis-prime mcp list
praxis-prime mcp test notes
praxis-prime mcp tools notes
```

`praxis-prime mcp serve` exposes `decide`, `recall`, and `skills_list` on stdio for other agents. It is off unless you run that command. The daemon does not start it. Bearer tokens for HTTP servers come from the environment or `secrets.env`. Full OAuth 2.1 is not implemented.

## Browser

Headless browsing is optional:

```bash
python -m pip install "praxis-prime[browser]"
python -m playwright install chromium
```

The `browser` tool can navigate, snapshot, click, type, screenshot, extract text, and close. The profile is disposable unless `browser.profile` is `persistent`. Domain allow and deny lists come from config. Form submits, logins, downloads, and purchase pages always ask. Page content is untrusted. Without Playwright, doctor warns and read actions use `web_fetch`. See [BROWSER.md](BROWSER.md).

## Not in this milestone

A coding-mode embedding index of the repo, regulatory dial enforcement beyond redaction and retention windows, the TUI, and the web UI are still stubs. ONNX classifiers, parallel jury calls, nightly recalibration, and the decision eval suites are not in this build. Per-hunk diff review, the `auto` coding classifier, background cloud coding, Ed25519 device pairing, an approval Edit button, and channels other than Telegram are not either. Natural-language cron, FTS5, sqlite-vec, skill security grading, and a skill hub lockfile are later work. Full MCP OAuth 2.1, an MCP security grade, a remote egress proxy, a browser vision loop, and driving the user's signed-in browser are later work too. See [ARCHITECTURE.md](ARCHITECTURE.md) §29 for the rest of the roadmap.
