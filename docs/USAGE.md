# Using Praxis Prime

This milestone runs the agent loop in a loopback daemon and in the terminal. Compliance dials still do nothing while they are off. The Decision Engine, TUI, and web UI are not in this build.

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

`shell` uses bubblewrap when `bwrap` is installed. The sandbox has no network. If bubblewrap is missing, or it fails to start, the command is not silently run on the host: every unsandboxed command needs approval, and a failed sandbox is reported as a failure.

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

## Not in this milestone

Decision Engine, MCP, skills, semantic memory, regulatory dial enforcement, the TUI, and the web UI are still stubs. Ed25519 device pairing, an approval Edit button, and channels other than Telegram are not in this build. See [ARCHITECTURE.md](ARCHITECTURE.md) §29 for the rest of the roadmap.
