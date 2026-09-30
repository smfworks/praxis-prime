# Using the agent loop

This is the first running milestone of Praxis Prime. It is a terminal agent, not the full blueprint. The gateway does not listen. Compliance dials still do nothing while they are off.

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

`ask` uses the same prompt when stdin is a terminal. Otherwise it denies the action and continues. A denied tool does not run.

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

## Not in this milestone

The daemon, gateway, Decision Engine, MCP, skills, semantic memory, regulatory dial enforcement, and the web UI are still stubs. See [ARCHITECTURE.md](ARCHITECTURE.md) §29 for the rest of the roadmap.
