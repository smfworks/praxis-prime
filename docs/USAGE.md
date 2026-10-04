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

## Accounts and profiles

The first account is the owner. There is no second owner. Admins cover day-to-day management. Passwords are argon2id and are not command arguments:

```bash
praxis-prime account create ada --password-stdin
praxis-prime account create bea --role admin --password-stdin
praxis-prime account list
praxis-prime account passwd ada --password-stdin
praxis-prime account transfer-owner bea
praxis-prime profile create work
praxis-prime profile list
praxis-prime profile assign work --account ada --role operator
praxis-prime profile migrate
```

`transfer-owner` hands the owner role to an existing admin and makes the previous owner an admin. It writes an `auth.owner_transfer` audit event.

Stop the daemon before that first `account create`. It moves an existing single-user `prime.db` into `profiles/default/` and keeps a copy under `data/backups/`. Anything that opens `prime.db` (the daemon, `chat --local`, and the other local commands) takes a shared flock on `prime.db.lock` without waiting, and refuses with `migration in progress` instead of creating a new file at the old path. After the marker exists, those commands open `profiles/default/prime.db`. Opening the old top-level file reports `this database moved to <path> after migration`. Migration takes that flock exclusively before it replaces `.migration.lock`, and refuses, naming the lock file, if it is held. A failure leaves `.migration.lock` in place. The command also refuses while `praxis-primed` is running. `praxis-primed` refuses to start while `.migration.lock` exists and prints that path. A stale lock (empty, garbage, a dead pid, or a reused pid) is cleared by `praxis-prime profile migrate`. A lock whose pid and start time still match a live process needs `praxis-prime profile migrate --force`, which still will not move a database another process has open. If the move is interrupted, `praxis-prime profile migrate` runs it again and is safe to repeat. Later runs see the migration marker and do not copy again. The migrated `default` profile is written with `allow = ["*"]` so the same tools stay available. A profile you create after that starts with an empty allow list, and a missing `profile.toml` allows nothing. An empty `allow` list allows nothing. A profile can only tighten the org tool list and dial floor. Persona text is appended after the fixed safety rules and cannot auto-approve. The gateway stays on `127.0.0.1`. Cookie sessions need the `x-csrf-token` header on changes. `httpx` and `urllib` drop the `Secure` cookie on `http://127.0.0.1`; send the `Cookie` header yourself or use the bearer token. A viewer cannot approve. An auditor gets 403 on `GET /v1/approvals` and can read `GET /v1/approvals/meta` (id, tool, risk, time, decision; no arguments or text) for every profile. Other accounts see meta only for their own profiles. See [SECURITY.md](SECURITY.md).

`account disable USER` disables an account. `account role USER --role admin` changes a server role. Both revoke sessions and tickets. `profile unassign NAME --account USER` removes a membership. The owner is changed only with `account transfer-owner`.

Passkeys and TOTP are optional until you enroll them. A passkey signs in on its own. TOTP, once confirmed, is required after the password, and recovery codes are the one-time fallback. The daemon is still `127.0.0.1:18790`. Enroll a passkey from `http://localhost:18790` (that name and `127.0.0.1` are different passkey identities). The CLI can start TOTP without a browser. It prints the secret and the recovery codes once:

```bash
praxis-prime account totp enroll ada
praxis-prime account totp confirm ada
praxis-prime account factors ada
praxis-prime account passkey list ada
```

`account totp confirm` reads one code from stdin. `account passkey remove USER CREDENTIAL_ID` drops a credential. `account passwd` also deletes that account's passkeys. Those commands append an audit event and do not write the secret into it. Creating a passkey is the daemon's `/v1/auth/passkey/register/*` routes, because that needs a WebAuthn client. The HTTP route also needs a step-up (`POST /v1/auth/step-up` with the password, plus a TOTP or recovery code once TOTP is on, or a passkey assertion at `/v1/auth/step-up/passkey/*`). Each of those changes spends its own step-up token. Passkey enrollment spends one token when the browser requests registration options, and the verify call finishes that ceremony. Confirming TOTP also deletes outstanding step-up rows. `account totp disable` still reads only the password. Logout drops that session's step-up tokens. The loopback bearer token and Telegram Approve/Deny are unchanged: they are not passkey or TOTP checks. See [SECURITY.md](SECURITY.md).

OpenID Connect sits beside those factors. Create the owner with `account create` first. The client secret is one line on stdin and is stored in `secrets.env` (or `PRAXIS_PRIME_SECRETS_FILE`). It is not a command argument. `list` prints the secret's key name, not the value.

```bash
printf '%s\n' "$OIDC_CLIENT_SECRET" | praxis-prime oidc add google \
  --display-name "Google" --client-id "$OIDC_CLIENT_ID" \
  --preset google --client-secret-stdin
printf '%s\n' "$OIDC_CLIENT_SECRET" | praxis-prime oidc add work \
  --display-name "Work" --client-id "$OIDC_CLIENT_ID" \
  --preset entra --tenant contoso.onmicrosoft.com --client-secret-stdin
praxis-prime oidc list
praxis-prime oidc link ada --issuer https://accounts.google.com --subject 123456
praxis-prime oidc remove google
```

Scopes default to `openid email profile` and must include `openid`. `--preset google` uses `https://accounts.google.com`. `--preset entra` needs `--tenant` and uses `https://login.microsoftonline.com/<tenant>/v2.0`, and it maps the `roles` claim `Praxis.Admin`, `Praxis.Operator`, `Praxis.Viewer`, and `Praxis.Auditor` unless you pass `--no-role-map`. `--preset authentik` and `--preset keycloak` need `--issuer`. A fixed preset issuer is rejected when `--issuer` names a different URL. `--dev-loopback` allows an `http://127.0.0.1` or `http://localhost` issuer for a local provider. `--allow-email user@example.com` (repeatable) is the only way a verified email can link or create an account. The address is matched with ASCII lowercasing. Omit it and sign-in requires a pre-linked `iss`+`sub`. An owner or admin is not linked from that list. Running `oidc add` again for an id that already exists exits 2, leaves the stored client secret unchanged, and tells you to `oidc remove` that id before adding it again. `oidc remove` exits 2 and leaves the provider in place when a linked account would lose its last sign-in factor. The sign-in page is `http://127.0.0.1:18790` once `ui/dist` is present. See [SECURITY.md](SECURITY.md).

## Setup

`praxis-prime setup` is the first-run wizard. The web UI uses the same backend. Nothing is preselected. A fresh install has no provider, and chat answers with "No model provider is configured. Run `praxis-prime setup` or open the web UI." If `config.toml` already names a provider that has not passed the setup test, chat names that spec and tells you to run `praxis-prime setup`. Rules and other non-LLM features keep working.

Interactive setup shows the current owner, provider, and dial positions and changes only what you confirm. The owner password and the API key are read without echo. Re-running it does not delete an account, a secret, an OIDC provider, or a Telegram binding. A config write copies `config.toml` to a timestamped mode-0600 backup and keeps the newest five of those files.

Creating the owner from the web UI runs the same profile migration as `praxis-prime setup`, including the backup and `profiles/.migration.json`. A rejected password does not close or move the database. After a successful create, the running daemon reopens `profiles/default` and keeps serving. Restart it when the response says a restart is required. Saving a provider from the web UI reloads that provider in the running daemon, so chat can use it without a restart. The page tells you to restart only when the save response says a restart is required. `llamacpp`, `vllm`, and `lmstudio` are stored in `provider-ready.json` as `openai-compatible:<model>`. An older file that still names `llamacpp:`, `vllm:`, or `lmstudio:` is still accepted. If an existing `prime.db` cannot be moved, the page tells you to stop the daemon and run `praxis-prime setup`. Changing a provider, or its base URL, that is already configured in the browser asks you to confirm the replacement and to sign a step-up (account password, authenticator code, or passkey) before the save. The WebSocket save uses that same step-up. A new base URL needs the replacement confirmed and the API key typed again in that same request.

```bash
praxis-prime setup
praxis-prime setup --section models
praxis-prime setup --section owner
praxis-prime setup --section dials
praxis-prime setup --section oidc
praxis-prime setup --section telegram
praxis-prime setup --web
```

`--section` edits that part only. `--section oidc` points at `praxis-prime oidc add` for the full form. `--section telegram` prints a `/pair` code and does not write the code into `config.toml`. `--web` prints `http://127.0.0.1:<port>/#setup=<token>` while no owner exists. The token is in the URL fragment, so it is not sent as a query string, a log line, or a Referer. After an owner exists, `--web` prints the sign-in URL and does not print a token.

A terminal is required. Without one, the command exits 2 and tells you to pass `--non-interactive`.

```bash
printf '%s\n' "$OWNER_PASSWORD" | praxis-prime setup --non-interactive \
  --owner ada --owner-password-stdin \
  --provider llamacpp --model local-model --base-url http://127.0.0.1:8080
printf '%s\n' "$OPENAI_API_KEY" | praxis-prime setup --non-interactive \
  --provider openai --model gpt-4o --api-key-stdin
PRAXIS_PRIME_OPENAI_API_KEY="$OPENAI_API_KEY" praxis-prime setup --non-interactive \
  --provider openai --model gpt-4o --api-key-env PRAXIS_PRIME_OPENAI_API_KEY
praxis-prime setup --non-interactive --provider skip
```

The key is read from stdin or from the named environment variable. It is not a command argument. Exit 0 means the choice was saved. An explicit `--provider skip` exits 0 and leaves inference not ready. Exit 1 means the live test failed. Exit 2 means the command was used wrong, the terminal was missing, or an existing provider would have been replaced. `--replace` is required to change an existing provider or key. `--skip-test` is refused and cannot mark a provider ready.

The lanes are "On this computer" (a detected server or a URL you type), "On my network" (a base URL, an optional key, and a TLS fingerprint for a self-signed certificate), "Cloud provider" (`openai`, `anthropic`, `xai`, or `openai-compatible`), and "Skip for now". The primary model is required. Utility, vision, and the Decision Engine judge are optional. The test is one completion and one tool call against only the provider you named, plus a context-length check when the server reports one. Below 32768 tokens is a warning. Below 16384, agent mode stays off and the provider is not marked ready.

When HIPAA, FERPA, COPPA, GDPR, or PCI is `monitor` or `enforce`, a cloud choice shows "Requires a BAA/DPA with the provider; PHI will leave this machine". The dials step shows the current positions. The default is all off, and a blank answer leaves them as they are. `models.allow_providers` is an org allowlist. An empty list allows every provider. A non-empty list refuses a save outside it.

With no owner, the web UI shows the wizard instead of the sign-in form. Open it from the `--web` URL so the page can read the fragment. After an owner exists, an owner or admin sees "Setup needed" with the missing items and a link to each step. Other roles see only "Inference not configured".

## Models

There is no default spec. Ollama's native chat API, when you choose it, is `http://127.0.0.1:11434`. Override that host with `PRAXIS_PRIME_OLLAMA_HOST` or `OLLAMA_HOST`. Those variables do not select Ollama.

Other specs:

| Spec | Provider |
|---|---|
| `ollama:<model>` | Local Ollama |
| `openai-compatible:<model>`, `vllm:<model>`, `llamacpp:<model>` | A server that speaks `/v1/chat/completions` |
| `openai:<model>` | OpenAI |
| `anthropic:<model>` | Anthropic Messages API |
| `xai:<model>` | xAI (OpenAI-compatible) |

Set the base URL for llama.cpp, vLLM, or LM Studio with `PRAXIS_PRIME_OPENAI_COMPATIBLE_BASE_URL` or in setup. `lmstudio:<model>` is the same OpenAI-compatible lane. A model name for that server can be `PRAXIS_PRIME_OPENAI_COMPATIBLE_MODEL`. It is empty until you set it. Example specs such as `ollama:qwen3:8b` are examples, not defaults.

Keys, in the environment or in the mode-0600 secrets file (`secrets.env` beside `config.toml`, or `PRAXIS_PRIME_SECRETS_FILE`):

- `PRAXIS_PRIME_OPENAI_API_KEY` or `OPENAI_API_KEY`
- `PRAXIS_PRIME_ANTHROPIC_API_KEY` or `ANTHROPIC_API_KEY`
- `PRAXIS_PRIME_XAI_API_KEY` or `XAI_API_KEY`

`praxis-prime config` never writes those values. Setup writes them only to the secrets file. If the selected provider is down, the router does not switch to another provider. A fallback runs only when that spec is listed in `PRAXIS_PRIME_FALLBACK_MODELS` or `models.fallback` and that spec has passed its own test. Paid providers are not called unless the spec names them. `PRAXIS_PRIME_MODEL` overrides `models.primary` for this process. It still has to have passed a test before chat will call it. `PRAXIS_PRIME_MAX_ITERATIONS` caps a turn (default 200).

## What the loop guarantees

- The system prompt is a fixed string for the process. The workspace path is a user message, so the prompt can stay cache-stable.
- Each tool call is checked before it runs. Dial hooks are skipped while every dial is off. A dial hook cannot turn an approval into a silent allow.
- Tool output is wrapped in `<<<UNTRUSTED` fences. Text inside a fence is data. The fence markers are escaped so a page cannot close the fence early.
- Sessions, messages, and audit rows are in `prime.db` under the XDG data directory. The audit rows are a SHA-256 chain of tool calls and approvals. Arguments that look like secrets are redacted. Full prompts are not stored in the audit log.

## Daemon

`praxis-primed` hosts the kernel and the gateway on `127.0.0.1:18790`. It refuses any other bind address. HTTP `GET /health` is open. `GET /status` and the approval routes need the bearer token. The token is created at `$XDG_RUNTIME_DIR/praxis-prime/gateway.token` (mode 0600) and is not written to `config.toml` or `gateway.json`. Once an account exists, that token is an owner-equivalent credential. Rotate it with `praxis-prime daemon rotate-token` (the file is replaced atomically), then restart the daemon. Set `gateway.bearer = false` and restart to refuse the token after an account exists. Cookie sessions still work. Logs are JSON lines at `$XDG_STATE_HOME/praxis-prime/daemon.log` (or `~/.local/state/praxis-prime/daemon.log`).

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

## Themes

A theme changes colours, type, and a few decorative hooks. It does not add controls, run code, or call the network.

Eight themes ship in the wheel. All of them pass WCAG 2.2 AA in both modes. `smf.high-contrast` is AAA. Fonts are subset WOFF2 files under the SIL Open Font License, stored in each package with `assets/fonts/OFL.txt`. The page does not request a font host.

| Id | Name | Type |
|---|---|---|
| `smf.praxis` | Praxis | Cinzel, Inter, JetBrains Mono. The default. |
| `smf.high-contrast` | High Contrast | Atkinson Hyperlegible and JetBrains Mono. AAA. |
| `smf.legal-office` | Legal Office | Praxis Legal Display Subset, Praxis Office Sans Subset, Praxis Office Mono Subset. Burgundy is danger only. |
| `smf.forensic` | Forensic Engineering | Praxis Forensic Sans Subset and Praxis Forensic Mono Subset. A faint grid. |
| `smf.education` | Education | Lexend, Atkinson Hyperlegible, JetBrains Mono. Base size 17. |
| `smf.classical` | Classical | Fraunces, Praxis Office Sans Subset, Praxis Office Mono Subset. Dark is the default. |
| `smf.medical` | Medical Office | Inter and JetBrains Mono. Motion is off. No ornaments. |
| `smf.dental` | Dental Office | Nunito, Figtree, JetBrains Mono. Radius 12. |

How to write a package is in [THEME-AUTHORING.md](THEME-AUTHORING.md).

```bash
praxis-prime theme list
praxis-prime theme lint ./my-theme
praxis-prime theme lint ./my-theme --json
praxis-prime theme pack ./my-theme
praxis-prime theme install ./my-theme-1.0.0.praxis-theme.zip
praxis-prime theme set smf.high-contrast --mode dark --profile default
praxis-prime theme set omarchy --profile default
praxis-prime theme set smf.praxis --lock --mode light
praxis-prime theme set --unlock
praxis-prime theme remove lab.sample
```

`theme pack` writes `<id>-<version>.praxis-theme.zip` in the current directory, or at `-o`. `theme lint --json` prints `{"ok": true, "id", "version", "contrast"}` or `{"ok": false, "error": {"code": "theme_invalid", "message", "issues"}}`. Each issue has `code`, `message`, `path`, and `fix`.

Install writes `theme.lock.json` beside the package. The lock lists the SHA-256 of every file and a package hash. The lock file itself is outside that hash. Loading and serving a user or system theme checks those hashes. A mismatch is skipped on the list, and the stylesheet URL is 404. Built-ins are read from the wheel at `praxis_prime/ui_themes` with `importlib.resources` and have no lock file. User themes go in `$XDG_DATA_HOME/praxis-prime/themes/<id>/<version>/` (or `--data-dir`). `--system` on `install` and `remove` uses `/var/lib/praxis-prime/themes`. The same id resolves user, then system, then built-in, except `smf`, `smf.*`, and `omarchy.live`, which cannot be installed. `smf` and `smf.*` stay the built-in. `omarchy.live` is reserved for the in-memory Omarchy stylesheet. Inside one source the highest `MAJOR.MINOR.PATCH` wins. A built-in cannot be removed.

Selection order is the admin lock, then the profile choice, then `smf.praxis`. `--mode system` follows `prefers-color-scheme` in the stylesheet. A lock also sets the mode when the lock names one. Device preference is a mode, not a theme id. System (Omarchy) is a profile choice (`theme set omarchy`), not a package. It applies only when that profile chose it and `~/.local/state/omarchy/current/theme/praxis-prime.json` compiles. `XDG_STATE_HOME` is honoured. `PRAXIS_PRIME_OMARCHY_THEME` overrides the path for a test. The file is untrusted. A palette that cannot pass WCAG 2.2 AA is logged and the page paints `smf.praxis`, while Appearance still shows System (Omarchy). A colour in that file is `#rgb` or `#rrggbb`. Eight-digit hex is refused. A parse failure is cached by the file inode, mtime, and size and the parent directory inode, and the page still paints `smf.praxis`. `GET /themes/omarchy.live/<hash>.css` opens the file only when some profile's stored choice is `omarchy`. Otherwise that route is 404 and the file is not opened. An unset profile stays on the lock or on `smf.praxis`. `omarchy` and `omarchy.live` cannot be locked. A later rewrite of a palette that already compiled appends `theme.activate` when `prime.db` exists. While System (Omarchy) is selected, the page asks for the active theme every 2 seconds and swaps the stylesheet when the file changes.

The CLI writes the data directory the same way `packs install` does. Account roles are enforced by the daemon. `theme install` and `theme set` (including `--lock`) append `theme.install` and `theme.activate` when that runtime's `prime.db` already exists. `theme remove` appends `theme.remove` for each removed version, with `id`, `version`, and `packageHash`. A missing database is left uncreated.

In the web UI, open Settings → Appearance. The page lists themes and sets light, dark, or system. An owner or admin can install a `.zip` (the file is checked, then you confirm Install), remove a user or system theme, and lock or unlock the theme for every profile. An owner or admin can set any profile. An operator can set a profile where their membership is owner or operator. A viewer or an auditor cannot change the theme. While a lock is set, a non-admin select is refused.

A legacy pack `theme` hint (`accent`, `panel` as `bgRaised`, `ok`, `warn`) is checked against `smf.praxis`. Lightness may move by at most 0.25 in OKLCH so each pair clears WCAG 2.2 AA. Past that the hint is refused and the pack still installs. `praxis-prime packs install` writes `pack.<name>` from that palette when the hint passes. Choosing `smf.praxis` itself leaves the hint off. Choosing a suggested built-in (`smf.legal-office`, `smf.forensic`, `smf.education`, or `smf.medical`) uses that built-in. The hint is not painted over it. See [PACKS-LEGACY.md](PACKS-LEGACY.md).

The package schema is `praxis.theme/v1`, published at `schemas/theme.v1.json`. Optional `theme.css` may set `--pp-*` custom properties on `:root` and `[data-mode]`, plus the decorative hooks `.pp-ornament-*`, `.pp-header-band`, `.pp-sidebar-texture`, and `.pp-divider`. The validator folds those custom properties into the token maps. The served stylesheet uses the compiled values for light, dark, system-light, and system-dark, and does not replay the author `:root` rules. The validator rejects `@import`, remote `url()`, scripts, rules aimed at approval, dial, or audit controls, and decorative lengths outside about 16px. Package paths are `assets/fonts/<name>.woff2` and `assets/ornaments/<name>.svg` (or png or webp), with a name of letters, digits, `.`, `_`, and `-`, plus exactly `assets/preview.png` or `assets/preview.webp`. Both modes are checked for contrast before install, and the served CSS resolves to those same colours.

## Browser

Headless browsing is optional:

```bash
python -m pip install "praxis-prime[browser]"
python -m playwright install chromium
```

The `browser` tool can navigate, snapshot, click, type, screenshot, extract text, and close. The profile is disposable unless `browser.profile` is `persistent`. Domain allow and deny lists come from config. Form submits, logins, downloads, and purchase pages always ask. Page content is untrusted. Without Playwright, doctor warns and read actions use `web_fetch`. See [BROWSER.md](BROWSER.md).

## Not in this milestone

A coding-mode embedding index of the repo, regulatory dial enforcement beyond redaction and retention windows, and the TUI are still stubs. The loopback page in `ui/dist` covers password, TOTP, configured OIDC providers, chat, and Settings → Appearance. The chat client in `ui/src` streams a turn over the gateway WebSocket. ONNX classifiers, parallel jury calls, nightly recalibration, and the decision eval suites are not in this build. Per-hunk diff review, the `auto` coding classifier, background cloud coding, Ed25519 device pairing, an approval Edit button, and channels other than Telegram are not either. Natural-language cron, FTS5, sqlite-vec, skill security grading, and a skill hub lockfile are later work. Full MCP OAuth 2.1, an MCP security grade, a remote egress proxy, a browser vision loop, and driving the user's signed-in browser are later work too. See [ARCHITECTURE.md](ARCHITECTURE.md) §29 for the rest of the roadmap.
