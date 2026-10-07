# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The package version is `0.1.0`. There is no git tag and no GitHub release.
Entries below are taken from `git log` on `main` (squash-merge subjects and
bodies) and from the tree. Dates are omitted because nothing has been released.

## [0.1.0] - Unreleased

What is on `main`.

### Added

- Setup asks you to choose a provider from a Local and Cloud list, with Back and Skip, and can point at an OpenAI-compatible model server on your network.

**Core agent loop, router, and terminal chat** ([#2](https://github.com/smfworks/praxis-prime/pull/2))

- Plan, check, act turn with a stable system prompt, approval gating, and fenced tool output.
- Model router with Ollama, OpenAI-compatible, Anthropic, OpenAI, and xAI adapters behind one interface. A later change ([#68](https://github.com/smfworks/praxis-prime/pull/68)) removed the hard-coded provider default.
- Terminal `praxis-prime chat` and `ask`. Sessions and a hash-chained audit log in SQLite under the XDG data directory.

**Daemon, gateway, and Telegram** ([#3](https://github.com/smfworks/praxis-prime/pull/3))

- `praxis-primed` hosts the kernel on a token-authenticated loopback gateway.
- `chat` and `ask` attach when the daemon is healthy. Approvals can be decided from the CLI or a paired Telegram chat.
- A systemd user unit installs on Ubuntu and Arch.

**Coding mode** ([#4](https://github.com/smfworks/praxis-prime/pull/4))

- `praxis-prime code` and `/code` run a task on a `prime/<slug>` branch so the checkout stays unchanged until accept.
- Instruction files, exact edits, sandboxed commands, and push and force gates.

**Decision Engine** ([#5](https://github.com/smfworks/praxis-prime/pull/5))

- Local cascade: rules, a keyword classifier, a router judge, a swarm-role jury, and an optional human tier. No hosted decision API.
- `praxis-prime decide`, `POST /v1/decide`, the decide tool, audit records, and calibration.
- The approval pre-screener cannot auto-approve always-ask actions, and it defaults off.

**Routines, memory, and skills** ([#6](https://github.com/smfworks/praxis-prime/pull/6))

- Saved prompts on cron, interval, file-watch, and webhook triggers.
- Profile, episodic, and semantic memory in SQLite, with redaction and a BM25 fallback.
- `SKILL.md` folders load by name. Git installs stay behind approval.

**MCP client and browser tool** ([#9](https://github.com/smfworks/praxis-prime/pull/9))

- MCP client over stdio and streamable HTTP, with tools gated by the existing approval hook. Optional `praxis-prime mcp serve`.
- Optional Playwright browser tool that falls back to `web_fetch`.

**Compliance dials and packs** ([#1](https://github.com/smfworks/praxis-prime/pull/1), [#10](https://github.com/smfworks/praxis-prime/pull/10), [#12](https://github.com/smfworks/praxis-prime/pull/12))

- Every dial defaults to `off` ([#1](https://github.com/smfworks/praxis-prime/pull/1)). A dial can be `off`, `monitor`, or `enforce` ([#10](https://github.com/smfworks/praxis-prime/pull/10)).
- The policy engine scans tool, model, memory, routine, MCP, browser, and Telegram paths. Starter TOML packs cover HIPAA, FERPA, COPPA, GDPR, thirteen US state laws, PCI, and the North Carolina Identity Theft Protection Act.
- Bundled compliance TOML ships in the wheel and loads through `importlib.resources`. A user or project pack with the same id replaces it. `praxis-prime packs install` reads legacy `pack.json` as data, ignores model pins and dashboard JavaScript, and does not execute pack Python ([#12](https://github.com/smfworks/praxis-prime/pull/12), [#17](https://github.com/smfworks/praxis-prime/pull/17)).

**M1 accounts, roles, and profiles** ([#22](https://github.com/smfworks/praxis-prime/pull/22))

- Local accounts (argon2id), private SQLite sessions, and CSRF. The gateway stays on loopback and checks Host and Origin. One owner; `transfer-owner` hands that role to an existing admin.
- Each profile has its own memory and a tool allowlist enforced before prepare and the approval card. An MCP tool requires both the server and the tool name.
- Follow-ups: [#30](https://github.com/smfworks/praxis-prime/pull/30), [#38](https://github.com/smfworks/praxis-prime/pull/38).

**M1b passkeys and TOTP** ([#45](https://github.com/smfworks/praxis-prime/pull/45))

- WebAuthn passkeys, TOTP, and recovery codes on the loopback daemon. Secrets stay in `accounts.db`.
- Factor changes need a short-lived step-up. The bearer token, CLI, and Telegram approvals are not factor ceremonies.

**M1c per-profile workers** ([#48](https://github.com/smfworks/praxis-prime/pull/48))

- Once profiles exist, `praxis-primed` starts one worker per profile with its own data root, memory, skills, routines, and approval queue.
- Workers authenticate to the supervisor with an HMAC credential derived from a master key they never see.
- Telegram Approve and Deny go to the chat bound to that profile and requester. Once any chat is bound, a decision needs both the profile and the requester.

**M1d web API and web app** ([#57](https://github.com/smfworks/praxis-prime/pull/57), [#58](https://github.com/smfworks/praxis-prime/pull/58))

- Loopback HTTP API for sessions, catalogs, and approvals, with a strict CSP and AG-UI chat events ([#57](https://github.com/smfworks/praxis-prime/pull/57)).
- React web app served by the daemon: sign-in, streaming chat, approval cards, profile switching, and factor management ([#58](https://github.com/smfworks/praxis-prime/pull/58)).

**M1e OIDC** ([#64](https://github.com/smfworks/praxis-prime/pull/64))

- OpenID Connect Authorization Code with PKCE on the loopback daemon. Owner-configured providers. `iss`+`sub` linking sits beside passkeys and password plus TOTP.
- The client secret stays in the secrets file. An OIDC sign-in is one factor and does not satisfy step-up.

**M2 setup wizard** ([#68](https://github.com/smfworks/praxis-prime/pull/68))

- No model provider is selected until `praxis-prime setup` or the web wizard chooses one and a live test passes. Detection, environment keys, and pack hints do not select a provider.
- Owner creation over HTTP works only while no account exists, only from a loopback peer, and only with a single-use first-run token.

**M3 themes** ([#73](https://github.com/smfworks/praxis-prime/pull/73), [#78](https://github.com/smfworks/praxis-prime/pull/78))

- Theme engine: `praxis.theme/v1` packages are checked for contrast, font licences, restricted CSS, SVG, and zip safety, then compiled to a static stylesheet. CLI and gateway install, select, and lock themes. Built-ins `smf.praxis` and High Contrast ([#73](https://github.com/smfworks/praxis-prime/pull/73)).
- Six more themes (Legal Office, Forensic, Education, Classical, Medical, Dental) and an Omarchy adapter ([#78](https://github.com/smfworks/praxis-prime/pull/78)).

**TUI** ([#80](https://github.com/smfworks/praxis-prime/pull/80))

- `praxis-prime tui` is a Textual client for the loopback gateway: chat, timeline, approvals, and the sessions opened in that visit. Nothing is sent until a decision is chosen. `--plain` is a linear transcript.
- Textual is an optional extra. Colours come from the active theme.

**Importer** ([#82](https://github.com/smfworks/praxis-prime/pull/82))

- `praxis-prime migrate --from-praxis` imports Praxis memory, skills, packs, routines, and history. The source database is opened read-only. A second run skips rows already imported. `--dry-run` writes nothing. Secrets stay out unless `--include-secrets` is set. Imported routines stay paused. Regulated dials recorded in the source move from `off` to `monitor`.

**Installers** ([#85](https://github.com/smfworks/praxis-prime/pull/85))

- Local `.deb` builder and a `praxis-prime-git` PKGBUILD. Hash-pinned runtime dependencies, a bubblewrap dependency, license attribution, and the two real systemd user units. Not published to an APT repository or the AUR.

**Omarchy theme template and keybind** ([#86](https://github.com/smfworks/praxis-prime/pull/86))

- `praxis-prime omarchy status`, `install`, and `uninstall` write the shipped theme template and a managed Hyprland bind. Super+Alt+A launches the TUI. Doctor reports that setup on an Omarchy host.

**Built-in regulated packs** ([#87](https://github.com/smfworks/praxis-prime/pull/87), [#88](https://github.com/smfworks/praxis-prime/pull/88))

- The six public MIT SMF Praxis verticals ship as data under `packs/regulated`. `packs install` copies that data and does not clone git. Cloud model pins are removed. Compliance dials stay off ([#87](https://github.com/smfworks/praxis-prime/pull/87)).
- Source lookup stops at the checkout root. A catalog name beats a same-named local directory. A built-in pack whose `SOURCE.toml` commit is missing or not 40 hex characters fails install and info ([#88](https://github.com/smfworks/praxis-prime/pull/88)).

**Documentation**

- Blueprint addendum and the M0–M8 roadmap ([#11](https://github.com/smfworks/praxis-prime/pull/11)).
- OpenDots patterns ([#34](https://github.com/smfworks/praxis-prime/pull/34), [#35](https://github.com/smfworks/praxis-prime/pull/35)) and the OpenClaw/Hermes gap review ([#36](https://github.com/smfworks/praxis-prime/pull/36)).
- Decision Engine, dials, and the M1 split documented as running ([#39](https://github.com/smfworks/praxis-prime/pull/39)).
- SMF attribution kit ([#75](https://github.com/smfworks/praxis-prime/pull/75)) and credits nits ([#77](https://github.com/smfworks/praxis-prime/pull/77)).
- The README shows the hero image at `docs/assets/praxis-prime-hero.jpg`, and this changelog records unreleased `0.1.0`. Status text moves from pre-alpha to alpha (M0–M3 roadmap complete; some blueprint MVP items deferred). The version stays `0.1.0`. There is still no tag and no security-supported release. Dials stay off by default ([#89](https://github.com/smfworks/praxis-prime/pull/89)).

### Security

- Read tools stay inside the workspace unless an absolute path is allowlisted. A shared secret denylist blocks credential files. `web_fetch` re-checks every redirect, including DNS ([#13](https://github.com/smfworks/praxis-prime/pull/13)). Browser fetches use that same guard, and an inode scan that hits its cap fails closed ([#16](https://github.com/smfworks/praxis-prime/pull/16), [#19](https://github.com/smfworks/praxis-prime/pull/19), [#21](https://github.com/smfworks/praxis-prime/pull/21), [#23](https://github.com/smfworks/praxis-prime/pull/23), [#24](https://github.com/smfworks/praxis-prime/pull/24)).
- Shell commands outside a read-only allowlist ask first. Sandboxed deletes fail closed, and the worktree bind stays read-only until a write is approved ([#14](https://github.com/smfworks/praxis-prime/pull/14)). An approved read-shaped command stays on a read-only bind ([#20](https://github.com/smfworks/praxis-prime/pull/20)).
- The shell sandbox masks the account data directory ([#29](https://github.com/smfworks/praxis-prime/pull/29)). Every account-data root is masked, and MCP stdio cwd is not writable unless an approved write scope is set ([#37](https://github.com/smfworks/praxis-prime/pull/37)).
- Migration refuses to run while any process has `prime.db` open ([#28](https://github.com/smfworks/praxis-prime/pull/28)).
- M1a review follow-ups on the data-directory cache, login audit, profile layout, and locks ([#30](https://github.com/smfworks/praxis-prime/pull/30), [#38](https://github.com/smfworks/praxis-prime/pull/38)).
- Pre-M1d follow-ups: step-up tokens are single-use, an unsandboxed MCP host start fails closed when account data exists, session lookups stay inside the caller's profiles, and the socket sweep lock stays private ([#53](https://github.com/smfworks/praxis-prime/pull/53)).
- Dropped the external sandbox runtime dependency. Isolation is the local bubblewrap sandbox, the data-root mask, and the denylist ([#47](https://github.com/smfworks/praxis-prime/pull/47)).
- The test suite isolates `HOME` and the XDG base directories so it does not touch the real data root ([#84](https://github.com/smfworks/praxis-prime/pull/84)).
- Pack install refuses names that escape `vertical-packs`, refuses symlink members, and refuses an install directory that is already a symlink ([#12](https://github.com/smfworks/praxis-prime/pull/12), [#17](https://github.com/smfworks/praxis-prime/pull/17)).
- `bundled_commit()` reads a built-in pack's `SOURCE.toml` with `lstat` and `O_NOFOLLOW`. A symlink is refused even when the earlier `Path.is_symlink` check is raced, and the target's commit is not returned. An installed module whose path contains `site-packages` or `dist-packages` does not use the source-checkout fallback. A `pyproject.toml` above a virtualenv cannot supply `packs/regulated` or `packs/compliance`. The wheel `importlib.resources` path is still tried first ([#89](https://github.com/smfworks/praxis-prime/pull/89)).

## Known limits

- Swarm, voice, and the desktop shell are stubs.
- There is no stable release, no git tag, and no security-supported version.
- Compliance dials default to `off`. The decision pre-screener defaults off.
- Signal, Email (IMAP/SMTP), Slack, Discord, and the generic webhook channel are not built. ARCHITECTURE §12 lists those, with Telegram, as MVP channels. Telegram is the only channel (`praxis_prime/channels/telegram.py`). Routines have a webhook trigger; that is not a webhook channel.
- Decision Engine v0 T1 ONNX classifiers (GLiClass zero-shot / GLiNER PII) are not built. ARCHITECTURE §29 lists them in the MVP row. T1 is a keyword-overlap classifier (`praxis_prime/decide/classifiers.py`).
- Routine delivery by email is not built. ARCHITECTURE §29's MVP row says routines deliver to Telegram/email. Delivery is Telegram only (`praxis_prime/scheduler/runner.py`, [docs/ROUTINES.md](docs/ROUTINES.md)).
