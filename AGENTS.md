# Guidance for coding agents

This file is for agents (and people) changing Praxis Prime. Read it before editing. The architecture blueprint wins if this file and the blueprint disagree about a name, path, or default.

## Read first

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the source of truth for layout, package names, ports, XDG paths, and the stack.
- [docs/CAPABILITY-MATRIX.md](docs/CAPABILITY-MATRIX.md) says what is reused, adapted, or new.
- [docs/SOURCE-NOTES.md](docs/SOURCE-NOTES.md) has licenses, pinned commits, and the list of things that are not verified.
- [THIRD_PARTY.md](THIRD_PARTY.md) is the attribution log. Update it in the same change that copies upstream code.

## What this repo is

Praxis Prime is an open-source (MIT), local-first agent for Ubuntu and Omarchy. It is pre-alpha. Most packages are stubs so the tree matches the blueprint. A stub's docstring should name the blueprint section and should not pretend the feature works.

Preferred stack, from ARCHITECTURE §23:

- Python 3.12+, asyncio, later FastAPI and Pydantic v2
- SQLite for state, when state exists
- React and Vite for the SPA, Tauri 2 for the desktop shell
- `uv` or pip, with Hatchling as the build backend

Identifiers:

| Thing | Value |
|---|---|
| Distribution | `praxis-prime` |
| Import package | `praxis_prime` |
| CLI | `praxis-prime`, alias `pprime` |
| Daemon | `praxis-primed` |
| Config | `$XDG_CONFIG_HOME/praxis-prime/` or `~/.config/praxis-prime/` |
| Loopback port | `127.0.0.1:18790` (do not bind it until the gateway exists) |
| Env prefix | `PRAXIS_PRIME_` |

Do not add a `prime` console script. That name collides with other tools.

## Defaults that must stay safe

- Every compliance dial defaults to `off`. The catalog is `praxis_prime.policy.dials`. Adding a dial means adding it there, so `default_positions()` and `praxis-prime config` pick it up. Tests fail if any default is not `off`.
- The baseline approval spine is not a dial and is not something a config key can disable. Do not add `spine = "off"`.
- Jarvis stays disabled in the default config.
- Sandbox network stays `off` in the default config.
- Gateway listen address stays on loopback.
- Do not put secrets, API keys, tokens, or personal data in the repo, in tests, or in the default config. Secrets belong in the OS keychain or `secrets.env.age` (ARCHITECTURE §25).
- `praxis-primed` must not listen until there is an explicit gateway implementation and tests for the bind address.

## Reuse rules

- Do not vendor large upstream trees. Copy a specific module only when a task asks for it, with the upstream copyright header left in place.
- If the file is Apache-2.0, keep its LICENSE and NOTICE beside it and add a row to THIRD_PARTY.md. Known cases are listed in that file (Hermes `plugins/security-guidance/patterns.py`, OpenClaw `skills/skill-creator`, TypeSafe WorkflowEvals).
- Do not copy the private Praxis commercial packs. They are not in this workspace. `packs/regulated/` stays a placeholder until those licenses are confirmed (ARCHITECTURE §32).
- Do not call TypeSafe's hosted API. The Decision Engine is local. Jev is a reference for the response shape, not a dependency.
- SMF Works does not own Hermes, OpenClaw, or Omarchy. Do not write copy that implies those authors ship or endorse Praxis Prime.
- Do not bundle openWakeWord's pre-trained models. Their weights are non-commercial. See THIRD_PARTY.md.
- Invoke bubblewrap, ydotool, and GPL Piper builds as external programs if they are used at all. Do not statically absorb them.

## Where code goes

| Change | Location |
|---|---|
| CLI commands | `packages/prime-core/praxis_prime/cli.py` until `packages/prime-cli/` becomes a real distribution |
| Config and XDG paths | `config.py`, `paths.py` |
| Dial catalog | `policy/dials.py` |
| Kernel features | the matching subpackage under `praxis_prime/` |
| NC pack data | `packs/jurisdictions/nc.py` and, later, `plugins/dials/state_nc/` |
| Desktop shell | `apps/desktop/` |
| Web UI | `ui/` |
| User services | `packaging/systemd/` |
| Tests | `tests/` |

Point new stubs at a blueprint section with a `TODO: ARCHITECTURE §N` line.

The NC pack research has rows marked S or U in SOURCE-NOTES §11. Do not encode those rows as if they were verified. Do not present statute summaries as legal advice.

## Checks

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
praxis-prime --version
praxis-prime doctor
praxis-prime config --config-dir /tmp/praxis-prime-config
```

CI runs `ruff check .` and `pytest` on Ubuntu with Python 3.12. Keep that green.

Style: Python 3.12, type hints, Ruff's default E/F/I/UP/B selection, line length 100. The standard library is enough for the skeleton. Add a dependency only when a real feature needs it.

## Tests worth adding with behavior

- CLI exit codes and help.
- Config defaults, including every dial at `off`, Jarvis disabled, sandbox network off, and a loopback listen address.
- Doctor classification for Ubuntu, Arch, Omarchy, Wayland, and X11. Ollama being down is a warning.
- Any new dial's default position.

Do not mark a test as passed by weakening the assertion that dials default to off.
