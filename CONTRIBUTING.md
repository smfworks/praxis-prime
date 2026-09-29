# Contributing to Praxis Prime

Thanks for looking. Praxis Prime is **pre-alpha**. The useful surface today is the CLI skeleton, the dial catalog, and the docs. Feature work should follow [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [AGENTS.md](AGENTS.md).

## Setup

Python 3.12 or newer.

```bash
git clone https://github.com/smfworks/praxis-prime.git
cd praxis-prime
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

With [uv](https://docs.astral.sh/uv/):

```bash
uv venv
uv pip install -e ".[dev]"
```

## Checks

```bash
ruff check .
pytest
praxis-prime --version
pprime doctor
praxis-prime config --config-dir "${TMPDIR:-/tmp}/praxis-prime-config"
```

GitHub Actions runs Ruff and pytest on Ubuntu. Please run them locally before opening a pull request.

## Pull requests

Use the pull request template. Say which blueprint section you are implementing. Keep the change focused.

A few rules that protect users of a local agent:

- New compliance dials default to `off`.
- Do not commit secrets, tokens, or private transcripts.
- Do not vendor Hermes, OpenClaw, Omarchy, or the private Praxis packs in a drive-by change. If you copy a file, keep its license notice and update [THIRD_PARTY.md](THIRD_PARTY.md).
- Do not add a `prime` command name.
- The daemon must not bind a public address. The planned listen address is `127.0.0.1:18790`.

## Code of conduct

This project uses the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md). Please report vulnerabilities privately.
