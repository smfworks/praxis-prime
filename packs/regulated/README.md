# Regulated packs

The six public MIT verticals ship in this directory as built-in data. They are part of the Praxis Prime wheel, the sdist, and therefore the `.deb` and AUR packages. There is no separate `praxis-prime-packs` package.

`praxis-prime packs install legal` (or `homeschool`, `education`, `forensic`, `medical`, `mbh`, or the `pack.json` name) copies the bundled directory. It does not clone git. Compliance dials stay off. A pack only suggests dials. Nothing here turns on monitor or enforce.

The loader reads `pack.json` and `knowledge.md`. It does not import pack Python or serve dashboard JavaScript. See [docs/PACKS-LEGACY.md](../../docs/PACKS-LEGACY.md).

| CLI name | Repository | Commit | `pack.json` name |
|---|---|---|---|
| `mbh` | `smfworks/smf-praxis-mbh` | `c3d1cc1d22a38d5d62ff1c71e6b68355ac79611d` | `behavioral_health` |
| `medical` | `smfworks/smf-praxis-medical` | `e19290c689156bc3a25de6627058392ba577eb68` | `medical_office` |
| `legal` | `smfworks/smf-praxis-legal` | `afc2340578138de71b9af6dc935dc288cf068fbe` | `law_firm` |
| `education` | `smfworks/smf-praxis-education` | `421a7f26432315779247913da6c5f5386984b268` | `school_system` |
| `homeschool` | `smfworks/smf-praxis-homeschool` | `d2adbbf997e14b74854e64552af06832da274868` | `homeschool` |
| `forensic` | `smfworks/smf-praxis-forensic` | `ab1797920350a4f4ae21297da8d9cd3c8c5a3c92` | `forensic` |

Each pack directory contains `pack.json`, `knowledge.md`, the upstream `LICENSE` and `NOTICE`, and `SOURCE.toml` (repo URL, commit, source path, license, and what was left out). All six are MIT, Copyright (c) 2026 SMF Works.

## What was left out

Upstream `model` pins (`ollama-cloud/…:cloud` on five packs; homeschool had none) are not in the vendored `pack.json`. `SOURCE.toml` records the removed value as `upstream_model_removed`. The user picks the provider during setup. A pack cannot select one. The loader still ignores a `model` or `provider` key if one is present.

These upstream paths were not copied. `SOURCE.toml` lists them per pack:

- Pack Python (`modules/`, `personas/`, `registration.py`, package `__init__.py`). Praxis Prime does not import it. Porting those modules to Praxis plugins remains a follow-up.
- Dashboard files under `web/` (`*.js`, `*.css`) from homeschool, legal, and behavioral health. They are not loaded or served.
- `pyproject.toml`, `scripts/`, `tests/`, and the upstream README. Those are the repository, not pack data.

No `.py`, `.js`, `.mjs`, `.wasm`, `.css`, or `.html` file belongs in this directory.

## License

The `LICENSE` file in this directory covers the directory README. It is MIT, Copyright (c) 2026 SMF Works. Each pack directory keeps the upstream MIT `LICENSE` and `NOTICE`. Copies released under MIT before Praxis 0.29.0 stay MIT for the people who received them. Any further private pack tree stays out of this repository until its license is confirmed (ARCHITECTURE §32). Quoted statutes and other third-party text inside a pack keep their own terms.

Compliance dial TOML still loads from `packs/compliance`, `~/.config/praxis-prime/packs`, and `.prime/packs`.
