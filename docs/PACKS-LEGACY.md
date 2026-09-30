# Legacy vertical packs

Praxis Prime can install the six public MIT packs without vendoring them and without running their Python.

| CLI name | Repository | `pack.json` name |
|---|---|---|
| `homeschool` | `smfworks/smf-praxis-homeschool` | `homeschool` |
| `education` | `smfworks/smf-praxis-education` | `school_system` |
| `forensic` | `smfworks/smf-praxis-forensic` | `forensic` |
| `legal` | `smfworks/smf-praxis-legal` | `law_firm` |
| `medical` | `smfworks/smf-praxis-medical` | `medical_office` |
| `mbh` | `smfworks/smf-praxis-mbh` | `behavioral_health` |

Those repositories use the older praxis-agent layout: `pack.json`, `knowledge.md`, and Python modules registered on the `praxis.verticals` entry point. Five of them pin a model such as `ollama-cloud/…:cloud`. Three ship dashboard JavaScript under `web/`.

## Commands

```bash
praxis-prime packs list
praxis-prime packs install legal
praxis-prime packs install /path/to/pack-or-repo
praxis-prime packs install https://github.com/smfworks/smf-praxis-legal.git
praxis-prime packs info law_firm
```

`install` accepts a catalog name, a directory, a `.zip`, or a git URL. Git clones use `git clone --depth 1` and do not run pack scripts. A git install has no size limit. Zip archives are capped at 200 members and 15 MiB uncompressed. Files land in `$XDG_DATA_HOME/praxis-prime/vertical-packs/<name>/` (or `--data-dir`). Each install appends an audit event `pack.install` with the repo, version, commit, and license.

## What is loaded

| Old field | Praxis Prime |
|---|---|
| `systemPrompt` | Persona text stored under the safety preamble. It cannot override that preamble. |
| `knowledge[]` | Read-only pack knowledge, with the source filename kept. |
| `skills[]` | `SKILL.md` files. `description` is the old `trigger`. Namespace `pack/<name>/<skill>`. |
| `tools[]` | An allowlist. `read_file`, `list_dir`, `fetch_url`, `search_web`, `query_knowledge`, and `save_private_note` map to Prime tools. Every other name is listed as unavailable. |
| `riskPolicy` | Recorded rules: dual approval, autonomous classes, egress check, injection check, approval TTL. |
| `complianceMode: enforced` | A suggestion only. Related dials, when known, are suggested at `monitor`. Nothing is written to config. Old `enforced` is not Praxis `enforce`. |
| `theme` | Hex token hints (`accent`, `panel` → `bgRaised`, `ok`, `warn`) and a suggested built-in theme id. Not applied yet. |
| `model`, `provider` | Ignored. Logged as a warning and shown as the author's suggestion. `selected model` stays none. |

## What is refused

- A pack cannot select an LLM or send data to a provider. Hard-coded `model` and `provider` fields are ignored and a warning is logged.
- JavaScript, WASM, and `web/` dashboard CSS or HTML are not copied, loaded, or served. A warning is logged for each file.
- Pack Python is not imported. Declared `praxis.verticals` entry points are recorded and skipped. The allowlist `ALLOWLISTED_ENTRY_POINTS` in `praxis_prime.packs.legacy` is empty, so nothing on that list runs today. If that allowlist is ever non-empty, the import must run inside the sandbox, not in the daemon process.
- The install directory name must be a single segment matching `^[a-z0-9][a-z0-9._-]{0,63}$` (no leading dot). Absolute names, `..`, and `/` or `\\` are refused before anything is created or deleted. If `vertical-packs/<name>` is already a symlink, install refuses it and does not delete the link target. Zip members are extracted one by one under that same containment check. Symlink members are refused.
- `pack.json`, `LICENSE`, `NOTICE`, knowledge files, and other files read or copied from the staged pack must be regular files. A symlink is refused, and the resolved path must stay inside the staged tree. The link target is not read or copied.
- Git URLs that use a remote helper (`ext::` and similar) are refused.

## Compliance TOML packs

Bundled dial packs in `packs/compliance/*.toml` are installed with the wheel at `praxis_prime/_data/packs/compliance` and read with `importlib.resources`. A source checkout still reads `packs/compliance` from the repo. The same pack id in `~/.config/praxis-prime/packs` or `<project>/.prime/packs` replaces the bundled file.

## Follow-ups

- Port each vertical's Python modules into Praxis plugins, in the order legal, medical, behavioral health, education, homeschool, forensic. Do not keep `hybridagent` shims in core.
- Enforce the tool allowlist per profile, and apply suggested dials only after an admin confirms them.
- Place the pack persona under the live safety preamble when profiles exist. It is stored on the loaded pack today and is not inserted into the chat prompt.
- Feed pack knowledge into the semantic memory collection when a profile enables the pack.
- Apply theme hints after the theme engine exists, including the contrast check.
- Replace dashboard JavaScript with declarative panels rendered by the Praxis UI.
