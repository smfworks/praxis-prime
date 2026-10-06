# Legacy vertical packs

The six public MIT packs ship as built-in data under `packs/regulated/` and in the wheel at `praxis_prime/_data/packs/regulated`. Installing one copies that data. It does not run pack Python.

| CLI name | Repository | Commit | `pack.json` name |
|---|---|---|---|
| `homeschool` | `smfworks/smf-praxis-homeschool` | `d2adbbf997e14b74854e64552af06832da274868` | `homeschool` |
| `education` | `smfworks/smf-praxis-education` | `421a7f26432315779247913da6c5f5386984b268` | `school_system` |
| `forensic` | `smfworks/smf-praxis-forensic` | `ab1797920350a4f4ae21297da8d9cd3c8c5a3c92` | `forensic` |
| `legal` | `smfworks/smf-praxis-legal` | `afc2340578138de71b9af6dc935dc288cf068fbe` | `law_firm` |
| `medical` | `smfworks/smf-praxis-medical` | `e19290c689156bc3a25de6627058392ba577eb68` | `medical_office` |
| `mbh` | `smfworks/smf-praxis-mbh` | `c3d1cc1d22a38d5d62ff1c71e6b68355ac79611d` | `behavioral_health` |

Upstream still uses the older praxis-agent layout: `pack.json`, `knowledge.md`, and Python modules registered on the `praxis.verticals` entry point. Five upstream manifests pin a model such as `ollama-cloud/…:cloud`. Those keys are removed from the vendored `pack.json`. `SOURCE.toml` keeps the removed value. Homeschool had no model pin. Three upstream repos ship dashboard JavaScript under `web/`. That JavaScript, the CSS, and the pack Python are not in this tree. Porting the modules to Praxis plugins remains a follow-up.

## Commands

```bash
praxis-prime packs list
praxis-prime packs install legal
praxis-prime packs install /path/to/pack-or-repo
praxis-prime packs install https://github.com/smfworks/smf-praxis-legal.git
praxis-prime packs info law_firm
```

`install` accepts a catalog name, a directory, a `.zip`, or a git URL. A bare catalog name (`legal`, `law_firm`, and the other aliases) copies the built-in directory and does not clone git. That name wins over a directory of the same name in the working directory. A path still installs the local folder or zip: `./legal`, a source that starts with `.` or `~`, or any source that contains `/` or `\`. A bare `foo.zip` is a local zip when it is not a catalog name. The audit commit for a built-in pack is the `commit` field in that pack's `SOURCE.toml`, and it must be 40 lowercase hex characters. When `SOURCE.toml` is missing, a symlink, unparsable, or the commit is not that form, `packs install` and `packs info` stop with an error. They do not record this repository's git HEAD. `packs list` does not read that commit. A directory or zip of some other pack still installs as data. A git URL still uses `git clone --depth 1` and does not run pack scripts. A git install has no size limit. Zip archives are capped at 200 members and 15 MiB uncompressed. Files land in `$XDG_DATA_HOME/praxis-prime/vertical-packs/<name>/` (or `--data-dir`). Each install appends an audit event `pack.install` with the repo, version, commit, and license. `packs list` shows the six as built in. `packs info` reads a built-in pack before it is installed.

A source checkout resolves `packs/regulated` and `packs/compliance` only under the repository root. That root is the nearest directory whose `pyproject.toml` is a regular file, not a symlink, and whose `[project] name` is `praxis-prime`. A directory above that root is ignored.

## What is loaded

| Old field | Praxis Prime |
|---|---|
| `systemPrompt` | Persona text stored under the safety preamble. It cannot override that preamble. |
| `knowledge[]` | Read-only pack knowledge, with the source filename kept. |
| `skills[]` | `SKILL.md` files. `description` is the old `trigger`. Namespace `pack/<name>/<skill>`. |
| `tools[]` | An allowlist. `read_file`, `list_dir`, `fetch_url`, `search_web`, `query_knowledge`, and `save_private_note` map to Prime tools. Every other name is listed as unavailable. |
| `riskPolicy` | Recorded rules: dual approval, autonomous classes, egress check, injection check, approval TTL. |
| `complianceMode: enforced` | A suggestion only. Related dials, when known, are suggested at `monitor`. Nothing is written to config. Old `enforced` is not Praxis `enforce`. |
| `theme` | Hex token hints (`accent`, `panel` → `bgRaised`, `ok`, `warn`) and a suggested built-in theme id. Applied to `smf.praxis` (or to that built-in when it is installed) through the theme contrast check. |
| `model`, `provider` | Ignored. Logged as a warning and shown as the author's suggestion. `selected model` stays none. |

## What is refused

- A pack cannot select an LLM or send data to a provider. Hard-coded `model` and `provider` fields are ignored and a warning is logged.
- JavaScript, WASM, and `web/` dashboard CSS or HTML are not copied, loaded, or served. A warning is logged for each file.
- Pack Python is not imported. Declared `praxis.verticals` entry points are recorded and skipped. The allowlist `ALLOWLISTED_ENTRY_POINTS` in `praxis_prime.packs.legacy` is empty, so nothing on that list runs today. If that allowlist is ever non-empty, the import must run inside the sandbox, not in the daemon process.
- The install directory name must be a single segment matching `^[a-z0-9][a-z0-9._-]{0,63}$` (no leading dot). Absolute names, `..`, and `/` or `\\` are refused before anything is created or deleted. If `vertical-packs/<name>` is already a symlink, install refuses it and does not delete the link target. Zip members are extracted one by one under that same containment check. Symlink members are refused.
- `pack.json`, `LICENSE`, `NOTICE`, knowledge files, and other files read or copied from the staged pack must be regular files. A symlink is refused, and the resolved path must stay inside the staged tree. The link target is not read or copied.
- Git URLs that use a remote helper (`ext::` and similar) are refused.

## Compliance TOML packs

Bundled dial packs in `packs/compliance/*.toml` are installed with the wheel at `praxis_prime/_data/packs/compliance` and read with `importlib.resources`. A source checkout reads `packs/compliance` from the repository root described above. The same pack id in `~/.config/praxis-prime/packs` or `<project>/.prime/packs` replaces the bundled file.

## Follow-ups

- Port each vertical's Python modules into Praxis plugins, in the order legal, medical, behavioral health, education, homeschool, forensic. Do not keep `hybridagent` shims in core.
- Enforce the tool allowlist per profile, and apply suggested dials only after an admin confirms them.
- Place the pack persona under the live safety preamble when profiles exist. It is stored on the loaded pack today and is not inserted into the chat prompt.
- Feed pack knowledge into the semantic memory collection when a profile enables the pack.
- Theme hints run through the theme engine. Lightness may move by at most 0.25 in OKLCH. A hint that still misses WCAG 2.2 AA is refused, and the pack still installs. `praxis-prime packs install` writes `pack.<name>` from the `smf.praxis` palette when the hint passes. `install_pack` does not. Choosing `smf.praxis` itself does not apply the hint. The suggested built-ins now ship. Choosing `smf.legal-office`, `smf.forensic`, `smf.education`, or `smf.medical` uses that built-in. The hint is not painted over it.
- Replace dashboard JavaScript with declarative panels rendered by the Praxis UI.
