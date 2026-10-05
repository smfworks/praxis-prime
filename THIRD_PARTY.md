# Third-party notices

Copyright (c) 2026 SMF Works. Praxis Prime itself is MIT; see LICENSE and NOTICE.

This file is the third-party notice named in the architecture blueprint
(§24, §32). No upstream source tree is vendored in this pre-alpha skeleton.
The built-in themes ship subset WOFF2 fonts under the SIL Open Font License;
see [Bundled fonts](#bundled-fonts). The entries below are the attribution
record for code and assets that may be reused later, and the notices that
must stay attached if they are.

SMF Works does not own Hermes Agent, OpenClaw, or Omarchy. Reuse is allowed
only under those projects' own licenses. Inclusion here is not an endorsement
by their authors, and Praxis Prime is not a fork of those products.

Research pins (2026-09-29, from docs/SOURCE-NOTES.md). Upstream moves quickly;
re-check the license at the commit you actually copy.

| Project | URL | Pinned commit | License | Owned by |
|---|---|---|---|---|
| Hermes Agent | https://github.com/NousResearch/hermes-agent | `f94fd4d` | MIT, with the Apache-2.0 exception below | Nous Research |
| OpenClaw | https://github.com/openclaw/openclaw | `2d85731` | MIT, with the Apache-2.0 exception below | OpenClaw Foundation, Peter Steinberger, and contributors |
| SMF Praxis | https://github.com/smfworks/smf-praxis | `69121b2` | MIT © 2026 SMF Works | SMF Works |
| SMF Swarm 2.0 | https://github.com/smfworks/smf-swarm-2.0 | `d3ec7f9` | MIT, SMF Works | SMF Works |
| Omarchy | https://github.com/basecamp/omarchy | `8b4eae6` | MIT © David Heinemeier Hansson | David Heinemeier Hansson / Basecamp |

## Apache-2.0 files to keep notices on

These files are Apache-2.0 even though their repositories are otherwise MIT.
If any of them (or a derivative) is added to this repo, keep the original
LICENSE, NOTICE, and copyright header next to the file, and add a row to the
table at the end of this document. Do not drop the Apache notice when moving
the file.

| Origin | Path | License | What to preserve |
|---|---|---|---|
| Hermes Agent (verbatim from `anthropics/claude-plugins-official`) | `plugins/security-guidance/patterns.py` | Apache-2.0 | The file's LICENSE and NOTICE, plus the Apache header |
| OpenClaw | `skills/skill-creator/license.txt` | Apache-2.0 | That license file beside any reused skill-creator material |
| TypeSafe AI `WorkflowEvals` (reference only; not vendored) | upstream repository | Apache-2.0 | Apache LICENSE and NOTICE if the eval harness is ever copied |

Hermes skills that carry their own MIT notices from other authors must keep
those notices too if a skill is reused. Known examples from the blueprint:
humanizer (Siqi Chen), auteur (agiwhitelist), ip-as-logo (s1dashu), ast-grep,
and pr-lens.

OpenClaw's `THIRD_PARTY_NOTICES.md` covers Pi / pi-mono (MIT) and GitHub
Octicons (MIT). Its icons include simple-icons (CC0) and devicon (MIT).
`extensions/typesafe/` has its own MIT license. Preserve those if those
files are copied. The TypeSafe extension talks to a hosted service; Praxis
Prime does not use that service. See the Decision Engine note below.

## What this tree actually contains

No file under this repository is a copy from Hermes, OpenClaw, Omarchy,
TypeSafe, SMF Praxis, or SMF Swarm 2.0. The agent loop, router, tool
registry, audit chain, loopback gateway, approval queue, Telegram adapter,
systemd unit, coding mode, and local Decision Engine are original code.
They follow patterns described in `docs/ARCHITECTURE.md`: Hermes
prompt-cache invariants and the idea of a per-task git worktree (not a
copy of `subagent_worktree.py`), OpenClaw's connect-first gateway and the
rule that chat text cannot approve, Praxis approval classes, Swarm's
hash-chained audit idea, and the public Claude Code hook event names
(`PreToolUse`, exit code 2 blocks). Jury role names Scout, Strategist,
Skeptic, and Forecaster are SMF Swarm 2.0's; the lens text in
`praxis_prime.decide.judges` was written here and was not copied.
The WebSocket handshake is the public RFC 6455 framing, written here, not
taken from another project's socket stack. The MCP client and the optional
stdio server speak the public Model Context Protocol (stdio NDJSON,
streamable HTTP, and the legacy SSE transport) and accept the public
`mcpServers` JSON object used by Claude Code and Cursor. That code was
written here. The official `mcp` Python SDK was not vendored. Playwright
(Apache-2.0) is an optional extra (`praxis-prime[browser]`); its source is
not copied into this tree. The `SKILL.md` parser reads
`name` and `description` frontmatter so a folder written for Claude Code,
Hermes, or OpenClaw still loads. That parser was written here. OpenClaw's
`skills/skill-creator` tree was not copied. Cron matching follows the
public five-field shape, including the Vixie day-of-month / day-of-week
rule, and was also written here. Nothing was vendored. When a
file is later copied:

1. Record the source repo, path, commit, and license in the table below.
2. Keep the original copyright header.
3. If the file is Apache-2.0, keep LICENSE and NOTICE with it.
4. Do not present the upstream author as endorsing Praxis Prime.

## SMF Praxis regulated packs

SMF Works owns SMF Praxis. Release 0.29.0 (2026-07-19) moved regulated
verticals out of the public `praxis-agent` wheel. Six of those verticals are
public MIT repositories. Praxis Prime does not vendor them. `praxis-prime
packs install` reads `pack.json` and `knowledge.md` at install time and does
not copy their Python or dashboard JavaScript into this tree.

| Repository | Distribution | License |
|---|---|---|
| `smfworks/smf-praxis-homeschool` | `praxis-homeschool` | MIT |
| `smfworks/smf-praxis-education` | `praxis-education` | MIT |
| `smfworks/smf-praxis-forensic` | `praxis-forensic` | MIT |
| `smfworks/smf-praxis-legal` | `praxis-legal` | MIT |
| `smfworks/smf-praxis-medical` | `praxis-medical` | MIT |
| `smfworks/smf-praxis-mbh` | `praxis-mbh` | MIT |

- `packs/regulated/` stays empty of their code. See its README and `docs/PACKS-LEGACY.md`.
- Code released under MIT before 0.29.0, including `hybridagent/vertical_templates.py`
  and `hybridagent/jurisdictions/` in the public Praxis repo, stays MIT for
  recipients of those versions.
- Any additional private pack repository is still out of this tree until its
  license is confirmed (ARCHITECTURE §32).
- Quoted statutes and other third-party text inside a pack keep their own terms.

`smf-swarm-2.0-fe` is a private commercial vertical and is not used.

## Decision Engine and TypeSafe

The local Decision Engine is Praxis Prime's own code. It is not TypeSafe's
Jev, and it does not call TypeSafe's hosted API. Jev's public request and
response shape is a reference for `POST /v1/decide` and the `/v1/systemone`
alias. TypeSafe's MIT SDKs are optional compatibility clients, not a
dependency. The Jev model weights are proprietary and must not be copied.
No TypeSafe source is vendored in `praxis_prime.decide`.

## Python packages bundled in the `.deb` and AUR package

The git tree does not vendor these projects as source. The `.deb` and AUR `praxis-prime-git` packages bundle the locked runtime wheels from `uv.lock` (also `packaging/requirements-runtime.txt`) into `/opt/praxis-prime`. Each wheel keeps its own license. Package builds write that inventory to `python-licenses.txt`. Optional `[tui]` packages are not part of that bundle.

| Package | License | Note |
|---|---|---|
| argon2-cffi | MIT | Password hashing for local accounts. Bundled in `/opt/praxis-prime` via locked wheels. The Argon2 reference implementation it binds is CC0 or Apache-2.0. |
| argon2-cffi-bindings | MIT | Transitive dependency of argon2-cffi. Bundled in `/opt/praxis-prime` via locked wheels. |
| cffi | MIT-0 | Transitive dependency of argon2-cffi-bindings and cryptography. Bundled in `/opt/praxis-prime` via locked wheels. |
| pycparser | BSD-3-Clause | Transitive dependency of cffi. Bundled in `/opt/praxis-prime` via locked wheels. |
| webauthn (`duo-labs/py_webauthn`) | BSD-3-Clause | Local WebAuthn registration and authentication. Bundled in `/opt/praxis-prime` via locked wheels. |
| pyotp | MIT | Local TOTP codes (RFC 6238). Bundled in `/opt/praxis-prime` via locked wheels. |
| cryptography | Apache-2.0 OR BSD-3-Clause | AES-GCM for TOTP seeds in `accounts.db`, and the signature checks `webauthn` already needs. `webauthn` 3.0.x requires `cryptography>=49`. Bundled in `/opt/praxis-prime` via locked wheels. |
| joserfc | BSD-3-Clause | JWT and JWKS checks for owner-configured OpenID Connect providers. Bundled in `/opt/praxis-prime` via locked wheels. |
| cbor2 | MIT | Transitive dependency of `webauthn` for CBOR. Bundled in `/opt/praxis-prime` via locked wheels. |
| pyOpenSSL | Apache-2.0 | Transitive dependency of `webauthn` 3.0.x (`pyOpenSSL>=26.3`). Bundled in `/opt/praxis-prime` via locked wheels. |
| pyasn1 | BSD-2-Clause | Transitive dependency of `webauthn` for attestation structures. Bundled in `/opt/praxis-prime` via locked wheels. |
| pyasn1-modules | BSD | Transitive dependency of `webauthn` for ASN.1 modules. Bundled in `/opt/praxis-prime` via locked wheels. |
| typing-extensions | PSF-2.0 | Transitive dependency of pyOpenSSL when Python is older than 3.13. Bundled in `/opt/praxis-prime` via locked wheels on those interpreters. |
| tinycss2 | BSD-3-Clause | CSS parser for the theme `theme.css` allowlist. Bundled in `/opt/praxis-prime` via locked wheels. |
| webencodings | BSD | Transitive dependency of tinycss2. Bundled in `/opt/praxis-prime` via locked wheels. |
| textual | MIT | Optional extra `[tui]` for `praxis-prime tui`. Not shipped in the `.deb` or AUR package. |
| rich | MIT | Optional `[tui]` transitive of textual. Not shipped in the `.deb` or AUR package. |
| markdown-it-py | MIT | Optional `[tui]` transitive of textual (via rich). Not shipped in the `.deb` or AUR package. |
| mdit-py-plugins | MIT | Optional `[tui]` transitive of markdown-it-py. Not shipped in the `.deb` or AUR package. |
| mdurl | MIT | Optional `[tui]` transitive of markdown-it-py. Not shipped in the `.deb` or AUR package. |
| platformdirs | MIT | Optional `[tui]` transitive of textual. Not shipped in the `.deb` or AUR package. |
| linkify-it-py | MIT | Optional `[tui]` transitive of markdown-it-py. Not shipped in the `.deb` or AUR package. |
| pygments | BSD-2-Clause | Optional `[tui]` transitive of rich. Not shipped in the `.deb` or AUR package. |

## Bundled fonts

The built-in themes ship subset WOFF2 files built from the
SIL Open Font License families in the `google/fonts` `ofl/` tree. The SPA
serves them from the theme package. It does not request a font host. Each
package keeps the upstream OFL 1.1 text in `assets/fonts/OFL.txt`. The
theme `LICENSE` is MIT and covers the palette and the package text. The
fonts stay OFL-1.1 and are not relicensed.

| Family | Package file | Copyright | License |
|---|---|---|---|
| Cinzel (variable, weight 400–900) | `praxis_prime/ui_themes/smf.praxis/assets/fonts/Cinzel.woff2` | Copyright 2020 The Cinzel Project Authors (https://github.com/NDISCOVER/Cinzel) | OFL-1.1 |
| Inter (variable) | `praxis_prime/ui_themes/smf.praxis/assets/fonts/Inter.woff2` | Copyright 2020 The Inter Project Authors (https://github.com/rsms/inter) | OFL-1.1 |
| JetBrains Mono (variable) | `…/smf.praxis/assets/fonts/JetBrainsMono.woff2` and `…/smf.high-contrast/assets/fonts/JetBrainsMono.woff2` | Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono) | OFL-1.1 |
| Atkinson Hyperlegible (regular and bold) | `praxis_prime/ui_themes/smf.high-contrast/assets/fonts/AtkinsonHyperlegible-Regular.woff2` and `AtkinsonHyperlegible-Bold.woff2` | Copyright 2020 Braille Institute of America, Inc. | OFL-1.1 |
| Praxis Legal Display Subset (subset of Libre Baskerville, weight 400–700) | `praxis_prime/ui_themes/smf.legal-office/assets/fonts/LibreBaskerville.woff2` | Copyright 2012 The Libre Baskerville Project Authors (https://github.com/impallari/Libre-Baskerville) | OFL-1.1 |
| Praxis Office Sans Subset (subset of Source Sans 3, weight 200–900) | `praxis_prime/ui_themes/smf.legal-office/assets/fonts/SourceSans3.woff2` | © 2023 Adobe (http://www.adobe.com/), with Reserved Font Name ‘Source’ | OFL-1.1 |
| Praxis Office Mono Subset (subset of Source Code Pro, weight 200–900) | `praxis_prime/ui_themes/smf.legal-office/assets/fonts/SourceCodePro.woff2` | © 2023 Adobe (http://www.adobe.com/), with Reserved Font Name ‘Source’ | OFL-1.1 |
| Praxis Forensic Sans Subset (subset of IBM Plex Sans, weight 100–700) | `praxis_prime/ui_themes/smf.forensic/assets/fonts/IBMPlexSans.woff2` | Copyright 2019 IBM Corp. All rights reserved. | OFL-1.1 |
| Praxis Forensic Mono Subset (subset of IBM Plex Mono, regular) | `praxis_prime/ui_themes/smf.forensic/assets/fonts/IBMPlexMono-Regular.woff2` | Copyright 2017 IBM Corp. All rights reserved. | OFL-1.1 |
| Praxis Forensic Mono Subset (subset of IBM Plex Mono, bold) | `praxis_prime/ui_themes/smf.forensic/assets/fonts/IBMPlexMono-Bold.woff2` | Copyright 2017 IBM Corp. All rights reserved. | OFL-1.1 |
| Lexend (variable, weight 100–900) | `praxis_prime/ui_themes/smf.education/assets/fonts/Lexend.woff2` | Copyright 2019 The Lexend Project Authors (https://github.com/googlefonts/lexend) | OFL-1.1 |
| Atkinson Hyperlegible regular | `praxis_prime/ui_themes/smf.education/assets/fonts/AtkinsonHyperlegible-Regular.woff2` | Copyright 2020 Braille Institute of America, Inc. | OFL-1.1 |
| Atkinson Hyperlegible bold | `praxis_prime/ui_themes/smf.education/assets/fonts/AtkinsonHyperlegible-Bold.woff2` | Copyright 2020 Braille Institute of America, Inc. | OFL-1.1 |
| JetBrains Mono (variable) | `praxis_prime/ui_themes/smf.education/assets/fonts/JetBrainsMono.woff2` | Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono) | OFL-1.1 |
| Fraunces (variable, weight 100–900) | `praxis_prime/ui_themes/smf.classical/assets/fonts/Fraunces.woff2` | Copyright 2020 The Fraunces Project Authors (github.com/undercasetype/Fraunces) | OFL-1.1 |
| Praxis Office Sans Subset (subset of Source Sans 3, weight 200–900) | `praxis_prime/ui_themes/smf.classical/assets/fonts/SourceSans3.woff2` | © 2023 Adobe (http://www.adobe.com/), with Reserved Font Name ‘Source’ | OFL-1.1 |
| Praxis Office Mono Subset (subset of Source Code Pro, weight 200–900) | `praxis_prime/ui_themes/smf.classical/assets/fonts/SourceCodePro.woff2` | © 2023 Adobe (http://www.adobe.com/), with Reserved Font Name ‘Source’ | OFL-1.1 |
| Inter (variable) | `praxis_prime/ui_themes/smf.medical/assets/fonts/Inter.woff2` | Copyright 2016 The Inter Project Authors (https://github.com/rsms/inter) | OFL-1.1 |
| JetBrains Mono (variable) | `praxis_prime/ui_themes/smf.medical/assets/fonts/JetBrainsMono.woff2` | Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono) | OFL-1.1 |
| Nunito (variable, weight 200–900) | `praxis_prime/ui_themes/smf.dental/assets/fonts/Nunito.woff2` | Copyright 2014 The Nunito Project Authors (https://github.com/googlefonts/nunito) | OFL-1.1 |
| Figtree (variable, weight 300–900) | `praxis_prime/ui_themes/smf.dental/assets/fonts/Figtree.woff2` | Copyright 2022 The Figtree Project Authors (https://github.com/erikdkennedy/figtree) | OFL-1.1 |
| JetBrains Mono (variable) | `praxis_prime/ui_themes/smf.dental/assets/fonts/JetBrainsMono.woff2` | Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono) | OFL-1.1 |

## Runtime components that are not bundled

These are not shipped here. If a release later vendors source, or if a
packaging script invokes them, honor the license in this table. Prefer
linking or executing them as separate programs when the license requires it.

| Component | License | Packaging note |
|---|---|---|
| Ollama | MIT | Local model host. Doctor only probes `127.0.0.1:11434`. |
| llama.cpp | MIT | Candidate judge backend. |
| faster-whisper, whisper.cpp | MIT | Future local STT. |
| bubblewrap | LGPL-2.0+ | Invoke the system binary. Do not statically absorb it. |
| ydotool | AGPL-3.0 | Optional external binary only. |
| piper1-gpl (`OHF-Voice/piper1-gpl`) | GPL-3.0 | Separate process, or prefer Kokoro. |
| rhasspy/piper | MIT | Fine to use. |
| Kokoro (`hexgrad/kokoro`) | Apache-2.0 | Check model-weight terms separately. Keep the Apache notice if code is copied. |
| sherpa-onnx | Apache-2.0 | Check model licenses. Keep the Apache notice if code is copied. |
| openWakeWord | Apache-2.0 code; pre-trained models CC BY-NC-SA 4.0 | Do not ship the pre-trained models in a commercial build. Train a custom wake word, or use sherpa-onnx models with a verified license. |
| Porcupine | Apache-2.0 engine; Picovoice AccessKey terms | Optional only. |
| SetFit | Apache-2.0 | Keep the Apache notice if code is copied. |
| xdotool | BSD-style | Fine. |
| wtype, grim | MIT | Fine. |
| Playwright (`microsoft/playwright-python`) | Apache-2.0 | Optional extra only. Not vendored. Install with `pip install 'praxis-prime[browser]'`. Browser binaries are a separate download. |

Judge and classifier weights (Qwen, Phi, ModernBERT, DeBERTa, Llama, Gemma,
and others) are not in this repository. Verify each model's license before
bundling, and download on first run only after the user agrees.

## Copied-file log

Append a row when a file is actually added. The font rows are subset WOFF2
files, not the upstream source trees. The OFL text in each package is the
upstream licence, kept beside the fonts.

| File in this repo | Upstream path | Commit | License | Notices kept |
|---|---|---|---|---|
| `praxis_prime/ui_themes/smf.praxis/assets/fonts/Cinzel.woff2` | `google/fonts` `ofl/cinzel` | subset WOFF2, retrieved 2026-10 | OFL-1.1 | `smf.praxis/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.praxis/assets/fonts/Inter.woff2` | `google/fonts` `ofl/inter` | subset WOFF2, retrieved 2026-10 | OFL-1.1 | `smf.praxis/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.praxis/assets/fonts/JetBrainsMono.woff2` | `google/fonts` `ofl/jetbrainsmono` | subset WOFF2, retrieved 2026-10 | OFL-1.1 | `smf.praxis/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.high-contrast/assets/fonts/JetBrainsMono.woff2` | `google/fonts` `ofl/jetbrainsmono` | subset WOFF2, retrieved 2026-10 | OFL-1.1 | `smf.high-contrast/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.high-contrast/assets/fonts/AtkinsonHyperlegible-Regular.woff2` | `google/fonts` `ofl/atkinsonhyperlegible` | subset WOFF2, retrieved 2026-10 | OFL-1.1 | `smf.high-contrast/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.high-contrast/assets/fonts/AtkinsonHyperlegible-Bold.woff2` | `google/fonts` `ofl/atkinsonhyperlegible` | subset WOFF2, retrieved 2026-10 | OFL-1.1 | `smf.high-contrast/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.legal-office/assets/fonts/LibreBaskerville.woff2` | `google/fonts` `ofl/librebaskerville` | Version 2.005; google/fonts b3d4b3ba7c4d54f15ed2be72d7f58b9097c3b252 (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.legal-office/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.legal-office/assets/fonts/SourceSans3.woff2` | `google/fonts` `ofl/sourcesans3` | Version 3.052;hotconv 1.1.0;makeotfexe 2.6.0; google/fonts 914ec116571b1162d886aa402e715552221f0b77 (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.legal-office/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.legal-office/assets/fonts/SourceCodePro.woff2` | `google/fonts` `ofl/sourcecodepro` | Version 1.026;hotconv 1.1.0;makeotfexe 2.6.0; google/fonts bd62bd8b4715f007af6905b0c9fd030f8410b289 (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.legal-office/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.forensic/assets/fonts/IBMPlexSans.woff2` | `google/fonts` `ofl/ibmplexsans` | Version 3.201; google/fonts 0b58fb370093f9a9f4ff785d94405710b79de67c (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.forensic/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.forensic/assets/fonts/IBMPlexMono-Regular.woff2` | `google/fonts` `ofl/ibmplexmono` | Version 2.3; google/fonts 0b58fb370093f9a9f4ff785d94405710b79de67c (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.forensic/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.forensic/assets/fonts/IBMPlexMono-Bold.woff2` | `google/fonts` `ofl/ibmplexmono` | Version 2.3; google/fonts 0b58fb370093f9a9f4ff785d94405710b79de67c (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.forensic/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.education/assets/fonts/Lexend.woff2` | `google/fonts` `ofl/lexend` | Version 1.007; google/fonts e2332cf862ac3145c0ee5f24f04f4c1819b2410b (retrieved 2026-10) | OFL-1.1 | `smf.education/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.education/assets/fonts/AtkinsonHyperlegible-Regular.woff2` | `google/fonts` `ofl/atkinsonhyperlegible` | Version 1.006; ttfautohint (v1.8.3) (retrieved 2026-10) | OFL-1.1 | `smf.education/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.education/assets/fonts/AtkinsonHyperlegible-Bold.woff2` | `google/fonts` `ofl/atkinsonhyperlegible` | Version 1.006; ttfautohint (v1.8.3) (retrieved 2026-10) | OFL-1.1 | `smf.education/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.education/assets/fonts/JetBrainsMono.woff2` | `google/fonts` `ofl/jetbrainsmono` | Version 2.211 (retrieved 2026-10) | OFL-1.1 | `smf.education/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.classical/assets/fonts/Fraunces.woff2` | `google/fonts` `ofl/fraunces` | Version 1.000;[b76b70a41]; google/fonts 4024282d9b0cffcdb8e3024560862746178d741f (retrieved 2026-10) | OFL-1.1 | `smf.classical/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.classical/assets/fonts/SourceSans3.woff2` | `google/fonts` `ofl/sourcesans3` | Version 3.052;hotconv 1.1.0;makeotfexe 2.6.0; google/fonts 914ec116571b1162d886aa402e715552221f0b77 (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.classical/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.classical/assets/fonts/SourceCodePro.woff2` | `google/fonts` `ofl/sourcecodepro` | Version 1.026;hotconv 1.1.0;makeotfexe 2.6.0; google/fonts bd62bd8b4715f007af6905b0c9fd030f8410b289 (retrieved 2026-10); modified subset, renamed per OFL 1.1 section 3 | OFL-1.1 | `smf.classical/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.medical/assets/fonts/Inter.woff2` | `google/fonts` `ofl/inter` | Version 4.001;git-66647c0bb (retrieved 2026-10) | OFL-1.1 | `smf.medical/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.medical/assets/fonts/JetBrainsMono.woff2` | `google/fonts` `ofl/jetbrainsmono` | Version 2.211 (retrieved 2026-10) | OFL-1.1 | `smf.medical/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.dental/assets/fonts/Nunito.woff2` | `google/fonts` `ofl/nunito` | Version 3.602; google/fonts 8b0a1d0f5983c89bc2b93f1b5fb55f9e252744b5 (retrieved 2026-10) | OFL-1.1 | `smf.dental/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.dental/assets/fonts/Figtree.woff2` | `google/fonts` `ofl/figtree` | Version 2.002; google/fonts a60a77e14f28abd4ef243a1b5dfc48df0cec5205 (retrieved 2026-10) | OFL-1.1 | `smf.dental/assets/fonts/OFL.txt` |
| `praxis_prime/ui_themes/smf.dental/assets/fonts/JetBrainsMono.woff2` | `google/fonts` `ofl/jetbrainsmono` | Version 2.211 (retrieved 2026-10) | OFL-1.1 | `smf.dental/assets/fonts/OFL.txt` |
