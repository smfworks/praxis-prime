# Third-party notices

Copyright (c) 2026 SMF Works. Praxis Prime itself is MIT; see LICENSE and NOTICE.

This file is the third-party notice named in the architecture blueprint
(§24, §32). No upstream source is vendored in this pre-alpha skeleton. The
entries below are the attribution record for code and assets that may be
reused later, and the notices that must stay attached if they are.

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
and systemd unit are original code. They follow patterns described in
`docs/ARCHITECTURE.md`: Hermes prompt-cache invariants, OpenClaw's
connect-first gateway and the rule that chat text cannot approve, Praxis
approval classes, and Swarm's hash-chained audit idea. The WebSocket
handshake is the public RFC 6455 framing, written here, not taken from
another project's socket stack. Nothing was vendored. When a file is later
copied:

1. Record the source repo, path, commit, and license in the table below.
2. Keep the original copyright header.
3. If the file is Apache-2.0, keep LICENSE and NOTICE with it.
4. Do not present the upstream author as endorsing Praxis Prime.

## SMF Praxis regulated packs

SMF Works owns SMF Praxis. Release 0.29.0 (2026-07-19) moved regulated
verticals (legal, medical, behavioral health, school, homeschool, forensic)
out of the public wheel into private repositories. Those repositories are not
in this tree, and their current LICENSE files were not available when this
notice was written.

- `packs/regulated/` is a reserved directory. See its README.
- Code released under MIT before 0.29.0, including `hybridagent/vertical_templates.py`
  and `hybridagent/jurisdictions/` in the public Praxis repo, stays MIT for
  recipients of those versions. A later license can cover only new or modified
  pack versions.
- Confirm each private repo's license, and that contributors assigned rights
  to SMF Works, before importing (ARCHITECTURE §32).
- Quoted statutes and other third-party text inside a future pack keep their
  own terms.

`smf-swarm-2.0-fe` is a private commercial vertical and is not used.

## Decision Engine and TypeSafe

The local Decision Engine is Praxis Prime's own code. It is not TypeSafe's
Jev, and it does not call TypeSafe's hosted API. Jev's public request and
response shape is a reference for the future `/v1/decide` route. TypeSafe's
MIT SDKs are optional compatibility clients, not a dependency of this
skeleton. The Jev model weights are proprietary and must not be copied.

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

Judge and classifier weights (Qwen, Phi, ModernBERT, DeBERTa, Llama, Gemma,
and others) are not in this repository. Verify each model's license before
bundling, and download on first run only after the user agrees.

## Copied-file log

Empty on purpose. Append a row when a file is actually added.

| File in this repo | Upstream path | Commit | License | Notices kept |
|---|---|---|---|---|
| — | — | — | — | — |
