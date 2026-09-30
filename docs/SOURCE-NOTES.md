# Source Notes — findings, licenses, file paths, reuse plan, unverified items

> Companion to `ARCHITECTURE.md` and `CAPABILITY-MATRIX.md` for **Praxis Prime**, the flagship evolution of SMF Praxis. Research done 2026-09-29 and revised the same day for Michael's decisions: the name, an own local Decision Engine instead of hosted Jev, the first dials plus the NC pack, and bundling the Praxis packs. All times are ET.
> Clones live in `/workspace/agent-arch/src/`. The notes reflect the commits listed below; upstream projects move quickly.
> **Ownership:** SMF Works authored **SMF Praxis** and **SMF Swarm 2.0** only. Hermes Agent belongs to Nous Research, OpenClaw to the OpenClaw Foundation / Peter Steinberger and contributors, Omarchy to David Heinemeier Hansson / Basecamp, and Jev to TypeSafe AI.

| Repo | URL | Commit | Commit time (ET) | License |
|---|---|---|---|---|
| Hermes Agent | https://github.com/NousResearch/hermes-agent | `f94fd4d` | 2026-09-29 16:57 | MIT © 2025 Nous Research |
| OpenClaw | https://github.com/openclaw/openclaw | `2d85731` | 2026-09-29 17:00 | MIT © 2026 OpenClaw Foundation |
| SMF Praxis | https://github.com/smfworks/smf-praxis | `69121b2` | 2026-08-16 06:30 | MIT © 2026 SMF Works |
| SMF Swarm 2.0 | https://github.com/smfworks/smf-swarm-2.0 | `d3ec7f9` | 2026-09-03 13:28 | MIT (SMF Works), v0.5.2 |
| Omarchy (integration target) | https://github.com/basecamp/omarchy | `8b4eae6` | 2026-09-29 13:44 | MIT © David Heinemeier Hansson (4.0.0.alpha) |

---

## 1. Hermes Agent (Nous Research)

**License details**
- The root license is MIT.
- **Exception:** `plugins/security-guidance/patterns.py` is **Apache-2.0**, a verbatim copy from `anthropics/claude-plugins-official`, shipped with its NOTICE and LICENSE files.
- Several skills carry **their own MIT licenses from other authors** (for example humanizer — Siqi Chen; auteur — agiwhitelist; ip-as-logo — s1dashu; ast-grep; pr-lens). Keep those notices if any are reused.

**Stack**
- Python `>=3.11,<3.15` (about 2,380 non-test `.py` files), managed with `uv`.
- Electron desktop at `apps/desktop` (React/Vite, nanostores).
- Ink (React) TUI at `ui-tui/` with a JSON-RPC backend in `tui_gateway/`.
- FastAPI dashboard (`hermes_cli/web_routers/`, `web/`).
- ACP adapter at `acp_adapter/`.
- About 39k tests.

**Key paths**

| Area | Paths | Notes |
|---|---|---|
| Agent loop | `run_agent.py` (AIAgent facade), `agent/conversation_loop.py::run_conversation`, `agent/turn_*.py` | Synchronous; OpenAI message format; `max_iterations` default 500. Invariants: byte-stable system prompt, strict role alternation, compression is the only cache break. |
| Architecture principle | — | "Narrow waist core, capability at edges" with the **Footprint Ladder**: extend → CLI + skill → `check_fn` tool → plugin → MCP → core tool. |
| Tools | `tools/registry.py` (auto-register), `model_tools.py`, `toolsets.py` | Terminal backends in `tools/environments/`: local, docker, ssh, singularity, modal, daytona, vercel_sandbox. |
| Providers | `plugins/model-providers/`, `agent/auxiliary_client.py` | The auxiliary client handles side-LLM tasks. |
| MCP | `tools/mcp_tool*.py` (client + OAuth), `mcp_serve.py` (server) | |
| Skills | `skills/`, `optional-skills/`, `tools/skills_hub*.py` (ClawHub + GitHub sources), skills guard/linter, `agent/curator.py` | SKILL.md + YAML frontmatter, agentskills.io-compatible. |
| Memory | memory tool + user profile (char limits, nudge every ~10 turns); `hermes_state*.py` SessionDB with SQLite FTS5; `plugins/memory/` (holographic, honcho, mem0, supermemory, byterover, openviking, retaindb) | |
| Cron | `cron/jobs.py`, `cron/scheduler.py` | Delivery to any platform. |
| Delegation | `tools/delegate_tool*.py` | `max_concurrent_children` 10, `MAX_DEPTH` 1 (configurable `max_spawn_depth`). Also `subagent_worktree.py` and kanban (`hermes_cli/kanban*.py`). |
| Gateway | `gateway/run.py`, `plugins/platforms/*`, `gateway/platforms/signal.py` | Adapters: Telegram, Discord, Slack, WhatsApp, Signal, email, SMS, Matrix, Mattermost, Teams, Home Assistant, IRC, Google Chat, A2A, ntfy and more. Also an `api_server` with OpenAI routes, and webhooks. |
| Approvals / security | `tools/approval*.py`, `tools/approval_smart.py`, `tools/threat_patterns.py`, `path_security.py`, `url_safety.py`, `agent/vault_store.py` | Smart approval uses an auxiliary-LLM reviewer "inspired by Codex Smart Approvals" that strips comments and fences the command as untrusted. Optional tirith pre-exec scan. `protected_instruction_files`: AGENTS.md, CLAUDE.md and SOUL.md writes always need approval, even under `--yolo`. |
| Voice | `tools/wake_word*.py`, `voice_mode.py`, `voice_live.py` | Wake word via openWakeWord, sherpa-onnx KWS or Porcupine. STT via faster-whisper. TTS via Piper or NeuTTS. |
| Computer use | `tools/computer_use/`, browser tool (CDP / Camofox / Lightpanda), `homeassistant_tool.py` | The cua-driver backend docstring calls Linux support "future". |
| Observability | Langfuse plugin | |
| Config | `~/.hermes/config.yaml`, `.env` (secrets only), profiles | |
| Omarchy | desktop HUD floated and pinned via Hyprland IPC; `--ozone-platform=wayland`; seeded interactive `-q` mode for Omarchy prompted-agent launches (basecamp/omarchy#8705) | Omarchy ships `omarchy-theme-set-hermes` and `default/themed/hermes.yaml.tpl`. |

**Reuse plan:** R = reuse code, A = adapt the pattern.
- R: channel adapters, voice/wake-word modules, Home Assistant tool, memory-provider contract, skills loader + guard, smart-approval prompt design.
- A: loop invariants, Footprint Ladder, tool registry/toolsets, cron, delegation caps, worktrees, kanban, ACP.

**Unverified or caveats**
- The Linux computer-use backend is marked "future".
- Hermes is Python but its desktop is Electron. Praxis Prime chooses Tauri, so the desktop code won't be reused.

## 2. OpenClaw (OpenClaw Foundation, a 501(c)(3); created by Peter Steinberger and community)

**License details**
- The root license is MIT.
- `THIRD_PARTY_NOTICES.md` covers Pi / pi-mono (MIT) and GitHub Octicons (MIT).
- `skills/skill-creator/license.txt` is **Apache-2.0**.
- Icons: simple-icons (CC0) and devicon (MIT).
- `extensions/typesafe/` has its own MIT LICENSE.

**Stack**
- TypeScript on Node `>=24.16` or `>=26.1`, a pnpm monorepo (about 23k `.ts` files). Vite Control UI in `ui/`.
- Rust crates `openclaw-gateway-client` and `openclaw-node-host`.
- Swift for macOS/iOS; an Android app.
- **Linux app: Tauri v2** at `apps/linux` (`src-tauri`), built on Ubuntu 22.04 (glibc 2.35 floor) as .deb and AppImage, with a signed AppImage self-updater and tray.

**Key paths and findings**

| Area | Paths | Notes |
|---|---|---|
| Gateway | `docs/gateway/*`, protocol | Single daemon at WebSocket `127.0.0.1:18789`. TypeBox → JSON Schema typed frames. The first frame must be `connect`. Signed-challenge device pairing, idempotency keys, nodes with `role: node` declaring caps and commands. Canvas / A2UI at `/__openclaw__/canvas/`. |
| Agent loop | `docs/concepts/*`, `openclaw-agent-runtime.md` | Serialized per-session lane plus a global lane. Queue modes: steer / followup / collect / interrupt. Writer-claim fencing on the SQLite transcript. |
| Plugin hooks | — | `before_model_resolve`, `before_prompt_build`, `before_tool_call` / `after_tool_call`, `agent_end`, compaction hooks. |
| Permission modes | `docs/gateway/permission-modes.md` | **read-only / guarded** (human) **/ workspace** (LLM reviewer allow/deny/ask; 3 denials escalate to a human) **/ full**. Approval cards in channels, or `/approve <id> allow-once|deny`. A free-text "yes" never authorizes. |
| Sandboxing | — | Off by default. Backends: Docker, Podman, SSH, OpenShell, Crabbox. |
| Multi-agent | `docs/concepts/parallel-specialist-lanes.md` | Isolated agents (workspace, agentDir, SQLite) bound to channels. `openclaw agents team create` gives coordinator / researcher / writer / reviewer lanes. |
| Automation | `docs/automation/cron-jobs.md`, `standing-orders.md`, `/gateway/heartbeat` | Cron jobs, standing orders, **heartbeat** (periodic main-session turns). |
| Extensions (173) | `extensions/*` | Channels (Telegram, Slack, Discord, Signal, WhatsApp, Matrix, MS Teams, iMessage…), providers (Ollama, llama-cpp, vLLM, SGLang, LM Studio, OpenAI, Anthropic, xAI…), memory-core / lancedb / wiki / active-memory, cua-computer, **linux-node** (notify-send, camera via FFmpeg, GeoClue location), talk-voice (voice selection only), tts-local-cli, voice-call (Twilio/Telnyx/Plivo phone calls), azure-speech, onnx, **typesafe**, vault, onepassword, diagnostics-otel / prometheus, migrate-hermes / migrate-claude. |
| Decision models | `docs/concepts/decision-models.md`, `extensions/typesafe/`, `extensions/onnx` | A `decisionModel` role separate from primary and `utilityModel`. Core tool `decision_evaluate` (choice, score, boolean via `probabilityTrue`). Providers `typesafe/jev-latest`, `typesafe/jev-1.13.0`, **`typesafe/kev-latest`** (local server at a loopback `baseUrl`, e.g. `127.0.0.1:8009`), and ONNX (DeBERTa-v3 zero-shot, GLiClass base/edge/instruct, GLiNER 2.5). No automatic fallback to a chat model; automatic consumers sit behind a Labs opt-in. Added after release 2026.9.5. |
| Wake word | swabble | A macOS-only Speech.framework daemon (MIT). |
| Omarchy plugin | `apps/linux/omarchy/` | Quickshell QML `Panel.qml` / `Service.qml`, `bridge.py` (calls `openclaw gateway call`), `manifest.json` (kinds: service, bar-widget), `install.sh` (`omarchy plugin validate/enable`, `omarchy-shell shell rescanPlugins`). |
| Vision | `VISION.md` | Security-first, lean core, plugins via npm/ClawHub, "Why TypeScript: hackable". |

**Reuse plan:** mostly A (the Praxis Prime core is Python):
- the gateway protocol concepts;
- queue modes and permission modes;
- the `/approve` rule;
- the decision-model role;
- the ONNX classifier choices;
- Tauri Linux packaging;
- the Omarchy Quickshell plugin structure;
- specialist lanes;
- plugin hook names;
- Canvas.

Small files such as the Omarchy `install.sh` and QML could be adapted, with attribution.

**Unverified or caveats**
- There is no local STT verified in OpenClaw.

## 3. SMF Praxis (SMF Works)

**Stack:** Python `>=3.10` with a dependency-free core and an offline mock LLM. The package is `praxis-agent`, the module `hybridagent/`. The Command Deck dashboard runs on port 8643 (vanilla JS/CSS in `hybridagent/web`), with a SQLite store at `~/.praxis/praxis.db`.

**Loop:** perceive → plan → govern → act/draft → reflect → consolidate. Principle: "autonomy for preparation, approval for consequence."

| Module | Findings |
|---|---|
| `hybridagent/broker.py` | **Risk classes:** READ/DRAFT run autonomously; SEND/DESTRUCTIVE need approval. **ComplianceMode:** ENFORCED (default), AUTONOMOUS, PERMISSIVE, with timed auto-revert (`praxis governance <mode> --for 1h`). Also a persisted kill switch, egress firewall, injection detection, **dual approval** (four-eyes) for DESTRUCTIVE, JSON-schema argument validation, an audit trail with secret redaction, and a `policy_hook` (OPA/Rego/Cedar/custom) that "may tighten, never weaken". |
| `data_policy.py` | Classes: PUBLIC, INTERNAL, CONFIDENTIAL, PRIVILEGED, PHI, EDUCATION_RECORD, EVIDENCE. Default retention days: 365 / 365 / 365 / 2555 / 2190 / 1825 / 2555. Legal hold. Approved-egress connectors per class. Export requires redaction for sensitive classes. |
| `memory.py` | `purge_expired`, `decay_episodic`, `forget_by_provenance` ("GDPR/HIPAA-style" purge hook). |
| `router.py` | Sensitivity classifier (secrets, SSNs, card numbers). Pins sensitive content to local models. |
| `compliance.py` | `praxis compliance` produces an attestation over the cycle_id / decision_id evidence chain. |
| `jurisdictions/` | 13 US states: **CT FL GA MA MD NJ NY OH PA SC TN VA WV**. Profiles: Forensic, Legal, Medical (HIPAA fields, breach days, record retention), Education (FERPA / state operator laws, NY Ed Law 2-d, OH AI policy). Each has a `confidence` field; several say `established_knowledge` rather than primary-source. NC is not included. |
| `vertical_templates.py` | 12 templates: general, legal, medical, forensic, education, homeschool, business, developer, law_firm, medical_office, behavioral_health, school_system. Each has a `complianceMode` (enforced for regulated packs; autonomous for education/business/developer) and a `riskPolicy` (`dualApprovalRisks`, `autonomousRisks`, `egressCheck`, `injectionCheck`, `approvalTtlSeconds` 900–1800). Packs live at `~/.praxis/packs/<name>/pack.json`. |
| Other | `identity.py` (Ed25519/HMAC signed attestations), `security_scan.py` (A–F grading of skills and MCP servers), `orchestrator.py` (role tool allowlists, `MAX_DEPTH=3`), scratchpad, `content_guard.py`, `perception.py` (injection-flagged input "treated as data only"), `sandbox.py`, voice, `m365_tools.py`, A2A client, OS-keychain secrets. |
| `docs/OWASP_AGENTIC_COVERAGE.md` | Maps OWASP Agentic Top-10 (AAI001–AAI010) to modules. |

**Regulation grep results**

| Regulation | Found in Praxis |
|---|---|
| HIPAA, FERPA, NY SHIELD, MA 201 CMR 17 WISP | present |
| 42 CFR Part 2 | mentioned in templates |
| GDPR | mentioned only in memory/README ("GDPR/HIPAA-style" forgetting) |
| SOC 2 | one hit, a test phrase in `evals.py` |
| **EU AI Act, CCPA, COPPA, PCI, ISO 42001** | not found |
| NIST | no substantive hits |

So the dials in the "not found" rows are **new work**.

**Key tension:** Praxis defaults to ENFORCED, while Michael wants compliance off by default. Praxis Prime resolves this with an always-on baseline spine plus regulatory dials that are off by default.

**Unverified or caveats**
- **Regulated packs: extraction history.**
  - `CHANGELOG.md` 0.29.0 (2026-07-19): "Vertical extraction cutover. Regulated packs leave the open-core wheel and register through `praxis.verticals`."
  - `docs/QUICKSTART.md`: "Commercial verticals (legal, medical, education, homeschool, forensic) live in private repos."
  - `SECURITY.md` names `praxis-legal` and `praxis-medical`.
  - `hybridagent/vertical_templates.py` and `jurisdictions/` remain in the public MIT repo.
- **Decision (Michael, 2026-09-29):** bundle the regulated packs into Praxis Prime and modify them as needed. Versions released under MIT before 0.29.0 stay MIT for their recipients (ARCHITECTURE §32).
- **Update (2026-09-30):** the six public repositories `smfworks/smf-praxis-{homeschool,education,forensic,legal,medical,mbh}` are MIT. M0 installs them as data and does not vendor their trees. See `docs/PACKS-LEGACY.md`. Any further private pack repository is still unverified.
- The jurisdiction data's confidence varies and needs legal review.

## 4. SMF Swarm 2.0 (SMF Works)

**Stack:** Python 3.10+, FastAPI plus a static UI at `127.0.0.1:8787`, about 2.8k LOC.

**Modules:** `src/smf_swarm/{analysis/engine.py, governance/{identity,audit,permissions}.py, capability/diagnostic.py, app/, cli.py}`.

**Honest finding.** It is a *governance-first predictive analysis app* with four personas: Scout, Strategist, Skeptic, Forecaster.
- In LLM mode, **one prompt** asks the model to role-play all four personas and return JSON.
- Mock mode is deterministic.
- It does **not** spawn independent agents. There is no blackboard and there are no budgets.

**Reusable pieces:**
- an append-only **SHA-256 hash-chained audit log** (`governance/audit.py`);
- a deny-by-default capability **PermissionEngine**;
- an **IdentityRegistry**;
- a TRACE-inspired **capability diagnostic**;
- the report schema (scenarios, probabilities, evidence).

**ADR-0001:** Michael is the sponsor; Aiona Edge implemented it. It defers "**HBHC** cryptographic revocation" to Phase 2. **HBHC is not expanded anywhere in the repo** (open question).

**Related repos, not analyzed:** a private commercial vertical `smf-swarm-2.0-fe` is referenced; the smfworks org also has `smf-swarm` (v1) and `smf-multi-agent-orchestration-CLI`.

## 5. Omarchy (basecamp/omarchy, by DHH) — integration target

**Shell and packages**
- License MIT; version 4.0.0.alpha at the cloned commit.
- Quickshell/QML shell (`shell/`, plugins, `docs/omarchy-shell.md`).
- Pacman repo `[omarchy]` at `https://pkgs.omarchy.org/stable/$arch`, plus `omarchy-pkg-add` and `omarchy-pkg-aur-add`. Hermes (`hermes-desktop`) and OpenClaw are packaged there.

**AI integration (`manual/17-ai.md`)**
- `omarchy default agent <name>`; `Super+Shift+Ctrl+A` runs `omarchy-agent --pick` (`default/hypr/bindings/utilities.lua:97`); `omarchy agent prompt "…"`.
- An agents usage panel.
- Installers `omarchy-install-ai-hermes` and `omarchy-install-ai-openclaw` with `# omarchy:summary=` headers.
- The Omarchy skill is symlinked into `~/.agents/skills`.
- Crash diagnosis is handed to the default agent. Dictation via Voxtype. Local LLMs via LM Studio / Ollama.

**Theming**
- `themes/<name>/colors.toml` keys: `mode`, `accent`, `selection`, `muted`, `background`, `dark_background`, `darker_background`, `lighter_background`, `foreground`, `dark_foreground`, `light_foreground`, `bright_foreground`, `red`, `yellow`, `orange`, `green`, `cyan`, `blue`, `magenta`, `brown`, `bright_*`.
- Templates `default/themed/*.tpl` (e.g. `hermes.yaml.tpl` with `{{ accent }}` placeholders, `claude.json.tpl`) render to `~/.local/state/omarchy/current/theme/`. User templates go in `~/.config/omarchy/themed/*.tpl`. Per-app hooks: `omarchy-theme-set-<app>`.

**Hyprland config** is in Lua in Omarchy 4: `~/.config/hypr/bindings.lua` using `o.bind("SUPER + …", "Label", "command")` and `o.rebind(...)`. Launches go through `uwsm-app`. Omarchy 3.x used `hyprland.conf` with `bindd`, which the architecture notes as the legacy path.

## 6. Jev (TypeSafe AI) — "Jev" layer research

**Correction from Michael:** "Jev" is **not** Jarvis. It is the model shown at https://jevai.net/.

**Decision (Michael, 2026-09-29): hosted TypeSafe Jev will NOT be used.** This section is kept as *reference research*. Praxis Prime builds its own self-hosted Decision Engine that mirrors Jev's public API shape (ARCHITECTURE §7; technical sources in §13 below).

**Official sources used for facts**
- https://typesafe.ai
- https://docs.typesafe.ai: `llms.txt` index, `/introduction`, `/concepts/system-one`, `/primitives` (choice / score / noul), `/confidence`, `/patterns/*` (fan-out, confidence-routing, composite-scoring, intent-routing), `/cookbooks/*` (llm_guardrails, citation_check, classifying_rag_passages, function_calling, **skill_suggestion** over Nous Research's 182-skill Hermes catalog, parallel_questions, …), `/demos/smart-home`, `/models`, `/api`, `/agent-skill`, `/sdk/*`, `/legal`, `/introduction/coding-agents`, `/model-jaggedness/jev-1.13`
- https://github.com/typesafe-ai

**Verified facts**
- **What it is:** Jev is TypeSafe's flagship "System One" model. It is **not an LLM and not an agent.** Input is `state` plus typed questions; output is typed answers with calibrated probabilities and confidence. There is no text generation.
- **Announcement and people:** publicly announced Sep 15, 2026. Founder Diogo Almeida (ex-OpenAI). Co-founders Erik Gafni and Sasha Sheng. A $40M seed led by DCVC is reported by third-party coverage and was not independently verified. The name references William Stanley Jevons. The training method is called RLCD (Reinforcement Learning for Calibrated Decisions).
- **API:** `POST https://api.typesafe.ai/v1/systemone`, Bearer key. Models `jev-latest`, `jev-preview`, `jev-1.13.0`.
- **Primitives:**
  - choice: ≤255 options, probabilities + confidence;
  - score: 2–10 ordered levels, fractional score + probabilities + confidence;
  - noul: yes/no probability.

  All questions in a call are evaluated in parallel and independently.
- **Limits (`/models`):**
  - 64k context per request (32k state plus the longest question); text only; English primary.
  - About 250k tokens/s and 1,200 requests/min (dynamic).
  - **$0.042 per million input tokens, output free.**
- **Claims:** latency around 70–500 ms (vendor claim); "no hallucinations" and zero type errors because it doesn't generate text.
- **Known weaknesses (`/model-jaggedness/jev-1.13`, reviewed 2026-09-17):** literal reading, math/counting, date comparison, indirection, large irrelevant state, **adversarial content can steer answers**, contradictory criteria, structural invariants, and no generation.
- **Legal:** a DPA and MCA are linked. The privacy policy says customer data is not used for training. Zero data retention is enterprise-only.
- **Not a coding-agent LLM:** the docs state Jev is not a drop-in replacement for the LLM behind coding agents.
- **Open source (MIT):** `typesafe-sdk-python`, `typesafe-sdk-js`, `n8n-nodes-typesafe-ai`, `system-one-adapter-python` (the `system_one` API backed by OpenAI / Anthropic / Gemini / OpenAI-compatible LLMs), and `skills` (agent skill). `WorkflowEvals` is Apache-2.0. **The Jev model itself is proprietary and hosted** (early access).

**About jevai.net**
- It presents Jev as "from TypeSafe AI".
- Signs that it is a **third-party, template-built** site:
  - the privacy page contains "sample copy for a starter template";
  - the pricing page shows generic $19 / $49 / $149 SaaS tiers;
  - `robots.txt` references "your-domain.com";
  - it quotes $0.084/MTok, which conflicts with the docs' $0.042.
- **Its affiliation with TypeSafe could not be verified.** No jevai.net-only features were adopted.

**Gaps (not verified — do not build on these)**
- A self-hosted or on-prem Jev.
- A HIPAA BAA, SOC 2 report or data residency.
- An SLA.
- Multilingual quality.
- Image or audio input.

**How it maps into Praxis Prime:**
- **Not used.** It is only a reference for the local Decision Engine: rules → ONNX classifiers → constrained small-LLM judges with logprob calibration → the Jury (swarm of judges) → escalation.
- The DE is escalate-only and never the sole security control.
- Jev's documented weaknesses are assumed to apply to our small judges as well.

## 7. Jarvis layer (Michael's ambient requirement — separate from Jev)

No single upstream. It is assembled from:
- Hermes voice: `tools/wake_word*.py`, faster-whisper, Piper/NeuTTS, `voice_mode.py`, `voice_live.py`, `homeassistant_tool.py`.
- OpenClaw nodes and `linux-node`: notify, camera, GeoClue.
- The TypeSafe smart-home demo pattern.
- Omarchy's Voxtype dictation.
- New Wayland/Hyprland desktop control and a presence-aware heartbeat.

## 8. Public product docs checked (patterns only, no code reuse)

- **Claude Code:**
  - Hook events: SessionStart, UserPromptSubmit, PreToolUse (allow / deny / ask / defer + updatedInput), PostToolUse, PermissionRequest, SubagentStart/Stop, PreCompact, WorktreeCreate, Stop, and others.
  - Handler types: command / http / mcp_tool / prompt / agent; exit code 2 blocks.
  - Settings scopes: user, project, local, managed.
  - Permission modes: default, acceptEdits, plan, auto (classifier), dontAsk, bypassPermissions. Deny rules apply in every mode.
  - Linux sandbox: bubblewrap + optional seccomp. CLAUDE.md and `.claude/rules`.
- **Codex:**
  - Sandbox modes read-only / workspace-write / danger-full-access, combined with an approval policy (on-request, etc.; "untrusted" is retired in favor of project `trust_level`).
  - Network is off by default; the Linux sandbox uses bubblewrap.
  - AGENTS.md discovery runs global → root → cwd, with AGENTS.override.md and a 32 KiB cap.
  - MCP tools annotated as destructive always need approval.
  - Cloud: a two-phase setup, then an offline agent.
- **Cursor:**
  - Cloud Agents (formerly Background Agents): isolated VMs, `.cursor/environment.json`, snapshots, MCP, hooks from `.cursor/hooks.json`, artifacts (screenshots/video), remote desktop, triggers from Slack/GitHub/Linear/API.
  - Rules: `.cursor/rules/*.mdc` (alwaysApply / globs / description), User and Team rules, AGENTS.md.
- **Grok Bot:** described from its product brief and operating environment:
  - persistent agents with memory; routines/cron and event triggers; skills; connectors/MCP;
  - a sandboxed box with a browser; subagents; approval cards + auto-review;
  - teammates / group channels; voice memos; templates.

  No source was reviewed.

## 9. Runtime dependency licenses (checked 2026-09-29 via raw LICENSE files)

| Dependency | License | Implication |
|---|---|---|
| rhasspy/piper | MIT | fine |
| OHF-Voice/piper1-gpl (Piper successor) | **GPL-3.0** | separate process only, or prefer Kokoro |
| hexgrad/kokoro | Apache-2.0 | fine (check model weight license separately) |
| dscripka/openWakeWord | code Apache-2.0; **pre-trained models CC BY-NC-SA 4.0** (per README) | train custom models for commercial builds |
| k2-fsa/sherpa-onnx | Apache-2.0 | fine (check model licenses) |
| Picovoice/porcupine | Apache-2.0 repo; requires Picovoice AccessKey / terms | optional only |
| SYSTRAN/faster-whisper, ggml-org/whisper.cpp | MIT | fine |
| containers/bubblewrap | LGPL-2.0+ | invoke the external binary |
| ReimuNotMoe/ydotool | **AGPL-3.0** | external binary only; optional fallback |
| atx/wtype, emersion/grim | MIT | fine |
| jordansissel/xdotool | BSD-style | fine |
| ollama/ollama | MIT | fine (≥0.12.11 for logprobs) |
| ggml-org/llama.cpp | MIT | fine |
| huggingface/setfit | Apache-2.0 | fine |

## 10. Consolidated list of unverified items

1. **Further private Praxis pack repos**, if any remain besides the six public MIT verticals. Those six were confirmed MIT on 2026-09-30 and are loaded as data, not vendored (`docs/PACKS-LEGACY.md`).
2. **NC pack rows marked S/U** (§11 below):
   - the full text of NC State Bar 2024 FEO 1;
   - §§ 115C-548/-549 record-keeping text;
   - § 132-1.10 duties;
   - the S.L. 2025-25 s. 29 amendments;
   - the scope of S.L. 2025-62;
   - the S.L. 2024-37 AI provisions;
   - NC medical record-retention years;
   - NC CLE, PE-board and forensic facts;
   - the NCDIT AI-policy details.
3. Praxis jurisdiction profiles marked `established_knowledge` (not primary-source).
4. **Decision Engine performance:**
   - All latency and ECE numbers are *targets*, not measurements.
   - Candidate judge-model licenses must be verified before bundling. Qwen3, Phi-4-mini, ModernBERT and DeBERTa are expected to be permissive; Llama and Gemma have custom terms.
5. Whether TypeSafe's MIT SDK tolerates extra response fields (`x_prime`). This decides whether extensions go in-band or behind `?extended=1`.
6. **HBHC** meaning (Swarm 2.0 ADR-0001).
7. Hermes computer-use Linux backend ("future").
8. OpenClaw local STT (not found).
9. Grok Bot internals (brief-only).
10. **Trademark** clearance for "Praxis Prime" (USPTO not searched) and domain availability.
11. Whether Basecamp would accept Praxis Prime into pkgs.omarchy.org.
12. jevai.net's affiliation with TypeSafe. This no longer matters for the design, because hosted Jev is not used.

## 11. North Carolina pack — sources (checked 2026-09-29 ET)

Legend: **V** = primary source text read; **S** = secondary summary only; **U** = not found / not reviewed.

| Item | Source | Status |
|---|---|---|
| Identity Theft Protection Act, §§ 75-60 to 75-66 (definitions, SSN protection, security freezes, disposal, breach notification, publication) | https://www.ncleg.gov/EnactedLegislation/Statutes/HTML/ByArticle/Chapter_75/Article_2A.html | **V** (full article read) |
| Identifying information list, § 14-113.20(b) | https://www.ncleg.gov/EnactedLegislation/Statutes/HTML/BySection/Chapter_14/GS_14-113.20.html | **V** |
| Public-agency SSN/PII, § 132-1.10 | https://www.ncleg.gov/EnactedLegislation/Statutes/HTML/BySection/Chapter_132/GS_132-1.10.html | **S** (header and findings read) |
| Physician–patient privilege, § 8-53 | …/BySection/Chapter_8/GS_8-53.html | **V** |
| Medical record copy fees, § 90-411 | …/BySection/Chapter_90/GS_90-411.html | **V** |
| MH/DD/SA confidentiality, § 122C-52 | …/BySection/Chapter_122C/GS_122C-52.html | **V** (a)–(b) |
| Student data system security, § 115C-402.5; parental notice, § 115C-402.15 | …/BySection/Chapter_115C/GS_115C-402.5.html, …/GS_115C-402.15.html | **V** |
| Home school qualifications, § 115C-564 | …/BySection/Chapter_115C/GS_115C-564.html | **V** |
| Home school records and testing guidance | https://www.doa.nc.gov/divisions/non-public-education/home-schools/requirements-recommendations | **S** |
| NC Medical Board position statement 3.2.1 (AI-assisted records; rationale documentation) | https://www.ncmedboard.org/resources-information/professional-resources/laws-rules-position-statements/position-statements/medical-records-documentation-electronic-health-records-access-and-retentio | **V** (AI passages read) |
| NC State Bar 2024 Formal Ethics Opinion 1 (AI) | https://www.ncbar.gov/for-lawyers/ethics-and-governing-rules/ethics-opinions/opinions/2024-formal-ethics-opinion-1/ | **S** |
| NCDPI generative-AI guidance (Jan 16, 2024) | https://www.dpi.nc.gov/news/press-releases/2024/01/16/ncdpi-releases-guidance-use-artificial-intelligence-schools | **V** (release exists) / **S** (contents) |
| Executive Order No. 24 (Sept 2, 2025) | https://governor.nc.gov/executive-order-no-24-advancing-trustworthy-artificial-intelligence-benefits-all-north-carolinians ; press release …/news/press-releases/2025/09/02/governor-stein-announces-executive-order-ai | **V** |
| AI Leadership Council roadmap (July 1, 2026; 17 goals) | https://it.nc.gov/about/boards-councils/ai-leadership-council ; EdNC coverage | **S** |
| Bill statuses: S757, H462, S1022, S624, H934, H301, S1033, S835, S133 (S.L. 2025-62) | https://www.ncleg.gov/BillLookUp/2025/<bill> (fetched; "Last Action" read) | **V** (status only) |
| H591 → S.L. 2024-37 "Modernize Sex Crimes" | https://www.ncleg.gov/BillLookUp/2023/H591 | **V** (status) / **S** (AI content) |
| S1022 effective date and S624 breach windows | UNC SOG Legislative Reporting Service summaries (lrs.sog.unc.edu) | **S** |
| H301: AI provisions dropped | WRAL, Sept 2026 (https://www.wral.com/news/nccapitol/north-carolina-lawmakers-regulate-ai-september-2026/) | **S** |
| NC comprehensive privacy law | none enacted as of 2026-09-29 (bill pages above; LawSignals tracker agrees) | **V** (per bill pages) |

## 12. Name / CLI collision check (2026-09-29 ET)

| Check | Method | Result |
|---|---|---|
| PyPI `prime` | `pypi.org/pypi/prime/json` | **taken**: Prime Intellect "CLI + SDK" v0.8.0 (github.com/PrimeIntellect-ai/prime). Its `pyproject.toml` declares the console script `prime = "prime_cli.main:run"`. |
| PyPI `praxis-prime`, `praxisprime`, `pprime`, `praxis-agent` | same | 404 (free). Note: Praxis's own `praxis-agent` is not on PyPI. |
| PyPI `praxis` / `pxp` | same | taken (google/praxis; "python-hosted expression language") |
| npm `praxis-prime` / `pprime` / `prime` | registry.npmjs.org | free / free / **taken** |
| crates.io `praxis-prime` | API | free |
| AUR `praxis-prime`, `prime`, `pprime` | aurweb RPC v5 `info` | no exact matches. `prime` search returns 43 unrelated `*prime*` packages. AUR `praxis` and `praxis-bin` exist ("Semantic Command & Control Framework"). |
| Arch official | archlinux.org packages JSON | `nvidia-prime` ships `/usr/bin/prime-run`; no `prime` package |
| Ubuntu noble | packages.ubuntu.com | `prime`, `praxis`, `praxis-prime`: "No such package". `nvidia-prime` ships `/usr/bin/prime-select` and `/usr/bin/prime-supported`. |
| Flathub | search API "praxis prime" | no hits |
| GitHub | `github.com/smfworks/praxis-prime` → 404; repo search `praxis-prime in:name` | 1 hit: `AaronPaden/Praxis_Prime` ("My first repository", created 2025-01-17, 0 stars) |
| Web | search "Praxis Prime" | an unrelated 2026 fintech "front-to-back prime brokerage" design prototype by Ed Chen (edwson.com), labelled a concept, not a product |
| Trademark / domains | — | **not searched** |

**Conclusion:**
- Use **`praxis-prime`** as the canonical binary and package name, with **`pprime`** as the short alias.
- Avoid bare `prime`: Prime Intellect's PyPI CLI installs a `prime` command, and `prime-*` commands from `nvidia-prime` are common on Linux.

## 13. Decision Engine — technical sources (checked 2026-09-29 ET)

| Fact used | Source |
|---|---|
| TypeSafe wire shape: request `model`/`state`/`questions`; answers map with `choice` + `probabilities` + `confidence`, `score` + `legend` + `probabilities` + `confidence`, `noul`; `usage`; limits ≤255 options, 2–10 levels | https://docs.typesafe.ai/api.md |
| Ollama `logprobs` / `top_logprobs` (up to 20) added in v0.12.11 (Nov 2025) | https://github.com/ollama/ollama/releases/tag/v0.12.11 ; commit 59241c5 (PR #12899) |
| llama.cpp server: `n_probs` returns `completion_probabilities`; `json_schema` or `grammar` constraints (not both at once) | https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md |
| Swarm 2.0 personas and roles (Scout / Strategist / Skeptic / Forecaster) | `src/smf-swarm-2.0/src/smf_swarm/analysis/engine.py` lines ~408–430 |
| Swarm 2.0 governance APIs (`AuditLog.append/verify_chain`, `PermissionEngine.grant/check/require`, `IdentityRegistry.register/require_active`) | `src/smf-swarm-2.0/src/smf_swarm/governance/{audit,permissions,identity}.py` |
| Licenses: Ollama MIT, llama.cpp MIT, SetFit Apache-2.0 | raw LICENSE files on GitHub |
