# Capability Matrix — Praxis Prime vs. source systems

> Companion to `ARCHITECTURE.md`. Compiled 2026-09-29 (ET); revised the same day with Michael's decisions (name, local Decision Engine, dials, packs).
>
> **Sources:**
> - Local clones: Hermes Agent @ f94fd4d, OpenClaw @ 2d85731, SMF Praxis @ 69121b2, SMF Swarm 2.0 @ d3ec7f9, Omarchy 4.0.0.alpha.
> - Public docs: Claude Code, Codex, Cursor.
> - TypeSafe AI docs and GitHub for Jev (reference only).
> - Grok Bot is described from its product brief and my own operating environment, not from source code.
>
> **Legend:**
> - ✅ native / strong
> - ◐ partial, limited or plugin-only
> - ✗ absent
> - ? not verified
> - — not applicable
>
> **Jev** = TypeSafe AI's System One decision model (hosted API plus MIT SDKs). **It is a reference column only: Praxis Prime does not use TypeSafe's service.** It builds its own local Decision Engine (ARCHITECTURE §7). Jev is not an agent, so most agent rows are "—".
> **Jarvis** = Michael's ambient-assistant requirement (voice, wake word, home/desktop control, proactive). It is a *target layer*, not an existing product: ★ = required by the Jarvis layer.
> **Plan:** R = reuse code (with attribution), A = adapt a pattern / re-implement by design, N = new.

## 1. Core agent

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Tool-using agent loop | ✅ sync loop, 500 max iters | ✅ per-session lanes + queue modes | ✅ | ✅ | ✅ | ✅ | ✅ perceive→…→consolidate | ✗ single-prompt analysis | — | ★ voice sessions | **A**: Hermes invariants + OpenClaw queue modes + Praxis phases |
| Prompt-cache discipline | ✅ byte-stable system prompt | ◐ | ? | ? | ✅ | ✅ | ✗ | ✗ | — | — | **A** (Hermes) |
| Steer / interrupt a running turn | ◐ | ✅ steer/followup/collect/interrupt | ◐ | ✅ | ✅ | ✅ | ✗ | ✗ | — | ★ barge-in | **A** (OpenClaw) |
| Multi-provider models | ✅ provider plugins | ✅ many provider extensions | ✅ (managed) | ✅ | ◐ Anthropic-first | ◐ OpenAI-first (OSS providers configurable) | ✅ incl. offline mock | ◐ OpenAI-compatible + mock | — | ★ local STT/TTS | **A** |
| Local models (Ollama/llama.cpp/vLLM) | ✅ | ✅ | ✗ | ◐ | ✗ | ◐ | ✅ | ◐ | ✗ (hosted only; LLM adapter can use local) | ★ | **A** |
| Model roles (primary/utility/reviewer/decision) | ◐ auxiliary client | ✅ incl. `decisionModel` role | ? | ◐ | ◐ subagent models | ◐ | ◐ router | ✗ | ✅ is the decision role | — | **A** (OpenClaw roles) |
| Sensitivity-based routing (pin local) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ `router.py` | ✗ | ◐ classifies, doesn't route | — | **R** (Praxis) |
| Budgets (tokens/$/time) | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | ✗ | — | — | **N** unified budgets |

## 2. Decision Engine (self-hosted "Jev-equivalent")

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev (ref.) | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Typed choice / score / yes-no with calibrated probabilities | ✗ | ✅ `decision_evaluate` tool (typesafe / onnx providers) | ✗ | ✗ | ✗ | ✗ | ✗ | ◐ scenario probabilities (LLM-generated, uncalibrated) | ✅ core product (choice ≤255, score 2–10, noul) | ★ fast intent | **N**: own cascade; wire shape mirrors TypeSafe's public API (`/v1/decide` + `/v1/systemone` compat) |
| Runs fully local / self-hosted | — | ◐ ONNX providers local; typesafe provider hosted | — | — | — | — | ✅ offline core | ✅ mock mode | ✗ hosted only | ★ | **N**: every tier local; no hosted provider |
| Rules tier (deterministic detectors, numbers/dates in code) | ◐ threat patterns | ◐ | ? | ✗ | ◐ deny rules | ◐ | ✅ router regex (SSN, PAN, secrets) | ✗ | ✗ (docs advise doing math in code) | — | **R/A** Praxis router + NC/US detectors |
| Local zero-shot / fine-tuned classifiers (ONNX) | ✗ | ✅ onnx ext. (GLiClass, DeBERTa, GLiNER) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ★ offline | **A/N**: GLiClass/GLiNER + SetFit/ModernBERT heads distilled from the Jury |
| Constrained small-LLM judge with logprob calibration | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ◐ LLM adapter (MIT) gives the same API on any LLM; calibration unstated | — | **N**: llama.cpp (`json_schema` + `n_probs`) / Ollama ≥0.12.11 (`logprobs`); single-token labels; temperature/Platt/isotonic |
| Swarm-of-judges ensemble with disagreement escalation | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ◐ dual approval (human) | ◐ 4 personas (role-played in one prompt) | ✗ | — | **N**: the Jury — Swarm 2.0 personas × ≥2 base models, log-opinion pool, JS-divergence → T4/human |
| Calibration metrics & reliability report | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ◐ evals (capability/safety) | ◐ capability diagnostic | ◐ "confidence" field; calibration claimed | — | **N**: ECE/MCE/Brier/NLL, risk–coverage, drift → auto trust reduction |
| Auto-review risk triage | ✅ `approval_smart.py` (aux LLM) | ✅ workspace mode LLM reviewer | ✅ auto-review | ? | ✅ auto mode classifier | ✅ auto-review | ◐ risk classes (static) | ✗ | ✅ documented pattern (confidence-gated routing) | — | **A/N**: DE Jury → reviewer LLM → human; escalate-only |
| Injection / jailbreak screening | ✅ threat patterns | ◐ | ✅ untrusted fencing | ? | ◐ | ◐ | ✅ injection detection | ✗ | ◐ guardrails cookbook; docs admit adversarial state can steer answers | ★ voice injection | **R/A/N**: rules + Skeptic judge + reviewer; never the sole check |
| Skill selection | ◐ index in prompt | ◐ | ◐ | ◐ rules globs | ◐ | ◐ | ✗ | ✗ | ✅ cookbook over Hermes's skill catalog | — | **A**: BM25 shortlist → DE choice |
| Decision audit trail | ✗ | ◐ transcripts | ◐ | ◐ | ◐ | ◐ | ✅ evidence chain | ✅ SHA-256 hash chain | ✗ | ★ | **R**: Swarm 2.0 AuditLog + IdentityRegistry per judge |

## 3. Tools, MCP, skills, plugins

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Tool registry with toolsets | ✅ `tools/registry.py`, `toolsets.py` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ role allowlists | ◐ capability permissions | — | ★ home/desktop toolsets | **A** |
| Risk class per tool | ◐ approval patterns | ✅ permission modes | ✅ | ◐ | ✅ allow/ask/deny rules | ✅ MCP destructive annotations | ✅ READ/DRAFT/SEND/DESTRUCTIVE | ✅ deny-by-default | — | ★ locks/garage = SEND | **R** Praxis + add SPEND/SHARE |
| MCP client | ✅ incl. OAuth | ✅ | ✅ connectors | ✅ | ✅ | ✅ | ◐ | ✗ | ✗ (n8n nodes, SDKs) | — | **A** |
| MCP server mode | ✅ `mcp_serve.py` | ◐ | ✗ | ✗ | ✅ | ✅ | ✗ | ✗ | ✗ | — | **A** |
| SKILL.md skills (agentskills.io) | ✅ + hub + guard | ✅ + ClawHub | ✅ | ◐ rules/commands | ✅ | ✅ | ✗ (packs) | ✗ | ✅ TypeSafe agent skill (MIT) | — | **A** (format compatibility) |
| Autonomous skill creation / curation | ✅ curator | ✅ skill-creator | ◐ | ✗ | ◐ | ✗ | ✗ | ✗ | — | — | **A** (proposals as DRAFT) |
| Skill/MCP security grading | ✅ skills guard | ◐ | ? | ✗ | ✗ | ✗ | ✅ A–F `security_scan.py` | ✅ capability diagnostic | — | — | **R** Praxis + Hermes guard |
| Plugin SDK with hooks | ✅ plugins | ✅ 173 extensions, lifecycle hooks | ◐ | ◐ | ✅ plugins + hooks | ◐ | ◐ `policy_hook` | ✗ | — | — | **A** (Python entry points, OpenClaw hook names) |
| Editor integration (ACP) | ✅ `acp_adapter/` | ◐ | ✗ | ✅ is the editor | ✅ IDE extensions | ✅ IDE extension | ✗ | ✗ | — | — | **A** v1.0 |

## 4. Memory & knowledge

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Persistent user memory / profile | ✅ memory + user profile | ✅ memory-core, active-memory | ✅ | ◐ memories | ◐ CLAUDE.md / auto memory | ◐ AGENTS.md | ✅ | ✗ | — | ★ preferences | **A** |
| Session search (FTS) | ✅ SQLite FTS5 | ✅ | ✅ | ◐ | ◐ | ◐ | ✅ SQLite | ✗ | — | — | **R/A** |
| Vector / semantic memory | ✅ provider plugins | ✅ lancedb | ? | ✅ codebase index | ✗ | ✗ | ◐ | ✗ | — | — | **N** sqlite-vec |
| Retention / decay / forget-by-provenance / legal hold | ✗ | ◐ | ◐ delete memories | ✗ | ✗ | ✗ | ✅ `purge_expired`, `decay_episodic`, `forget_by_provenance`, legal hold | ✗ | — | ★ voice data TTL | **R** (Praxis) |
| Memory-write gating | ◐ nudges | ◐ | ? | ✗ | ✗ | ✗ | ◐ data policy | ✗ | ✅ yes/no + score pattern | — | **A** DE + policy H6 |

## 5. Scheduling, triggers, channels

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Cron / routines | ✅ `cron/` | ✅ | ✅ routines | ◐ automations via API/triggers | ◐ (via external) | ✗ | ◐ | ✗ | — | ★ briefings | **A** |
| Event triggers (email, webhook, files, HA) | ✅ webhooks | ✅ | ✅ event triggers | ✅ Slack/GitHub/Linear triggers | ✗ | ✗ | ◐ perception | ✗ | — | ★ HA state changes | **A** |
| Proactive heartbeat | ◐ | ✅ heartbeat (periodic main-session turns) | ◐ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ urgency scoring pattern | ★ core | **N** (DE-gated) |
| Messaging channels | ✅ ~20 (Telegram, Discord, Slack, WhatsApp, Signal, email, SMS, Matrix, Teams, HA …) | ✅ many (incl. iMessage) | ◐ app + group channels + connectors | ◐ Slack | ✗ | ✗ | ◐ M365 tools, A2A | ✗ | ◐ n8n nodes | ★ | **R/A** Hermes adapters |
| Channel-native approvals (never free-text "yes") | ◐ | ✅ `/approve <id>` | ✅ approval cards | ◐ | ✗ | ✗ | ✅ approval queue | ✗ | — | ★ spoken + card | **A** (OpenClaw rule) |
| Voice memos in chat | ✅ | ✅ | ✅ | ✗ | ✗ | ✗ | ◐ | ✗ | ✗ (text-only input) | ★ | **R** Hermes |

## 6. Computer use, sandbox, coding

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Shell sandbox | ✅ local/docker/ssh/singularity/modal/daytona/vercel | ✅ Docker/Podman/SSH/Crabbox (off by default) | ✅ isolated box | ✅ cloud VMs | ✅ bubblewrap + seccomp (Linux) | ✅ bubblewrap (Linux), network off | ◐ `sandbox.py` | ✗ | — | — | **A** tiers T1–T4 |
| Browser automation | ✅ CDP/Camofox/Lightpanda | ✅ | ✅ box browser | ✅ | ◐ (MCP) | ◐ | ✗ | ✗ | — | ◐ | **A** |
| Desktop computer use (Linux) | ◐ cua-driver (Linux backend "future" per docstring) | ◐ cua-computer ext.; linux-node (notify, camera, location) | ✅ in its box desktop | ✅ cloud VM desktop | ◐ | ✗ | ✗ | ✗ | — | ★ host control | **N** Wayland/X11 adapters + virtual desktop |
| Git worktrees per task | ✅ `subagent_worktree.py` | ◐ | ◐ | ✅ | ✅ | ✅ (cloud) | ✗ | ✗ | — | — | **A** |
| Instruction files (AGENTS.md / CLAUDE.md / .cursor rules) | ✅ AGENTS/CLAUDE/SOUL | ✅ | ◐ | ✅ .mdc + AGENTS.md | ✅ CLAUDE.md + rules | ✅ AGENTS.md chain | ◐ charter | ✗ | — | — | **A** read all |
| Hooks (pre/post tool, etc.) | ✅ plugin hooks | ✅ plugin hooks | ◐ | ✅ `hooks.json` | ✅ rich hook events | ◐ | ◐ policy hook | ✗ | — | — | **A** Claude Code-compatible subset |
| Diff review + test loop | ◐ | ◐ | ◐ | ✅ | ✅ | ✅ | ✗ | ✗ | — | — | **A** |
| Background/cloud coding with artifacts | ◐ | ◐ | ◐ | ✅ Cloud Agents | ✅ (web/cloud) | ✅ Codex cloud | ✗ | ✗ | — | — | **N** self-hosted v1.0 |

## 7. Governance, compliance, audit

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Permission modes | ◐ approval + `--yolo` | ✅ read-only/guarded/workspace/full | ✅ auto-review + approvals | ◐ | ✅ 6 modes | ✅ sandbox × approval policy | ✅ ENFORCED/AUTONOMOUS/PERMISSIVE + timed revert | ✅ deny-by-default | — | ★ voice-safe confirmations | **A**: plan/ask/auto/full + spine |
| Always-on "consequence needs approval" spine | ◐ protected files | ◐ | ✅ | ◐ | ◐ deny rules | ◐ | ✅ core principle | ◐ | — | ★ | **R** Praxis principle |
| Dual approval (four-eyes) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ | ✗ | — | — | **R** |
| Kill switch | ◐ | ◐ | ◐ | ◐ | ◐ | ◐ | ✅ persisted | ✗ | — | ★ panic hotkey + mute | **R** + N hotkey |
| Egress firewall / allowlist | ◐ url safety | ◐ | ✅ | ✅ (cloud) | ✅ sandbox network rules | ✅ network off by default | ✅ | ✗ | — | — | **A** proxy |
| Data classification + retention | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ 7 classes, retention days, legal hold | ✗ | ✅ classification pattern | — | **R** + DE |
| Jurisdiction packs (13 US states) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ (some low-confidence) | ✗ | — | — | **R** (first-wave dial) |
| North Carolina pack (N.C.G.S. §§ 75-60–75-66, NC professional overlays) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ (NC not among the 13) | ✗ | — | — | **N** (first-wave dial; ARCHITECTURE §17.2) |
| Regulated vertical packs (legal, medical, behavioral health, school, homeschool, forensic) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ extracted to private repos in 0.29.0 | ✗ | — | — | **R**: bundled into `packs/regulated/` (approved by Michael); license per §32 |
| HIPAA / FERPA(+COPPA) / GDPR controls | ✗ | ✗ | ✗ | ◐ (enterprise terms) | ◐ (enterprise terms) | ◐ (enterprise terms) | ✅ HIPAA/FERPA templates; ◐ GDPR-style forgetting | ✗ | ✗ (no BAA seen) | — | **R** + N (BAA registry, COPPA, DSAR) — first-wave dials |
| CCPA / PCI / SOC 2 / EU AI Act / NIST RMF / ISO 42001 dials (v1.0) | ✗ | ✗ | ✗ | ◐ vendor certs only | ◐ vendor certs only | ◐ vendor certs only | ◐ GDPR-style forgetting only | ✗ | ✗ | — | **N** |
| Hash-chained audit log | ✗ | ◐ transcripts | ◐ | ◐ | ◐ | ◐ | ✅ evidence chain + attestation | ✅ SHA-256 chain | — | ★ voice actions audited | **R** Swarm + Praxis |
| Signed identity / attestations | ✗ | ✅ device pairing keys | ? | ✗ | ✗ | ✗ | ✅ Ed25519/HMAC | ✅ IdentityRegistry | — | — | **R/A** |
| OWASP Agentic Top-10 mapping | ✗ | ◐ security docs | ? | ✗ | ✗ | ✗ | ✅ | ✗ | — | — | **R** |
| OpenTelemetry / tracing | ◐ Langfuse | ✅ otel + prometheus | ? | ✗ | ◐ OTel metrics | ◐ | ◐ | ✗ | — | — | **A** |

## 8. Multi-agent / swarm

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Subagents / delegation | ✅ 10 concurrent, depth 1 (configurable) | ✅ isolated agents, specialist lanes | ✅ subagents | ✅ parallel agents | ✅ subagents | ◐ | ✅ orchestrator, MAX_DEPTH=3 | ✗ personas role-played in one prompt | ✅ speculative fan-out pattern | — | **A** + N spawn tokens |
| Blackboard / shared claims | ✗ | ◐ | ✗ | ✗ | ✗ | ✗ | ◐ scratchpad | ◐ report schema | — | — | **N** |
| Policy inheritance to children | ✗ | ◐ per-agent config | ? | ✗ | ◐ | ✗ | ◐ role allowlists | ✗ | — | — | **N** (intersection, signed) |
| Kanban / long-running project board | ✅ | ◐ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | — | — | **A** |

## 9. Ambient / "Jarvis" layer

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Wake word (on-device) | ✅ openWakeWord / sherpa-onnx / Porcupine | ◐ swabble (macOS-only) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ★ | **R** Hermes |
| Local STT | ✅ faster-whisper | ? (not verified; `talk-voice` only manages voice selection) | ◐ voice memos | ✗ | ✗ | ✗ | ◐ voice module | ✗ | ✗ | ★ | **R** |
| Local TTS | ✅ Piper/NeuTTS | ✅ `tts-local-cli` ext. | ? | ✗ | ✗ | ✗ | ◐ | ✗ | ✗ | ★ | **A** Kokoro/Piper |
| Full-duplex / barge-in | ◐ live voice | ◐ `voice-call` (phone calls via Twilio/Telnyx/Plivo) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ★ | **N** |
| Home Assistant control | ✅ tool + platform | ◐ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✅ smart-home demo pattern | ★ | **R/A** |
| Desktop control (Wayland/Hyprland) | ◐ HUD pinning via hyprctl | ◐ linux-node | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | — | ★ | **N** |
| Presence / idle awareness | ✗ | ◐ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | — | ★ | **N** logind/hypridle |

## 10. Desktop, packaging, UX

| Capability | Hermes | OpenClaw | Grok Bot | Cursor | Claude Code | Codex | Praxis | Swarm 2.0 | Jev | Jarvis | **Praxis Prime plan** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Desktop app on Linux | ✅ Electron | ✅ Tauri v2 (.deb/AppImage) | ✅ desktop app | ✅ Electron IDE | ◐ terminal (+ desktop app, platform support not checked) | ◐ CLI/IDE | ◐ web dashboard :8643 | ◐ web UI :8787 | — | ★ HUD | **A** Tauri 2 |
| TUI | ✅ Ink | ✅ | ✗ | ✗ | ✅ | ✅ | ◐ CLI | ◐ CLI | — | — | **N** Textual |
| Web UI / dashboard | ✅ FastAPI dashboard | ✅ Control UI | ✅ | ✅ web agents | ✅ web | ✅ web | ✅ Command Deck | ✅ | — | — | **A** React SPA |
| Canvas / artifacts | ◐ | ✅ Canvas/A2UI | ✅ files/attachments | ✅ artifacts | ◐ | ◐ | ✗ | ◐ reports | — | — | **A** |
| Omarchy integration | ✅ installer, theme template, seeded prompt mode | ✅ installer + Quickshell bar plugin | ✗ | ✗ | ◐ `claude.json.tpl` theme | ? | ✗ | ✗ | — | ★ keybind, bar mic indicator | **A** all of it |
| Ubuntu packaging | ◐ install script / pip | ✅ .deb + AppImage | — | ✅ .deb/AppImage | ✅ npm / native installer | ✅ npm / binary | ◐ pip | ◐ pip | — | — | **A** APT repo + .deb + AppImage |
| Arch/AUR / Omarchy pacman | ✅ in Omarchy repo | ✅ in Omarchy repo | — | ◐ AUR (community) | ◐ | ◐ | ✗ | ✗ | — | — | **N** AUR, later upstream |

## 11. Jev reference inventory — what TypeSafe's Jev does, and how Praxis Prime's own DE answers it

| Jev feature | Verified from | Status | Praxis Prime DE equivalent (local) |
|---|---|---|---|
| System One model: typed answers with calibrated probabilities, no text generation | typesafe.ai, docs.typesafe.ai | ✅ verified | Cascade T0–T4 returning typed answers; calibration fitted and measured locally |
| `choice` (≤255), `score` (2–10), `noul` (yes/no); `state` + `questions` map → `answers` map with `probabilities`, `confidence`, `legend`, `usage` | docs.typesafe.ai/api | ✅ | Same wire shape; `x_prime` extension block (tiers, jury, calibrator, audit id) |
| Parallel independent evaluation of all questions in one call | docs | ✅ | Shared cached prefix (KV cache) per state; questions fanned out across judges |
| Latency ~70–500 ms | TypeSafe claims | ◐ vendor claim | Targets: T1 ≤15 ms, T2 ≤120 ms GPU, Jury ≤250 ms GPU (p50; to validate) |
| 64k context, text-only, English primary | docs.typesafe.ai/models | ✅ | Shortlist state before judging; multilingual evals in v1.0 |
| Known weaknesses (literal reading, math/dates/counting, large state, adversarial content, contradictions, invariants, no generation) | docs "Jev 1.13 jaggedness" | ✅ | Assumed to apply to our judges too: T0 handles numbers and dates; the Skeptic judge; escalate-only; `literal` and `numbers_dates` eval suites |
| MIT SDKs, n8n nodes, LLM adapter, agent skill; WorkflowEvals Apache-2.0 | github.com/typesafe-ai | ✅ | Optional: SDKs as compatibility test clients; adapter and evals as references. No service dependency. |
| Cookbooks (routing, guardrails, citation check, RAG filtering, function calling, skill suggestion, smart home) | docs cookbooks | ✅ | Used as design patterns for the DE use-cases (ARCHITECTURE §7.9) |
| Hosted service, pricing, rate limits, legal terms | docs | ✅ | **Not applicable**: nothing is sent to TypeSafe |
| jevai.net | jevai.net | ? template-built site; affiliation unverified | Ignored |

## 12. Reuse summary (what to take from where)

| From | Take (R = code, A = pattern) |
|---|---|
| **Hermes** (Nous Research, MIT) | R: channel adapters, wake word / STT / TTS modules, Home Assistant tool, memory provider contract, SKILL.md loader + guard, smart-approval prompt design. A: loop invariants, Footprint Ladder, tool registry/toolsets, cron, delegation caps, worktrees, kanban, ACP, Omarchy HUD rules |
| **OpenClaw** (OpenClaw Foundation, MIT) | A: gateway protocol (connect-first, pairing, idempotency, roles/nodes), queue modes, permission modes + 3-denials escalation, `/approve` rule, decision-model role + `decision_evaluate`, ONNX classifier set, Tauri v2 Linux packaging, Omarchy Quickshell plugin, specialist lanes, plugin hook names, Canvas |
| **SMF Praxis** (SMF Works, MIT; Praxis Prime's direct ancestor) | R: regulated vertical packs (bundled, approved by Michael), broker risk classes + compliance modes + timed revert, kill switch, dual approval, data_policy classes/retention/legal hold, memory forgetting, sensitivity router, jurisdiction profiles, vertical template structure, identity signing, security scan A–F, OWASP mapping, compliance attestation |
| **SMF Swarm 2.0** (SMF Works, MIT) | R: hash-chained audit, PermissionEngine, IdentityRegistry, capability diagnostic, report schema, personas as worker roles **and as Decision Engine Jury judge lenses** |
| **Omarchy** (DHH, MIT) | Integrate via its commands: `omarchy plugin …`, themed `*.tpl` templates, `bindings.lua`, default-agent mechanism, `~/.agents/skills` |
| **TypeSafe** (reference only) | A: public API *shape*, primitives, documented failure modes, cookbook patterns. Optional MIT SDKs as compatibility test clients. **No hosted Jev, no service dependency.** |
| **Claude Code / Codex / Cursor** (proprietary products; public docs only) | A: hook event model, permission-mode vocabulary, AGENTS.md discovery + size cap, bubblewrap sandbox approach, network-off default, `.mdc` rules, cloud-agent artifacts. **No code reused.** |
| **Grok Bot** (product brief) | A: routines + event triggers, approval cards + auto-review, persistent box with browser, subagents, teammates/channels, voice memos |
