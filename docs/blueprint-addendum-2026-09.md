# Praxis Prime — Blueprint Addendum A (2026-09-30)

> **Status:** owner-approved design, landed as this file on 2026-09-30. It stays one document (themes, onboarding, OpenShell, remote access, Windows, and profiles together). [`ARCHITECTURE.md`](ARCHITECTURE.md) §29 follows the M0–M8 order in §8. The other stance changes in the table below stay in this addendum until those sections are revised.
> **Requested by:** Michael (SMF Works), 2026-09-30.
> **Scope:** five additions (themes, no default LLM, NVIDIA OpenShell, any-device + Windows, multi-user/multi-profile) and a re-ordered roadmap.
> **Baseline:** `smfworks/praxis-prime` main @ `029b5ccc` (2026-09-30 07:44 ET). Reference clones, all read-only: NVIDIA/OpenShell @ `5acaaba1`, NousResearch/hermes-agent @ `f42f579c`, openclaw/openclaw @ `1de9a42f`, and the six `smfworks/smf-praxis-*` pack repos (HEADs as of 2026-09-30 08:29 ET).

### How to read this document

- **[V]** = verified against a primary source (repo file or official doc) cited in §10.
- **[U]** = unverified. It needs a test on real hardware or a follow-up before we rely on it.
- **[E]** = an estimate or judgment call by the author, not a fact.
- **Attribution.** SMF Works does **not** own Hermes Agent (MIT, © 2025 Nous Research) or OpenClaw (MIT, © 2026 OpenClaw Foundation). This addendum borrows *ideas and patterns* from them. If code is ever copied, keep their MIT notices, per ARCHITECTURE §32. NVIDIA OpenShell is Apache-2.0 **[V]**. Praxis would call it as an external runtime; it is not vendored.

---

## 0. Decisions at a glance

| # | Topic | Decision |
|---|---|---|
| A | Themes | Declarative **theme packages** (`theme.toml` tokens + local assets + optional *restricted* `theme.css` + `THEME.md`). **No JavaScript, no remote resources, no raw CSS injection.** Validated on install: schema, size caps, WCAG 2.2 AA contrast, font licence allowlist. Seven built-in themes. Per-profile selection; an admin can lock it. Omarchy `colors.toml` stays as a live "system" theme. |
| B | No default LLM | Delete the hard-coded `ollama:qwen3:32b` defaults. On first run, chat is blocked until the user **explicitly picks** a provider in one of three lanes (this machine / my network / cloud) and it passes a **real completion test**. Nothing ever silently falls back to another provider. The web wizard and the `praxis-prime setup` CLI share one backend. |
| C | OpenShell | NVIDIA OpenShell is an Apache-2.0, Rust, policy-enforced sandbox runtime for agents. **No GPU is required.** It needs Linux ≥ 6.2 (Landlock ABI 3) plus Docker ≥ 28, Podman 5, k8s, or a microVM. **Make it the default sandbox tier for "regulated" installs on supported hosts**, with telemetry off and version pinning. Praxis's own approval spine stays in charge of SEND/SPEND. **Fallback:** bubblewrap + rootless Podman, with a visible "OpenShell unavailable" status. |
| D | Any device / Windows | Keep **loopback as the default**. Add opt-in `gateway.bind = tailnet | lan | proxy` modes that fail closed without account auth and TLS. Add an installable PWA. Windows = **WSL2-only** "supported beta" via a PowerShell/winget bootstrap. Difficulty: medium **[E]**. M365 (Entra OIDC, Teams connector, Intune/winget) is a separate, later milestone. |
| E | Multi-user / profiles | Real **accounts** (local passwords + passkeys, or OIDC) with roles `owner/admin`, `operator`, `viewer`, `auditor`. **Profiles** are separate homes: memory, skills, routines, dials, theme, provider allowlist. One worker process per active profile. Hash-chained audit records `actor=user, profile=…`. There is a profile picker. We say plainly where the isolation boundary is. |
| F | Packs | M0: ship `packs/compliance` inside the wheel, and write a **loader/port for the legacy `pack.json` + `knowledge.md` format** used by the six public MIT packs. It must ignore their `ollama-cloud/*` model pins and must not serve their dashboard JS. |
| G | Roadmap | M0 packaging/packs → M1 web shell + accounts + profiles → M2 onboarding (remove the Ollama default) → M3 themes → M4 OpenShell → M5 installers (Ubuntu/Omarchy, then WSL2) → M6 remote access + PWA hardening → M7 Tauri desktop → M8 Microsoft 365. See §8. |

### Changes to existing ARCHITECTURE.md stances

§29 is applied in [`ARCHITECTURE.md`](ARCHITECTURE.md). The other rows are the edits to make when those sections are revised.

| Section | Today | Change |
|---|---|---|
| §2 Non-goals | "No Windows or macOS builds in v1.0"; "single-user or small-team" | Windows **via WSL2** becomes a supported beta target, with no native Windows build. "Small team" becomes "small team with accounts/roles on one server". Multi-tenant SaaS remains a non-goal. |
| §4 Gateway / remote | "Remote only via tunnel + pairing" | Add exposure modes (§4.2). The loopback-only assert in `gateway/server.py` becomes a *policy* check: allowed only when accounts auth + TLS are configured. |
| §6 Model router | "Ollama/llama.cpp + 2 cloud providers" with Ollama the default | No default provider. There is an explicit first-run choice (§2). |
| §13.1 Sandbox tiers | T1 bwrap, T2 Podman, T3 microVM, T4 remote | Add **T2-OS: OpenShell** (§3.5). It is the default for regulated installs. |
| §21 UX / UI | "Themes itself from Omarchy (§28.2)" | Add the theme engine (§1). Omarchy becomes one theme *source*. |
| §25 Config & paths | `profiles/<name>.toml` | Profiles become directories with an account/ACL model (§6). |
| §29 Roadmap | MVP / v0.5 / v1.0 | **Applied in this landing.** [`ARCHITECTURE.md`](ARCHITECTURE.md) §29 nests M0–M8 (§8) inside the same phases. |
| §31 Open question 12 (team mode before v1.0?) | open | Proposed answer: **yes, a minimal version** (accounts + roles + profiles in M1), because the owner wants a central server serving many devices. |

---
## 1. Themes: responsive UI with installable theme packages

### 1.1 Goals and non-goals

- **Responsive:** one React SPA covers phone (≥ 360 px), tablet, and desktop. Layout adapts at `sm` 640 / `md` 768 / `lg` 1024 / `xl` 1280, the Tailwind defaults already in the §23 stack.
  - Phone: single column, bottom navigation, approval cards as full-width sheets.
  - Tablet: two panes (sessions + chat, canvas as a drawer).
  - Desktop: the §21.1 three-pane layout.
- **Themes change *appearance only*.** A theme can never change behaviour, add UI, call the network, or run code.
- **AI-authorable:** a model given `THEME.md` (§1.5) and a brief ("dental office, calm mint") can produce a valid package in one pass. The validator gives actionable errors the model can fix.
- **Non-goal:** arbitrary CSS or JS "skins". Hermes skins let a `custom_css` field inject raw CSS into its desktop app (32 KiB cap) **[V]** (`hermes_cli/skin_engine.py`, `website/docs/user-guide/features/skins.md`). OpenClaw's Control UI is **tokens-only**: CSS colour values are validated, "definitions cannot load external stylesheets or resources", and definitions are size-capped **[V]** (`docs/tools/theme.md`). **Praxis follows the OpenClaw model**, with a small, parsed, allowlisted CSS escape hatch for decoration.

### 1.2 Token model

The existing §28.2 token names stay canonical, so Omarchy's `praxis-prime.json.tpl` keeps working. A shadcn-style semantic set is added for component coverage:

| Group | Tokens (CSS custom property `--pp-<token>`) |
|---|---|
| Surfaces | `bg`, `bgRaised`, `bgSunken`, `overlay` |
| Text | `fg`, `fgMuted`, `fgSubtle` (large text / decorative only) |
| Brand | `accent`, `accentFg`, `accentMuted`, `ring` (focus) |
| Lines | `border` (decorative), `borderStrong` (inputs and controls, must meet 3:1) |
| Status | `ok`, `warn`, `danger`, `info`, each with an `*Fg` companion |
| Agent-specific | `tool` (tool timeline), `selection`, `approval` (SEND/SPEND approval cards), `dialOff`, `dialMonitor`, `dialEnforce` |
| Code | `codeBg`, `codeFg`, plus 8 syntax slots `syn1`…`syn8` |
| Typography | `fontDisplay`, `fontBody`, `fontMono`; `scale` (1.125–1.333); `baseSize` (15–18 px); `lineHeight` |
| Shape and motion | `radius` (0–16 px), `density` (`compact`/`cozy`/`comfortable`), `borderWidth`, `motion` (`none`/`subtle`/`standard`, always forced to `none` under `prefers-reduced-motion`) |
| Ornament (optional) | `ornamentHeader`, `ornamentDivider`, `watermark` refer to **package-local** sanitized SVG/PNG assets; `watermarkOpacity` ≤ 0.06 |

Safety-critical colours (`approval`, `danger`, the dial states) have **floors**:
- A theme may restyle them, but the validator enforces contrast.
- The approval card always keeps a text label and an icon, never colour alone (WCAG 1.4.1).
- An admin policy can pin them organisation-wide.

### 1.3 Package format

```
praxis-theme-legal-office/
├── theme.toml          # required: manifest + tokens
├── THEME.md            # required: human/AI-readable description, credits, preview notes
├── LICENSE             # required: licence of the package itself (MIT/Apache-2.0/CC-BY-4.0/CC0)
├── assets/
│   ├── fonts/          # optional: WOFF2 only; each family needs its OFL.txt / LICENSE
│   │   ├── LibreBaskerville-Regular.woff2
│   │   └── OFL.txt
│   ├── ornaments/      # optional: SVG (sanitized) or PNG/WebP, ≤ 256 KiB each
│   └── preview.png     # optional: 1200×750 screenshot for the gallery
└── theme.css           # optional: restricted CSS (§1.4); rejected if it breaks any rule
```

`theme.toml` (schema `praxis.theme/v1`):

```toml
schema   = "praxis.theme/v1"
id       = "smf.legal-office"            # reverse-DNS-ish, [a-z0-9.-], ≤ 64 chars
name     = "Legal Office"                # ≤ 80 chars
version  = "1.0.0"                       # semver
license  = "MIT"                         # SPDX id of the package
authors  = ["SMF Works"]
description = "Navy, parchment and burgundy; book-serif headings."   # ≤ 320 chars
modes    = ["light", "dark"]             # at least one
default_mode = "light"
min_praxis = "0.6.0"

[fonts]
display = { family = "Libre Baskerville", files = ["assets/fonts/LibreBaskerville-Regular.woff2", "assets/fonts/LibreBaskerville-Bold.woff2"], license = "OFL-1.1", fallback = "Georgia, serif" }
body    = { family = "Source Sans 3", files = ["assets/fonts/SourceSans3-Variable.woff2"], license = "OFL-1.1", fallback = "system-ui, sans-serif" }
mono    = { family = "Source Code Pro", files = ["assets/fonts/SourceCodePro-Variable.woff2"], license = "OFL-1.1", fallback = "ui-monospace, monospace" }

[shape]
radius = 6
density = "cozy"
motion = "subtle"
scale = 1.2
baseSize = 16

[tokens.light]
bg = "#f7f3ea"; bgRaised = "#ffffff"; fg = "#1b2233"; fgMuted = "#4d5566"
accent = "#1f3a68"; accentFg = "#ffffff"; danger = "#8c1c2b"; ok = "#2e6b3f"; warn = "#8a5a00"
border = "#d6cfbf"; borderStrong = "#8a8272"; ring = "#1f3a68"
# … every required token (see THEME.md); omitted optional tokens are derived

[tokens.dark]
bg = "#0f1522"; bgRaised = "#172033"; fg = "#ece6d8"; fgMuted = "#a9b0bf"
accent = "#c9a45c"; accentFg = "#0f1522"; danger = "#e57373"; ok = "#7cc48a"; warn = "#e0b04a"
border = "#2a3550"; borderStrong = "#6b7896"; ring = "#c9a45c"

[ornaments]
divider = "assets/ornaments/rule.svg"
```

Rules:
- Colours are hex (`#rgb`, `#rrggbb`, `#rrggbbaa`) or `oklch()`. Nothing else, so no `url()`, `var()`, or `expression` can sneak in.
- Derived tokens (e.g. `bgSunken`, `accentMuted`, `*Fg`) are computed by the engine in OKLCH when omitted.
- On install, `theme.lock.json` is written: the SHA-256 of every file plus the package hash. The UI shows the hash. Signed packages (minisign/Sigstore) are **optional** in v1, and an admin policy can require them.

### 1.4 Safety model (no arbitrary JS; sanitized CSS only)

| Threat | Control |
|---|---|
| Script execution | No JS files are accepted (any `.js/.mjs/.html/.wasm` means reject). SVGs are parsed and re-serialised through an allowlist (shapes, paths, gradients, `<title>`). They are stripped of `<script>`, `<foreignObject>`, event attributes, `href`/`xlink:href` to anything but `#fragment`, `<style>`, and external refs. SVGs are only ever rendered via `<img>` or CSS `background-image`, never inlined. |
| Data exfiltration / tracking | Nothing leaves the package: every `url()` must resolve to a package-local asset rewritten to `/themes/<id>/<hash>/…`. The CSP for the SPA is `default-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'`, with no `unsafe-inline` for scripts. |
| UI spoofing (hiding approval buttons, faking "approved") | `theme.css` is parsed with a real CSS parser (e.g. `lightningcss`/`csstree`) and must be **only**: (a) `:root`/`[data-mode]` custom-property declarations for `--pp-*` tokens; (b) rules on an **allowlisted set of decorative hooks** (`.pp-ornament-*`, `.pp-header-band`, `.pp-sidebar-texture`, `.pp-divider`) with an allowlist of properties (colours, backgrounds from local assets, borders, border-radius, box-shadow, letter-spacing, text-transform, font-feature-settings). **Rejected:** `@import`, `@font-face` (fonts come from the manifest only), `@namespace`, remote `url()`, `content:` (text injection), `display/visibility/opacity/position/z-index/transform/pointer-events/clip*/filter` (which could hide or overlay controls), `!important`, attribute selectors, `:has()`, and anything targeting `.pp-approval*`, `.pp-dial*`, or `.pp-audit*`. |
| Unreadable UI | WCAG 2.2 AA is enforced at install for **each mode**: `fg`/`fgMuted` on `bg`/`bgRaised` ≥ 4.5:1; `accentFg` on `accent` ≥ 4.5:1; status colours on `bg` ≥ 4.5:1; `borderStrong`/`ring` ≥ 3:1 (non-text contrast, 1.4.11). A failure means reject, with the exact pair and ratio. ARCHITECTURE §21.7 already requires AA. |
| Licence contamination | Fonts must be WOFF2 with a bundled licence file. The SPDX id must be in the allowlist `OFL-1.1`, `Apache-2.0`, `MIT`, `CC0-1.0`, `Ubuntu-font-1.0`. Assets must be `CC0/CC-BY/MIT/Apache/OFL`. Unknown means reject. |
| Zip bombs / path traversal | Uploads are ≤ 5 MiB compressed and ≤ 15 MiB expanded, ≤ 200 files. No symlinks, absolute paths, or `..`. Extraction happens into a temp dir, then an atomic move. |
| Supply chain | Themes are data, not code. The optional signature (above) plus the hash appear in the audit log (`theme.install`, `theme.activate`). |

### 1.5 `THEME.md`: authoring guide (normative)

Every package carries a `THEME.md`. The repo ships `docs/THEME-AUTHORING.md`, the guide an AI or human follows. It includes the full token table, the rules above, and this recipe:

1. **Brief → palette.** Choose 1 neutral ramp (bg → fg), 1 accent, and status colours. Work in OKLCH. Keep chroma low for large surfaces.
2. **Pair fonts** only from the OFL/Apache allowlist. Name them in `[fonts]` with fallbacks, and bundle WOFF2 + `OFL.txt`.
3. **Fill `[tokens.light]` and/or `[tokens.dark]`.** Every *required* token (`bg bgRaised fg fgMuted accent accentFg border borderStrong ring ok warn danger`) must be present.
4. **Check contrast** with `praxis-prime theme lint <dir>`. Fix every reported pair.
5. **Ornaments are optional and subtle:** watermark opacity ≤ 0.06, and nothing behind body text above 0.03.
6. **Write `THEME.md`:** what it is for, colours and fonts with licences, credits, and screenshots.
7. **Pack it:** `praxis-prime theme pack <dir>` produces `<id>-<version>.praxis-theme.zip`.

A JSON Schema (`schemas/theme.v1.json`) is published so a model can self-validate. The lint output is machine-readable (`--json`) for AI fix-up loops.

### 1.6 Install, select, and govern

- **Web UI:** Settings → Appearance → *Install theme…* (drag/drop the `.zip`).
  - The server validates it and shows a preview (live-rendered in a sandboxed preview pane using the same token pipeline), the contrast report, licences, and the hash.
  - Then the user chooses **Install**. Admins can install for all profiles; users only for their own profile unless policy allows.
- **CLI:** `praxis-prime theme install <zip|dir>`, `theme list`, `theme lint`, `theme pack`, `theme remove`, `theme set <id> [--mode light|dark|system] [--profile p]`.
- **Storage:** built-ins live in the wheel (`praxis_prime/ui_themes/`, via `importlib.resources`). User themes go in `~/.local/share/praxis-prime/themes/<id>/<version>/`. System/admin themes go in `/var/lib/praxis-prime/themes/` (server installs).
- **Selection precedence:** admin lock > profile choice > user device preference (`prefers-color-scheme`) > Omarchy live theme (when running under Omarchy and the profile chooses "System (Omarchy)") > `smf.praxis`.
- **Delivery:** the server compiles the token set into a small static CSS file (`/themes/<id>/<hash>.css`) and serves the fonts. The SPA swaps a `<link>`, with no inline styles. The Omarchy inotify hot-swap (§28.2) re-renders into the same pipeline.
- **Packs may *recommend* a theme.** The legacy pack `theme` hints (`accent`/`panel`/`ok`) map to token overrides on the default theme (§7).

### 1.7 The seven built-in themes

All fonts below are in the `ofl/` tree of `github.com/google/fonts` (SIL Open Font License 1.1) **[V]** (checked 2026-09-30: Cinzel, Inter, Source Sans 3, Source Serif 4, Source Code Pro, Libre Baskerville, EB Garamond, IBM Plex Sans/Mono, Atkinson Hyperlegible, Lexend, Cormorant Garamond, Fraunces, Nunito, Figtree, Alegreya Sans, JetBrains Mono). Bundle the WOFF2 plus `OFL.txt`. Do not hot-link Google Fonts (local-first, and the CSP forbids it).

Core palettes (bg / raised / fg / muted / accent) were checked with the WCAG 2.x formula in [`scripts/contrast_check.py`](../scripts/contrast_check.py) (`python scripts/contrast_check.py`). **Every pair listed passes ≥ 4.5:1** for text in both modes **[V]** (computed). `borderStrong`/`ring` values will be tuned to ≥ 3:1 during M3.

| Theme (`id`) | Mood | Light core | Dark core | Typography | Ornament |
|---|---|---|---|---|---|
| **Praxis** (`smf.praxis`), default | Roman Praetorian Guard / Greek hoplite: disciplined, bronze and oxblood, marble; *tasteful, not costume* | bg `#f6f1e7` marble ivory · raised `#fffdf8` · fg `#231c17` · muted `#5e5247` · accent `#7a1f1f` oxblood | bg `#14110f` · raised `#1e1a17` · fg `#efe7da` · muted `#b3a894` · accent `#c08a3e` bronze | Display **Cinzel** (Roman inscriptional capitals; headings and wordmark only, small caps, tracking +4%); body **Inter**; mono **JetBrains Mono** | Thin meander (Greek key) divider SVG; optional laurel-and-shield crest watermark at 4% opacity (avoid eagle/aquila and fasces motifs, which carry unwanted political connotations). No helmets on every page. |
| **Legal Office** (`smf.legal-office`) | Chambers, case reporters, restraint | bg `#f7f3ea` parchment · raised `#ffffff` · fg `#1b2233` · muted `#4d5566` · accent `#1f3a68` navy | bg `#0f1522` · raised `#172033` · fg `#ece6d8` · muted `#a9b0bf` · accent `#c9a45c` brass | Display **Libre Baskerville** (or **EB Garamond**); body **Source Sans 3**; mono **Source Code Pro** | Hairline double rule; burgundy (`#8c1c2b`) reserved for `danger`/privilege flags |
| **Forensic Engineering** (`smf.forensic`) | Lab bench, blueprint, evidence tags | bg `#f4f6f8` · raised `#ffffff` · fg `#15191d` · muted `#4f5a65` · accent `#0b5c8c` blueprint | bg `#121416` graphite · raised `#1b1f23` · fg `#e6e9ec` · muted `#9aa4ae` · accent `#f2a900` safety amber | **IBM Plex Sans** (display + body), **IBM Plex Mono** (data, measurements, chain-of-custody IDs) | Faint 8 px engineering grid on canvas at 3%; tabular numerals on |
| **Education** (`smf.education`) | Friendly, legible, K-12 staff and families | bg `#f8fafc` · raised `#ffffff` · fg `#0f172a` · muted `#475569` · accent `#1d4ed8` (matches the education pack's accent) | bg `#0f172a` · raised `#1e293b` · fg `#f1f5f9` · muted `#a3b1c6` · accent `#60a5fa` | Display **Lexend**; body **Atkinson Hyperlegible** (designed for low-vision legibility); mono **JetBrains Mono**; `baseSize` 17 | Rounded (`radius` 10); `comfortable` density |
| **Classical / Socratic** (`smf.classical`) | WisdomForge lineage: great books, dialogue, lamplight | bg `#f5efe3` stone · raised `#fcf8f0` · fg `#221d16` · muted `#5b5041` · accent `#5b6b2f` olive/laurel | bg `#0a0a0f` · raised `#13131a` · fg `#f3eadc` · muted `#b5a48c` · accent `#c9a96e` antique gold — **taken from smfwisdomforge.com's live CSS tokens** **[V]** | Display **Fraunces** (as WisdomForge) or **Cormorant Garamond**; body **Source Sans 3** (as WisdomForge) or **Alegreya Sans**; mono **Source Code Pro** (as WisdomForge) | Dark mode is the default. Optional column-capital divider. The "Socratic" prompt style belongs to the pack/persona, not the theme. |
| **Medical Office** (`smf.medical`) | Calm, clinical, trustworthy, high-contrast | bg `#f7fafa` · raised `#ffffff` · fg `#10222a` · muted `#46606a` · accent `#0e7490` teal (matches the medical pack's accent) | bg `#0c1a1f` · raised `#13262d` · fg `#e8f2f4` · muted `#9db7bf` · accent `#4fc3d9` | **Inter** (display + body; tabular numerals for vitals and dates); mono **JetBrains Mono** | None. PHI badges use `info`/`warn` with labels. `motion = none` by default. |
| **Dental Office** (`smf.dental`) | Fresh, gentle, reassuring; mint and aqua | bg `#f6fbfa` · raised `#ffffff` · fg `#12302c` · muted `#4a6661` · accent `#0f766e` deep mint | bg `#0d1b1a` · raised `#142826` · fg `#e9f6f4` · muted `#9fc2bc` · accent `#5eead4` | Display **Nunito** (rounded); body **Figtree**; mono **JetBrains Mono** | Soft radius 12; no clinical imagery |

An eighth, **"High Contrast"** (AAA, Atkinson Hyperlegible, pure black/white, yellow focus ring), is recommended for accessibility, following OpenClaw's AAA "Beacon" theme idea **[V]** (`docs/tools/theme.md`). It is not in the requested seven but costs almost nothing.

---
## 2. No default LLM: first-run onboarding and provider selection

### 2.1 What has to change in the code (verified current state)

| Location (main @ 029b5ccc) | Today | Change |
|---|---|---|
| `packages/prime-core/praxis_prime/router/settings.py:22` | `_DEFAULT_MODEL = "ollama:qwen3:32b"` | `None`. The router raises `InferenceNotConfigured` (UI: "Choose a model provider") instead of guessing. |
| `packages/prime-core/praxis_prime/config.py` (≈ l. 68–92) | primary `ollama:qwen3:32b`, utility `ollama:qwen3:8b`, vision `ollama:qwen2.5-vl`, Decision Engine tiers/judges on Ollama | All default to unset. The wizard writes them. The Decision Engine T2 judge also stays unset until chosen; T0 rules + T1 ONNX classifiers still work without an LLM. |
| `router/types.py:108` | error text "Start Ollama…" | Neutral text: "No model provider is configured. Run `praxis-prime setup` or open the web UI." |
| `README.md`, `doctor` | "Ollama is the default provider"; `doctor` probes Ollama | README describes the choice. `doctor` checks the *configured* provider and lists detected local servers as information. |
| Legacy packs (§7) | `pack.json` `"model": "ollama-cloud/…:cloud"` | **Ignored** as a default. At most shown as "pack author suggests …", and never selected automatically (it is a cloud route, and HIPAA-relevant). |

Known provider kinds stay `ollama`, `openai-compatible`, `openai`, `anthropic`, `xai` **[V]**. We add `llamacpp`, `vllm`, and `lmstudio` as named presets of `openai-compatible` (they all speak `/v1/chat/completions`), plus optional `google`, `openrouter`, `mistral`, `groq`, `azure-openai`, `bedrock` presets later. Secrets move from env-only to keychain / `secrets.env.age`, which §25 already specifies.

### 2.2 What we borrow (and from whom)

- **OpenClaw — explicit choice, verify, never auto-select [V].** From `docs/start/wizard.md`: onboarding offers *Quick start* / *Custom setup*. "Both lanes require an explicit provider choice before a live completion or any provider installation, model selection, or credential write."
  - Quick start first runs a **read-only detection pass**: configured models, API-key env vars, local AI CLIs, and installed tool-capable models on reachable Ollama/LM Studio. It "never downloads a model".
  - Only the chosen connection is tested with a real completion. A failure does not fall through to another provider.
  - *Skip for now* prepares the workspace but is "not a working AI connection". "Inference ready" appears only after verification.
  - Source: `src/commands/onboard-guided.ts`, `onboard-inference.ts`, `onboard-inference-ambient.ts` (`detectAmbientInferenceBackends`), `onboard-custom.ts` (custom base URL + key + compatibility + model id, verified before save).
  - `docs/gateway/local-model-services.md` also describes starting a local server on demand (`localService`: health probe, spawn, idle stop).
- **Hermes — mode picker, local probes, credential guard, context floor [V].**
  - `hermes setup` (`hermes_cli/setup.py`, `run_setup_wizard`; `_FIRST_TIME_MODES` at l. 662) offers **Quick Setup** (Nous Portal OAuth), **Full Setup** (bring your own keys: Model & Provider → Terminal Backend → Messaging → Tools), and **Blank Slate** (`setup_quick.py`: provider/model plus file and terminal tools only).
  - Re-running shows current values; `--quick` fills only missing items. It backs up config before writing. Non-TTY runs print guidance instead of prompting.
  - Local servers: `hermes_cli/models_local.py` probes Ollama `/api/tags` and LM Studio `/api/v1/models` (load-on-demand). Custom endpoints: `model_setup_flows_custom.py` probes `/models` and context length.
  - `hermes_cli/models_detect.py` adds guards so the user is never "put … on a provider they never selected" and never auto-switched to a provider they hold no credentials for. It cites a real billing incident ("the $100 Astra incident").
  - Hermes requires **≥ 64K context** and rejects smaller models at startup (`website/docs/getting-started/quickstart.md` l. 157–158).
  - Hermes Desktop can download a pinned llama.cpp with a hardware-fit model catalog (`website/docs/user-guide/local-models.md`). That is a later nice-to-have for Praxis.
- **What Praxis does differently:**
  - No vendor-portal "recommended" lane; SMF has no portal, and neutrality matters for regulated buyers.
  - Compliance-aware: when HIPAA/FERPA/COPPA/GDPR/PCI dials are at monitor/enforce, cloud choices show a warning: "Requires a BAA/DPA with the provider; PHI will leave this machine".
  - A *network* lane as a first-class option (DGX Spark / GPU box).

### 2.3 The flow (web wizard and CLI share one backend)

The backend is a new gateway API, `onboarding.*`: `detect`, `probe(endpoint)`, `test(provider, model)`, `save(selection)`, `status`. The web wizard (M2) and `praxis-prime setup` (TUI/CLI, plus `--non-interactive --provider … --model … --base-url … --api-key-env …` for scripted installs) both call it.

```
Step 0  Welcome & security note   ─ loopback/remote status, what data leaves the machine
Step 1  Where should Praxis think? (explicit choice required; nothing preselected)
        ○ On this computer        ○ On my network        ○ Cloud provider        ○ Skip for now
Step 2  Lane-specific setup (below)
Step 3  Pick models by role       ─ primary (chat/tools), utility (cheap/fast), vision (optional),
                                     Decision-Engine judge (optional; T0/T1 work without it)
Step 4  Live test                 ─ real completion + tool-call round trip + context-length check
Step 5  Done → "Inference ready"  ─ written to config; audit event `provider.configured`
```

**Lane 1: On this computer.** The detect pass is read-only and never downloads or starts anything without consent.

| Server | Default probe | Model listing | Notes |
|---|---|---|---|
| Ollama | `http://127.0.0.1:11434` | `GET /api/tags` (native); OpenAI-compat at `/v1` | Offer "pull a model" only after explicit choice; show size/VRAM fit. |
| llama.cpp `llama-server` | `http://127.0.0.1:8080` | `GET /v1/models`, `GET /props` (ctx) | Warn if `n_ctx` < 32K (Praxis floor, §2.4). |
| vLLM | `http://127.0.0.1:8000` | `GET /v1/models` (returns `max_model_len`) | Common on DGX / RTX boxes. |
| LM Studio | `http://127.0.0.1:1234` | `GET /v1/models` (+ LM Studio native API if present) | Hermes uses LM Studio's native `/api/v1/models`, which supports load-on-demand. |
| Other OpenAI-compatible (SGLang, TGI, LocalAI, Lemonade) | user-entered | `GET /v1/models` | Generic preset. |

If nothing is found, show one-click-copy install instructions per distro (Ubuntu apt/snap/curl; Omarchy `pacman`/AUR), not an automatic install.

**Lane 2: On my network** (DGX Spark, RTX box, AMD/ROCm box).
- **Manual entry first:** a base URL (`http(s)://host:port/v1`), an optional API key, and a TLS option ("trust this certificate fingerprint" for self-signed; the fingerprint is pinned and shown).
- **Optional discovery, with explicit consent** (it touches the LAN):
  - (a) mDNS/DNS-SD browse for `_ollama._tcp`, `_openai._tcp`, and a Praxis-defined `_praxis-infer._tcp` (not yet a standard; we would advertise it from Praxis server installs);
  - (b) the Tailscale peer list via `tailscale status --json` when Tailscale is present;
  - (c) a bounded probe of the /24 on known ports 11434/8000/8080/1234, only when the user clicks "Scan my network". It is rate-limited and logged.
- **Test:** `GET /v1/models` → pick a model → a real chat completion with a tool call → read the context length (from `max_model_len`/`/props`/`/api/show`, else ask). Show latency and tokens/s.
- **Egress policy:** a network endpoint is recorded as `locality = "lan"`. Compliance dials treat `lan` as on-prem when the host is in the admin's "trusted inference hosts" list; otherwise they warn. OpenShell blocks private IPs by default, so regulated installs add an `allowed_ips` entry for exactly this host (§3.5).
- **Hardware notes shown in UI** (informational):
  - DGX Spark = GB10, 128 GB unified memory, DGX OS (Ubuntu-based, arm64) **[V]** (nvidia.com product page); typical servers are vLLM / Ollama / NIM **[U]**, whichever is installed.
  - AMD boxes: vLLM-ROCm, llama.cpp-HIP, or Ollama-ROCm all expose OpenAI-compatible endpoints. Praxis does not care which GPU is behind the URL.

**Lane 3: Cloud provider.**
- Pick a provider, paste a key (stored in the keychain, never in `config.toml`), fetch the live model list, test.
- A cost notice shows the provider's pricing link; we do not hard-code prices.
- Regulated-dial warning as above.
- An OAuth lane (e.g. "Sign in with …") is out of scope for M2.

**Skip for now.** The daemon runs; chat shows a persistent "Inference not configured" banner. Non-LLM features (routines without LLM steps, T0/T1 Decision Engine, audit, compliance dashboard) still work.

### 2.4 Rules (normative)

1. **No provider is ever selected implicitly.** Not from env vars, not from detection, not from pack hints. Detection results are *offers*.
2. **No silent fallback.** If the chosen provider fails at runtime, the task pauses with an actionable error. Automatic failover only exists if the user configured an explicit ordered fallback list, and each entry must have passed its own test. Regulated dials can forbid cloud entries in that list.
3. **Verify before "ready".** A real completion plus a tool-call round trip. Store the test result, timestamp, and model id in the audit log.
4. **Context floor:** warn below 32K; block below 16K for agent mode. [E] These numbers are proposed; Hermes uses a hard 64K floor.
5. **Secrets:** keychain / `secrets.env.age` only, and never echoed back. `setup` backs up `config.toml` before writing (Hermes pattern).
6. **Re-runnable:** `praxis-prime setup` shows current values. `praxis-prime setup --section models` edits only the models. `praxis-prime model` is a quick switcher.
7. **Per-profile:** each profile (§6) can have its own provider/model selection, restricted by the admin's provider allowlist.

---
## 3. NVIDIA OpenShell

### 3.1 What it is **[V]**

NVIDIA OpenShell (`github.com/NVIDIA/OpenShell`, docs at `docs.nvidia.com/openshell/latest/`) describes itself as "the safe, private runtime for fleets of autonomous AI agents". It is an **open-source sandbox runtime and control plane for agents**, written in Rust. It is not a model, not a GPU runtime, and not a shell replacement.

| Component | Role |
|---|---|
| **Gateway** | Control plane: sandbox lifecycle, policy, provider (credential) management, and the API/CLI endpoint. Package installs run it as a **systemd user service** `openshell-gateway` (config `~/.config/openshell/gateway.toml`), listening on `https://127.0.0.1:17670` with mTLS for local single-user use. |
| **Supervisor** | Trusted process *outside* the workload. It mediates the workload's network and process activity and enforces policy. If it disconnects, **the sandbox freezes the agent** (fail closed) (`docs/about/architecture.mdx`). |
| **Sandbox** | The workload: an OCI image (default `nvcr.io/nvidia/base/ubuntu:24.04`), run on Docker, Podman, Kubernetes, or a libkrun microVM, as a non-root user with no capabilities. |

Security and compliance controls it provides:
- **Filesystem:** Landlock rules (`filesystem_policy`, `landlock`). A mandatory baseline protects OpenShell's private files.
- **Process:** seccomp, non-root, no capabilities.
- **Network:** default deny. All TCP/DNS goes through the supervisor. Rules are **per binary**, with **L7 inspection** of HTTP, GraphQL, and MCP methods (`network_policies`, `network_middlewares`).
  - Private IPs are blocked for undeclared, wildcard, or hostless endpoints.
  - **Loopback, link-local, and `0.0.0.0` are always blocked** and cannot be re-allowed (`docs/security/best-practices.mdx`).
  - Host-local services are reached via `host.openshell.internal` (`docs/how-it-works/inference.mdx`).
- **Credential isolation:** "providers" hold real credentials and substitute them **only at endpoints authorised by the provider profile**. The agent never sees raw keys.
- **Policy lifecycle:**
  - Declarative YAML (`version: 1`). Layers: global admin policy → sandbox policy → image policy → restrictive default.
  - A **policy advisor** lets the agent *propose* rules for a human to approve.
  - A **formal-verification policy prover** (`openshell-prover`, usable in CI) checks policies.
  - Blocked actions return descriptive errors so agents can adapt.
- **Audit:** OCSF JSON event export for SIEM. NVIDIA explicitly calls collection "best-effort, not a guarantee of complete audit history" (`docs/observability/ocsf-json-export.mdx`).
- **Multi-user:** "workspaces" with Platform Admin / Workspace Admin / User roles and OIDC (`docs/how-it-works/workspaces.mdx`). A broader multi-player design is still an RFC draft (`rfc/0011-multi-player-design`).
- **SDKs:** Python (`openshell` package, e.g. `sandbox.create/exec/delete/wait_ready`), TypeScript, Go, Rust.

### 3.2 Licence **[V]**: Apache-2.0 (the owner's belief is correct)

- The `LICENSE` file is Apache License 2.0, "Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES". The Cargo workspace declares `license = "Apache-2.0"`, and `docs/resources/license.mdx` agrees. Source files carry SPDX headers.
- Compatible with Praxis's MIT licence. If we ever **redistribute** OpenShell binaries, we must ship the Apache-2.0 licence text and any NOTICE, and mark modifications. Calling an installed binary or SDK needs nothing beyond attribution in docs.
- **Separately:** container images such as `nvcr.io/nvidia/base/ubuntu:24.04` come from NGC and may carry their own terms **[U]**. Check before a regulated default depends on that image. Praxis should default to its own Ubuntu/Debian-based sandbox image.

### 3.3 Platform requirements **[V]** (`docs/about/support-matrix.mdx`)

| Requirement | Detail | Consequence for Praxis |
|---|---|---|
| Host OS | **Supported:** Linux Debian/Ubuntu x86_64 **and arm64**; macOS Apple Silicon (Docker Desktop). **Experimental:** Windows (WSL 2 + Docker Desktop), x86_64 only. | Ubuntu is first-class. Arch/Omarchy is **not listed**, so it is best-effort **[U]**: the static binaries should run if kernel features pass, but that is untested. WSL2 is experimental, so it is not a regulated default. |
| Kernel | **Landlock ABI ≥ 3 (Linux ≥ 6.2) and enabled**; seccomp user-notification features; `WAIT_KILLABLE_RECV` (5.19+) recommended. "A kernel version alone does not establish support." The sandbox probes actively and **fails closed**. | Ubuntu 24.04 (6.8) passes. **Ubuntu 22.04 GA (5.15) fails**; it needs the HWE kernel. Arch (current kernel) passes if Landlock is in the LSM list **[U]** per machine. DGX OS: Ubuntu-based arm64 **[U]** kernel version per release; the doctor check decides. |
| Runtime | Docker Engine/Desktop **≥ 28.0**, or **Podman 5.x** (rootless, cgroups v2, user socket), or **Kubernetes ≥ 1.29** via Helm (the CNI must enforce NetworkPolicy), or **MicroVM** (libkrun; needs KVM). | Praxis already prefers rootless Podman (§13.1), so default to Podman 5. Docker 28 is an alternative. |
| libc | CLI is static musl; `openshell-gateway` needs glibc ≥ 2.28. | Fine on all targets. |
| **GPU** | **Not required.** Optional GPU access via NVIDIA CDI (Docker/Podman), `nvidia.com/gpu` (k8s), or single-GPU passthrough (VM) (`docs/how-it-works/sandboxes/runtimes.mdx`). | Works on any Praxis host. GPU passthrough only matters if a sandboxed *tool* needs the GPU. Inference usually runs outside the sandbox. |
| Install | `curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh \| sh` installs a `.deb`/`.rpm` (systemd user service), or a snap (needs non-snap Docker), or Homebrew. | Praxis installer offers it with consent and a pinned version. We verify the package checksum/signature rather than piping to sh. |
| Telemetry | **On by default** (anonymous). Disable with `OPENSHELL_TELEMETRY_ENABLED=false` (Helm: `server.telemetryEnabled=false`); it propagates to supervisors. Telemetry-free builds are possible with `--no-default-features --features defaults-without-telemetry` (`docs/observability/telemetry.mdx`). | **Praxis always sets telemetry off** and asserts it in `doctor`. This is required for regulated installs. |
| Maturity | Latest tags **v0.1.0 → v0.1.2**, published between about 2026-09-25 and 2026-09-27 (ET), after a long v0.0.x series (GitHub releases page). Weekly stable cadence; security fixes for N and N-1 (`rfc/0014-release-stability`). Native Windows (`rfc/0013-native-windows-mxc`) is in review, not shipped. | Young and fast-moving. Pin versions, run a compatibility test matrix, and track N/N-1. |

### 3.4 Ecosystem precedent **[V]**

- **NVIDIA NemoClaw** (`github.com/NVIDIA/NemoClaw`, **Apache-2.0**): "an open source reference stack for running supported AI agents more safely inside NVIDIA OpenShell sandboxes". It supports **OpenClaw (default), Hermes, and LangChain Deep Agents Code**, with guided onboarding, managed inference, and network policy. It offers express install presets for **DGX and WSL** hosts (README).
- NVIDIA's DGX Spark product page markets "NVIDIA Agent Toolkit with NVIDIA OpenShell".
- **OpenClaw** has an OpenShell sandbox backend (`docs/gateway/openshell.md`). It drives the `openshell` CLI + SSH, requires OpenShell ≥ v0.0.88, and offers "mirror" (sync the workspace in and out) and "remote" workspace modes.
- **Implication:** OpenShell is becoming the NVIDIA-blessed containment layer for exactly Praxis's product category. Being a well-behaved OpenShell citizen (and possibly a NemoClaw-supported agent later [E]) is strategically useful, especially on DGX Spark.

### 3.5 How Praxis integrates it: sandbox tier **T2-OS**

**Two stages:**

1. **M4a: tool sandbox (T2-OS).** The daemon stays on the host. Every `shell`, code-execution, build, browser, and untrusted-MCP tool call for a session runs inside a per-session OpenShell sandbox, created through the Python SDK (preferred) or the CLI (OpenClaw's approach). The workspace sync pattern follows OpenClaw's "mirror" mode.
2. **M4b: contained agent worker.** For regulated profiles, the **whole per-profile agent worker** (§6.4) runs inside an OpenShell sandbox. That is the NemoClaw model. The gateway, approval spine, audit chain, and UI stay on the host outside the sandbox. LLM calls leave only through an OpenShell provider bound to the admin-approved inference endpoint, and connectors go through per-binary L7 rules. This gives kernel-enforced egress control over the agent itself, not just its tools.

**Policy compilation.** Praxis dials and policy (§16–17) compile to OpenShell policy YAML:
- `filesystem_policy`: workspace rw, `/tmp`, nothing from `$HOME` unless mounted.
- `network_policies`: one entry per allowed destination, e.g. the chosen inference host (with `allowed_ips: ["10.0.5.20/32"]` for a LAN DGX), package mirrors during builds only, MCP servers with method-level rules.
- `providers`: inference keys and connector tokens injected only at their endpoints, which replaces Praxis's env-var injection.

The compiled policy is:
- checked by `openshell-prover` in Praxis CI (golden policies per dial pack) and at runtime before activation;
- hash-recorded in the Praxis audit chain (`sandbox.policy.applied`).

**Division of responsibility (important):**
- OpenShell enforces *what the process can touch*. It does **not** replace Praxis's **approval spine**: human approval of SEND/SPEND/destructive actions, dual approval, Telegram/UI approval cards, and the Decision Engine.
- OpenShell's policy advisor proposals are routed into Praxis approval cards ("Agent requests network access to api.example.com:443 for `curl`"). They are approved by a user with the `admin` role, or `operator` if policy allows.

**Audit:** OCSF JSONL from OpenShell is tailed into the Praxis hash-chained audit as a separate stream. It is labelled "best-effort (per NVIDIA)", so Praxis's own audit of tool calls remains the system of record.

**Compliance dashboard** shows the containment tier per profile ("OpenShell 0.1.x · policy hash · prover ✓ · telemetry off"), or "Fallback: bubblewrap/Podman — reason: kernel lacks Landlock ABI 3".

### 3.6 Verdict: OpenShell as the default for regulated installs

**Recommendation [E]:** **Yes.** Make OpenShell the **default containment tier for the "Regulated" install profile** (any of HIPAA/FERPA/COPPA/GDPR/PCI/state packs at monitor or enforce) **when the host qualifies**:

- Ubuntu 24.04+ (or 22.04 with HWE ≥ 6.2), Debian (NVIDIA lists "Debian/Ubuntu"; the version floor is set by the kernel check [E]), or DGX OS, on x86_64 or arm64;
- `openshell doctor`-style qualification passes (Landlock ABI ≥ 3 active, seccomp features, cgroups v2);
- Podman 5.x rootless, or Docker ≥ 28;
- telemetry disabled; version pinned to a Praxis-tested release.

Arch/Omarchy: offer it and run qualification, but label it **"best-effort (not on NVIDIA's support matrix)"**.

**Fallback (automatic, visible, never silent):**
- Host does not qualify (WSL2, macOS, old kernel, no container runtime, user declines) → **T1 bubblewrap + Landlock/seccomp for shell, and T2 rootless Podman with egress proxy for builds/untrusted code**, i.e. the current §13.1 design.
- `doctor` and the compliance dashboard show "OpenShell unavailable: <reason>".
- **Admin option:** `sandbox.require_openshell = true` refuses to start regulated profiles without it (fail closed) instead of falling back.
- Non-regulated installs: OpenShell is opt-in (Settings → Security → "Use NVIDIA OpenShell").

**Do not bundle binaries initially.** Install via NVIDIA's packages with explicit consent and a pinned version. Revisit bundling (with the Apache NOTICE) once OpenShell hits a stable API.

**Caveats to state in docs:**
- OpenShell is 0.1.x.
- Its OCSF export is best-effort.
- It is technical containment, **not a certification**; HIPAA still needs BAAs, risk analysis, and so on.
- Loopback is always blocked from inside sandboxes, so host-local model servers must be reached via `host.openshell.internal` or a LAN address. That needs testing with each local server (Ollama binds 127.0.0.1 by default; it must listen on the bridge interface) **[U]**.

---
## 4. Any device: central server install + browser UI + PWA

### 4.1 Target topology

```
                        ┌──────────── Praxis server (DGX Spark / RTX box / any Linux host) ─────────────┐
 phone (PWA) ─┐         │  praxis-primed (gateway :18790, loopback)  ← reverse proxy / tailscale serve  │
 laptop ──────┼─ TLS ──▶│  per-profile agent workers (optionally inside OpenShell, §3.5)               │
 Windows PC ──┘         │  inference: vLLM / Ollama / llama.cpp (local GPU) or LAN/cloud per profile    │
                        └────────────────────────────────────────────────────────────────────────────────┘
```

**Principle:** the daemon keeps listening on **loopback only**. Remote reach is added *in front of it* by a component that terminates TLS and (ideally) authenticates. This preserves today's `gateway/server.py` invariant (`host` must be 127.0.0.1) for the default and the proxy/tailnet modes. Only the explicit `lan` mode binds a non-loopback address, and only after the gates below.

### 4.2 Bind / exposure modes (`[gateway] exposure = …`)

| Mode | How | Auth requirement | TLS | Recommended for |
|---|---|---|---|---|
| `loopback` (default) | 127.0.0.1:18790 | bearer token (today) or accounts | n/a | single machine |
| `tailnet` | `tailscale serve --https=443 http://127.0.0.1:18790`. Tailscale provides tailnet HTTPS certs and injects `Tailscale-User-Login` / `Tailscale-User-Name` identity headers, stripped from inbound requests to prevent spoofing, and absent for tagged devices and Funnel **[V]** (tailscale.com/docs/features/tailscale-serve) | **accounts auth**. Tailscale identity may be *mapped* to an account (verified with the local `tailscale whois` API, as OpenClaw's `gateway.auth.allowTailscale` does **[V]** in `docs/gateway/remote.md`), but never trusted for tagged devices | automatic | **default recommendation** for "reach it from anywhere" |
| `proxy` | Caddy/nginx/Traefik on the host terminates TLS (ACME or internal CA) and forwards to loopback. Optional identity-aware proxy (Cloudflare Access, oauth2-proxy, Authentik) passes a *signed* header/JWT | accounts auth (or trusted-proxy JWT verified against the IdP's keys) | required | offices with a domain; public exposure (discouraged) |
| `lan` | bind `0.0.0.0:18443` with Praxis-managed TLS (self-signed CA; clients pin the fingerprint; PWA install needs the CA trusted on the device) | accounts auth | required | isolated office LAN without Tailscale |

**Fail-closed rules** (same stance as both reference projects):
- Hermes' dashboard binds 127.0.0.1 with no login, and **refuses non-loopback binds unless an auth provider is configured**. It adds a DNS-rebinding Host-header guard and single-use WebSocket tickets **[V]** (`website/docs/user-guide/features/web-dashboard.md`).
- OpenClaw requires token/password/trusted-proxy auth for non-loopback binds and `wss://` for public hosts **[V]** (`docs/gateway/remote.md`).

Praxis:
1. refuses any non-loopback exposure unless accounts auth + TLS are configured;
2. enforces a Host/Origin allowlist (DNS-rebinding guard);
3. issues single-use, short-TTL WebSocket tickets;
4. sets secure, HttpOnly, SameSite=Strict session cookies, with CSRF tokens for mutations;
5. rate-limits and locks out logins;
6. writes every login, logout, and failure to the audit log.

`doctor` flags a public (non-RFC1918, non-tailnet) exposure in red.

### 4.3 Authentication

- **Local accounts:** argon2id password hashes, **passkeys (WebAuthn)** preferred, and TOTP as a second factor. Admin-enforced MFA for any role above `viewer` when exposure ≠ loopback.

  M1b implements the local factors on the loopback daemon: passkey enrollment and sign-in, TOTP as a second factor after the password or as a fallback when a passkey is not used, recovery codes, and the same 5-failure lockout as passwords. Passkey register, passkey remove, TOTP enroll, and TOTP disable over HTTP require a five-minute step-up (password plus TOTP or a recovery code, or a fresh passkey assertion). `account totp disable` stays password-only. Sign-in challenges are sealed and stored only once spent, so anonymous option calls cannot exhaust a cap. Passkeys require user verification. `account passwd` revokes passkeys. The loopback bearer token and `praxis-prime account` stay local-operator credentials and are not WebAuthn ceremonies. Telegram approvals are unchanged. OIDC is M1e. Requiring MFA whenever exposure is not loopback, and passkey re-authentication on SEND/SPEND, stay in M6.
- **OIDC:** generic OIDC (auth code + PKCE). Presets for **Microsoft Entra ID** (§5.4), Google Workspace, Authentik, Keycloak. Group/app-role claims map to Praxis roles.
- **Device pairing:** the §4 Ed25519 device pairing (planned, not built) becomes "remember this device" plus an admin-revocable device list.
- **API/automation tokens:** per-user, scoped, expiring. The existing single bearer-token file (`gateway/auth.py`, mode 0600) becomes the *owner's bootstrap token* (loopback only).

### 4.4 PWA

- `manifest.webmanifest` (name, short_name, `start_url`, `display: standalone`, theme colour from the active theme, 192/512 maskable icons).
- A service worker caches the app shell only. Chats, memory, and PHI are **not** cached offline (regulated default). An optional "offline read-only cache" can be enabled per profile when no regulated dial is on.
- Installability requires a secure context (HTTPS or localhost) plus the manifest and icons **[V]** (MDN).
- Push notifications (approval requests) via Web Push. On iOS, Web Push only works for PWAs added to the Home Screen (iOS 16.4+) **[U]**; verify during M6. Telegram approvals remain the robust mobile fallback.
- Mobile layout = §1.1 phone breakpoint. Approval cards are full-screen sheets with a biometric/passkey re-auth option for SEND/SPEND.

---

## 5. Windows via WSL2, and Microsoft 365 tenants

### 5.1 Approach: WSL2-only, no native Windows port (for now)

Praxis is Linux-native (systemd user units, bubblewrap, Landlock, Secret Service). Porting to native Windows would be a large rewrite of the sandbox and service layers. Hermes has since shipped native Windows/MSIX **[V]** (`website/docs/user-guide/windows-native.md`), but its WSL guide shows the WSL route is viable. OpenClaw's Windows support runs its Gateway inside WSL2 **[V]** (`docs/platforms/windows.md`). **Praxis: run the daemon inside WSL2 Ubuntu 24.04; the UI opens in any Windows browser.**

**Installer:** `PraxisPrimeSetup.ps1`, distributed through winget as a thin bootstrapper (§5.4). It:
1. checks Windows 11 (or Windows 10 21H2+ for GPU) and virtualization, then runs `wsl --install -d Ubuntu-24.04` (or imports a Praxis-branded rootfs [E]);
2. writes `/etc/wsl.conf` with `[boot] systemd=true` (default in current Ubuntu WSL images; needs WSL ≥ 0.67.6 **[V]**, learn.microsoft.com/windows/wsl/systemd) and `[automount] options="metadata"`;
3. installs Praxis inside WSL (the same `.deb`/installer as Ubuntu, M5a) and runs `loginctl enable-linger`;
4. configures networking (§5.2) and the keep-alive (§5.2);
5. checks GPU (§5.2), then opens `http://localhost:18790` in the default browser, where the M2 onboarding wizard starts.

### 5.2 Gotchas and how we handle them

| Gotcha | Fact | Handling |
|---|---|---|
| **WSL idles out; systemd does not keep it alive** | "systemd services do NOT keep a WSL instance alive" **[V]** (MS systemd doc). OpenClaw documents WSL ≥ 2.6.1 idle-terminating distros (microsoft/WSL #13416) and uses a **scheduled task at logon running `wsl.exe -d Ubuntu --exec dbus-launch true` as the user (not SYSTEM)** plus `loginctl enable-linger` **[V]** (`docs/platforms/windows.md`). Hermes uses a similar keep-alive trick **[V]**. | Installer registers a per-user Scheduled Task (at logon + on-idle restart). Optional `vmIdleTimeout` in `.wslconfig` **[U]** (confirm semantics per WSL version). Tray/status indicator in M7. |
| **Networking** | Default **NAT**: Windows→WSL `localhost` forwarding works, but LAN devices can't reach WSL without `netsh interface portproxy` + firewall rule, and the WSL IP changes. **Mirrored** mode (`networkingMode=mirrored`, Windows 11 22H2+) gives LAN access and two-way localhost, but needs a **Hyper-V firewall** rule (`New-NetFirewallHyperVRule`) **[V]** (learn.microsoft.com/windows/wsl/networking). DNS/VPN quirks in mirrored mode; `dnsTunneling`/`autoProxy` settings exist **[V]**. | Single-PC use: NAT + `localhost` is enough. "Serve other devices": prefer **Tailscale inside WSL** (`tailnet` mode, no port forwarding). Else mirrored mode + Hyper-V firewall rule written by the installer. Else (Win10) portproxy with an IP-refresh task, following OpenClaw's recipe. |
| **GPU** | CUDA on WSL needs the **Windows** NVIDIA driver only. Never install a Linux NVIDIA driver inside WSL. Windows 11 or Windows 10 21H2+, WSL kernel ≥ 5.10.43.3; NVIDIA Container Toolkit works **[V]** (MS "GPU accelerated ML training in WSL"). AMD: ROCm on WSL via ROCDXG for selected Radeon RX 7000/9000, PRO W7000/R9700, and Strix Halo, with specific Adrenalin + ROCm versions, Ubuntu 22.04/24.04 **[V]** (rocm.docs.amd.com WSL how-to). | Installer runs `nvidia-smi` inside WSL and reports. It warns if a Linux driver package is present. Most Windows users will pick **Lane 2 (network)** or **Lane 3 (cloud)** in onboarding, or run Ollama/LM Studio *on Windows* and point Praxis at `http://<windows-host>:11434` (mirrored mode makes this `localhost`). |
| **Filesystem** | `/mnt/c` via 9P is much slower than the Linux filesystem, and inotify there is unreliable (Hermes WSL guide cites 10–100× slower) **[V]**. | Keep Praxis data and workspaces in the Linux filesystem (`~`). Expose them to Windows via `\\wsl$\Ubuntu-24.04\home\…`. Warn when a coding-mode repo lives under `/mnt/c`. |
| **Sandboxing** | bubblewrap works in WSL2 if user namespaces are enabled **[U]**. OpenShell on WSL2 is **Experimental** and documented only with Docker Desktop **[V]**. WSL kernel Landlock ABI/enablement **[U]** (the WSL kernel is 6.6-based in recent releases **[U]**). | Regulated profiles on WSL: fallback tier (T1/T2) with the dashboard warning. **Don't market WSL as a regulated-grade host** until OpenShell's WSL status leaves Experimental. |
| **Keychain** | No Secret Service daemon by default in WSL. | Use `secrets.env.age` with a key protected by Windows DPAPI via a small helper [E], or `gnome-keyring` headless. Decide in M5b. |
| **Enterprise policy** | Intune can allow/deny WSL (`AllowWSL`, `AllowInboxWSL`, `*UserSettingConfigurable`) **[V]** (learn.microsoft.com/windows/wsl/intune). A WSL compliance plugin can require allowed distros/versions **[V]** (Intune WSL compliance doc). | Document the Intune settings an IT admin must allow. Ship distro/version values for the compliance plugin. |

### 5.3 Difficulty estimate **[E]**

| Piece | Effort (1 experienced engineer) | Risk |
|---|---|---|
| PowerShell bootstrap + winget manifest + WSL config + keep-alive task | 1.5–2 weeks | medium (WSL version drift) |
| Networking modes (NAT/mirrored/tailnet) + docs + doctor checks | 1 week | medium |
| GPU detection + guidance; Windows-side Ollama/LM Studio lane | 0.5 week | low |
| Secrets on WSL; sandbox fallback; CI on a Windows runner with WSL | 1–1.5 weeks | medium |
| **WSL2 supported beta total** | **≈ 3–5 weeks** | **Medium.** No kernel work; most risk is environmental. |
| Native Windows (no WSL) | 3–6+ months | high. Not recommended now; revisit if OpenShell native Windows (RFC 0013) ships. |

### 5.4 Microsoft 365 tenant deployment (M8)

| Need | Design | Notes |
|---|---|---|
| **Sign-in (Entra ID)** | OIDC authorization-code flow with **PKCE (S256)** against `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{authorize,token}` **[V]** (MS identity platform docs). Single-tenant app registration by the customer's admin. Redirect URI = the Praxis server URL. App roles (`Praxis.Admin`, `Praxis.Operator`, `Praxis.Viewer`, `Praxis.Auditor`) map to Praxis roles. Optional group claims map to profiles. Use a maintained OIDC library (MSAL is what Microsoft recommends **[V]**; `authlib` is fine for generic OIDC). | Requires HTTPS on the Praxis URL: Tailscale Serve, proxy, or an internal PKI cert. Conditional Access applies automatically at the IdP. |
| **Teams channel connector (optional)** | Bot Framework / Azure Bot resource + Teams app manifest. Messages and approval cards (Adaptive Cards) go to/from a Praxis profile. | **Constraint:** Teams bots need a **publicly reachable HTTPS messaging endpoint** (Azure Bot Service), which conflicts with local-first [V: MS Bot Framework docs/Q&A]. Options: Cloudflare Tunnel / Azure Relay / APIM forwarding only `/api/messages`, with the Bot Framework JWT validated in Praxis. Label it "data transits Microsoft 365" in the compliance dashboard. The existing §12 plan already lists Teams in v0.5. |
| **Graph connectors (mail/calendar/files)** | Delegated Graph scopes per user via the same Entra app (incremental consent). Least privilege. | Covered by the existing MCP/connector plan; mention only. |
| **Packaging: winget** | A winget manifest (YAML) for the bootstrapper, submitted by PR to `microsoft/winget-pkgs` (`wingetcreate` helps) **[V]**. | Needs a signed installer (code-signing certificate cost) [E]. |
| **Packaging: Intune** | Wrap the bootstrapper as a **Win32 app (`.intunewin`)** via the Microsoft Win32 Content Prep Tool **[V]**, with detection rule = Praxis version file inside WSL (a PowerShell script). Plus the WSL settings-catalog policy and optional WSL compliance plugin. | "Per-user" install (WSL distros are per user) makes device-context deployment awkward **[U]**. Test the user-context Win32 app + first-logon script. |
| **Effort [E]** | Entra OIDC 1–1.5 weeks (on top of M1 accounts); Teams connector 2–3 weeks; Intune/winget packaging + docs 1–1.5 weeks → **≈ 4–6 weeks** | Needs a test M365 tenant (Microsoft 365 Developer Program eligibility has changed over time **[U]**). |

---
## 6. Multi-user and multi-profile

### 6.1 What the reference projects do **[V]**

**Hermes profiles** (`website/docs/user-guide/profiles.md`, `hermes_cli/profiles.py`):
- A profile is a **separate Hermes home**, `~/.hermes/profiles/<name>/`, with its own `config.yaml`, `.env`, `SOUL.md`, memories, sessions, skills, cron jobs, and `state.db`. Each profile gets its own command alias.
- Creation can `--clone` (config, skills, SOUL, memory files), `--clone-all`, or `--clone-from <profile>`. Messaging channels are **not** cloned unless `--clone-channels`.
- Single-use OAuth refresh tokens are deliberately *not* copied. They are shared from the root, because copies would revoke each other.
- "Never point two agent processes at the same profile." Two writers corrupt each other's memory.
- Profiles can be distributed as git repos (`hermes profile install`, `profile-distributions.md`) and served together (`multi-profile-gateways.md`).
- **Limitation:** profiles are personas for one OS user, not authenticated accounts.

**OpenClaw:**
- *Multi-agent* (`docs/concepts/multi-agent.md`): isolated agents inside one Gateway, each with its own workspace, agent dir/state (SQLite under `~/.openclaw/agents/<id>/agent/`), and session store. **Bindings** route channel accounts to agents (`openclaw agents add <name> --role --model --bind`), with per-agent skill allowlists. "Each agent's workspace is the **default cwd**, not a hard sandbox."
- *Multi-user* (`docs/concepts/multi-user.md`, `docs/cli/users.md`): durable per-person Gateway profiles, creator/owner/participant session attribution, per-person model accounts. It is explicit: "Everyone who can operate an agent can make it do anything that agent can do. Session ownership, visibility… and presence indicators are usability features, not security boundaries."
- *Operator scopes* (`docs/gateway/operator-scopes.md`): `operator.read`, `sessions.read/write`, `write`, `admin`, `pairing`, `approvals`. These are "not hostile multi-tenant isolation".
- *Multi-tenant hosting* (`docs/gateway/multi-tenant-hosting.md`): `openclaw fleet` (experimental) runs one containerised cell per tenant, with an isolation ladder of hardened container → gVisor/Kata/microVM → separate machines.

**What Praxis takes:**
- Hermes's "profile = separate home + one writer".
- OpenClaw's bindings, per-agent skill allowlists, scopes, and above all its **honest trust-boundary statement**.
- Added on top: real accounts, roles, and compliance-aware isolation (OpenShell workspaces / OS users) for regulated deployments.

### 6.2 Concepts

| Concept | Meaning |
|---|---|
| **Account** | A human who signs in (local password + passkey/TOTP, or OIDC subject). Fields: `id`, `display_name`, `email`, `auth` (argon2id hash / WebAuthn credentials / OIDC `iss`+`sub`), `roles`, `status`, `mfa`, `created_at`. |
| **Role** (server-wide) | `owner` (the first account; break-glass), `admin` (manage accounts, profiles, providers, dial floors, themes, exposure), `operator` (use assigned profiles, approve within policy), `viewer` (read-only chats/artifacts of assigned profiles), `auditor` (read-only audit log + compliance evidence; **no** chat access to content unless granted, for HIPAA minimum-necessary). |
| **Profile** | An *agent configuration + state home*. It belongs to an account (personal) or is shared by a group (e.g. "Front Desk", "Paralegal Team"). It holds persona/SOUL, packs, skills allowlist, routines, memory (its own `prime.db`: profile-facts, episodic, and semantic tiers plus scopes), provider/model selection, dial positions, theme, connectors/channel bindings, and sandbox tier. |
| **Membership** | `(account, profile, profile_role)` where `profile_role ∈ {owner, operator, viewer}`. Approvals can require a specific profile role, or two distinct accounts for dual approval (the legacy packs' `dualApprovalRisks`). |
| **Org policy floor** | Admin-set minimum dial positions and allowlists (providers, tools, MCP servers, egress). **A profile may tighten but never loosen them** (e.g. HIPAA `enforce` org-wide means no profile can set `monitor`). |

### 6.3 Storage layout (extends ARCHITECTURE §25)

```
/var/lib/praxis-prime/            # server install (system service user `praxis`); single-user installs keep ~/.local/share/praxis-prime
├── accounts.db                   # SQLite: accounts, roles, memberships, sessions, devices, api_tokens (WAL, 0600)
├── audit/                        # hash-chained audit segments (existing design) — actor + profile on every event
├── org/policy.toml               # dial floors, provider/tool/egress allowlists, theme lock, exposure
├── themes/                       # admin-installed themes
└── profiles/<profile-id>/
    ├── profile.toml              # persona, packs, model selection, dials (≥ floor), theme, sandbox tier, bindings
    ├── SOUL.md                   # persona text (Hermes-style)
    ├── prime.db                  # today's single SQLite store, now one per profile: transcripts + memory tiers (profile facts / episodic / semantic, docs/MEMORY.md)
    ├── skills/                   # profile-local SKILL.md skills (+ allowlist of global skills)
    ├── routines/                 # routines owned by this profile
    ├── sessions/                 # chat sessions & artifacts
    ├── workspaces/               # coding-mode worktrees / files
    └── secrets.env.age           # profile-scoped connector credentials (key in keychain / KMS)
```

- `praxis-prime profile create <name> [--clone-from p] [--clone skills,persona,routines] [--no-memory]`. Memory and channel bindings are **not** cloned by default (Hermes lesson). `profile export/import` produces a signed tarball without secrets or memory unless `--include-memory`, which prompts, is audited, and is blocked under enforce-mode dials.
- Migration: an existing single-user install becomes `owner` account + profile `default`.
- Naming: `docs/MEMORY.md` already uses `profile` for the "short durable facts" memory tier. Rename that tier to `facts` (keeping an alias) or always say "agent profile" in UI copy, to avoid confusion.

### 6.4 Runtime isolation ladder

| Level | Mechanism | When |
|---|---|---|
| L0 Logical | One daemon. Per-profile DB files and directories; authorization checks in the gateway on every call. | Personal/home use. Honest label: "profiles are organisational, not a security boundary", as OpenClaw says. |
| **L1 Process** (default for server installs) | **One agent worker process per active profile** (spawned by `praxis-primed`, supervised, idle-stopped). A worker opens only its own profile dir (enforced by Landlock on the worker [E]). The "one writer per profile" rule holds with a lock file, as Hermes warns. | Small office. |
| L2 OS user | Worker runs as a dedicated Linux user per profile (`praxis-p-<id>`), with systemd `DynamicUser=`/templated units, so file permissions separate profiles. | Mixed-sensitivity profiles (e.g. "Billing" vs "Clinical"). |
| **L3 OpenShell** | Worker runs inside an OpenShell sandbox (§3.5 M4b), with its own policy, providers, and egress rules. Optionally mapped to an **OpenShell workspace** with OIDC. | Regulated profiles (default when a regulated dial is on and the host qualifies). |
| L4 Separate host | Separate Praxis server. | Hostile tenants. Out of scope (multi-tenant SaaS is a non-goal). |

### 6.5 Audit

- Every audit event gains `actor_account`, `actor_role`, `profile`, `device`, `auth_method`, and `via` (web/pwa/cli/telegram/teams/routine).
- New event types: `auth.login/logout/fail/mfa`, `account.create/disable/role_change`, `profile.create/clone/export/delete`, `membership.change`, `policy.floor_change`, `theme.install/activate`, `provider.configured/tested`, `exposure.change`, `sandbox.policy.applied`, `openshell.ocsf` (ingested stream).
- Auditors can export a profile's evidence bundle. The PHI-bearing payload is redacted by default. Access to raw content is itself audited.

### 6.6 UI

- **Profile picker** in the top bar (avatar + profile name + colour chip from its theme), keyboard `Ctrl/⌘+Shift+P`.
- The URL carries the profile (`/p/<profile>/…`) so tabs can hold different profiles.
- The active profile's dial states and sandbox tier are always visible in the status bar, as today's `dials:` indicator.
- **Admin console:** accounts (invite link / OIDC auto-provision), roles, profiles (create, clone, assign members), org policy floors, provider allowlist, themes (install, lock), exposure mode, audit viewer, sessions/devices (revoke).
- **Telegram/Teams bindings:** each channel account binds to exactly one profile (OpenClaw "bindings" idea). Approval requests go to members with the right profile role.

---

## 7. Packs: packaging fix and legacy-pack loader

### 7.1 Current state **[V]**

- `compliance/packs.py` `bundled_pack_dir()` walks up from `__file__` looking for `packs/compliance/*.toml`. The wheel only packages `packages/prime-core/praxis_prime` (`pyproject.toml`), so **an installed wheel has no compliance packs**.
- `packs/regulated/` contains only `LICENSE` and `README` ("not imported"). `packs/general/` is empty.
- User overrides: `~/.config/praxis-prime/packs`, `.prime/packs`.

### 7.2 The six public legacy packs **[V]** (cloned 2026-09-30)

| Repo | Pack dir | complianceMode | Skills (inline) | Tools | Modules | Notes |
|---|---|---|---|---|---|---|
| `smf-praxis-homeschool` | `packs/homeschool` | enforced | 9 | 9 | 13 | ships `web/homeschool.{css,js}`; no `model` field |
| `smf-praxis-education` | `packs/school_system` | enforced | 6 | 11 | 7 | |
| `smf-praxis-forensic` | `packs/forensic` | enforced | 1 | 4 | 0 (persona only) | |
| `smf-praxis-legal` | `packs/law_firm` | enforced | 4 | 13 | 6 | ships `web/law_firm.{css,js}` |
| `smf-praxis-medical` | `packs/medical_office` | enforced | 6 | 14 | 9 | |
| `smf-praxis-mbh` | `packs/behavioral_health` | enforced | 8 | 17 | 9 | ships `web/behavioral_health.{css,js}` |

- All six are MIT. They are Python distributions depending on **`praxis-agent>=0.29.1/0.30.0`** (package `hybridagent`), registered via the entry point group **`praxis.verticals`**.
- `pack.json` keys: `name, version, vertical, description, systemPrompt, complianceMode, tools, riskPolicy{dualApprovalRisks, autonomousRisks, egressCheck, injectionCheck, approvalTtlSeconds}, knowledge[], skills[{name, trigger, body}], theme{accent, panel, ok, warn?}, model`.
- `knowledge.md` is 1–14 KB of domain text.
- Python modules (e.g. `legal_hold.py`, `crisis_safety_gate.py`, `telemedicine_gate.py`) implement jurisdiction logic and dashboards, importing `hybridagent.*` APIs that Praxis Prime does not have.

### 7.3 Loader / port design

1. **M0a: bundle packs in the wheel.** Move them to `praxis_prime/_data/packs/{compliance,jurisdictions}` (or add hatch `force-include`), and load them via `importlib.resources.files()`. Keep the repo-root path for dev. Add a test that builds the wheel, installs it into a clean venv, and asserts every TOML pack loads.
2. **M0b: legacy manifest adapter** (`praxis_prime/packs/legacy.py`). Reads `pack.json` + `knowledge.md` from (a) an installed `praxis.verticals` distribution's package data **without importing its Python** (read files via `importlib.metadata` + `importlib.resources`), or (b) a directory/zip. It maps:
   - `systemPrompt` → profile persona layer (below the Praxis safety preamble; it can't override it);
   - `knowledge[]` → the semantic memory "pack knowledge" collection (read-only, provenance-tagged);
   - `skills[]` → generated `SKILL.md` files (`name`, `description = trigger`, body), namespaced `pack/<name>/…`;
   - `tools[]` → a tool allowlist. Names are mapped to Praxis tools via a table; unknown tools are listed as "unavailable in Praxis Prime" and never silently dropped;
   - `riskPolicy` → Policy Engine rules: `dualApprovalRisks` → dual approval (two distinct accounts, §6.2); `autonomousRisks` → auto-allow classes; `egressCheck/injectionCheck` → Decision Engine templates on; `approvalTtlSeconds` → approval TTL;
   - `complianceMode: "enforced"` → **suggests** dial positions. The admin confirms, because the old enforced ≠ Praxis `enforce` semantics until the regression suites exist;
   - `theme` → token overrides (`accent`, `bgRaised ← panel`, `ok`, `warn`) on `smf.praxis` or the matching built-in theme (legal → `smf.legal-office`, etc.), after the contrast check;
   - **`model` → ignored** (displayed as the author's suggestion only). Every pack but homeschool pins an `ollama-cloud/…:cloud` model, which would violate §2 and, for medical/MBH, send PHI to a cloud service.
3. **Never load the packs' `web/*.js`** (it conflicts with §1.4 and the CSP). The dashboard surfaces (legal-hold badge, credential card, ad-filing tracker, crisis gate, etc.) are ported to **declarative panels**: a JSON panel spec rendered by the Praxis SPA, with data from a pack's server-side endpoints.
4. **Python modules:** port per vertical into Praxis-native plugins (§20 plugin SDK), with jurisdiction data converted to TOML where possible. Keep `hybridagent` shims out of core. Order by owner priority [E]: legal → medical → mbh → education → homeschool → forensic.
5. **CLI:** `praxis-prime pack install <pypi-name|git-url|dir>`, `pack list`, `pack inspect` (shows the mapping report), `pack enable <pack> --profile p`.

---
## 8. Re-ordered roadmap: PR-sized milestones

Each milestone is a small series of reviewable PRs (listed). Each has a demo-able exit criterion. Estimates assume one experienced engineer plus AI assistance **[E]**.

```
M0 packs/packaging ─┐
                    ├─▶ M1 web shell + accounts + profiles ─▶ M2 onboarding (no default LLM) ─▶ M3 themes
                    │                                   │                                        │
                    │                                   └──────────────▶ M6 remote access + PWA ◀─┘
                    └─▶ M4 OpenShell (M4a tools; M4b contained workers needs M1 workers) ─┐
                                                   M5a Ubuntu/Omarchy installers ◀────────┘ (M2, M4a)
                                                   M5b WSL2 bootstrap (needs M5a, M6 tailnet mode helps)
                                                   M7 Tauri desktop wrapper (needs M1–M3)
                                                   M8 Microsoft 365 (needs M1 OIDC, M5b, M6)
```

| # | Milestone | PRs (each independently mergeable) | Depends on | Exit criterion | Est. |
|---|---|---|---|---|---|
| **M0** | **Packaging + packs** | (1) move `packs/compliance` + `jurisdictions` into package data, `importlib.resources`, wheel-install test in CI; (2) `packs/legacy.py` adapter + mapping report + tests against the 6 public packs (read files, don't import); (3) `pack install/list/inspect/enable` CLI; (4) `docs/PACKS-LEGACY.md` | — | `pip install praxis-prime*.whl` in a clean venv loads all compliance TOML packs; all 6 legacy packs `inspect` cleanly; `model` pins ignored | 1–1.5 wk |
| **M1** | **Web UI shell + auth + accounts + profiles** | (1) SPA scaffold (React 19 + Vite + Tailwind + TanStack, the existing `ui/` stub), responsive layout, protocol client; (2) `accounts.db` + argon2id + sessions/CSRF + WS tickets + Host guard; (3) passkeys + TOTP; (4) roles/memberships + gateway authz middleware; (5) profile dirs + migration of single-user state → `default`; (6) per-profile worker processes (L1) + lock; (7) profile picker + admin console v0; (8) audit actor/profile fields; (9) generic OIDC | M0 (pack loading per profile) | Two accounts, two profiles, isolated memory; admin can create/assign; audit shows actors; still loopback-only | 4–6 wk |
| **M2** | **Onboarding wizard + remove Ollama default** | (1) remove defaults in `router/settings.py`, `config.py`, `router/types.py`; `InferenceNotConfigured`; README/doctor; (2) `onboarding.*` API (detect/probe/test/save); (3) local detectors (Ollama, llama.cpp, vLLM, LM Studio); (4) network lane (manual + TLS pin + consented mDNS/tailnet/port scan); (5) cloud lane + keychain; (6) web wizard; (7) `praxis-prime setup` CLI/TUI + `--non-interactive`; (8) compliance-aware warnings + per-profile provider allowlist | M1 (per-profile selection, web shell) | Fresh install cannot chat until a provider is chosen and passes a live completion + tool call; no implicit fallback (tests) | 2–3 wk |
| **M3** | **Theme engine + 7 themes** | (1) token pipeline + CSS generation + CSP; (2) `theme.toml` schema + JSON Schema + validator (contrast, licences, CSS parser allowlist, SVG sanitizer, zip limits); (3) install/select/lock UI + CLI; (4) Omarchy source adapter onto the new pipeline; (5) 7 built-in themes + fonts + `OFL.txt`; (6) `THEME-AUTHORING.md` + AI round-trip test (a model generates a package from a brief → lint passes); (7) legacy pack `theme` hint mapping | M1 (profiles), M2 (wizard uses theme) | All 7 themes pass AA in both modes; malicious test packages (JS, `@import`, remote url, hidden approval button) are rejected | 2–3 wk |
| **M4** | **OpenShell integration** | (1) `doctor` qualification (kernel/Landlock ABI/runtime/telemetry); (2) consented pinned install helper; (3) policy compiler (dials → OpenShell YAML) + prover in CI; (4) **M4a** T2-OS tool sandbox (Python SDK), mirror workspace; (5) providers for inference/connectors; (6) advisor → approval cards; (7) OCSF ingest into audit; (8) **M4b** contained per-profile workers; (9) fallback + dashboard status + `require_openshell` | M0; M1 workers for M4b; M2 for provider binding | On Ubuntu 24.04 + Podman 5: regulated profile runs tools in OpenShell with telemetry off, prover ✓; on an unsupported host it falls back visibly | 3–5 wk |
| **M5a** | **Installers: Ubuntu + Omarchy/Arch** | (1) `.deb` (+ APT repo already planned in §27) including packs/themes; (2) AUR `praxis-prime` + Omarchy integration (theme hook, keybind); (3) `install.sh` wizard: server vs desktop, regulated profile toggles OpenShell, systemd units (user or system `praxis` service for server mode); (4) DGX OS / arm64 CI | M2, M4a | One-command install on Ubuntu 24.04 x86_64/arm64 and Omarchy lands in the web onboarding wizard | 2–3 wk |
| **M5b** | **Windows WSL2 bootstrap** | (1) PowerShell bootstrap; (2) wsl.conf/.wslconfig + keep-alive task; (3) networking modes; (4) GPU checks; (5) secrets on WSL; (6) winget manifest (unsigned preview → signed) | M5a; M6 tailnet mode recommended | Windows 11 box: `winget install SMFWorks.PraxisPrime` → browser onboarding in ≤ 10 minutes | 3–5 wk |
| **M6** | **Remote access + PWA hardening** | (1) exposure modes `tailnet/proxy/lan` + fail-closed gates; (2) Tailscale identity mapping via `whois`; (3) Caddy recipe + trusted-proxy JWT; (4) Praxis-managed CA for `lan`; (5) PWA manifest + SW + Web Push approvals; (6) mobile approval sheets + passkey re-auth; (7) external pen-test checklist | M1, M3 | Phone on tailnet installs PWA, logs in with passkey, approves a SEND; non-loopback start without auth is refused | 2–3 wk |
| **M7** | **Desktop wrapper (Tauri 2)** | (1) Tauri shell loading the same SPA (local or remote server URL); (2) tray, notifications, deep links; (3) Linux packages (AppImage/.deb/Flatpak per §27); (4) optional Windows Tauri client that connects to a WSL/remote server (client only) | M1–M3 (M6 for remote) | Desktop app connects to local or remote Praxis server with the same accounts | 2–3 wk |
| **M8** | **Microsoft 365** | (1) Entra OIDC preset + app-role mapping + setup guide; (2) Teams connector (Bot Framework, Adaptive Card approvals, tunnel design); (3) Intune Win32 packaging + WSL policy docs; (4) Graph delegated connectors (if not already via MCP) | M1 (OIDC), M5b, M6 | Tenant user signs in with Entra; approvals arrive in Teams; Intune deploys to a pilot group | 4–6 wk |

**M1 lettered split.** The numbered PRs in the M1 row are also named this way: **M1a** is (2), (4), (5), and (8) (accounts, roles, profiles, and audit actors; merged); **M1b** is (3), passkeys + TOTP (local enrollment and sign-in on the loopback daemon); **M1c** is (6), per-profile workers and the supervisor; **M1d** is (1) and (7), the SPA, profile picker, and admin console; **M1e** is (9), generic OIDC. The same labels are in the README roadmap and in [OPENDOTS-BORROWED-PATTERNS.md](OPENDOTS-BORROWED-PATTERNS.md).

**Placement in the existing phases (ARCHITECTURE §29):**
- M0–M3 = **MVP completion** (v0.2–0.3).
- M4–M6 = **v0.5**, alongside the existing v0.5 items. Teams moves to M8.
- M7–M8 = **v0.6–v0.8**.
- Everything else in §29 (Jury, Jarvis, swarm, etc.) is unchanged but sequenced after M3.

**Patterns borrowed from OpenDots (2026-10-01):** see [OPENDOTS-BORROWED-PATTERNS.md](OPENDOTS-BORROWED-PATTERNS.md). These are ideas only, with no code copied. They are folded into the milestones above as follows:
- **M1**, PR (6) per-profile workers (M1c): live revocation of in-flight runs and leased routine runs (pattern 3); per-worker derived credentials (pattern 6); grants re-checked on every tool call, with a one-time migration (pattern 11); upstream response hardening (pattern 12).
- **M1**, PRs (1) and (7) SPA shell (M1d): AG-UI event types on the gateway stream (pattern 1); approval cards decided once per tool call (pattern 2); extra gateway request checks (pattern 7); optional revision-checked autosave for the canvas (pattern 9); a route allowlist whose ids agree across path, body, and query (pattern 10).
- **M2:** the "setup needed" screen lists exactly what is missing (pattern 8).
- **M4:** human takeover and handback of the sandboxed browser or desktop, with a redacted activity log (pattern 5); derived sandbox credentials (pattern 6); snapshot-bound element actions (pattern 4), which start in the current browser tool; upstream response hardening (pattern 12).
- **M6:** approval-card idempotency on mobile sheets (pattern 2); re-check the gateway request checks for remote exposure (pattern 7); re-check the route allowlist and session-id agreement (pattern 10).

**Per-person agents** (one agent per individual): see [Per-person agents](OPENDOTS-BORROWED-PATTERNS.md#per-person-agents).

- **M1**, PRs (4) and (5): a personal profile, an admin boundary with break-glass, requester-routed approvals, and per-session visibility ([Per-person agents](OPENDOTS-BORROWED-PATTERNS.md#per-person-agents)).
- **M1**, PR (6): a supervisor, run-as routines, revocation (pattern 3), per-worker credentials with a generation counter, and a systemd slice (`MemoryMax`, `CPUQuota`, `TasksMax`) ([Per-person agents](OPENDOTS-BORROWED-PATTERNS.md#per-person-agents)).
- **M2:** per-profile provider keys ([Per-person agents](OPENDOTS-BORROWED-PATTERNS.md#per-person-agents)).
- **M4:** L3 (OpenShell). L2 (per-profile Linux users) is unscheduled, after M4 ([Per-person agents](OPENDOTS-BORROWED-PATTERNS.md#per-person-agents)).
- **M6:** per-account channel bindings, with approvals pushed to the requester ([Per-person agents](OPENDOTS-BORROWED-PATTERNS.md#per-person-agents)).

**OpenClaw and Hermes gaps (2026-10-01):** see [OPENCLAW-HERMES-GAPS.md](OPENCLAW-HERMES-GAPS.md). Ideas only, with no code copied.

- **MVP:** tool search, and the start of smarter approvals ([gaps 6 and 9](OPENCLAW-HERMES-GAPS.md#high-value-gaps)).
- **M1c / M1 PR 6** per-person workers: one process, folder, secrets, and chat bindings per person, with approvals back to the requester ([gap 1](OPENCLAW-HERMES-GAPS.md#1-real-per-person-isolation)).
- **M2:** API-key pools with fallback for side tasks, external secret-store pointers, and the start of doctor fixes ([gaps 2, 3, and 7](OPENCLAW-HERMES-GAPS.md#high-value-gaps)).
- **M4 / M4a:** external secret stores, and isolated code execution ([gaps 3 and 5](OPENCLAW-HERMES-GAPS.md#high-value-gaps)).
- **M5a:** doctor fixes, a security audit, safe updates, and backup ([gap 7](OPENCLAW-HERMES-GAPS.md#7-doctor-fixes-security-audit-updates-backup-and-recovery)).
- **v0.5:** file undo, the skill lifecycle, smarter approvals, agent-level evals, memory upgrades, and a signed skill hub ([gaps 4 and 8–12](OPENCLAW-HERMES-GAPS.md#high-value-gaps)).

The security lessons in that note are explicit requirements: a SECURITY.md response deadline, no gateway URL or token taken from a link, an owner check on settings-changing chat commands, policy enforced at dispatch and at the sandbox (including an outside harness's built-in tools), compression summaries treated as untrusted, webhook signatures verified before rate-limiting, and CSV formula-injection guards ([Security lessons](OPENCLAW-HERMES-GAPS.md#security-lessons)).

---

## 9. Risks and open questions

| Risk / question | Note |
|---|---|
| OpenShell API churn (0.1.x, weekly releases) | Pin versions; run a compatibility matrix in CI; wrap it behind Praxis's own `SandboxBackend` interface so T1/T2 remain drop-in. |
| OpenShell on Arch/Omarchy and WSL2 | Not on NVIDIA's supported list (Arch) or Experimental (WSL2) **[V]**; actual behaviour **[U]**. Test on real Omarchy and Windows 11 hardware in M4/M5. |
| Host-local inference from inside OpenShell | Loopback is always blocked; must use `host.openshell.internal`. Local servers must bind a reachable interface **[U]** per server. |
| NGC base image terms | **[U]**. Prefer a Praxis-built image. |
| Multi-user raises the security bar | Accounts + remote exposure make Praxis an internet-facing app if misconfigured. Fail-closed defaults, a doctor red flag, and an external review before marketing M6. |
| Teams requires a public endpoint | Conflicts with local-first. Keep it optional and clearly labelled. |
| Legacy pack semantics | Old `enforced` vs new `enforce`, and tool names differ. The mapping report must list every gap; no silent drops. |
| Owner decisions needed | (1) Confirm "Regulated profile ⇒ OpenShell default when supported" and whether `require_openshell` should be the default for HIPAA enforce. (2) Choose default exposure recommendation (tailnet vs proxy) for office installs. (3) Priority order for porting legacy pack modules. (4) Whether to add the 8th "High Contrast" theme. (5) Code-signing certificate for Windows. (6) Context-length floor (32K proposed vs Hermes 64K). |

---

## 10. Sources (primary; accessed 2026-09-30)

**Praxis Prime (smfworks/praxis-prime @ 029b5ccc):** `docs/ARCHITECTURE.md` (§2, §4, §6, §13.1, §21, §21.7, §25, §28.2, §29, §31), `packages/prime-core/praxis_prime/router/settings.py`, `config.py`, `router/types.py`, `gateway/server.py`, `gateway/auth.py`, `compliance/packs.py`, `pyproject.toml`, `packs/`, `ui/`, `apps/desktop/`, `apps/omarchy/praxis-prime.json.tpl`.

**Legacy packs (MIT):** https://github.com/smfworks/smf-praxis-homeschool, -education, -forensic, -legal, -medical, -mbh (`*/packs/*/pack.json`, `knowledge.md`, `registration.py`, `pyproject.toml`).

**NVIDIA OpenShell (Apache-2.0) @ 5acaaba1:**
- Repo: https://github.com/NVIDIA/OpenShell (LICENSE, Cargo.toml, `rfc/0011`, `rfc/0013`, `rfc/0014`)
- Docs: https://docs.nvidia.com/openshell/latest/ (repo `docs/`)
- Pages used: `about/overview.mdx`, `about/architecture.mdx`, `about/support-matrix.mdx`, `about/installation.mdx`, `how-it-works/inference.mdx`, `how-it-works/workspaces.mdx`, `how-it-works/sandboxes/runtimes.mdx`, `how-it-works/policies/*`, `security/best-practices.mdx`, `observability/telemetry.mdx`, `observability/ocsf-json-export.mdx`, `resources/license.mdx`
- Releases: https://github.com/NVIDIA/OpenShell/releases
- Blog: https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/
- NemoClaw (Apache-2.0): https://github.com/NVIDIA/NemoClaw
- DGX Spark: https://www.nvidia.com/en-us/products/workstations/dgx-spark/

**Hermes Agent (MIT, © 2025 Nous Research) @ f42f579c** — https://github.com/NousResearch/hermes-agent:
- `hermes_cli/setup.py`, `setup_quick.py`, `models_local.py`, `model_setup_flows_custom.py`, `models_detect.py`, `profiles.py`, `skin_engine.py`
- `website/docs/getting-started/quickstart.md`
- `website/docs/user-guide/{profiles,profile-distributions,multi-profile-gateways,local-models,windows-wsl-quickstart,windows-native}.md`
- `website/docs/user-guide/features/{skins,web-dashboard}.md`

**OpenClaw (MIT, © 2026 OpenClaw Foundation) @ 1de9a42f** — https://github.com/openclaw/openclaw:
- `docs/start/wizard.md`, `docs/cli/onboard.md`, `docs/cli/users.md`
- `src/commands/onboard-{guided,inference,inference-ambient,custom}.ts`
- `docs/gateway/{local-model-services,operator-scopes,multi-tenant-hosting,remote,openshell}.md`
- `docs/concepts/{multi-agent,multi-user}.md`
- `docs/tools/theme.md`, `docs/platforms/windows.md`

**Microsoft:**
- WSL systemd https://learn.microsoft.com/en-us/windows/wsl/systemd
- WSL networking https://learn.microsoft.com/en-us/windows/wsl/networking
- CUDA on WSL https://learn.microsoft.com/en-us/windows/ai/directml/gpu-cuda-in-wsl
- WSL + Intune https://learn.microsoft.com/en-us/windows/wsl/intune
- WSL compliance https://learn.microsoft.com/en-us/intune/device-security/compliance/configure-wsl
- winget manifests https://learn.microsoft.com/en-us/windows/package-manager/package/manifest
- Win32 app packaging https://learn.microsoft.com/en-us/intune/app-management/deployment/create-win32-package
- Entra auth-code + PKCE https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- Bot Framework / Azure Bot Service docs (public messaging endpoint requirement)

**Other:**
- AMD ROCm on WSL https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/install/installrad/wsl/howto_wsl.html
- Tailscale Serve https://tailscale.com/docs/features/tailscale-serve
- MDN PWA installability https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Making_PWAs_installable
- Google Fonts OFL tree https://github.com/google/fonts/tree/main/ofl
- SMF WisdomForge https://smfwisdomforge.com (live CSS tokens: `--color-bg #0a0a0f`, `--color-accent #c9a96e`, Fraunces / Source Sans 3 / Source Code Pro)

---

## Appendix A — `docs/THEME-AUTHORING.md` (skeleton for M3)

```markdown
# Authoring a Praxis Prime theme
You are producing a *theme package*: data only. No JavaScript, no remote URLs, no @import.
1. Create `theme.toml` with schema = "praxis.theme/v1", id, name, version, license, authors, description, modes.
2. Required tokens per mode: bg bgRaised fg fgMuted accent accentFg border borderStrong ring ok warn danger.
   Colours: #rgb, #rrggbb, #rrggbbaa or oklch(L C H). Nothing else.
3. Contrast (per mode): fg & fgMuted vs bg & bgRaised ≥ 4.5; accentFg vs accent ≥ 4.5; ok/warn/danger vs bg ≥ 4.5;
   borderStrong & ring vs bg ≥ 3.0.
4. Fonts: WOFF2 only, licence in {OFL-1.1, Apache-2.0, MIT, CC0-1.0, Ubuntu-font-1.0}; include the licence file.
5. Optional theme.css: only --pp-* custom properties, plus these selectors: .pp-ornament-*, .pp-header-band,
   .pp-sidebar-texture, .pp-divider. Allowed properties: color, background(-color|-image: url(assets/...)), border*,
   border-radius, box-shadow, letter-spacing, text-transform, font-feature-settings.
   Forbidden: @import, @font-face, content, display, visibility, opacity, position, z-index, transform, filter,
   pointer-events, clip*, !important, attribute selectors, :has(), anything matching .pp-approval*/.pp-dial*/.pp-audit*.
6. Run `praxis-prime theme lint . --json`; fix every error; then `praxis-prime theme pack .`.
7. Write THEME.md: purpose, palette, fonts + licences, credits, screenshots.
```

## Appendix B — Palette contrast check

[`scripts/contrast_check.py`](../scripts/contrast_check.py) reproduces the numbers in §1.7. Run `python scripts/contrast_check.py`. Result on 2026-09-30: 14 palettes (7 themes × light/dark), 0 failures at 4.5:1 for fg, muted, accent-on-accentFg, and status colours.
