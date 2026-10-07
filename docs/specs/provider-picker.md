# Praxis Prime: provider picker and "Sign in with Grok" (spec)

| | |
|---|---|
| Status | Approved by owner. PR1 (registry, picker, Back/Skip) in progress on feat/provider-picker. |
| Owner | Michael (smfworks) |
| Written | 2026-10-06 |
| Base | `smfworks/praxis-prime` `main` at `fcb7493` |
| Tracks | Issue [#90: Setup: add xAI OAuth for Grok (no API key required)](https://github.com/smfworks/praxis-prime/issues/90) |
| Scope | Praxis Prime only: the first-run wizard (web and `praxis-prime setup` / `pprime setup`) and the Settings page. |

---

## 0. Summary

Today the provider step is a radio list of four "lanes" (this computer, my network, cloud, skip), followed by a form of free-text fields: provider id, base URL, primary, utility, vision, judge, and API key. It has one "Test and save" button and no Back button. This spec replaces that with a **provider picker**: one searchable list with a **Local** section (Ollama, LM Studio, llama.cpp, vLLM, any OpenAI-compatible server on this computer or the network) and a **Cloud** section (xAI, OpenAI, Anthropic, a custom OpenAI-compatible cloud endpoint). Local servers that are already running get a badge, and the Local section shows a note when no GPU is detected. After you pick a provider, a **Connect** step asks only what that provider needs. For xAI that step offers two choices: **Sign in with Grok (SuperGrok / X Premium subscription)** or **API key (billed to your xAI API account)**. If you choose sign-in, you go through a device-code flow: Praxis shows a short code and an xAI link, you approve on any browser, and the daemon finishes the sign-in. That works the same way on a headless box over SSH. A **Model** step then shows a dropdown filled from the provider, with `grok-4.7` as the default for xAI, plus a typed-entry fallback. Utility, vision, and judge models sit under an "Advanced" disclosure and default to "same as primary". Every step has Back, "Skip for now" stays on the provider step, and Settings reuses the same component. The live completion and tool-call test still has to pass before a provider is marked ready. The OAuth part (PR3 and PR4) depends on an owner decision about xAI's terms, and on a short manual check with a real subscription, because xAI has not published a way for third-party apps to register for subscription sign-in (section 3.6).

---

## 1. Goals and non-goals

**Goals**

1. You can find a provider by name, see what's already running locally, and pick it, with no provider ids to type.
2. For xAI you can choose subscription sign-in or an API key. If you choose sign-in, you finish it without pasting a secret.
3. The model list comes from the provider when the provider can list models, with typing as a fallback.
4. Back works on every step, and Skip works on the provider step.
5. The web wizard, the terminal wizard, `--non-interactive`, and Settings all use one backend and one provider registry.
6. The existing security model doesn't get weaker: loopback daemon, owner/admin-only setup, step-up for credential changes, secrets never shown again, the live test before "ready", and no default provider.

**Non-goals (for this spec)**

- Downloading or starting local model servers. Detection stays read-only, as the blueprint requires.
- LAN-wide discovery. It stays manual, with explicit consent, as in blueprint §2.3.
- Per-profile provider credentials (blueprint M2 follow-up). The design leaves room for them.
- Other subscription sign-ins (ChatGPT, Claude). The registry supports them later, but nothing is built here.
- Showing SuperGrok quota (OpenClaw does this; see Open Questions).

---

## 2. What exists today (main @ fcb7493)

| Area | Where | What it does today |
|---|---|---|
| Web wizard | `ui/src/setup.tsx` | Steps: `welcome → owner → factors → lane → models → dials → extras → done`. `LANES` = local / lan / cloud / skip. The models step has free-text Provider id, Base URL, Primary, Utility, Vision, Judge, and API key fields, plus a single **Test and save** button. There is no Back. "Look for local servers" is a button that lists `provider at baseUrl` as plain text. On a replacement, it asks for the account password plus TOTP or a passkey step-up. |
| Backend | `packages/prime-core/praxis_prime/onboarding/service.py` | `CLOUD_PROVIDERS`, `LOCAL_PROVIDERS`, `KEY_NAMES` (for example `xai → PRAXIS_PRIME_XAI_API_KEY`), `CLOUD_BASES` (`xai → https://api.x.ai/v1`), `_REQUIRED_KEY = {openai, anthropic, xai}`. `save()` validates the lane and provider, runs `test()` (context length from `/v1/models`, then a completion and a tool-call test against `/v1/chat/completions`, or `/v1/messages` for Anthropic), then writes `config.toml`, `secrets.env`, and `provider-ready.json`. `_skip()` clears the primary model and writes a not-ready record. A stored key is only sent to the base URL it was saved for (`_key_for` / `_bound_base`). |
| Detection | `onboarding/detect.py` | Read-only probes of Ollama `:11434/api/tags`, llama.cpp `:8080/v1/models` (+`/props`), vLLM `:8000`, LM Studio `:1234`. It reports env-key **names** (`XAI_API_KEY`, ...) and GPU facts (`detect_hardware`). |
| Gateway | `gateway/onboarding.py` | `/v1/onboarding/{status,owner,detect,probe,test,save,dials,oidc,telegram}`. Everything except `status` is POST. Before an owner exists, only the first-run token on loopback works. After that, only owner/admin (`sees_all_profiles`). There are WebSocket `onboarding.*` twins for status, detect, probe, test, and save. |
| Secrets | `channels/secrets.py` | `secrets.env` (mode 0600, atomic replace). Values are capped at **2048 chars** and cannot contain quotes or backslashes. Workers do not receive `PRAXIS_PRIME_SECRETS_FILE`, but `router/settings.py` reads `secrets.env` next to `config.toml`. |
| Router | `router/factory.py`, `router/openai_compat.py`, `router/types.py` | `xai` is an `OpenAICompatibleProvider` with a **static** `api_key` and `require_key=True`, using streaming Chat Completions. Known adapters are `ollama`, `openai-compatible`, `openai`, `anthropic`, and `xai`. `llamacpp`, `vllm`, and `lmstudio` are aliases of `openai-compatible`. |
| CLI | `onboarding/cli.py` | `praxis-prime setup` (alias `pprime`). Interactive: a numbered lane choice, then free-text prompts. Scripted: `--non-interactive --provider --model --base-url --api-key-env/--api-key-stdin --lane --replace ...`. `--skip-test` is refused. |
| Provider plugins | `plugins/providers/xai/README.md` | Placeholder ("Not implemented"). |
| Docs | `docs/blueprint-addendum-2026-09.md` §2, `docs/SECURITY.md` (first-run window, step-up, OIDC PKCE rules), `docs/USAGE.md` (Setup) | The blueprint calls for "no default LLM; explicit choice; verify before ready". SECURITY.md already describes a PKCE + state + nonce OIDC client with endpoint pinning, which we can reuse. |

What issue #90 asks for: "Sign in with xAI" (or device auth) on the cloud xAI lane, `grok-4.7` selectable and listed, the live test still required, the API-key path kept, and docs for both billing paths.

---

## 3. Research findings

Everything in this section comes from documentation or source code I read. Links are in §9. Anything I could not confirm is marked **unconfirmed** and repeated in §7.

### 3.1 How Hermes Agent presents providers and models

Source: `NousResearch/hermes-agent` at `cbffbee` (2026-10-06).

- **One list, grouped by vendor, not split into Local/Cloud headers.** `hermes model` (shared with `hermes setup`) builds the rows in `_build_provider_picker_rows`. Canonical providers fold into **display groups** (`PROVIDER_GROUPS` in `hermes_cli/models_catalog_static.py`). xAI is one row: **"xAI Grok ▸ (Direct API or SuperGrok / Premium+ OAuth)"**. Picking it opens a sub-picker with two members: `xai` ("xAI Grok (Direct API)") and `xai-oauth` ("xAI Grok OAuth (SuperGrok / Premium+ subscription)"). OpenAI, MiniMax, Qwen, and others are grouped the same way, with subscription/OAuth and API-key variants. The groups are display-only: each member stays its own provider id.
- **Local entries.** These are a "Local models (run open models on this machine — no account or API key)" row, shown only when a local engine build is available for this machine; LM Studio as its own provider; and "Custom endpoint (enter URL manually)". Trailing actions are "Reasoning effort…", "Configure auxiliary models…", and "Leave unchanged". The current provider is marked "← currently active".
- **Per-provider auth choice = picking the group member.** Picking `xai-oauth` checks for stored tokens. If there are none, it runs the login. Then it opens the model picker.
- **Model list.** For both xAI members, the list is a **curated catalog** from the cached `models.dev` file plus pinned extras (`_XAI_CURATED_EXTRAS`), with the headline model pinned at the top. It is not a live call. A code comment says some models are "callable via xAI OAuth but omitted from models.dev and /v1/models listings". The picker also offers "Enter custom model name". Custom endpoints probe `/models`. Local servers are probed (Ollama `/api/tags`, LM Studio `/api/v1/models`).
- **xAI subscription sign-in (current).** This is an **OAuth 2.0 device-code** flow (RFC 8628) against `https://auth.x.ai`. Hermes opens a browser when it can, and on SSH or remote sessions it prints the verification URL and user code. Tokens go to `~/.hermes/auth.json` and refresh in the background. `hermes auth logout xai-oauth` removes them. The web dashboard runs the same device-code flow, showing the URL and code and polling in the background (`web_server_oauth.py`: "Device code works in remote shells/containers without a reachable 127.0.0.1 callback").
- **History.** The first version (PR #26457, May 2026) used **browser PKCE with a loopback callback** against `accounts.x.ai`, with `plan=generic` and `referrer=hermes-agent` on the authorize URL. A later fix (#26999) had to "echo code_challenge in token POST so PKCE exchange succeeds". Hermes later moved to device code as the default.
- **Inference.** For `xai-oauth`, Hermes uses its Responses-style transport (`codex_responses`) against `https://api.x.ai/v1` and refuses to send the OAuth bearer to any host outside `x.ai` / `*.x.ai`.
- **Failure handling Hermes learned the hard way.** It treats any `xai-oauth` 403 as an **entitlement/quota** problem and does not refresh-loop, except for xAI's stale-token markers (`[WKE=unauthenticated:` and "OAuth2 access token could not be validated"). The error code `personal-team-blocked:spending-limit` is classified as billing. Terminal refresh errors quarantine the tokens, so later calls fail fast with one "sign in again" message.

### 3.2 xAI subscription OAuth: confirmed mechanics

| Fact | Confirmed by |
|---|---|
| Issuer `https://auth.x.ai`. Discovery at `/.well-known/openid-configuration` lists `authorization_endpoint` `/oauth2/authorize`, `device_authorization_endpoint` `/oauth2/device/code`, `token_endpoint` `/oauth2/token`, `revocation_endpoint` `/oauth2/revoke`, `userinfo_endpoint`, `jwks_uri`. Grants: `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code`. PKCE `S256` only. `token_endpoint_auth_methods_supported` includes `none` (public clients). ID tokens are signed `ES256`. | Live discovery document (fetched 2026-10-06), grok-build `config.rs` (`XAI_OAUTH2_ISSUER`) |
| Scopes advertised include `openid profile email offline_access grok-cli:access api:access` (plus many others: `conversations:*`, `workspaces:*`, `api-keys:*`, `billing:*`, ...). | Discovery document |
| Every third-party integration I found sends client id **`b1a00492-…`** with scope `openid profile email offline_access grok-cli:access api:access`. That id is **Grok Build's own built-in client id** (grok-build `config.rs`, hard-coded via `obfstr!`). OpenClaw's docs call it "xAI's shared OAuth client". | grok-build `config.rs` L380, Hermes `auth_constants.py` L96–97, OpenCode `plugin/xai.ts` L6 and L17, OpenClaw `extensions/xai/xai-oauth.ts` L29–30, OpenClaw docs |
| A `referrer` parameter identifies the calling app: Grok Build sends `grok-build`, Hermes `hermes-agent` (authorize URL), OpenCode `opencode` (device-code request). Grok Build's code describes it as "Client-supplied referrer so analytics can attribute OAuth usage." | grok-build `config.rs` L120–122 and L152, Hermes PR #26457, OpenCode `xai.ts` L115 |
| **Device code (RFC 8628)**: POST `client_id` + `scope` to `/oauth2/device/code`. The response has `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, and `interval`. Poll `/oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `client_id`, and `device_code`. Back off on `slow_down` (+5 s), and stop on `access_denied` / `expired_token`. No local listener is needed. | grok-build `device_code.rs` (L18–20, L117), Hermes `auth_xai.py` L504–584, OpenCode `xai.ts` L108–196, OpenClaw docs |
| **Browser PKCE + loopback**: Grok Build binds `127.0.0.1` on an **OS-chosen random port** in production (fixed `56121` only in local-dev mode), uses redirect `http://127.0.0.1:<port>/callback`, and sends `state`, `nonce`, and an S256 challenge. It races the callback against a paste-the-code prompt for remote VMs. xAI's consent page (served from `https://accounts.x.ai`) delivers the code to the loopback server with a CORS `fetch`. Kilo Code and Warp bind the fixed port `127.0.0.1:56121`. Warp added a "Paste sign-in code" fallback because xAI's page sometimes shows a code instead of redirecting (for example, when the browser blocks the Private Network Access fetch). | grok-build `oidc/login.rs` L356–387, `config.rs` L614–615, Kilo docs, Warp PR #12599, Warp issue #12638 |
| **Refresh**: POST `grant_type=refresh_token`, `client_id`, `refresh_token` to the token endpoint. **xAI rotates the refresh token on every use**, and re-sending a used one trips reuse detection and can revoke the newer token. A second process refreshing the same grant breaks the first. | Hermes `auth_xai.py` L300–351 and L100–106, Kilo docs ("Token rotation"), grok-build `oidc/refresh.rs` L35 |
| **Access-token lifetime is not fixed.** Hermes' code says "~6h", and also that "device-code logins often return ~15-minute JWTs". Clients read the JWT `exp` claim and `expires_in` rather than assuming a lifetime. | Hermes `auth_constants.py` L99–102, `auth_xai.py` L181–192 |
| **Which API base URL the token is used against: two routes are in use.** (a) Hermes and OpenCode send the bearer to **`https://api.x.ai/v1`**. Hermes uses the Responses API there. OpenCode leaves the AI SDK default and only swaps the `Authorization` header and `User-Agent`. (b) Grok Build and OpenClaw send it to **`https://cli-chat-proxy.grok.com/v1`** using the Responses API. Grok Build's config says "Only API-key inference uses `xai_api_base_url`". OpenClaw's OAuth provider uses base URL `https://cli-chat-proxy.grok.com/v1` and model list `.../v1/models`. | Hermes `auth_constants.py` L73, `runtime_provider.py` L513; OpenCode `xai.ts` L218–293; grok-build `xai-grok-env/src/lib.rs` L21–27, `xai-grok-config/src/endpoints.rs` L1–4; OpenClaw `provider-catalog.ts` L23–26 and L38–44 |
| Extra headers: OpenClaw's quota call to `https://cli-chat-proxy.grok.com/v1/billing?format=credits` sends `x-grok-client-mode: cli` and `x-grok-client-version`. Inference with the token on `api.x.ai` needs only `Authorization: Bearer` in Hermes and OpenCode. | OpenClaw `usage.ts` L17–19 and L199–202, OpenCode `xai.ts` L290–291 |
| **Grok Build CLI commands**: `grok login` (browser OAuth at `auth.x.ai`, the default; also `--oauth`), `grok login --device-auth` (alias `--device-code`) for SSH, containers, and remote VMs, and `grok logout` (clears cached credentials). Credentials are stored in `~/.grok/auth.json` and refresh automatically. Grok Build writes that file with owner-only permissions (0600). | docs.x.ai/build/enterprise, grok-build `02-authentication.md`, grok-build `storage.rs` L240 |
| The consent screen may say "Grok Build" even when another app is signing in, because the client is shared. | OpenClaw docs ("Known limits") |

**Not confirmed:**
- Whether a non-Grok-Build app may use that client id. See §3.6.
- Whether the subscription token works with **Chat Completions** at `api.x.ai`, which is what Praxis's adapter speaks. Every working subscription integration I read uses the **Responses** API, except OpenCode, which uses the AI SDK default; I did not verify which xAI endpoint that is. A Hermes issue comment shows a `POST /v1/chat/completions` with an OAuth token returning the same entitlement 403 as other calls, which doesn't prove the endpoint is supported.
- Whether the redirect URI is restricted to certain ports or paths for this client.
- Whether `/oauth2/revoke` accepts a public-client refresh token.
- Which scopes are actually required.

### 3.3 How other tools do it

| Tool | User-facing entry | Flow(s) | Where tokens live | API base for inference | Notes |
|---|---|---|---|---|---|
| **Grok Build** (xAI) | `grok login`, `grok login --device-auth`, `grok logout` | Browser PKCE (random loopback port, paste fallback) and device code | `~/.grok/auth.json`, 0600 | `cli-chat-proxy.grok.com/v1` for OAuth; `api.x.ai/v1` for API keys | Enterprise can pin `preferred_method`, disable API keys, or use its own OIDC IdP. |
| **Hermes Agent** | `hermes model` → "xAI Grok" group → OAuth member; `hermes auth add xai-oauth [--no-browser]`; dashboard | Device code (was PKCE loopback) | `~/.hermes/auth.json` | `api.x.ai/v1`, Responses transport | xAI announced it ("Connect Grok to Hermes Agent"). Docs warn about 403s from tier gating. |
| **OpenClaw** | `openclaw onboard` → xAI OAuth; `openclaw models auth login --provider xai --method oauth|api-key` | Device code only ("does not need a localhost callback") | OpenClaw auth profiles | OAuth: `cli-chat-proxy.grok.com/v1`; API key: `api.x.ai/v1` | Default `xai/grok-4.7`. Shows SuperGrok quota via `/v1/billing`. Announced by xAI. |
| **OpenCode** | `/connect` → xAI → "SuperGrok Subscription" or "Manually enter API Key"; `opencode auth login` | Device code in current source; xAI's announcement also lists a browser method | `~/.local/share/opencode/auth.json` | `api.x.ai/v1` (AI SDK default) with the bearer swapped in | Single-flight refresh to avoid replaying a rotated refresh token. Announced by xAI. |
| **Kilo Code** | xAI provider settings, with a browser option and a headless (device-code) option | PKCE loopback on fixed `127.0.0.1:56121`, plus device code | Not stated | Not stated | Warns that concurrent processes can invalidate each other's tokens. Announced by xAI. |
| **Warp** | Settings → "Connect SuperGrok subscription"; Agent CLI `/connect-grok` | PKCE loopback on fixed `127.0.0.1:56121`, plus a paste-code fallback | OS keychain on the device | Via Warp's backend; the token is used "in-flight" | "Usage draws from the same weekly pool as Grok Build." No ZDR for subscription traffic. Announced by xAI. |

### 3.4 Can xAI's model list fill a dropdown?

- **With an API key: yes.** `GET https://api.x.ai/v1/models` is documented as "List all models available to the authenticating API key". Each entry has `id`, `aliases`, and `context_length`. Praxis's `_parse_models` / `_context_number` already read `context_length`. `GET /v1/language-models` adds `input_modalities` and `output_modalities`, which lets us mark vision-capable models and hide image/video models from chat roles.
- **With the subscription token: unconfirmed.** Hermes doesn't call it and notes that some OAuth-callable models are missing from `/v1/models`. A Hermes user shows `GET /v1/models` with an OAuth token returning **403** when the account had no entitlement, which suggests the endpoint takes the bearer but proves nothing about the contents. OpenClaw fetches an OAuth "subscription catalog" from `https://cli-chat-proxy.grok.com/v1/models`, and Grok Build's default model list is `{proxy}/models`.
- **Design consequence:** for OAuth, try the live list (route decided in the PR3 spike), and **fall back to a curated list in the registry**: `grok-4.7` (default), `grok-4.6`, `grok-4.5`, `grok-build-0.1`, `grok-4.3` (OpenClaw's current catalog), plus typed entry. A curated list can go stale, so the typed entry stays.

### 3.5 Billing and the usage pool

- xAI's FAQ: the xAI account is shared between Grok and the xAI API, but **"the billing is separate for Grok and xAI API."** API keys are billed through xAI Console. Issue #90 records that SuperGrok Heavy includes no API credits. So for the UI we can say: **a SuperGrok/X Premium subscription does not pay for API-key usage; API keys are billed separately in xAI Console.**
- Warp's docs say: "xAI gives every paid Grok subscription one weekly usage pool that is shared across all Grok products — Grok chat, Grok Build ... and API access all draw down the same pool", and requests from Warp appear under the "API" label on grok.com. OpenClaw likewise treats SuperGrok quota and Console API credits as "separate billing buckets". This is **third-party documentation**. I found no xAI page that states the pool size or the reset rules. Hermes issue #26847 has conflicting user reports: some say "weekly", some say a monthly reset ("June 1"), some had 403s on day one. **Treat the pool size and reset as unconfirmed.**
- xAI decides which accounts are eligible. xAI's announcements say "available on every tier", while Hermes, OpenClaw, and Warp all say xAI may reject some accounts with a 403.

### 3.6 Is subscription OAuth officially usable by third-party apps?

What I found:
1. xAI **has officially announced** subscription sign-in for specific third-party apps: Hermes Agent, OpenClaw, OpenCode, Kilo Code, and Warp. The announcements say the integration is available on every tier and/or that "More open-source agents and integrations are coming soon." A reviewer named `mark-xai` reviewed the Hermes PR.
2. All of those apps reuse **Grok Build's client id** and identify themselves only through `referrer`. I found **no public xAI documentation for registering your own OAuth client** for subscription access, and no developer program or terms written for it. xAI's docs only describe enterprise OIDC for Grok Build itself, meaning your own IdP for *Grok Build* users.
3. xAI's Acceptable Use Policy (effective 2026-08-14) prohibits "Accessing the Services through **unauthorized** automated or non-human means, whether through a bot, script, or otherwise."

**Conclusion:** subscription OAuth is officially offered for the apps xAI has named. **Praxis Prime is not one of them**, and there is no published way to become one. Building it is technically simple, and others have done it, but shipping it on by default carries a real terms risk until xAI says yes. Recommendations:

- Michael contacts xAI before PR3 merges (Open Question Q1).
- Until then, ship sign-in behind an **"Experimental"** label and a config flag (`[providers.xai] allow_subscription_oauth = true`, default off in release builds). The UI says plainly that this uses xAI's shared Grok sign-in client.
- Send `referrer=praxis-prime` and `User-Agent: praxis-prime/<version>` so traffic is honestly labelled. Never present Praxis as Grok Build.

---

## 4. UX spec

### 4.1 Flow

```
Welcome → Owner → Second factor → Provider → Connect → Model → (Test and save) → Dials → Extras → Done
                                     │          │
                                     │          ├─ local/LAN: base URL (prefilled when detected), optional key, TLS pin
                                     │          ├─ cloud, key: API key (or "use the key found in XAI_API_KEY")
                                     │          └─ xAI: [Sign in with Grok] or [API key]  → sign-in screen
                                     └─ [Skip for now] → Dials (inference not configured)
```

**Settings → Model provider** opens the same component at **Provider** (or at **Model** for a model-only change).

### 4.2 Navigation rules

- **Back on every step**, top-left, as `← Back` and the browser Back key. The wizard keeps a step history stack, and each step's URL hash (for example `#/setup/provider`, `#/setup/connect/xai`) drives it, so the browser Back button works too.
- Back keeps what you entered (provider, base URL, model choices) **except secrets**. An API key typed on Connect is cleared when you go Back past Connect. It is never put in the URL or `sessionStorage`. It lives only in React state until you save.
- **Steps after something irreversible don't re-run it.** After the owner is created, Back from "Second factor" goes to Welcome, which shows "Owner created: ada". It does not show the owner form again. After a successful save, Back from Dials goes to a read-only "Provider saved: xai:grok-4.7 (signed in as …)" card with a "Change" link that starts at Provider.
- Leaving the sign-in screen with Back **cancels** the pending device-code flow on the server.
- **Skip for now** is a visible secondary button on the Provider step (and as option 0 in the terminal picker). It keeps today's behavior (`_skip`): chat stays up with the "Inference not configured" banner. If a provider is already configured, Skip needs the same confirm and step-up as today.

### 4.3 Provider step (the picker)

Layout (web):

```
Choose where Praxis thinks                                   [Skip for now]
Nothing is selected until you choose it.

[ Search providers…                                   ]

LOCAL — prompts stay on this computer or your network
  ● Ollama                          Running here · 7 models        >
  ● LM Studio                       Running here · 2 models        >
    llama.cpp server                Not detected (port 8080)       >
    vLLM                            Not detected (port 8000)       >
    Other OpenAI-compatible server  This computer or your network  >
  ⓘ No GPU detected. Local models will run on the CPU and may be slow.
    A small model, a server on your network, or a cloud provider may work better.
  [Scan again]

CLOUD — prompts leave this machine
  xAI (Grok)                        Sign in with Grok or API key   >
  OpenAI                            API key · key found in OPENAI_API_KEY  >
  Anthropic                         API key                        >
  Other OpenAI-compatible cloud     Base URL + API key             >
  ⚠ Requires a BAA/DPA with the provider; PHI will leave this machine   (only when a compliance dial is monitor/enforce)
```

Behavior:

- **Detection runs automatically** when the step opens. It is the same read-only `detect` call with the same 0.8 s per-server timeout, and "Scan again" repeats it. A detected server gets a green dot and the text "Running here · N models". **Nothing is preselected**, even when exactly one server is found. This keeps the blueprint rule.
- **Hardware note**: shown in the Local section when `detect.hardware` is empty. It is information only and blocks nothing. The note never names a GPU vendor.
- **Env key badges**: if `detect.envKeys` contains a provider's key name, the row shows "key found in XAI_API_KEY". It shows the name only, never the value.
- **Search** filters by display name, id, and aliases (`grok`, `x.ai` → xAI; `llama.cpp`, `llamacpp` → llama.cpp server). Sections with no matches collapse. If there are no results, show "No match. Use 'Other OpenAI-compatible server' for anything that speaks /v1/chat/completions."
- **Allowlist**: if `models.allow_providers` is set, providers that aren't on it are shown greyed out with "Blocked by the admin provider allowlist". They are not hidden, so the user knows why.
- **Compliance**: Cloud rows show the existing cloud warning when a dial is at monitor or enforce. For **subscription sign-in**, see §4.4.
- **Keyboard and accessibility**: the list is a `listbox` with `group` sections and headings. Arrow keys move, Enter selects, `/` focuses search, and Esc clears the search.
- "On my network" is no longer a separate lane. The Local section covers both. The lane (`local` / `lan` / `cloud`) is **worked out from the provider and base URL** using the existing `_locality()` rule, and is still sent to the backend for compatibility.

### 4.4 Connect step

What this step shows depends on the provider's `authMethods` in the registry (§5.1).

**Local / network provider** (Ollama, LM Studio, llama.cpp, vLLM, other OpenAI-compatible):
- Base URL, prefilled with the detected or default URL and editable. If the host is not loopback, the step shows "This server is on your network" and the existing TLS fingerprint option (probe + pin, as today).
- Optional API key, collapsed under "This server needs a key".
- "Check connection" runs `probe` and shows "Reachable · N models" or the error.

**Cloud provider with an API key only** (OpenAI, Anthropic, other OpenAI-compatible cloud):
- An API key field (password type, `autocomplete=off`) with a link to where you get a key. If the env var is present: a radio "Use the key in OPENAI_API_KEY" versus "Paste a different key".
- Other OpenAI-compatible cloud also gets a Base URL field.

**xAI (Grok)**: two cards, with no default selected:

```
How do you want to connect to Grok?

( ) Sign in with Grok                                   [Experimental]
    Use your SuperGrok or X Premium subscription. No API key.
    Usage counts against your Grok subscription's limits, which xAI sets.
    xAI's sign-in page may say "Grok Build". That is expected.

( ) API key
    Billed to your xAI API account in console.x.ai, pay as you go.

ⓘ A SuperGrok or X Premium subscription does not include API credits.
  API-key usage is billed separately by xAI, even if you also subscribe.
                                                          [← Back]  [Continue]
```

- If an xAI API key is found in the environment, the API key card says "Key found in XAI_API_KEY".
- If OAuth tokens are already stored, the sign-in card says "Signed in as m…@… · Continue with this account / Use a different account". Using a different account needs a step-up (§5.10).
- **Compliance gate**: when any regulated dial (HIPAA, FERPA, COPPA, GDPR, PCI) is at **enforce**, the sign-in card is disabled with "Subscription sign-in runs under xAI's consumer terms and can't be covered by a BAA/DPA. Use an API key under an agreement with xAI, or a local model." At **monitor**, it shows a stronger warning. The "Requires a BAA/DPA" warning stays on the API key card too. (Owner decision: Q6.)
- **Feature flag**: if `allow_subscription_oauth` is off, the sign-in card shows "Turned off on this install (Settings → Model provider → Experimental)". Owners can turn it on there after reading a short notice (§3.6).

### 4.5 "Sign in with Grok" screen (web)

The screen uses the device-code flow (§5.3), because it works for a laptop browser, an SSH tunnel, and a headless box all the same way.

```
Sign in with Grok

1. Open this page on any device:   https://accounts.x.ai/…   [Open sign-in page ↗]  [Copy link]
2. Enter this code:                 WDJB-MJHT                 [Copy code]
   (The link above already has the code filled in.)

Waiting for you to approve…   ◌        Code expires in 14:32

[← Back]  [Cancel]  [Get a new code]
```

- "Open sign-in page" opens `verification_uri_complete` in a new tab (`rel="noopener noreferrer"`). The daemon checks that the URL is HTTPS on `x.ai` or `*.x.ai` before returning it.
- An optional QR code of `verification_uri_complete` lets you approve on a phone. It is rendered locally with no external QR service.
- States:
  - **waiting**: spinner and countdown.
  - **approved**: "Signed in as ‹email from the ID token›" plus [Continue] to the Model step.
  - **denied**: "Sign-in was cancelled on the xAI page." plus [Try again].
  - **expired**: "The code expired before it was approved." plus [Get a new code].
  - **ineligible**: if xAI returns a 403 at token or first use, show "xAI signed you in but says this account can't use Grok here (no eligible subscription, or no usage left)." plus [Use an API key instead] and [Back].
  - **network**: "Couldn't reach auth.x.ai." plus [Try again].
- **Tokens never reach the browser.** The browser only ever sees `flowId`, `userCode`, the verification URLs, and the countdown, then the account display name and email.

### 4.6 Model step

```
Pick a model                                   Provider: xAI (Grok) · Signed in

Primary model   [ grok-4.7                          ▾ ]   ← live list or curated list
                256k context · text, image
                [ Type a model id instead ]

▸ Advanced (optional)
    Utility model           [ Same as primary ▾ ]   used for quick background tasks
    Vision model            [ Same as primary ▾ ]   only image-capable models listed
    Decision Engine judge   [ None (rules only) ▾ ] T0/T1 rules keep working without it

                                        [← Back]  [Test and save]
```

- **Where the list comes from.** `POST /v1/onboarding/models` (§5.2) returns `models[]` plus a `source` of `live` or `curated`. The caption says "From your xAI account" or "Suggested models (couldn't load the live list)".
- **Default selection.** xAI: `grok-4.7`, from the registry's `defaultModels.primary`, if it is in the list or the list is curated. Local servers: no default unless the server has exactly one model. Other cloud providers: no default; the user picks. Picking a model inside a provider you chose explicitly doesn't break the "no default provider" rule.
- **Filtering.** Hide image/video generation models (from `output_modalities`, or `grok-imagine-*` when only `/v1/models` data is available). Sort by `created` (newest first), with the registry default pinned at the top. Show `context_length` when known. Mark entries below the 32K warn floor or 16K block floor (from `messages.py`) before the test runs.
- **Typed entry**: "Type a model id instead" swaps the dropdown for a text field. It is always available.
- **Advanced roles**: collapsed by default. "Same as primary" means the role isn't written to config, which is today's behavior for blank fields. Each chosen role is tested like today (`_optional_roles`). A role that fails is reported and left unchanged. It does not fail the save.

### 4.7 Test and save

One button, as today. Behavior by auth type:

| Auth | What the test does | What gets saved |
|---|---|---|
| none (local) | Same as today: context length from `/v1/models` or `/api/tags`, a completion, a tool call. | `config.toml`, `provider-ready.json` |
| api_key | Same as today. The key is used only for the base URL it's bound to. | The key goes to `secrets.env` (`PRAXIS_PRIME_XAI_API_KEY`, etc.) |
| oauth (xAI) | The same three checks, using the **current access token from the token store** against the **pinned xAI route** (§5.6). It refreshes once if the token is expiring. If the token is refused, it refreshes once and retries once. | `config.toml` gets `[models.providers.xai] auth = "oauth"`. Tokens are already in the token store; nothing is written to `secrets.env`. |

While testing: "Testing… 1/3 reaching xAI · 2/3 completion · 3/3 tool call". On success, go to Dials with "Inference ready". If the router reloads in-process, there's no restart notice; otherwise, keep today's restart notice.

**Error messages.** Each message is one plain sentence plus one next step. Raw provider text goes under a "Details" disclosure, with secrets scrubbed.

| Condition | Detected by | Message |
|---|---|---|
| Missing key | No key supplied or stored for a key provider | "xAI needs an API key. Paste one from console.x.ai, or go Back and choose Sign in with Grok." |
| Key rejected | 401 on test | "xAI rejected this API key. Check it in console.x.ai → API keys." |
| Not signed in | `auth=oauth` but no tokens | "You're not signed in to Grok. Sign in again." |
| Sign-in expired or revoked | Refresh returns 400/401 or `invalid_grant` (terminal) | "Your Grok sign-in has expired or was revoked. Sign in again." (tokens quarantined) |
| Out of usage / not eligible | 403 whose body matches xAI's entitlement or quota text ("run out of credits", "do not have an active Grok subscription", `personal-team-blocked:spending-limit`, "used all available credits", "monthly spending limit") | "xAI says this account has no Grok usage left or isn't eligible here. Check usage on grok.com and wait for the reset, or switch to an API key (billed separately)." No refresh loop. |
| Stale token | 401, or a 403 with `[WKE=unauthenticated:` or "OAuth2 access token could not be validated" | Silent refresh plus one retry; if that fails, "Sign in again." |
| Rate limited | 429 | "xAI is rate-limiting requests. Wait a minute and try again." |
| Model not available | 404, or a model-not-found error | "This model isn't available to your account. Pick another one from the list." |
| Context too small | Existing check | Existing text (16K block / 32K warn). |
| No tool call | Existing check | "The model answered but didn't make a tool call. Agent mode needs tool calls. Pick another model." |
| Network / DNS / TLS | Probe error | "Couldn't reach ‹host›. Check the network and try again." |
| Admin allowlist | Existing | Existing. |
| Policy gate | Dial at enforce | "Subscription sign-in is off because the ‹dial› dial is set to enforce." |

### 4.8 Terminal wizard and scripted setup

**Interactive (`praxis-prime setup --section models`):**

```
Choose a provider. Nothing is preselected.

  Local (prompts stay here)
    1  Ollama                     running · 7 models
    2  LM Studio                  running · 2 models
    3  llama.cpp server           not detected
    4  vLLM                       not detected
    5  Other OpenAI-compatible    this computer or your network
  No GPU detected. Local models will run on the CPU and may be slow.

  Cloud (prompts leave this machine)
    6  xAI (Grok)                 sign in or API key
    7  OpenAI                     key found in OPENAI_API_KEY
    8  Anthropic
    9  Other OpenAI-compatible cloud

    0  Skip for now        b  Back        /  search
Choice: 6

How do you want to connect to Grok?
    1  Sign in with Grok (SuperGrok / X Premium subscription)   [experimental]
    2  API key (billed to your xAI API account)
  A SuperGrok or X Premium subscription does not include API credits.
  API-key usage is billed separately by xAI.
    b  Back
Choice: 1

Open this page on any device:  https://accounts.x.ai/…
Enter the code:                WDJB-MJHT
Waiting for approval (code expires in 15:00, Ctrl+C to cancel)…
Signed in as m…@….

Models from your xAI account:
    1  grok-4.7   (default)
    2  grok-4.6
    …
    t  type a model id     b  Back
Choice [1]:
Advanced roles (utility, vision, judge)? [y/N]
Testing… completion ok, tool call ok. Inference ready (xai:grok-4.7).
```

- `b` goes back one step at every prompt. Ctrl+C during sign-in cancels the flow and leaves the provider unchanged.
- If the terminal can open a browser (a graphical session, not SSH), it may also open `verification_uri_complete`. The URL and code are always printed.

**Scripted (`--non-interactive`) — new flags:**

| Flag | Meaning |
|---|---|
| `--provider xai` | Unchanged (registry id). |
| `--auth api-key\|oauth\|none` | Default: `none` for local providers; `api-key` for cloud providers. `oauth` is valid only for providers whose registry entry lists it. |
| `--oauth-timeout SECONDS` | How long to wait for approval. Default: the code's `expires_in`. Exit 1 on timeout. |
| `--list-providers [--json]` | Print the registry and the detection snapshot. Makes no changes. |
| `--list-models --provider P [--auth …]` | Print the model list the wizard would show. Makes no changes. |
| `--provider-status [--json]` | Show the configured provider, auth method, signed-in account, and token state (`ok`, `expiring`, `needs_reauth`, `quota`). Never prints token values. |
| `--sign-out xai` | Revoke (best effort) and delete stored xAI tokens. Needs `--replace` if xAI OAuth is the active primary (inference then becomes unconfigured). |

Examples:

```bash
# Subscription sign-in on a headless box (prints URL + code on stdout, waits for approval)
pprime setup --non-interactive --provider xai --auth oauth --model grok-4.7

# API key, as today
printf '%s\n' "$XAI_API_KEY" | pprime setup --non-interactive --provider xai --auth api-key --model grok-4.7 --api-key-stdin

pprime setup --provider-status
pprime setup --sign-out xai --replace
```

`--non-interactive --auth oauth` still requires someone to approve in a browser. That's fine for a first-run script on a box you're watching. It is not for unattended CI; use an API key there.

The **TUI** (`praxis-prime tui`) is a gateway client and doesn't run setup. When `status.auth.state` is `needs_reauth` or `quota`, it shows the banner text from §4.7 and the command `pprime setup --section models`.

### 4.9 Settings → Model provider

A card on the existing `#/settings` page:

```
Model provider
  xAI (Grok) · Signed in with Grok as m…@… · grok-4.7
  Token: refreshed 10 min ago                        Status: Ready
  [Change model]   [Change provider]   [Sign out of Grok]   [Sign in again]
  Advanced: utility = same as primary · vision = same as primary · judge = none
  Experimental: [x] Allow subscription sign-in (xAI)
```

- **Change model** opens the Model step only. A model-only change needs `replace` but not a step-up, as today.
- **Change provider** opens the picker at Provider. It needs a step-up, as today.
- **Sign out of Grok** asks for confirmation, needs a step-up, revokes the token (best effort), and deletes it. If xAI OAuth is the primary, inference becomes "not configured" and the confirm dialog says so.
- **Sign in again** runs the sign-in screen and replaces the tokens. It needs a step-up because it changes the credential (it may be a different account).
- Non-admin roles see a read-only line: "Model provider: xAI (Grok) · Ready" (or "Needs attention"). They see no buttons and no account email.
- The same React component (`ProviderPicker`, `ConnectStep`, `GrokSignIn`, `ModelStep`) is used by the wizard and by Settings. The props are `mode: "first" | "admin"` and `startAt`.

---

## 5. Technical design

### 5.1 Provider registry

New module `praxis_prime/onboarding/registry.py`, with pure data and no I/O. It is the single source for the CLI, the gateway, and the UI (served by `POST /v1/onboarding/providers`). It replaces `CLOUD_PROVIDERS`, `LOCAL_PROVIDERS`, `KEY_NAMES`, `CLOUD_BASES`, `_REQUIRED_KEY`, `detect.LOCAL_SERVERS`, and `cli._lane_for`. Those names stay as thin derived aliases for one release so tests and imports keep working.

```python
@dataclass(frozen=True)
class AuthMethod:
    id: Literal["none", "api_key", "oauth"]
    label: str                      # "Sign in with Grok (SuperGrok / X Premium subscription)"
    note: str                       # plain-language billing note
    secret_name: str = ""           # api_key: "PRAXIS_PRIME_XAI_API_KEY"
    env_names: tuple[str, ...] = () # api_key: ("PRAXIS_PRIME_XAI_API_KEY", "XAI_API_KEY")
    oauth: OAuthSpec | None = None  # oauth only
    experimental: bool = False
    regulated_ok: bool = True       # False → disabled when a regulated dial is at enforce

@dataclass(frozen=True)
class OAuthSpec:
    issuer: str                     # "https://auth.x.ai"
    client_id: str                  # see Q1
    scopes: tuple[str, ...]         # ("openid","profile","email","offline_access","grok-cli:access","api:access")
    flows: tuple[str, ...]          # ("device",) in PR3; ("device","browser") later
    referrer: str                   # "praxis-prime"
    allowed_hosts: tuple[str, ...]  # (".x.ai",) for auth endpoints and verification URIs
    inference_base_url: str         # decided by the PR3 spike (api.x.ai/v1 or cli-chat-proxy.grok.com/v1)
    inference_hosts: tuple[str, ...]# the bearer may only go to these hosts

@dataclass(frozen=True)
class ModelList:
    supported: bool
    path: str                       # "/v1/models", "/api/tags", "/v1/language-models"
    parser: Literal["openai", "ollama"]
    by_auth: Mapping[str, str] = {} # oauth may use a different base or path
    curated: tuple[str, ...] = ()   # fallback list

@dataclass(frozen=True)
class ProviderEntry:
    id: str                         # wizard id: "xai", "ollama", "lmstudio", ...
    adapter: str                    # router id: "xai", "ollama", "openai-compatible", ...
    display_name: str
    aliases: tuple[str, ...]        # search terms
    section: Literal["local", "cloud"]
    description: str
    auth_methods: tuple[AuthMethod, ...]
    default_base_url: str
    base_url_editable: bool
    detect: DetectSpec | None       # (base, models_path, props_path)
    model_list: ModelList
    default_models: Mapping[str, str]   # {"primary": "grok-4.7"}; empty → no default
    docs_url: str
    key_url: str = ""               # where to get a key
```

Initial entries (PR1 ships only adapters the router already has):

| id | adapter | section | auth | default base | model list | default primary |
|---|---|---|---|---|---|---|
| `ollama` | ollama | local | none (optional key) | `http://127.0.0.1:11434` | `/api/tags` | none |
| `lmstudio` | openai-compatible | local | none | `http://127.0.0.1:1234` | `/v1/models` | none |
| `llamacpp` | openai-compatible | local | none | `http://127.0.0.1:8080` | `/v1/models` (+`/props`) | none |
| `vllm` | openai-compatible | local | none | `http://127.0.0.1:8000` | `/v1/models` | none |
| `openai-compatible` | openai-compatible | local | none / api_key | user-entered | `/v1/models` | none |
| `xai` | xai | cloud | api_key; oauth (PR3, experimental) | `https://api.x.ai/v1` | api_key: `/v1/language-models` → `/v1/models`; oauth: per spike, curated fallback | `grok-4.7` |
| `openai` | openai | cloud | api_key | `https://api.openai.com/v1` | `/v1/models` | none |
| `anthropic` | anthropic | cloud | api_key | `https://api.anthropic.com` | `/v1/models`, if it works with Praxis's headers; otherwise typed | none |
| `openai-compatible-cloud` | openai-compatible | cloud | api_key | user-entered | `/v1/models` | none |

**OpenRouter** (and other named cloud presets) wait for a later PR. Today every OpenAI-compatible preset shares one adapter slot and one key (`PRAXIS_PRIME_OPENAI_COMPATIBLE_API_KEY`), so a named cloud preset would overwrite a local server's settings. Adding presets needs named adapter instances in `router/factory.py` and their own key names. Until then, OpenRouter works through "Other OpenAI-compatible cloud".

### 5.2 Gateway API

Every new route sits under `/v1/onboarding/`, is POST (matching `_dispatch`), and requires an **owner/admin session**, plus the existing CSRF, `Sec-Fetch-Site`, 413, and 415 checks. During the first-run window (no owner yet), `providers`, `detect`, and `models` also accept the first-run token, like `probe` does today. The `oauth/*` routes do **not**: sign-in happens after the owner exists. Each route gets a matching WebSocket frame (`onboarding.providers`, `onboarding.models`, `onboarding.oauth.start`, …).

| Route | Body | Returns |
|---|---|---|
| `providers` | `{}` | `{providers:[ProviderEntry…], detection:{servers, envKeys, hardware}, policy:{allowProviders, regulatedEnforce:bool, subscriptionOauthEnabled:bool}}` |
| `models` | `{provider, authMethod, baseUrl?, apiKey?, tlsFingerprint?}` | `{models:[{id, contextLength?, input?:["text","image"], created?}], source:"live"\|"curated", default?, warning?}`. `apiKey` follows the same binding rule as `test`: a stored key is used only for its bound base URL. |
| `oauth/start` | `{provider:"xai", flow:"device", stepUpToken?}` | `{flowId, userCode, verificationUri, verificationUriComplete, expiresAt, interval}`. Needs `stepUpToken` when xAI tokens already exist (it's a replacement). |
| `oauth/poll` | `{flowId}` | `{status:"pending"\|"approved"\|"denied"\|"expired"\|"ineligible"\|"failed", account?:{name, email}, error?}` |
| `oauth/cancel` | `{flowId}` | `{ok:true}` |
| `oauth/signout` | `{provider:"xai", stepUpToken, replace?}` | `{ok:true, revoked:bool, inferenceReady:bool}` |
| `save` (changed) | adds `authMethod` (`"none"\|"api_key"\|"oauth"`). `lane` becomes optional (derived). | Unchanged. For `oauth`, rejects with `code:"oauth_missing"` if there are no approved tokens. |
| `status` (changed) | — | adds `auth:{provider, method, account?, state:"ok"\|"expiring"\|"needs_reauth"\|"quota"\|"ineligible", lastRefresh?}` for owner/admin. Other roles get only `inferenceReady`, as today. |

Rules for `flowId`:
- It is 128-bit random and kept only in daemon memory, together with `device_code`, the principal's account id, **and the session id**.
- Only the same session can poll or cancel it.
- There is one pending flow per daemon. Starting a new one cancels the old one.
- A flow dies at `expires_in`, or after 15 minutes, whichever is sooner.
- `device_code` is never returned to the client.

Polling the token endpoint happens **in the daemon**. The browser's `oauth/poll` just reads the flow's state, so the daemon controls the polling rate and `slow_down` backoff. A WebSocket `onboarding.oauth.update` push may replace browser polling later.

### 5.3 OAuth client

New module `praxis_prime/providers_auth/xai_oauth.py`. It uses the existing `onboarding/probe.fetch` (no redirects, size caps, timeouts, address checks) for every call.

1. **Discovery**: GET `https://auth.x.ai/.well-known/openid-configuration`. Every endpoint used (`device_authorization_endpoint`, `token_endpoint`, `revocation_endpoint`, `jwks_uri`) must be `https` on `x.ai` or `*.x.ai`; otherwise fail (the Hermes pattern). Cache it for 1 hour, and re-check cached values before each use.
2. **Device code**: POST `client_id`, `scope`, `referrer=praxis-prime` (form-encoded). Check that `verification_uri` and `verification_uri_complete` are `https` on `*.x.ai`.
3. **Poll**: wait `interval` seconds **before** the first poll (as Grok Build does). Handle `authorization_pending` (continue), `slow_down` (+5 s), `access_denied` (denied), and `expired_token` (expired). Stop at the deadline. A 403 → `ineligible`.
4. **Token response**: require `access_token` and `refresh_token`. A missing refresh token means `offline_access` wasn't granted, which is an error. Validate the `id_token`: ES256 against the JWKS, `iss`, `aud` = client id, `exp`, `iat`. Reuse the existing OIDC validator. Keep only `sub`, `email`, and `name` from it.
5. **Refresh**: see §5.5.
6. **Revoke**: POST `token`, `token_type_hint=refresh_token`, `client_id` to `revocation_endpoint`. This is best effort; failure is logged without the token. Local deletion always happens.

**Browser PKCE + loopback (later, PR6, optional).** Only for the **terminal wizard on a desktop**, where the browser runs on the same machine. It binds `127.0.0.1` (never `0.0.0.0`) on a random port with path `/callback`; uses `state`, `nonce`, and an S256 challenge; is single-use; times out after 10 minutes; and gets a CORS allow-origin for exactly `https://accounts.x.ai` on that one route. It also has a paste-the-callback-URL fallback (Warp's lesson). The web wizard does **not** get this, because the daemon's gateway refuses cross-site requests on purpose, and a remote browser couldn't reach the loopback anyway. This waits on Q3 (allowed redirect URIs).

### 5.4 Token storage

- **Where:** `$XDG_CONFIG_HOME/praxis-prime/provider-auth/xai.json.enc`. The directory is 0700 (`tighten_dir`) and the file is 0600, replaced atomically (temp file + `os.replace`). It is opened with `O_NOFOLLOW`, and owner and regular-file are checked with `fstat`, as `gateway.token` already does.
- **Not in `secrets.env`**, because:
  - values there are capped at 2048 chars, and JWTs can get close;
  - every refresh would rewrite the file that holds the other secrets;
  - `router/settings.py` reads `secrets.env` in workers, and refresh tokens must not reach workers (§5.5).
- **Encryption:** AES-GCM, with associated data = `"xai" + issuer + client_id`. The key lives in `provider-auth/.key` (0600), or in the OS keyring (Secret Service) when one is available, picked at write time and recorded in the file header. Being honest about what this buys: with the key file on the same disk, encryption protects against copied backups and casual reads, not against a process running as the same user. That matches how TOTP seeds are stored today (`SECURITY.md`). Moving to keyring or `secrets.env.age` follows blueprint §25 and the M5 decisions.
- **Contents (before encryption):** `issuer`, `client_id`, `scope`, `token_endpoint`, `access_token`, `refresh_token`, `expires_at` (from JWT `exp`, else `expires_in`), `last_refresh`, `account:{sub, email, name}`, `state` (`ok` / `needs_reauth` with reason), `version`.
- **Never logged.** The audit, log, and API layers get a redacting wrapper (`scrub_secrets` plus a `SecretStr` type whose `__repr__` and `__str__` print `[redacted]`). Tests assert that no token reaches captured logs, audit rows, API JSON, or exception text.
- **Backups:** the existing config backup (`backup_config`) does not copy `provider-auth/`. Copying a rotating refresh token would make the copies revoke each other, the same reason Hermes doesn't clone single-use refresh tokens into profiles (blueprint §6.1).

### 5.5 Token broker, refresh, and workers

- A single **`ProviderAuthBroker`** in the supervisor/daemon process owns the token file. **Only the broker refreshes.**
- **Single-flight:** one in-process lock plus an `fcntl` lock on `provider-auth/xai.lock`, so the CLI and the daemon don't both refresh. After taking the lock, it re-reads the file in case another holder already rotated the token.
- **Order of operations:** POST refresh → atomically write the **new pair** → then hand out the new access token. If the write fails after xAI has rotated the token, keep the new pair in memory for this process, mark `state=needs_persist`, and keep retrying the write. Never send the old refresh token again.
- **When to refresh:** proactively when `exp - now < max(120 s, min(10 min, 25% of lifetime))`. Hermes uses a 1-hour lead time for xAI but had to shrink it for ~15-minute device-code tokens, so the lead time must scale with the token's real lifetime. Reactively, refresh once on a 401 or stale-token 403, then retry the request once.
- **Terminal failure** (400, 401, `invalid_grant`): set `state=needs_reauth`, drop the access and refresh tokens from memory and disk (keep the account info for display), emit `provider.auth.expired`, and make chat show the banner. There are no automatic re-tries until the user signs in again.
- **Workers:** a worker asks the supervisor for an access token over the existing authenticated worker socket (`provider.credential {provider:"xai"}` → `{accessToken, expiresAt}`). It caches the token in memory until 60 s before expiry. **The refresh token never leaves the supervisor.** Add the token-store path and key to the worker environment drop list (`_DROPPED_ENV`).
- **CLI while the daemon runs:** the CLI writes the token file under the same lock. The daemon notices the new file `mtime` on the next credential request and reloads. No restart is needed.

### 5.6 Router and adapter changes

- `OpenAICompatibleProvider` gains an optional `credential: Callable[[], str]` (it gets the bearer per request) alongside `api_key`. `require_key` checks whichever one is configured.
- `default_providers()` builds `xai` with `credential=broker.access_token` when `[models.providers.xai] auth = "oauth"`, or with the static key otherwise.
- **Host pin:** with OAuth, the adapter refuses to send the bearer unless the URL is `https` and its host is in `OAuthSpec.inference_hosts`. `PRAXIS_PRIME_XAI_BASE_URL` overrides that point outside the pinned hosts are ignored with a warning (the Hermes pattern).
- **Transport (blocked on the spike, Q2):** if the subscription route accepts Chat Completions at `api.x.ai/v1`, nothing else changes. If it only accepts Responses (Hermes, OpenClaw, and Grok Build all use Responses), PR3 adds a small `xai_responses.py` adapter (streaming text and function calls into the existing `StreamAssembler`), used only for `auth = "oauth"`. The test in `service.test()` uses the same transport as chat.
- `parse_model_spec` is unchanged: the spec stays `xai:grok-4.7`. How it authenticates is config, not part of the model spec, so existing specs, `provider-ready.json`, and `specs_cover` keep working.

### 5.7 Error classification

A new helper, `classify_xai_error(status, body) -> ok | stale_token | entitlement | rate_limited | model_missing | other`. It follows Hermes' tested rules:
- 401 → stale_token.
- 403 with `[WKE=unauthenticated:` or "OAuth2 access token could not be validated" → stale_token.
- Any other 403 on the OAuth route → entitlement. This covers `personal-team-blocked:spending-limit`, "run out of credits", "do not have an active Grok subscription", and "used all available credits / monthly spending limit".
- 429 → rate_limited.
- 404 → model_missing.

Entitlement is **not** retried and **does not** trigger a refresh. It sets `status.auth.state = "quota"` or `"ineligible"` for the banner. On the API-key route, a 403 keeps today's generic handling.

### 5.8 Config, records, migration

```toml
[models]
primary = "xai:grok-4.7"

[models.providers.xai]
auth = "oauth"                    # "api_key" (default when absent) | "oauth"

[providers.xai]
allow_subscription_oauth = false  # experimental flag; owner toggles in Settings
```

- `provider-ready.json` adds `"auth_method": "oauth"` and `"account": {"issuer": "https://auth.x.ai", "sub_hash": "<sha256 prefix>"}`. It never stores tokens, and the email lives only in the encrypted store.
- **Migration:** nothing has to be rewritten.
  - An existing `xai:*` primary with no `auth` key means `api_key`, and the stored key binding rules don't change.
  - Existing `lane` values are still read. New saves still write `lane` (derived) so older daemons and tools can read the record.
  - Old clients that post `{lane, provider, …}` without `authMethod` work as today: the method is `none` for local providers and `api_key` for cloud ones.
  - The `KEY_NAMES` and `CLOUD_BASES` aliases stay for one release.
- **Fallback to an API key when the subscription runs out** is **off** and not built in this plan (Q7). Silently moving a user from subscription usage to pay-as-you-go API billing would be a surprise charge.

### 5.9 Audit events

These use the existing `provider.*` pattern with the existing actor field. None of them carries a token, a user code, or a device code.
- `provider.oauth.started` — provider, flow.
- `provider.oauth.connected` — provider, `sub_hash`, scope.
- `provider.oauth.failed` — reason: `denied`, `expired`, `ineligible`, `network`.
- `provider.oauth.refreshed` — sampled, or written only on failure, to avoid noise.
- `provider.auth.expired` — `needs_reauth`.
- `provider.oauth.signed_out` — `revoked: bool`.

`provider.configured` gains `auth_method`.

### 5.10 Owner, admin, and multi-user rules

These match `SECURITY.md`.
- **Who may sign in or out:** only owner/admin (`sees_all_profiles`), as for every other onboarding route. Operators, viewers, and auditors see status only.
- **Step-up:** needed for anything that changes a credential: starting sign-in when xAI tokens already exist, signing out, switching an xAI provider between `api_key` and `oauth`, and changing provider (as today). A model-only change needs `replace` only. The CLI uses `--replace` instead of a step-up, as today. The loopback bearer token cannot spend a step-up.
- **First run:** the provider step comes after owner creation, so sign-in always runs with an owner session. The first-run token is never accepted on `oauth/*`.
- **Remote access (M6):** device code needs no inbound callback, so it works through a tunnel or reverse proxy without opening ports.
- **Sharing one subscription:** the xAI sign-in is **server-wide**. Every profile and every user of this Praxis instance uses the owner's Grok subscription. When more than one account exists, the Connect card and Settings say: "Everyone who uses this Praxis Prime will use your Grok subscription." Whether xAI's consumer terms allow that is Q5. Per-profile credentials (blueprint M2 follow-up) are the long-term answer.

---

## 6. Security review notes

| Topic | Decision |
|---|---|
| Token scope | Ask only for what others ask for: `openid profile email offline_access grok-cli:access api:access`. Don't ask for `conversations:*`, `workspaces:*`, `api-keys:*`, `billing:*`, `teams:*`, or other scopes Grok Build or the discovery document list. Whether a smaller set works is part of the PR3 spike (Q4). |
| CSRF / state | The device flow has no redirect, so there is no `state`. The risk is **device-code phishing** (tricking the owner into approving a code someone else made). Mitigations: codes are only made by the daemon for an authenticated owner/admin session; `flowId` is bound to that session; the code shows only in that session; the verification URL must be on `*.x.ai`; and xAI's page shows the code for the user to confirm. For the later browser flow: `state` and `nonce` are single-use and checked; PKCE S256; a paste fallback that requires the full callback URL (with `state`), not a bare code. |
| PKCE | S256 only. The verifier stays in process memory and is never written to disk or logs. This matches the existing OIDC client. |
| Loopback binding (later browser flow) | Bind `127.0.0.1` only, on a random port, single-use, with a 10-minute timeout. CORS allows exactly `https://accounts.x.ai`, only on `/callback`. The daemon's main gateway port is never used as the redirect target. |
| Endpoint pinning | Discovery, token, revocation, JWKS, and verification URLs must be `https` on `x.ai` or `*.x.ai`, checked on every use, including cached values. The inference bearer goes only to `OAuthSpec.inference_hosts`. All calls go through `probe.fetch` (no redirects, address-class checks, size caps). |
| No tokens in URLs or logs | The browser never receives tokens. Tokens never go in a query string. Use `SecretStr`, `scrub_secrets` on provider error text, audit payload filtering (the existing `"key"` / `"secret"` filter is extended to `token` and `code`), and tests that grep logs for token fixtures. `user_code` is not a credential, but it isn't logged at info level either. |
| Storage | Encrypted file, 0600 in a 0700 directory, `O_NOFOLLOW` + `fstat`, kept out of backups, and the refresh token never reaches workers (§5.4–5.5). |
| Refresh-token rotation | One refresher (the broker) with a file lock. Write the new pair before using it. Never replay a used refresh token. If a token is lost, the user signs in again rather than the daemon guessing. |
| Revoke | Best-effort `revocation_endpoint` call, then delete locally. Tell the user they can also remove the app's access in their xAI account (Q8: where exactly). |
| Compliance | Subscription traffic is under xAI consumer terms. Warp notes it can't apply its ZDR agreement to subscription traffic. Praxis's regulated packs should disable subscription sign-in when a regulated dial is at enforce (Q6). |
| Terms of service | Praxis isn't one of xAI's named integrations, and it would reuse Grok Build's client id. xAI's AUP bans "unauthorized automated … means". Keep it experimental, behind a flag, honestly labelled (`referrer=praxis-prime`, UA), and ask xAI (Q1). Never imitate Grok Build's UA or headers (for example `x-grok-client-mode: cli`) to get access. |
| Denial of wallet | No silent fallback to API-key billing. Entitlement 403s don't loop. Refresh is bounded. |

---

## 7. Open questions

1. **Q1 — Permission (blocking for PR3/PR4).** Will xAI allow Praxis Prime to use subscription sign-in? With Grok Build's shared client id (`b1a00492-…`) and `referrer=praxis-prime`, as Hermes, OpenCode, and OpenClaw do, or with a client id of our own? There's no public registration path. Michael to contact xAI. Until there's an answer, ship as experimental and off by default.
2. **Q2 — Inference route and API shape (blocking for PR3).** Does the subscription token work for **Chat Completions** at `https://api.x.ai/v1`? Or only for **Responses** there? Or should we use `https://cli-chat-proxy.grok.com/v1` like Grok Build and OpenClaw? Does usage on each route draw from the same pool? To settle this, do a 30-minute manual check with Michael's own account before PR3 (see the checklist in PR3 below).
3. **Q3 — Redirect URIs.** For the shared client, which loopback redirect URIs does xAI accept: any port at `/callback` (as Grok Build's random port suggests) or only `:56121`? This only matters for the later browser flow.
4. **Q4 — Minimum scopes.** Is `grok-cli:access` needed for `api.x.ai`, or only for the proxy? Can `profile` be dropped?
5. **Q5 — Sharing.** Do xAI's consumer terms allow one person's subscription to serve several Praxis users or profiles? Should multi-account installs block subscription sign-in, or just warn?
6. **Q6 — Regulated dials.** Should subscription sign-in be disabled at `enforce` (my recommendation) and warned at `monitor`? Or blocked whenever any regulated pack is installed?
7. **Q7 — Fallback.** Do you want an opt-in "if my subscription runs out, use my API key" switch later? Building it needs both credentials stored side by side.
8. **Q8 — Revocation.** Does `POST /oauth2/revoke` accept a public-client refresh token? Where in the xAI account UI can a user see and revoke third-party sign-ins? I found no xAI page that documents this.
9. **Q9 — Live model list under OAuth.** Does `GET /v1/models` (api.x.ai) return the subscription's models for an OAuth bearer, or do we need the proxy's `/v1/models`? Until it's confirmed, use the curated fallback.
10. **Q10 — Usage pool.** What are the actual size and reset rules (weekly per Warp, monthly per some Hermes reports)? Should Praxis show quota like OpenClaw does (it calls `cli-chat-proxy.grok.com/v1/billing?format=credits` with Grok client headers)? I'd say not until Q1 is answered, since it relies on undocumented headers.
11. **Q11 — Eligibility copy.** The labels say "SuperGrok / X Premium", as requested, but Hermes labels the option "SuperGrok / Premium+". Hermes, OpenClaw, and Warp all warn that xAI may refuse some accounts. Which X tiers qualify is unconfirmed, so the help text should add "xAI decides which subscriptions are eligible".
12. **Q12 — Key storage backend.** Is a key file in the config dir acceptable for now, with keyring/`secrets.env.age` in M5? Or do you want the keyring in PR3?

---

## 8. Rollout plan

Each PR is small, can be reverted on its own, and keeps `main` working. Every PR updates `docs/USAGE.md` and `docs/SECURITY.md` for what it changes, and adds a CHANGELOG line.

### PR1 — Provider registry, picker, Back/Skip (no OAuth)

**Changes**
- `onboarding/registry.py` (+ derived aliases). `detect.py` and `cli.py` read from it.
- `POST /v1/onboarding/providers` and the `onboarding.providers` WebSocket frame.
- Web: the `ProviderPicker` (sections, search, auto-detect badges, env-key badges, hardware note, allowlist greying, compliance warning), a `ConnectStep` for local and API-key providers, a history-stack wizard with Back on every step, hash routing per step, and Skip on the Provider step. The Model step still has the existing fields for now.
- `save` accepts `authMethod` (only `none` and `api_key`), and `lane` becomes optional (derived).
- CLI: a numbered, sectioned picker with `b` (Back) and `0` (Skip); `--auth api-key|none`; `--list-providers [--json]`.
- Add Vitest + Testing Library to `ui/` (none today) for the components.

**Acceptance criteria**
- A fresh install shows Local and Cloud sections. Running servers are flagged and nothing is preselected. Search finds "grok" → xAI.
- With no GPU detected, the Local note appears. It never names a vendor.
- Back works on every step, and browser Back works. An API key is cleared when going Back past Connect.
- Skip for now on the Provider step leads to "Inference not configured", the same as today.
- Every existing `test_onboarding*.py` and `test_setup_chat.py` test passes unchanged, except where it asserts the old radio text.
- Old-style `save` payloads (with `lane` and without `authMethod`) still work.

**Tests**
- Registry: unique ids, every adapter is known to `parse_model_spec`, aliases resolve, derived aliases equal the old constants.
- API: `providers` is owner/admin only after the owner exists, and accepts the first-run token before that. It never returns key values.
- UI: Back/Skip navigation, search filtering, no preselection with one detected server, secret cleared on Back.
- CLI: transcript tests for the picker, `b` and `0`, and `--list-providers --json`.

### PR2 — Model step: live list, dropdown, Advanced roles

**Changes**
- `POST /v1/onboarding/models`. It uses the registry's `model_list` (`/api/tags`, `/v1/models`, `/v1/language-models` for xAI with a key), filters out image and video models, and adds context and modalities. It falls back to `curated` with a warning.
- Web `ModelStep`: a dropdown, "Type a model id instead", the registry default (`grok-4.7` for xAI), context-floor hints, and an Advanced disclosure (roles default to "Same as primary"; vision lists only image-capable models).
- CLI: a numbered model list, `t` to type, an Advanced y/N prompt, and `--list-models`.

**Acceptance criteria**
- An xAI API key shows the live list, with `grok-4.7` preselected when present.
- Ollama and LM Studio show their models.
- An unreachable list falls back to curated or typed entry with a clear caption.
- Saving with Advanced collapsed writes only the primary.

**Tests**
- Fetcher-injected tests for each parser (OpenAI and Ollama shapes, xAI `language-models` modalities).
- Key-binding rule: a stored key is never sent to a different base URL by `models`.
- Filtering of `grok-imagine-*`.
- Role tests unchanged.

### PR3 — xAI subscription sign-in: backend + CLI (experimental, flag off)

**Gate before merge:** Michael's answer on Q1, and the manual spike for Q2 and Q9. Spike checklist (run by Michael on his own machine; never paste tokens into chat or logs):
1. Run the device flow with `curl` against the discovery endpoints and keep the access token in a shell variable.
2. `GET https://api.x.ai/v1/models` with the bearer: note the status and whether `grok-4.7` is listed.
3. A small `POST /v1/chat/completions` (with one tool) on `api.x.ai`: note the status.
4. The same request through `POST /v1/responses` on `api.x.ai`.
5. Optional: the same against `cli-chat-proxy.grok.com/v1`.
6. Check grok.com → Settings → Usage to see where the calls were counted.

Record only status codes and model ids in the PR description.

**Changes**
- `providers_auth/xai_oauth.py` (discovery with pinning, device flow, ID-token validation, refresh, revoke).
- Encrypted token store (§5.4) and `ProviderAuthBroker` (single-flight, file lock, quarantine).
- The worker `provider.credential` request, plus additions to the worker environment drop list.
- Adapter `credential=` support, the host pin, and a Responses adapter if the spike requires it.
- `classify_xai_error` and the `status.auth` block.
- `oauth/start|poll|cancel|signout` routes and WebSocket frames, and `save` with `authMethod=oauth`.
- CLI `--auth oauth`, `--oauth-timeout`, `--provider-status`, `--sign-out xai`, and interactive sign-in.
- `[providers.xai] allow_subscription_oauth` flag (default off), the regulated-dial gate, and the audit events.

**Acceptance criteria**
- With the flag on, `pprime setup --provider xai --auth oauth --model grok-4.7` prints a URL and code. After approval, the live test passes and chat works without any `XAI_API_KEY`.
- No token appears in `config.toml`, `secrets.env`, logs, audit rows, API responses, or `ps`/env of workers.
- Token file permissions are 0600 and the directory 0700.
- An expired access token refreshes silently, and the rotated refresh token is persisted before use.
- A revoked grant leads to `needs_reauth` and a single banner, with no loop.
- An entitlement 403 leads to `quota`/`ineligible` with no refresh.
- `--sign-out` deletes tokens and calls revoke (best effort). With xAI OAuth as primary, it requires `--replace`.
- With the flag off or a regulated dial at enforce, OAuth is refused with the policy message.

**Tests (all with a fake xAI server or an injected fetcher; no network in CI)**
- Discovery: endpoint pin rejection (non-https, wrong host).
- Device flow: pending → approved; `slow_down` backoff; `access_denied`; `expired_token`; a token response missing `refresh_token`.
- ID token: bad signature, wrong `aud`, expired.
- Refresh: rotation persisted before use; concurrent refresh (two threads, plus a simulated second process holding the lock) → exactly one POST; write failure path; terminal 400/401 → quarantine.
- Error classifier: table-driven, using xAI body strings from Hermes' tests.
- Host pin: `PRAXIS_PRIME_XAI_BASE_URL=https://evil.example` → ignored, and the bearer is never sent.
- Session binding: another session can't poll or cancel a `flowId`; a non-admin gets 403; the first-run token is refused on `oauth/*`; step-up is required for a second sign-in and for sign-out.
- Redaction: fixture tokens never appear in caplog, audit, API JSON, or exception strings.
- Worker: `provider.credential` returns an access token only, and the worker environment has no token-store path.

### PR4 — Sign in with Grok in the web wizard

**Changes**
- `ConnectStep` xAI cards (billing note, experimental badge, regulated gate, multi-account notice), the `GrokSignIn` screen (copy buttons, open link, local QR, countdown, all states), Back = cancel, and the "Use an API key instead" path from the ineligible state.
- Test-and-save progress text and the error table (§4.7).
- Docs: `USAGE.md` gets "Connecting Grok: subscription vs API key"; `SECURITY.md` gets "Provider sign-in tokens".

**Acceptance criteria**
- On a box reached through an SSH tunnel, an owner can sign in from a laptop browser and reach "Inference ready" on `xai:grok-4.7`.
- Back during sign-in cancels the flow server-side.
- The browser never receives a token (verified in tests and in devtools during manual QA).
- All error states render the plain-language message from §4.7.

**Tests**
- Vitest: state machine (waiting → approved / denied / expired / ineligible), Back cancels, copy buttons, no token fields in the rendered DOM.
- An API contract test for `oauth/poll` response shapes.

### PR5 — Settings reuse

**Changes**
- A Settings "Model provider" card with Change model, Change provider, Sign out, and Sign in again; the experimental toggle (owner-only, with the §3.6 notice); a read-only line for other roles.
- The chat banner for `needs_reauth` and `quota`, and the TUI banner text.
- The wizard and Settings share the components (`mode`, `startAt`).

**Acceptance criteria**
- Change model needs no step-up. Change provider, Sign out, and Sign in again each need a step-up.
- After Sign out with xAI OAuth as primary, chat shows "Inference not configured".
- Non-admins see status only.

**Tests**
- Vitest for the card's role-based rendering.
- API tests for step-up rules on `oauth/signout` and re-sign-in.
- A banner rendering test for each `status.auth.state`.

### Later (not scheduled)

- **PR6:** browser PKCE + loopback for the terminal wizard on desktops, with a paste fallback (after Q3).
- **PR7:** named cloud presets (OpenRouter and others) with their own adapter instances and key names.
- **PR8:** keyring / `secrets.env.age` backend for all provider secrets (blueprint §25 / M5).
- **PR9:** optional quota display (after Q1 and Q10); opt-in API-key fallback (Q7); per-profile provider credentials.

---

## 9. Sources

All accessed 2026-10-06.

**Praxis Prime** (`smfworks/praxis-prime` @ `fcb7493`)
- `ui/src/setup.tsx`, `ui/src/App.tsx`
- `packages/prime-core/praxis_prime/onboarding/{service,cli,detect}.py`
- `packages/prime-core/praxis_prime/gateway/onboarding.py`
- `packages/prime-core/praxis_prime/channels/secrets.py`
- `packages/prime-core/praxis_prime/router/{factory,openai_compat,settings,types}.py`
- `packages/prime-core/praxis_prime/supervisor/supervisor.py` (worker environment drop list)
- `plugins/providers/xai/README.md`
- `docs/blueprint-addendum-2026-09.md` §2, §6.1; `docs/SECURITY.md` (first-run window, passkeys/TOTP/step-up, OIDC); `docs/USAGE.md` (Setup)
- Issue #90: https://github.com/smfworks/praxis-prime/issues/90

**xAI**
- OIDC discovery: https://auth.x.ai/.well-known/openid-configuration
- Grok Build auth methods and enterprise docs: https://docs.x.ai/build/enterprise
- Grok Build user guide, authentication: https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md
- Grok Build source @ `2bdd1d6a`:
  - client id and scopes: https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-login/src/config.rs
  - loopback/PKCE: https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-login/src/oidc/login.rs
  - device code: https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-login/src/device_code.rs
  - refresh-token reuse detection: https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-login/src/oidc/refresh.rs
  - 0600 storage: https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-login/src/storage.rs
  - proxy base URL: https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-env/src/lib.rs and https://github.com/xai-org/grok-build/blob/2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8/crates/codegen/xai-grok-config/src/endpoints.rs
- Models endpoint: https://docs.x.ai/developers/rest-api-reference/inference/models
- Accounts FAQ (billing is separate): https://docs.x.ai/console/faq/accounts
- Acceptable Use Policy: https://x.ai/legal/acceptable-use-policy
- Announcements: https://x.ai/news/grok-hermes, https://x.ai/news/grok-openclaw, https://x.ai/news/grok-opencode, https://x.ai/news/grok-kilocode, https://x.ai/news/grok-warp

**Hermes Agent** (`NousResearch/hermes-agent` @ `cbffbee`)
- xAI OAuth guide: https://hermes-agent.nousresearch.com/docs/guides/xai-grok-oauth (source `website/docs/guides/xai-grok-oauth.md`)
- Constants (issuer, client id, scope, device URL, refresh lead time): https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/hermes_cli/auth_constants.py
- xAI OAuth implementation: https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/hermes_cli/auth_xai.py
- Picker rows / groups: https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/hermes_cli/main_provider_setup.py and https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/hermes_cli/models_catalog_static.py
- Dashboard device flow: https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/hermes_cli/web_server_oauth.py
- Transport: https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/hermes_cli/runtime_provider.py
- Entitlement and billing classification: https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/agent/agent_runtime_helpers.py and https://github.com/NousResearch/hermes-agent/blob/cbffbeecf4ebb7f24e17241f8738923bfa069fd2/agent/error_classifier.py
- PR #26457 (original PKCE loopback provider): https://github.com/NousResearch/hermes-agent/pull/26457
- Issue #26847 (403 / tier / quota reports): https://github.com/NousResearch/hermes-agent/issues/26847

**OpenClaw**
- xAI provider docs: https://docs.openclaw.ai/providers/xai
- Source @ `0288eb1`: https://github.com/openclaw/openclaw/blob/0288eb1f3692a1d56f8c50f6bd3a33c44f02dc94/extensions/xai/xai-oauth.ts, https://github.com/openclaw/openclaw/blob/0288eb1f3692a1d56f8c50f6bd3a33c44f02dc94/extensions/xai/provider-catalog.ts, https://github.com/openclaw/openclaw/blob/0288eb1f3692a1d56f8c50f6bd3a33c44f02dc94/extensions/xai/usage.ts

**OpenCode**
- xAI plugin source @ `ecc4916`: https://github.com/anomalyco/opencode/blob/ecc4916b5a9608c30e6dd58a67f2137b594407ca/packages/opencode/src/plugin/xai.ts

**Kilo Code**
- https://kilo.ai/docs/ai-providers/xai

**Warp**
- https://docs.warp.dev/agents/inference/grok-subscription/
- PR #12599 (paste-code fallback): https://github.com/warpdotdev/warp/pull/12599
- Issue #12638: https://github.com/warpdotdev/warp/issues/12638
