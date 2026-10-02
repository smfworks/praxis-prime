# Patterns borrowed from OpenDots

**Status:** owner-approved plan input (2026-10-01). Nothing in this file is built yet. Effort figures are estimates **[E]**: one experienced engineer with AI assistance, the same basis as [Blueprint Addendum A §8](blueprint-addendum-2026-09.md#8-re-ordered-roadmap-pr-sized-milestones).

## Credit and licence

[OpenDots](https://github.com/CopilotKit/OpenDots) is an open-source TypeScript template for always-on agents, built on CopilotKit and AG-UI. It is MIT-licensed, © Atai Barkai. We reviewed it at commit `b01ac1f` (2026-10-01) as a **reference only**.

- Praxis Prime re-implements these patterns in Python: the daemon, the gateway, and the tools.
- The UI parts are written fresh in the planned `ui/` SPA.
- **No OpenDots code is copied.** For that reason, no THIRD_PARTY.md row is needed.
- If a later change does copy code, that change must add the MIT notice and a THIRD_PARTY.md row (see [AGENTS.md](../AGENTS.md), "Reuse rules").

OpenDots is a two-day-old alpha with no release. We borrow ideas from it, not a dependency on it.

## Summary

| # | Pattern | Milestone | Effort **[E]** |
|---|---|---|---|
| 1 | AG-UI event types for streaming to the UI | M1d | 1–2 wk |
| 2 | Approval cards as paused tool calls, decided once per tool call | M1d, M6 | 2–4 days |
| 3 | Live revocation of in-flight runs, plus leased background jobs | M1c (and routines) | 2–4 days |
| 4 | Browser clicks bound to a fresh page snapshot | browser tool, M4 | ~1 wk |
| 5 | Human takeover and handback of the agent's sandboxed browser or desktop, with a redacted activity log | M4 (UI in M1d) | 2–3 wk, after M4 |
| 6 | Per-worker credentials derived from one master key, and scrubbing secrets from responses | M1c, M4 | 1–2 days |
| 7 | Extra gateway request checks | M1d, M6 | ~1 day |
| 8 | "Setup needed" screen that lists exactly what is missing | M2 | < 1 day |
| 9 | Autosaved documents with revision checks (optional) | M1d and later (canvas) | ~1 wk |

How the milestone labels map to [Addendum A §8](blueprint-addendum-2026-09.md#8-re-ordered-roadmap-pr-sized-milestones):

| Label | Addendum A §8 |
|---|---|
| M1c | M1 PR (6), per-profile worker processes |
| M1d | M1 PRs (1) and (7): the SPA shell, profile picker, and admin console |
| M2, M4, M6 | Those milestones |
| "browser tool" | The existing tool in [BROWSER.md](BROWSER.md) |

## The patterns

### 1. AG-UI event types for streaming to the UI

- **Seen in OpenDots:**
  - `src/server/dot-agent.ts`: the agent emits AG-UI `BaseEvent`s.
  - `src/client/Chat.tsx`: the UI consumes them.
  - The README section "AG-UI connects the agent to the interface".
- **What Praxis Prime will do:**
  - Use the open [AG-UI](https://github.com/ag-ui-protocol/ag-ui) event vocabulary (MIT) as the payload of streaming event frames on the existing gateway WebSocket ([ARCHITECTURE §4](ARCHITECTURE.md#4-the-gateway-protocol)). The events are:
    - `RUN_STARTED` / `RUN_FINISHED` / `RUN_ERROR`
    - `TEXT_MESSAGE_*`
    - `TOOL_CALL_START` / `ARGS` / `END` / `RESULT`
    - `STATE_SNAPSHOT` / `STATE_DELTA`
    - `STEP_*`
  - Optionally, also expose them on a loopback SSE endpoint.
  - The loop's `LoopEvent` types (`loop/events.py`) are mapped onto these events.
  - The Python SDK `ag-ui-protocol` (MIT) may be used for the models. The CopilotKit runtime is not used.
- **Milestone:** M1d. M6 (PWA) and M7 (Tauri) reuse it.
- **Effort [E]:** 1–2 weeks.
- **Acceptance criteria:**
  - A chat turn with one tool call streams, in order: run start, text deltas, tool-call start, args, end, result, then run finished. Tests check this.
  - Event frames validate against the exported JSON Schema, and the generated TypeScript types compile in `ui/`.
  - Approval requests and policy verdicts are carried as AG-UI events (custom or tool-call events), so the SPA needs no second channel.
  - Nothing in this path calls a hosted service.

### 2. Approval cards as paused tool calls, decided once per tool call

- **Seen in OpenDots:**
  - `src/client/Chat.tsx` (`useHumanInTheLoop`)
  - `src/client/page-review-decision.ts`
  - `src/server/page-routes.ts` (`/conversations/:id/reviewed-page/:toolCallId`)
- **What Praxis Prime will do:**
  - Render the approval card ([ARCHITECTURE §21.2](ARCHITECTURE.md#212-approval-card-identical-in-ui-desktop-notification-telegramslack)) for a paused tool call.
  - Record the decision keyed by the tool-call ID, using the protocol's `idempotencyKey`.
  - If the user double-clicks, reloads, or reconnects, the card looks up the existing decision and result instead of acting again.
- **Milestone:** M1d (web card). M6 (mobile approval sheets).
- **Effort [E]:** 2–4 days.
- **Acceptance criteria:**
  - Approving twice, or approving after a reload, runs the action once. The audit log shows one decision.
  - A reloaded page shows the card's final state (approved with its result, or denied).
  - A decision for one account or profile cannot be replayed under another. Tests cover this.

### 3. Live revocation of in-flight runs, plus leased background jobs

- **Seen in OpenDots:**
  - `src/server/dot-agent.ts`: `check()` runs on a 100 ms watcher and aborts the run when the owner pauses or changes permissions.
  - `src/server/runner.ts` (ownership check) and `src/server/store.ts` (`lease`, `leaseUntil`, expired-lease recovery).
- **What Praxis Prime will do:**
  - Each per-profile worker watches for pause, role or membership revocation, profile changes, and dial changes, and cancels the running turn.
  - Each routine run holds a lease. A crashed worker's lease expires, and the run is retried once with an audit note.
- **Milestone:** M1c, plus the scheduler in [ROUTINES.md](ROUTINES.md).
- **Effort [E]:** 2–4 days.
- **Acceptance criteria:**
  - Revoking a user's access or pausing the agent cancels an in-flight turn within one second. No further tool call starts.
  - Killing a worker mid-routine leads to one safe retry after the lease expires, never two concurrent runs.
  - Both events are in the audit log with the actor.

### 4. Browser clicks bound to a fresh page snapshot

- **Seen in OpenDots:**
  - `src/shared/computer-types.ts`: click and type take a `ref` plus a `snapshotId`.
  - `src/server/computer-service.ts`: HTTP 409 means "take a new snapshot first".
- **What Praxis Prime will do:**
  - The `browser` tool's `snapshot` returns element refs and a snapshot ID.
  - `click` and `type` accept a ref and snapshot ID, and are refused if the page changed since that snapshot.
  - CSS selectors stay available but are second choice.
- **Milestone:** browser tool now ([BROWSER.md](BROWSER.md)). Reused by the M4 virtual desktop ([ARCHITECTURE §13.2](ARCHITECTURE.md#132-desktop-computer-use-host)).
- **Effort [E]:** about 1 week.
- **Acceptance criteria:**
  - A click with a stale snapshot ID is refused with a clear "take a new snapshot" message.
  - Refs from one page never act on another page.
  - Tests run against a local fixture page with no network.

### 5. Human takeover and handback, with a redacted activity log

- **Seen in OpenDots:**
  - `src/server/computer-service.ts`: control state `holder`, `requested`, `resumeSnapshotRequired`.
  - `src/client/ComputerPanel.tsx`.
  - `docs/COMPUTERS.md`, the sections "Take control" and "Activity".
- **What Praxis Prime will do:**
  - The user can take control of the agent's sandboxed browser or virtual desktop, which pauses agent input.
  - On handback, the agent must take a fresh snapshot before acting.
  - The activity log records the action name, actor and outcome. It does **not** record typed values, file contents, or full commands.
  - This works only on the sandboxed desktop. Host control stays the separate `desktop.control` permission.
- **Milestone:** M4 (T2 / OpenShell virtual desktop). The UI is in the M1d shell.
- **Effort [E]:** 2–3 weeks, after M4.
- **Acceptance criteria:**
  - While the human holds control, every agent browser or desktop action is refused.
  - After handback, the first agent element action without a fresh snapshot is refused.
  - Activity entries contain no typed text, file bodies, or command lines. Tests check this.

### 6. Per-worker credentials derived from one master key, and secret scrubbing

- **Seen in OpenDots:**
  - `src/server/computer-service.ts`: `token()` computes `HMAC-SHA256(master, "opendots-computer:" + id)`, and `json()` removes infrastructure secrets from upstream responses.
  - `deployment/computers/harden-supervisor.mjs`.
- **What Praxis Prime will do:**
  - Each per-profile worker and each sandbox gets its own credential, derived from a master key held only by the daemon.
  - Responses from workers and sandboxes are scrubbed of any infrastructure secret before they reach the model or the UI.
- **Milestone:** M1c (worker tokens). M4 (sandbox and connector credentials).
- **Effort [E]:** 1–2 days.
- **Acceptance criteria:**
  - The master key never appears in a worker's or sandbox's environment.
  - One worker's credential is rejected for another profile.
  - Rotating the master key invalidates all derived credentials.
  - A test checks that an upstream response which echoes a secret is redacted.

### 7. Extra gateway request checks

- **Seen in OpenDots:** the middleware in `src/server/app.ts`.
- **What Praxis Prime will do:**
  - Add three checks to the existing Host/Origin guard (`gateway/guard.py`):
    - refuse `Sec-Fetch-Site: cross-site`;
    - accept only `application/json` for mutating HTTP requests;
    - enforce a request body size limit.
  - Before adding each one, check it does not already exist elsewhere in the gateway.
- **Milestone:** M1d (when the SPA talks to the gateway). Re-checked in M6 for remote exposure.
- **Effort [E]:** about 1 day.
- **Acceptance criteria:**
  - A cross-site request gets 403, a non-JSON mutation gets 415, and an oversized body gets 413. Tests cover all three.
  - Existing loopback clients (CLI, Telegram) are unaffected.

### 8. "Setup needed" screen

- **Seen in OpenDots:**
  - `src/server/platform-config.ts`: `setupStatus()` returns the list of missing settings.
  - The header of `.env.example`.
- **What Praxis Prime will do:** the gateway's `onboarding.status` ([Addendum A §2.3](blueprint-addendum-2026-09.md#23-the-flow-web-wizard-and-cli-share-one-backend)) returns the exact missing items. The SPA and `praxis-prime setup` show them instead of failing.
- **Milestone:** M2.
- **Effort [E]:** less than 1 day (it refines a design already in M2).
- **Acceptance criteria:**
  - A fresh install opens on a screen listing what is missing, for example "no provider chosen".
  - Each item links to the wizard step that fixes it.

### 9. Autosaved documents with revision checks (optional)

- **Seen in OpenDots:**
  - `src/server/pages.ts` (`revision` column)
  - `src/client/editor/autosave.ts`
  - `src/client/editor/use-page-autosave.ts`
- **What Praxis Prime will do:**
  - Canvas and artifact documents ([ARCHITECTURE §21.1](ARCHITECTURE.md#211-main-window--chat--canvas--tool-timeline)) carry a revision number.
  - A save based on an old revision is refused, so neither the agent nor the user overwrites newer work.
  - Autosave keeps the local draft when a save fails.
- **Milestone:** M1d or later, when the canvas is built.
- **Effort [E]:** about 1 week.
- **Acceptance criteria:**
  - Two concurrent edits: the second save, based on the old revision, is refused and the draft is kept.
  - An agent edit made after a user edit must re-read the document first.

## Not adopting

| OpenDots part | Why not |
|---|---|
| CopilotKit Intelligence (threads, memories, channels) | OpenDots cannot chat without it (`src/server/platform.ts`), and conversation history is stored there, not locally (`docs/SETUP.md`). It is cloud-hosted unless you buy a self-hosting licence and run Kubernetes, Postgres and Redis. That breaks local-first, "no cloud engines forced on users", and the HIPAA/FERPA posture. |
| CopilotKit Node runtime (`@copilotkit/runtime`) | It would add a second, Node.js server layer. The Praxis Prime core is Python by design ([ARCHITECTURE §23](ARCHITECTURE.md#23-tech-stack)). Pattern 1 uses the open AG-UI events directly instead. |
| Cloud "Automatic Learning" and learned-skill delivery | Skills are learned, reviewed and published inside Intelligence (`src/server/learning.ts`). Praxis Prime keeps skills as local `SKILL.md` folders ([SKILLS.md](SKILLS.md)). |
| OpenAI Realtime voice | Hard-wired to `api.openai.com` (`src/server/voice.ts`). Praxis Prime plans local voice (ARCHITECTURE §19, §23). |
| Managed Slack (Channels SDK) | Delivery is run by Intelligence (`docs/SETUP.md`, "Slack"). Praxis Prime runs its own channel adapters (`plugins/channels/`). |
| OpenBot Docker-socket supervisor | The supervisor mounts the Docker socket. Containers share the host kernel, and there is no egress policy by default (`docs/COMPUTERS.md`). That is weaker than bubblewrap now and OpenShell later ([Addendum A §3](blueprint-addendum-2026-09.md#3-nvidia-openshell)). We borrow its UX and credential ideas (patterns 5 and 6), not its runtime. |
| TanStack AI loop and the OpenDots memory model | Its loop is capped at 5–10 steps and has no policy, Decision Engine, or hooks in the path (`src/server/dot-agent.ts`). Its memory is a flat list of preference strings (`src/server/store.ts`). Praxis Prime's loop and three-tier memory ([MEMORY.md](MEMORY.md)) already go further. |
