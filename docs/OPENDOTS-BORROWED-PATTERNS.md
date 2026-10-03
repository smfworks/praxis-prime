# Patterns borrowed from OpenDots

**Status:** owner-approved plan input (2026-10-01). Nothing in this file is built yet. Effort figures are estimates **[E]**: one experienced engineer with AI assistance, the same basis as [Blueprint Addendum A §8](blueprint-addendum-2026-09.md#8-re-ordered-roadmap-pr-sized-milestones). Peyton's independent review of the same day is folded in as [Frontend decision](#frontend-decision) and [Per-person agents](#per-person-agents).

## Credit and licence

[OpenDots](https://github.com/CopilotKit/OpenDots) is an open-source TypeScript template for always-on agents, built on CopilotKit and AG-UI. It is MIT-licensed, © Atai Barkai. We reviewed it at commit `b01ac1f` (2026-10-01) as a **reference only**. CopilotKit was reviewed at `f835ce8` and AG-UI at `ec28a11`, also as reference only.

`deployment/computers/LICENSE.openbot` is MIT, © 2026 CopilotKit, separate from the Atai Barkai copyright on the rest of the repository. Patterns 5 and 6 cite that directory (`src/server/computer-service.ts`, `deployment/computers/harden-supervisor.mjs`). The ideas are fine to borrow. No code from that directory is copied.

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
| 10 | Route allowlist, with the same id in the path, body, and query | M1d, M6 | ~1 day |
| 11 | Grants re-checked on every tool call, with a one-time migration | M1c | 1–2 days |
| 12 | Upstream response hardening (size cap, deadline, no redirects) | M1c, M4 | ~1 day |

How the milestone labels map to [Addendum A §8](blueprint-addendum-2026-09.md#8-re-ordered-roadmap-pr-sized-milestones):

| Label | Addendum A §8 |
|---|---|
| M1a | M1 PRs (2), (4), (5), and (8): accounts, roles, profiles, and audit actors. Merged. |
| M1b | M1 PR (3): passkeys + TOTP |
| M1c | M1 PR (6): per-profile workers and the supervisor |
| M1d | M1 PRs (1) and (7): the SPA shell, profile picker, and admin console |
| M1e | M1 PR (9): generic OIDC |
| M2, M4, M6 | Those milestones |
| "browser tool" | The existing tool in [BROWSER.md](BROWSER.md) |

## Frontend decision

Build our own UI and borrow patterns only. The SPA uses `@ag-ui/core` types kept consistent with our Pydantic schema ([ARCHITECTURE §4](ARCHITECTURE.md#4-the-gateway-protocol): Pydantic v2 models, exported JSON Schema, generated TypeScript). On the Python side the models may come from `ag-ui-protocol` only. Never add `@copilotkit/*` or the `copilotkit` PyPI package.

Reasons, from CopilotKit `f835ce8`:

- Using those packages against our own backend means either `agents__unsafe_dev_only` or `selfManagedAgents`. The code labels `selfManagedAgents` an "Enterprise Intelligence tier" and logs a warning when there is no licence key (`react-core/src/v2/providers/CopilotKitProvider.tsx:515-536`).
- The threads drawer locks without a licence (`packages/react-core/src/v2/components/chat/CopilotThreadsDrawer.tsx:247-262`).
- `@scarf/scarf` phones home from a postinstall script (`react-core/package.json:91`), and the `shared` package pulls in Segment and a licence verifier.
- react-ui v1's dev console POSTs to `api.cloud.copilotkit.ai` whenever it runs on localhost (`packages/react-ui/src/components/dev-console/console.tsx:103-113`).
- The transport does not match our WebSocket, ticket, and CSRF gateway.
- The dependency tree is heavy.
- The `copilotkit` PyPI package pulls in langchain and langgraph.

Apache-2.0 dependencies in that tree (`websandbox`, `streamdown`, `a2ui`, `scarf`) need a NOTICE file beside them, and a [THIRD_PARTY.md](../THIRD_PARTY.md) row, if they are ever bundled (see [AGENTS.md](../AGENTS.md), "Reuse rules"). This plan does not bundle them.

Still worth borrowing as patterns, written fresh in `ui/`:

- Hook shapes: a single agent message stream, human-in-the-loop renderers keyed by `toolCallId`, and a wildcard tool renderer.
- Small UI pieces: reasoning messages, suggestion pills, an attachment queue, and stick-to-bottom scrolling.
- From OpenDots: `ComputerToolCard`, `PageReviewCard`, the result pane, and the takeover panel.

A2UI, OpenGenerativeUI, and MCP Apps iframes are listed under [Not adopting](#not-adopting). They would run arbitrary UI, which [Addendum A §1.4](blueprint-addendum-2026-09.md#14-safety-model-no-arbitrary-js-sanitized-css-only) rules out.

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
  - Optionally, also expose them on a loopback SSE endpoint. AG-UI `RunAgentInput` carries client-supplied `messages`, `tools`, `state`, `context`, and `forwardedProps`. The server ignores or validates those fields and keeps the transcript and the tool list server-side. The endpoint uses the same ticket, CSRF, and Host guard as the gateway.
  - The loop's `LoopEvent` types (`loop/events.py`) are mapped onto these events.
  - The Python SDK `ag-ui-protocol` (MIT) may be used for the models. UI types come from `@ag-ui/core`, kept consistent with that schema. `@copilotkit/*` and the `copilotkit` PyPI package are not dependencies. See [Frontend decision](#frontend-decision).
- **Milestone:** M1d. M6 (PWA) and M7 (Tauri) reuse it.
- **Landed in M1d:** a chat turn's gateway event frames include an `agui` object (`RUN_*`, `TEXT_MESSAGE_*`, `TOOL_CALL_*`) beside the existing `kind` payload. `protocol/agui.schema.json` lists those types. The optional SSE endpoint is not in this build. One turn's frames stay in that order. A second turn on the same worker has its own stream id, so it does not receive the first turn's text, tool arguments, or tool results.
- **Effort [E]:** 1–2 weeks.
- **Acceptance criteria:**
  - One chat turn with one tool call streams, on that turn only and in order: run start, text deltas, tool-call start, args, end, result, then run finished. Tests check this. Concurrent turns do not share the buffer.
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
  - Record the decision keyed by the tool-call ID, using Praxis's own gateway-frame `idempotencyKey` ([ARCHITECTURE.md:182](ARCHITECTURE.md#4-the-gateway-protocol)). That field belongs to the gateway frame, not to AG-UI or OpenDots.
  - An AG-UI tool result is never an approval. In CopilotKit the browser returns the approval as a tool result (OpenDots `src/client/Chat.tsx:170-182`), and `src/server/page-routes.ts:24-46` saves the draft the client sent. Decisions go through the approval queue and authz.
  - An Edit re-runs pre-tool policy on the edited arguments.
  - `queue.decide` is already exactly-once (`packages/prime-core/praxis_prime/approvals/queue.py:150-171`). If the user double-clicks, reloads, or reconnects, the card looks up that decision and result.
- **Milestone:** M1d (web card). M6 (mobile approval sheets).
- **Landed in M1d:** `POST /v1/approvals/<id>` records `allow_once`, `allow_session`, or `deny` once. A second decide for that id fails, and the turn's audit row is the same one a Telegram decision produces. An edited approval that re-runs pre-tool policy is not on the web card yet.
- **Effort [E]:** 2–4 days.
- **Acceptance criteria:**
  - Approving twice, or approving after a reload, runs the action once. The audit log shows one decision. A second `queue.decide` for the same id fails.
  - An edited approval re-runs pre-tool policy on the edited arguments before the tool runs.
  - A reloaded page shows the card's final state (approved with its result, or denied).
  - A decision for one account or profile cannot be replayed under another. Tests cover this.

### 3. Live revocation of in-flight runs, plus leased background jobs

- **Seen in OpenDots:**
  - `src/server/dot-agent.ts`: `check()` runs on a 100 ms watcher and aborts the run when the owner pauses or changes permissions.
  - `src/server/runner.ts` (ownership check) and `src/server/store.ts` (`lease`, `leaseUntil`, expired-lease recovery).
- **What Praxis Prime will do:**
  - Actors are defined by account and profile role. A pause, a permission change, or a revocation names that account and that role.
  - Each per-profile worker watches for pause, role or membership revocation, profile changes, and dial changes, and cancels the running turn.
  - Each routine run holds a lease. A crashed worker's lease expires, and the run is retried once with an audit note.
- **Milestone:** M1c, plus the scheduler in [ROUTINES.md](ROUTINES.md).
- **Landed in M1c:** a worker watches membership and `profile.toml` and cancels the running turn; `supervisor.pause` sends `revoke`; a routine lease allows one retry after a crash and then skips. Dial-change watching is not a separate signal beyond the profile file.
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
  - This means snapshot-bound `click` and `type` on the current Playwright browser tool. [BROWSER.md](BROWSER.md) is still selector-based: `click` and `type` take a selector today.
  - The `browser` tool's `snapshot` returns element refs and a snapshot ID.
  - `click` and `type` accept a ref and snapshot ID, and are refused if the page changed since that snapshot.
  - CSS selectors stay available but are second choice.
- **Milestone:** the current Playwright browser tool ([BROWSER.md](BROWSER.md)). Reused by the M4 virtual desktop ([ARCHITECTURE §13.2](ARCHITECTURE.md#132-desktop-computer-use-host)).
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
  - Takeover and handback are authorized by account and profile role.
  - The user can take control of the agent's sandboxed browser or virtual desktop, which pauses agent input.
  - On handback, the agent must take a fresh snapshot before acting.
  - `deployment/computers/LICENSE.openbot` covers the computers directory this pattern cites. It is MIT, © 2026 CopilotKit. See [Credit and licence](#credit-and-licence).
  - The activity log records the action name, actor and outcome. It does **not** record typed values, file contents, or full commands.
  - This works only on the sandboxed desktop. Host control stays the separate `desktop.control` permission.
- **Milestone:** M4 (T2 rootless Podman virtual desktop, [ARCHITECTURE §13.2](ARCHITECTURE.md#132-desktop-computer-use-host)). The UI is in the M1d shell.
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
  - HMAC(master, id) cannot revoke a single worker. Each profile has a generation counter mixed into the derived credential, so one worker can be revoked on its own.
  - Per-person OAuth tokens live in an encrypted per-profile store.
  - Responses from workers and sandboxes are scrubbed of any infrastructure secret before they reach the model or the UI.
  - `deployment/computers/LICENSE.openbot` covers the computers directory this pattern cites. It is MIT, © 2026 CopilotKit. See [Credit and licence](#credit-and-licence).
- **Milestone:** M1c (worker tokens). M4 (sandbox and connector credentials).
- **Landed in M1c:** worker HMAC credentials, a per-profile generation counter, master-key rotation, and redaction that does not shorten the rest of a worker payload. Sandbox credentials and per-person OAuth stores stay M4 and M2.
- **Effort [E]:** 1–2 days.
- **Acceptance criteria:**
  - The master key never appears in a worker's or sandbox's environment.
  - One worker's credential is rejected for another profile.
  - Rotating the master key invalidates all derived credentials.
  - Expiry and rotation tests cover the HMAC worker credentials. Bumping one profile's generation counter rejects that profile's old credential and leaves other profiles valid.
  - A test checks that an upstream response which echoes a secret is redacted.

### 7. Extra gateway request checks

- **Seen in OpenDots:** the middleware in `src/server/app.ts`.
- **What Praxis Prime will do:**
  - Land the three checks in prime-core's `packages/prime-core/praxis_prime/gateway/guard.py`, beside the existing Host/Origin guard:
    - refuse `Sec-Fetch-Site: cross-site`;
    - accept only `application/json` for mutating HTTP requests;
    - enforce a request body size limit.
  - Before adding each one, check it does not already exist elsewhere in the gateway.
- **Milestone:** M1d (when the SPA talks to the gateway). Re-checked in M6 for remote exposure.
- **Landed in M1d:** `Sec-Fetch-Site: cross-site` is 403, a mutating request that is not JSON is 415, and a body over 1 MB (1,000,000 bytes) is 413. The CLI and Telegram are unchanged.
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

### 10. Route allowlist, with the same id in the path, body, and query

- **Seen in OpenDots:** `src/server/runtime-scope.ts` allowlists routes and requires ids to agree across the path, the body, and the query.
- **What Praxis Prime will do:**
  - Allowlist the gateway routes the SPA and the channels may call.
  - When an id appears in more than one of the path, the body, and the query, the values must match. A mismatch is rejected.
  - The gateway rejects a frame whose `sessionId` disagrees with `payload.sessionId` on `session.drop` and `chat.send`. The SPA client for this allowlist stays M1d.
- **Milestone:** M1d, with pattern 7. Re-checked in M6 for remote exposure.
- **Landed with M1c (gateway only):** an unknown HTTP route returns 404, a frame whose `sessionId` disagrees with `payload.sessionId` is rejected, and an approval id that disagrees across the path, the body, and the query is rejected. Pattern 7 landed with the M1d web API.
- **Landed in M1d (SPA):** the web app calls allowlisted routes only. An approval decision sends the same id in the path and the body.
- **Effort [E]:** about 1 day.
- **Acceptance criteria:**
  - A frame whose `sessionId` disagrees with `payload.sessionId` is rejected.
  - An id in the path that disagrees with the same id in the body or the query is rejected.
  - A route outside the allowlist is rejected. Tests cover all three.

### 11. Grants re-checked on every tool call

- **Seen in OpenDots:** Dot-to-Space grants are re-checked on every tool call, with a one-time migration so a restart never restores a revoked grant (`src/server/workspace.ts:39-50`, `src/server/page-tools.ts:17`).
- **What Praxis Prime will do:**
  - Re-check a grant on every tool call, against the account and profile role that holds it.
  - Ship a one-time migration so a restart never restores a revoked grant.
- **Milestone:** M1c, with pattern 3.
- **Landed in M1c:** `ApprovalGate.recheck` runs on every later tool call. `grants-v1` runs once per profile database and does not copy still-active legacy rows. A revoked row stays revoked across a new worker process.
- **Effort [E]:** 1–2 days.
- **Acceptance criteria:**
  - Revoking a grant stops the next tool call that needed it.
  - Restarting the daemon after that revocation leaves the grant revoked.
  - The migration runs once. A second start does not replay it.

### 12. Upstream response hardening

- **Seen in OpenDots:** `src/server/computer-service.ts:64-117` caps an upstream body at 4 MB, sets a deadline, and uses `redirect: 'error'`.
- **What Praxis Prime will do:**
  - Cap upstream response bodies at 4 MB.
  - Enforce a deadline on the upstream call.
  - Refuse redirects (`redirect: 'error'`).
  - This sits with the secret scrubbing in pattern 6.
- **Milestone:** M1c (worker and connector calls). M4 (sandbox and computer-use calls).
- **Landed in M1c:** model HTTP streams and the Telegram Bot API refuse redirects, stop at 4 MiB, and stop at a deadline. Sandbox and computer-use calls stay M4.
- **Effort [E]:** about 1 day.
- **Acceptance criteria:**
  - A body over 4 MB is refused.
  - A call that passes the deadline is refused.
  - A redirect response is refused. Tests cover all three.

## Per-person agents

Michael wants one agent per individual. OpenDots is single-owner: `identifyUser` always returns the owner (`src/server/platform.ts:63-66`), and every allowlisted Slack user maps to the owner (`src/server/slack-channel.ts:31-43`). The numbered gaps below were the list on main at `ab66507`. M1c closed the worker, credential, lease, Telegram approval routing, and slice items. The rest of the list is still open.

1. Supervisor and per-profile workers are in the tree (M1c). With no profile directory the daemon still runs one in-process agent. Landlock is not part of this split.
2. New accounts do not get a personal profile automatically (`packages/prime-core/praxis_prime/accounts/cli.py:126`).
3. `sees_all_profiles` lets owner and admin chat in, read, and approve on every profile (`packages/prime-core/praxis_prime/gateway/authz.py:136-178`). This needs an audited break-glass mode instead (HIPAA minimum necessary).
4. `_decide` checks the profile, not the session owner (`packages/prime-core/praxis_prime/gateway/server.py:613-639`), so any operator can approve another member's action. The default should be "requester decides", plus optional dual approval.
5. Non-approval events reach every member of a shared profile in full (`packages/prime-core/praxis_prime/gateway/server.py:860-878`).
6. Model config, MCP servers, and `secrets.env` are global (`packages/prime-core/praxis_prime/channels/secrets.py:30-35`, `packages/prime-core/praxis_prime/mcp/cli.py:284-289`). Per-profile `secrets.env.age` is not built.
7. Telegram approval cards route to the chat bound to that profile and requester. With no bindings, the paired owner chat still receives `default`. Broader channel bindings stay M6.
8. A routine can record a run-as account (`routine_actors`). The worker rechecks that membership and holds a lease. A revoked membership cancels the turn.
9. Workers can join `praxis-prime-workers.slice` (`MemoryMax`, `CPUQuota`, `TasksMax`) and cap open files at 256. There is still no per-profile concurrency cap. `RLIMIT_NPROC` is not set.
10. L1 Landlock and L2 per-profile Linux users are not built. Each worker's approval queue is in that process's memory.

Suggested placement, folded into [Addendum A §8](blueprint-addendum-2026-09.md#8-re-ordered-roadmap-pr-sized-milestones):

- **M1 PR 4/5:** personal profile, admin boundary with break-glass, requester-routed approvals, per-session visibility.
- **M1 PR 6:** supervisor, run-as routines, revocation (pattern 3), per-worker credentials with a generation counter, systemd slice (`MemoryMax`, `CPUQuota`, `TasksMax`).
- **M2:** per-profile provider keys.
- **M4:** L3 (local sandbox: T1 bubblewrap and T2 Podman). L2 (per-profile Linux users) is unscheduled, after M4.
- **M6:** per-account channel bindings with approvals pushed to the requester.

## Not adopting

| OpenDots part | Why not |
|---|---|
| CopilotKit Intelligence (threads, memories, channels) | OpenDots cannot chat without it (`src/server/platform.ts`), and conversation history is stored there, not locally (`docs/SETUP.md`). It is cloud-hosted unless you buy a self-hosting licence and run Kubernetes, Postgres and Redis. That breaks local-first, "no cloud engines forced on users", and the HIPAA/FERPA posture. |
| CopilotKit Node runtime (`@copilotkit/runtime`) | It would add a second, Node.js server layer. The Praxis Prime core is Python by design ([ARCHITECTURE §23](ARCHITECTURE.md#23-tech-stack)). Pattern 1 uses the open AG-UI events directly instead. See [Frontend decision](#frontend-decision). |
| `@copilotkit/*` React packages and runtime | [Frontend decision](#frontend-decision). `selfManagedAgents` is labelled an Enterprise Intelligence tier and warns when there is no licence key (`packages/react-core/src/v2/providers/CopilotKitProvider.tsx:515-536`). The threads drawer locks without a licence (`packages/react-core/src/v2/components/chat/CopilotThreadsDrawer.tsx:247-262`). `@scarf/scarf` phones home from postinstall (`packages/react-core/package.json:91`), and `shared` pulls in Segment and a licence verifier. react-ui v1's dev console POSTs to `api.cloud.copilotkit.ai` on localhost (`packages/react-ui/src/components/dev-console/console.tsx:103-113`). The transport does not match our WebSocket, ticket, and CSRF gateway, and the dependency tree is heavy. |
| `copilotkit` PyPI package | It pulls in langchain and langgraph. The Python side uses `ag-ui-protocol` only ([Frontend decision](#frontend-decision)). |
| A2UI, OpenGenerativeUI, and MCP Apps iframes | They would run arbitrary UI from a model or a tool. [Addendum A §1.4](blueprint-addendum-2026-09.md#14-safety-model-no-arbitrary-js-sanitized-css-only) allows no arbitrary JS. |
| Cloud "Automatic Learning" and learned-skill delivery | Skills are learned, reviewed and published inside Intelligence (`src/server/learning.ts`). Praxis Prime keeps skills as local `SKILL.md` folders ([SKILLS.md](SKILLS.md)). |
| OpenAI Realtime voice | Hard-wired to `api.openai.com` (`src/server/voice.ts`). Praxis Prime plans local voice (ARCHITECTURE §19, §23). |
| Managed Slack (Channels SDK) | Delivery is run by Intelligence (`docs/SETUP.md`, "Slack"). Praxis Prime runs its own channel adapters (`plugins/channels/`). |
| OpenBot Docker-socket supervisor | The supervisor mounts the Docker socket. Containers share the host kernel, and there is no egress policy by default (`docs/COMPUTERS.md`). That is weaker than bubblewrap now and the T2 rootless Podman desktop in M4 ([Addendum A §3](blueprint-addendum-2026-09.md#3-local-sandbox)). We borrow its UX and credential ideas (patterns 5 and 6), not its runtime. |
| TanStack AI loop and the OpenDots memory model | The loop is capped at 5–10 steps (`src/server/dot-agent.ts`). `dot-agent.ts:87-127` does gate on pause and permissions. The Decision Engine stays Praxis Prime's. Memory is a flat list of preference strings (`src/server/store.ts`). Praxis Prime's loop and three-tier memory ([MEMORY.md](MEMORY.md)) already go further. |
