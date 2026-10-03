# Gaps from OpenClaw and Hermes Agent

**Status:** owner-approved plan input (2026-10-01). Nothing in this file is built yet. Milestone labels are the ones in Peyton's review, mapped onto [Blueprint Addendum A §8](blueprint-addendum-2026-09.md#8-re-ordered-roadmap-pr-sized-milestones). Sizes below are the review's own words (small, medium, large), not new week estimates.

Reviewed commits: OpenClaw `openclaw/openclaw` `0b7d21f`, Hermes Agent `NousResearch/hermes-agent` `5bba024`, Praxis Prime main `ab66507`. The review read the docs, READMEs, and selected code paths. It did not audit either codebase line by line. The marketplace-malware and exposed-instance figures come from security-firm reports and were not re-checked that day.

## Credit and licence

[OpenClaw](https://github.com/openclaw/openclaw) and [Hermes Agent](https://github.com/NousResearch/hermes-agent) are both MIT-licensed. Their ideas are free to borrow. Their code can be reused only with attribution, and this plan does not copy any of it.

Two trees inside those repositories are Apache-2.0, not MIT: OpenClaw `skills/skill-creator`, and Hermes `plugins/security-guidance`. Hermes `plugins/security-guidance` is already listed in [THIRD_PARTY.md](../THIRD_PARTY.md), and OpenClaw `skills/skill-creator` is also listed there (THIRD_PARTY.md:36). If either tree is ever bundled, that change keeps the Apache-2.0 LICENSE and NOTICE beside the files and adds the row in the same change (see [AGENTS.md](../AGENTS.md), "Reuse rules"). Until then these are ideas only.

The smfworks mirrors are stale: `smfworks/openclaw` sits at `d545f11` (last pushed 19 September 2026), and `smfworks/hermes-agent` at `22c5684`. The commits above are the ones this note is about.

In the gaps below, "OC" means OpenClaw and "HE" means Hermes Agent.

## High-value gaps

### 1. Real per-person isolation

One agent per person. Chat accounts bind to agents, with one-time pairing. Each person gets their own process, folder, secrets, and chat bindings, and approvals go back to whoever asked.

- **Upstream:** OC `docs/concepts/multi-agent.md` and `agent-bindings.md`; HE `user-guide/profiles.md`.
- **Praxis:** M1c is in the tree. Each profile has a worker process, its own data root, an HMAC credential, and a Telegram binding for approvals. A routine can run as a named account, and the worker slice caps memory, CPU, and tasks. Per-profile provider secrets stay M2. Channel bindings beyond Telegram approval routing stay M6. Landlock and a Linux user per profile are not in this change. The [per-person agents](OPENDOTS-BORROWED-PATTERNS.md#per-person-agents) note lists what is still open.
- **Milestone:** M1, plus M1c for the workers (large). M1c is the existing M1 PR 6 (per-person workers), not a new PR series.
- **Acceptance criteria:**
  - Each person has a separate worker process, data folder, secrets, and chat bindings.
  - A chat account is bound to that person's agent through one-time pairing.
  - An approval goes back to the person who asked.
  - A routine runs as a named person, and a revoked membership cancels it.
  - The worker has a resource limit.
- **Landed in M1c:** separate worker process and data folder, Telegram chat binding for approvals, requester routing for those cards, run-as routines with revocation, and the worker slice. Per-profile secrets are still M2. One-time pairing of a Telegram chat to a profile is a local bindings file, not a second pairing ceremony.

### 2. API-key pools and fallback for side tasks

Several API keys per provider, with fallback for side tasks, so the agent keeps working when one key is rate-limited.

- **Upstream:** HE `features/credential-pools.md`, `fallback-providers.md`; OC `docs/concepts/model-failover.md`.
- **Praxis:** a fallback chain exists. Key pools do not.
- **Milestone:** M2 (small to medium).
- **Acceptance criteria:**
  - A provider can hold more than one API key.
  - When one key is rate-limited, a side task uses another key from that pool.
  - Fallback still does not cross a sensitivity or policy pin.

### 3. External secret stores

1Password, Bitwarden, Vault, or a custom command. Secrets are referenced by pointer, never written back to disk. Access is approved and audited.

- **Upstream:** HE `user-guide/secrets/*`; OC `extensions/vault`, `extensions/onepassword`.
- **Praxis:** not planned.
- **Milestone:** M2/M4 (medium).
- **Acceptance criteria:**
  - A secret can be named as a pointer into 1Password, Bitwarden, Vault, or a custom command.
  - Reading it requires an approval, and the read is in the audit log.
  - The secret value is not written back to a config file on disk.

### 4. Undo for file edits

Snapshot files before risky operations, with a `/rollback` command. The review's top recommendations also name `praxis-prime backup` and `restore`; backup and recovery are gap 7.

- **Upstream:** HE `checkpoints-and-rollback.md`, `tools/checkpoint_manager.py`.
- **Praxis:** not planned.
- **Milestone:** v0.5 (small to medium).
- **Acceptance criteria:**
  - A risky file change snapshots the file first.
  - `/rollback` restores that snapshot.
  - A rollback is one audit event.

### 5. Isolated code execution

A code mode where the model writes code that runs inside a contained interpreter.

- **Upstream:** OC `extensions/code-mode-quickjs` (QuickJS in WebAssembly); HE `tools/code_execution_tool.py`.
- **Praxis:** not planned.
- **Milestone:** M4a (medium).
- **Acceptance criteria:**
  - The model can write code that runs only inside a contained interpreter.
  - That interpreter cannot reach the host except through the sandbox policy.
  - A test runs a fixture snippet with no host network and no host filesystem outside the sandbox.

### 6. Tool search

Load MCP tool definitions only when needed, instead of every tool every turn.

- **Upstream:** HE `features/tool-search.md`.
- **Praxis:** not planned.
- **Milestone:** MVP (small).
- **Acceptance criteria:**
  - A turn does not send every MCP tool definition to the model.
  - A tool the model needs is loaded when the turn searches for it.
  - A tool that was not loaded cannot be called.

### 7. Doctor fixes, security audit, updates, backup and recovery

Doctor fixes problems and runs a security audit. A safe update command has stable and beta channels. Backup and recovery sit here too.

- **Upstream:** OC `doctor`, `backup`, `security audit --fix`, and development channels; HE `updating.md`, `session-storage-recovery.md`.
- **Praxis:** doctor reports only. Only a signed AppImage updater is planned.
- **Milestone:** M2/M5a (medium).
- **Acceptance criteria:**
  - `praxis-prime doctor` can fix the problems it knows how to fix, and it can run a security audit.
  - `praxis-prime update` is a separate command, with a stable channel and a beta channel, and it refuses an update it cannot verify.
  - `praxis-prime backup` and `praxis-prime restore` round-trip a fixture install.

### 8. Skill learning lifecycle

Track usage, move skills from active to stale to archived, and review proposals in batches.

- **Upstream:** HE `features/curator.md`; OC `skill-workshop`.
- **Praxis:** drafts and curator suggestions are planned. The lifecycle is not.
- **Milestone:** v0.5 (medium).
- **Acceptance criteria:**
  - Each skill records usage.
  - A skill can move from active to stale to archived.
  - Proposed skills are reviewed in a batch, and an unreviewed proposal is not active.

### 9. Smarter approvals

Rules suggested from approval history, a hard blocklist floor, and approvals bound to the exact command, folder, environment, and a file snapshot.

- **Upstream:** HE `security.md`; OC `SECURITY.md:254`.
- **Milestone:** MVP/v0.5 (small to medium).
- **Acceptance criteria:**
  - Approval history can suggest a rule. The suggestion does not become a rule until a person accepts it.
  - A hard blocklist floor cannot be overridden by an approval.
  - An approval names the exact command, folder, environment, and file snapshot. A later run that differs on any of those is not covered.

### 10. Agent-level evals

Personal-assistant scenario packs, a synthetic test channel, and trajectory export.

- **Upstream:** OC `personal-agent-benchmark-pack.md`, `extensions/qa-lab`; HE `evals/`, `batch_runner.py`.
- **Praxis:** only the Decision Engine has evals.
- **Milestone:** v0.5 (medium).
- **Acceptance criteria:**
  - A scenario pack of personal-assistant tasks runs through a synthetic chat channel.
  - The run exports a trajectory.
  - The Decision Engine evals stay a separate suite.

### 11. Memory upgrades

A per-person user model, event-triggered standing intents ("remind me when X comes up"), forgetting traced back to the source session, background consolidation, and session search as a tool.

- **Upstream:** OC `docs/concepts/user-model.md`, `standing-intents.md`, `memory-provenance.md`, `dreaming.md`, `session-search.md`.
- **Praxis:** tiers, forgetting, and consolidation are planned. The rest is not. See [MEMORY.md](MEMORY.md).
- **Milestone:** v0.5 (medium).
- **Acceptance criteria:**
  - Each person has a user model of their own.
  - A standing intent fires when the named event comes up.
  - A forgotten item points back at the source session.
  - Consolidation can run in the background.
  - Session search is a tool the model can call.

### 12. Plugin and skill hub with supply-chain controls

A signed index, pinned hashes, OSV dependency checks, sandboxed installs, and no install scripts. This is how the review says to avoid an open skill marketplace.

- **Upstream:** HE `plugin-catalog/`, `tools/osv_check.py`, `tools/plugin_guard.py`.
- **Praxis:** an A–F scan is planned. See [SKILLS.md](SKILLS.md).
- **Milestone:** v0.5 (medium to large).
- **Acceptance criteria:**
  - The index is signed, and each skill pin is a hash.
  - Install runs an OSV dependency check and happens inside the sandbox.
  - A skill with an install script, or an auto-installed prerequisite, is refused.
  - A skill is treated as code.

## Security lessons

These are explicit requirements, not optional notes. References are copied from the review. No extra advisory detail is added here.

1. **Never take a server URL or token from a link, and never auto-connect with credentials.** OpenClaw CVE-2026-25253 (CVSS 8.8) let one click steal the token and run code remotely.
2. **Marketplace malware is the main threat.** Koi's ClawHavoc report found 341 of 2,857 ClawHub skills were malicious, most delivering a macOS stealer through fake "prerequisites". Snyk found flaws in 36% of skills. The rules for Praxis: no install scripts, no auto-installed prerequisites, signed and pinned skills, installs inside the sandbox, and treat every skill as code.
3. **Exposure at scale.** Censys and SecurityScorecard found 21k to 40k OpenClaw instances on the open internet. Keep loopback-only and fail-closed as the default, and have doctor flag any exposure.
4. **An owner check on every chat command that changes settings,** enforced centrally. In GHSA-wwx7-573h-pqwc, a non-owner could run `/mcp set` and get code execution.
5. **Tool policy must also cover an outside harness's built-in tools** (GHSA-wwcw-jfpp-gpxw). Enforce at the sandbox, not at the tool list. The same rule covers running Claude Code or Codex as a sub-harness.
6. **Carry the person's identity through every file read** (GHSA-xvwp-wmh2-fq48).
7. **Verify webhook signatures before rate-limiting,** and rate-limit per real client.
8. **Neutralize spreadsheet formulas in CSV exports,** such as audit and cost exports.
9. **Avoid OpenClaw's trust model:**
   - one trusted operator;
   - a shared bearer token that grants full admin;
   - a session key that only routes and doesn't authorize;
   - commands run on the host by default;
   - plugins run in-process;
   - node:vm used as if it were a boundary;
   - memory files trusted;
   - session ownership treated as isolation.
10. **Hermes guard CVEs:** CVE-2026-9353, -10223, -10221, -10222 and -18976.
    - What they cover: skills-guard bypass, memory-scan bypass, injection through context compression, environment-sanitizer injection, and disabled toolsets not enforced at dispatch.
    - What to do: Praxis plans to reuse the Hermes skills guard, so treat it as advisory only, enforce deny lists where tools are dispatched, and treat compression summaries as untrusted.
    - Disclosure: the advisories say Nous Research didn't respond to the reports, so Praxis should publish its own security policy with a response deadline and GitHub advisories.

The roadmap names these as requirements now: a [SECURITY.md](../SECURITY.md) response deadline, no gateway URL or token taken from a link, an owner check on settings-changing chat commands, policy enforced at dispatch and at the sandbox (including an outside harness's built-in tools), compression summaries treated as untrusted, webhook signatures verified before rate-limiting, and CSV formula-injection guards.

## Medium-value gaps

- **A live progress message in chats** that's edited as the agent works, instead of many separate "still working" messages (OC `progress-drafts.md`). Size: small.
- **More channels.** iMessage, phone calls through Twilio or Telnyx, and meeting bots for Meet, Zoom and Teams (OC extensions). Praxis code has only Telegram so far.
- **Running Claude Code or Codex as a sub-harness** through ACP (OC `extensions/acpx`). Policy has to apply to the harness's own tools too.
- **A typed workflow engine** with approval and input checkpoints and JSON-schema LLM steps (OC `extensions/lobster`, `llm-task`).
- **Small reliability wins.** Compacting noisy command output, repairing malformed tool calls, a clarify tool, a background-process registry, and LSP diagnostics after edits.
- **Guest access** that expires after 14 days, and read-only session sharing (OC `visitor-access`, `session-share`).
- **Compliance as code inside doctor** (OC `extensions/policy`).
- **Local document extraction,** with a vision fallback.
- **Install breadth.** Nix, Docker/Podman, Raspberry Pi and VPS guides, migration import with a dry run, and QR device pairing.
- **Community infrastructure.** A docs site, a maturity page, a threat-model guide, an incident-response doc, and Opengrep rules in CI.

## Low-value gaps

Pets and achievements, language packs, a screen-snapshot work journal, encrypted agent-to-agent messaging, mixture-of-agents, and Bonjour discovery.
