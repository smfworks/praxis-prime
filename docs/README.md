# Praxis Prime docs

The blueprint is the source of truth for layout, names, and stack.

| File | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture blueprint. §29 follows milestones M0–M8 |
| [blueprint-addendum-2026-09.md](blueprint-addendum-2026-09.md) | Addendum A (2026-09-30): themes, no default LLM, NVIDIA OpenShell, any-device access (central server, WSL2, Microsoft 365), multi-user profiles, and the M0–M8 build order. **[V]** verified, **[U]** unverified, **[E]** estimate |
| [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md) | Comparison with the source systems and the reuse plan |
| [SOURCE-NOTES.md](SOURCE-NOTES.md) | Licenses, paths, unverified items |
| [OPENDOTS-BORROWED-PATTERNS.md](OPENDOTS-BORROWED-PATTERNS.md) | Nine patterns borrowed from OpenDots (MIT, ideas only), mapped to M1 (per-profile workers and the SPA shell), M2, M4, M6, and the browser tool, with acceptance criteria |
| [architecture.html](architecture.html) | Rendered copy of the blueprint, the matrix, and the source notes |

These files were approved as the design. The repository still points at later sections with `TODO: ARCHITECTURE §…` notes.

[USAGE.md](USAGE.md) is the operator note for chat, ask, the daemon, coding mode, and `praxis-prime decide`. [SECURITY.md](SECURITY.md) covers the one owner, profile allowlists, auditors, and the loopback bearer token. [COMPLIANCE.md](COMPLIANCE.md) and [packs](packs/) cover dial enforcement. [DECISION-ENGINE.md](DECISION-ENGINE.md) describes the local cascade. [ROUTINES.md](ROUTINES.md), [MEMORY.md](MEMORY.md), and [SKILLS.md](SKILLS.md) cover the scheduler, memory tiers, and `SKILL.md` folders. [MCP.md](MCP.md) covers the MCP client and `praxis-prime mcp serve`. [BROWSER.md](BROWSER.md) covers the optional Playwright browser tool.
