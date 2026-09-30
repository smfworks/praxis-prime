# Bundled skills

These `SKILL.md` folders ship with the repo. `praxis-prime skills list` shows their names and descriptions. The agent loads a body with the `use_skill` tool.

| Skill | When it is useful |
|---|---|
| `morning-brief` | A short dated brief |
| `project-notes` | A note about what changed |
| `daily-standup` | Yesterday, today, and blockers |

A skill does not skip approval for sending, spending, sharing, or deleting. Installing from git still needs a yes in the terminal, and install never runs scripts in the tree.

An Omarchy install step that symlinks a skill into `~/.agents/skills/` is not in this build.

TODO: ARCHITECTURE §9 hub scan, lockfile, and A–F grading.
