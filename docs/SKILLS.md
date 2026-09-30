# Skills

A skill is a folder with one `SKILL.md`. YAML frontmatter has `name` and `description`. The rest is markdown. The name is lowercase words separated by hyphens. This is the same file shape used by Claude Code, Hermes, and OpenClaw. The parser here only reads `key: value` lines. It is not a copy of those loaders.

Only the name and description are put in the prompt. The agent loads the body with `use_skill`. That tool result is trusted skill text, not an untrusted fence. It still cannot skip approval: a later send, spend, share, or delete goes through the same gate as any other tool.

## Where skills are found

Later directories win. The same name in a project folder hides the user copy, which hides the shared copy, which hides the bundled copy.

1. Bundled skills in the repository `skills/` directory (`morning-brief`, `project-notes`, `daily-standup`).
2. `~/.agents/skills/` when that directory exists.
3. `$XDG_CONFIG_HOME/praxis-prime/skills/` (or `~/.config/praxis-prime/skills/`).
4. `<project>/.prime/skills/`.

`--project` selects the project root. The default is the current directory.

## Commands

```bash
praxis-prime skills list
praxis-prime skills show morning-brief
praxis-prime skills new weekly-review
praxis-prime skills install ./path/to/skill
praxis-prime skills install https://example.com/some-skill.git
praxis-prime skills remove weekly-review
```

`new` writes a template under the user skills directory. `install` of a local folder copies the tree. `install` of a git URL asks first. Without a terminal the answer is no, and nothing is cloned. A yes runs `git clone --depth 1` only. Scripts in the tree, including `install.sh`, are copied and not executed. `remove` deletes one skill from the user directory. It does not delete a bundled skill.

A routine can name a skill with `--skill`. The run is told to call `use_skill` for that name. The body is still loaded by the tool, not pasted in ahead of time.

Security grading, a hub lockfile, and a curator that proposes new skills are not in this build. See ARCHITECTURE §9.
