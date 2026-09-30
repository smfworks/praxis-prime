# Routines

A routine is a saved prompt plus a trigger. `praxis-primed` runs it as an ordinary agent session. The system prompt stays the fixed string. Profile facts, the skill index, and a bound skill name go in the first user message, the same way a chat turn does.

Commands:

```bash
praxis-prime routines list
praxis-prime routines add --name morning --prompt "Draft the brief." --cron "0 8 * * *" --skill morning-brief
praxis-prime routines add --name pulse --prompt "Check the inbox." --every 15m
praxis-prime routines add --name notes --prompt "Summarize the file." --watch ./NOTES.md
praxis-prime routines add --name hook --prompt "Handle the webhook." --webhook
praxis-prime routines edit rt_0123abcd --prompt "Draft a shorter brief."
praxis-prime routines pause rt_0123abcd
praxis-prime routines resume rt_0123abcd
praxis-prime routines run rt_0123abcd
praxis-prime routines history rt_0123abcd
praxis-prime routines delete rt_0123abcd
```

`--data-dir` and `--config-dir` belong on the subcommand (`routines list --data-dir ...`). The timezone defaults to `core.timezone` in the config, which is `America/New_York` until you change it.

## Triggers

| Trigger | Flag | Behavior |
|---|---|---|
| Cron | `--cron "M H DOM MON DOW"` | Five fields, in the routine timezone. Names (`mon`, `jan`) and `7` for Sunday are accepted. When both day-of-month and day-of-week are restricted, either match is enough. |
| Interval | `--every 15m` or `--cron "@every 15m"` | Units are `s`, `m`, `h`, and `d`. |
| File | `--watch PATH` | inotify when the kernel has it, otherwise a stat each tick. A token of size and mtime (or a hash of a directory's children) catches a change that happened while the daemon was down. |
| Webhook | `--webhook` | `POST /v1/routines/<id>/fire` on the loopback gateway. The bearer token is required, same as `/status`. |

The shortest gap is one minute. `30s` is rejected. A second fire inside that gap returns HTTP 429 and does not start a session. A paused routine returns 409. An unknown id returns 404. A missing or wrong token returns 401 and does not run anything.

## Missed runs

`praxis-primed` ticks about every five seconds. If the machine was asleep or the daemon was down, the next tick looks at `next_fire_at`.

- `skip` (the default): a fire that is late by more than the grace window is recorded as `skipped` and the schedule jumps ahead. The grace window is the routine's minimum interval, and at least 60 seconds.
- `once`: one run catches up, then the schedule jumps to the next future slot. Older slots are not replayed.

`--missed once` selects the second policy. A file that changed while the daemon was down follows the same choice. A live change (mtime inside the grace window) runs. If the minimum interval has not elapsed, the new token is left unread so a later tick still sees it.

## What a run does

Each run gets its own session. `--max-iterations` caps the loop (default 20). `--max-usd` is a cap used only when the caller supplies a price per iteration. Local models are treated as zero, so the cap does not stop a run unless that price is set. The outcome is stored in `routine_runs`: `ok`, `error`, `denied`, `skipped`, or `budget`. Every run, including a skip, is one `routine_run` row in the hash-chained audit log.

Sending, spending, sharing, and deleting still ask. On the daemon those cards go to the approval queue and, when Telegram is paired, to the bot. If nobody answers before the approval TTL, the action is denied and the tool does not run. `routines run` from the CLI is non-interactive: it denies those actions immediately instead of waiting.

`--deliver telegram` sends the redacted summary to the paired owner chat, including a denial. Until a chat is paired, delivery is a no-op. `--skill NAME` tells the run to call `use_skill` for that skill before answering. The skill body is not copied into the prompt until that tool runs.

`routines delete` removes the schedule and keeps the history rows.
