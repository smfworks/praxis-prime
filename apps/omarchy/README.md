# Omarchy integration

`praxis-prime omarchy install` writes the theme template and the Super+Alt+A keybind. `praxis-prime omarchy status` reports them. `praxis-prime omarchy uninstall` removes the bytes this command wrote. `pprime omarchy` is the same command. The steps, flags, and live-theme behaviour are in [docs/USAGE.md](../../docs/USAGE.md).

The template in this directory, `praxis-prime.json.tpl`, matches the copy shipped in the wheel at `praxis_prime/omarchy/praxis-prime.json.tpl`. A test checks the bytes. Omarchy renders `~/.config/omarchy/themed/praxis-prime.json.tpl` into `~/.local/state/omarchy/current/theme/praxis-prime.json` when the theme changes, or when `omarchy-theme-refresh` runs. The adapter reads that rendered file.

What install writes today:

1. `~/.config/omarchy/themed/praxis-prime.json.tpl`. Omarchy reads this from `$HOME/.config/omarchy/themed`.
2. A managed block in `~/.config/hypr/bindings.lua` on Omarchy 4, or `~/.config/hypr/bindings.conf` on Omarchy 3.x. Super+Alt+A launches the TUI: `omarchy-launch-or-focus-tui --app-id=org.omarchy.praxis-prime praxis-prime tui`.

Each step is printed first. The command asks before it changes anything, unless `--yes`. `--dry-run` writes nothing. `--profile NAME` selects `omarchy` for that profile and leaves an admin lock unchanged.

Still future (ARCHITECTURE §27.2):

1. Quickshell bar plugin, then `omarchy plugin validate`, `omarchy plugin enable`, and `omarchy-shell shell rescanPlugins`.
2. Optional `omarchy default agent praxis-prime`.
3. A skill symlink into `~/.agents/skills/`.

`praxis-prime omarchy install` does not enable `praxis-prime.service` or the voice service. User-service install stays `praxis-prime service install`.

SMF Works does not maintain Omarchy. Nothing here is proposed upstream. Upstreaming `omarchy-install-ai-praxis-prime` waits on Basecamp's review (ARCHITECTURE §31).
