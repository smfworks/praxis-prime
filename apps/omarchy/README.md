# Omarchy integration

Not installed by anything in this skeleton. `praxis-prime omarchy install` does not exist yet.

When it does, it should print each step and ask before changing the machine (ARCHITECTURE §27.2):

1. Quickshell bar plugin, then `omarchy plugin validate`, `omarchy plugin enable`, and `omarchy-shell shell rescanPlugins`.
2. Theme template `~/.config/omarchy/themed/praxis-prime.json.tpl`. The placeholder committed here is `praxis-prime.json.tpl`.
3. Keybind in `~/.config/hypr/bindings.lua` (Omarchy 4): Super+Alt+A launches Praxis Prime. Omarchy 3.x uses `hyprland.conf`.
4. Optional `omarchy default agent praxis-prime`.
5. Symlink a skill into `~/.agents/skills/`.
6. Enable the user service, and the voice service only if Jarvis is enabled.

SMF Works does not maintain Omarchy. Nothing here is proposed upstream. Upstreaming `omarchy-install-ai-praxis-prime` waits on Basecamp's review (ARCHITECTURE §31).

TODO: ARCHITECTURE §27.2 and §28.2.
