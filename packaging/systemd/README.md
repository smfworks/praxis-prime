# systemd user units

`praxis-prime.service` is the kernel and gateway. It is the same unit on Ubuntu and on Arch/Omarchy: systemd user specifiers (`%h`, `%t`), no distro package manager, and no wait that requires a graphical session to be pulled in.

Install it with:

```bash
praxis-prime service install
praxis-prime service uninstall
```

`install` copies the unit to `$XDG_CONFIG_HOME/systemd/user/praxis-prime.service`, points `ExecStart` at the `praxis-primed` on `PATH`, and runs `systemctl --user enable --now`. It does not enable linger.

| Unit | Role |
|---|---|
| `praxis-prime.service` | Kernel, gateway, and the profile-worker supervisor. Loopback only. |
| `praxis-prime-workers.slice` | Memory, CPU, and task cap for per-profile workers. |
| `praxis-prime-voice.service` | Jarvis layer. Off unless a person enables it. |
| `praxis-prime-gateway@.service` | Optional out-of-process channel adapter. Not used by the in-process Telegram MVP. |
| `praxis-prime-sweeper.timer` | Daily retention sweep backup. |
| `praxis-prime-decide.timer` | Nightly Decision Engine recalibration. |

`loginctl enable-linger` stays documented and off by default. Do not enable linger from a package script.

The `.deb` and the AUR `praxis-prime-git` package copy these units to `/usr/lib/systemd/user/`. They do not enable the units and they do not enable linger. `praxis-prime service install` is still the command that enables the daemon for a user.
