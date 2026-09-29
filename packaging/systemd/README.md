# systemd user units

These files are the units from ARCHITECTURE §26. They are not installed into `~/.config/systemd/user/`.

| Unit | Role |
|---|---|
| `praxis-prime.service` | Kernel and gateway. The ExecStart binary is the stub daemon today. |
| `praxis-prime-voice.service` | Jarvis layer. Off unless a person enables it. |
| `praxis-prime-gateway@.service` | Optional out-of-process channel adapter. |
| `praxis-prime-sweeper.timer` | Daily retention sweep backup. |
| `praxis-prime-decide.timer` | Nightly Decision Engine recalibration. |

`loginctl enable-linger` stays documented and off by default. Do not enable linger from a package script.
