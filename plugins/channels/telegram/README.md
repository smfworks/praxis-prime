# telegram

The MVP adapter lives in `praxis_prime.channels.telegram` and runs inside `praxis-primed`.

Pairing is a one-time code from `praxis-prime telegram pair`. Only that chat can talk to the agent. Approval buttons (Approve, Deny, Always this session) are the only way a Telegram update can approve an action. A text reply, including "yes" or `/approve`, cannot.

The bot token is `PRAXIS_PRIME_TELEGRAM_BOT_TOKEN` or a `secrets.env` file. It is not committed and not written to `config.toml`.

An out-of-process `praxis-prime-gateway@telegram.service` is later work (ARCHITECTURE §12).
