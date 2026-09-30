# Security notes for accounts and the gateway

The daemon still binds `127.0.0.1` only. These notes are the operator rules for accounts, profiles, and the loopback bearer token. They are not legal advice.

## One owner

The first account is the owner. A second owner cannot be created. Admins cover day-to-day management. The owner can hand the role to an existing admin:

```bash
praxis-prime account transfer-owner bea
```

`bea` must already be an admin. The previous owner becomes an admin. The change is one database transaction and one audit event, `auth.owner_transfer`, on the hash chain. The event records the two account ids and usernames. It does not record a password.

## Profile allowlists

An empty `allow` list allows nothing. That is fail closed. A profile cannot add a tool or MCP server the org floor omitted.

A profile created without an explicit list, including the migrated `default` profile, is written with `allow = ["*"]` for tools and for MCP. `*` means that layer adds no extra restriction, so a single-user install keeps the same tools after the upgrade. Tighten the list in `profile.toml` when you want fewer tools. An approval cannot put a tool back.

## Auditors

An auditor does not chat and does not receive approval content. `GET /v1/approvals` stays 403 for that role.

`GET /v1/approvals/meta` is the content-free view: `id`, `tool`, `risk`, `createdAt`, and `decision`, plus a `count`. It has no arguments, summary, reason, or mount line. Auditors may read it. Pending rows use `decision` `pending`.

## Loopback bearer token

The token file is `$XDG_RUNTIME_DIR/praxis-prime/gateway.token` (mode 0600). It is not in `config.toml` and it is not logged.

Once an account exists, a valid bearer token is an **owner-equivalent** credential. It acts as the owner account: it can chat, approve, and administer, on loopback only. With no accounts yet, the same file is the operator credential the single-user gateway already used.

Rotate it by replacing the file, then restarting the daemon so the process drops the old value:

```bash
praxis-prime daemon rotate-token
praxis-prime daemon stop
praxis-prime daemon start
```

`rotate-token` does not print the new token. Clients that read the file (the CLI, after restart) pick it up from disk. Delete the file and start the daemon if you want `praxis-primed` to create one itself.

`gateway.bearer` defaults to `true`. After an account exists, set `bearer = false` in `config.toml` and restart to refuse the token. Cookie sessions and WebSocket tickets still work. Before any account exists the flag does not apply, so the gateway is not left open and the first-run token still works.
