# Security notes for accounts and the gateway

The daemon still binds `127.0.0.1` only. These notes are the operator rules for accounts, profiles, and the loopback bearer token. They are not legal advice.

Owner login under a 200-connection flood takes about 1 to 1.3s. That is the argon2id check plus the login concurrency cap. It is not a hang, and it is not something this build tries to make faster.

## One owner

The first account is the owner. A second owner cannot be created. Admins cover day-to-day management. The owner can hand the role to an existing admin:

```bash
praxis-prime account transfer-owner bea
```

`bea` must already be an admin. The previous owner becomes an admin. The change is one database transaction and one audit event, `auth.owner_transfer`, on the hash chain. The event records the two account ids and usernames. It does not record a password.

## Profile allowlists

An empty `allow` list allows nothing. That is fail closed. A profile cannot add a tool or MCP server the org floor omitted.

The migrated `default` profile is written with `allow = ["*"]` for tools and for MCP. `*` means that layer adds no extra restriction, so a single-user install keeps the same tools after the upgrade. A profile created after that starts with an empty allow list. A missing `profile.toml` allows nothing. Tighten `default` in `profile.toml` when you want fewer tools. An approval cannot put a tool back.

Stop `praxis-primed` before the first `account create`. That command moves `prime.db` into `profiles/default/`. Every process that opens `prime.db` takes a shared flock on `prime.db.lock` without waiting. If migration holds that file, the open fails with `migration in progress` and does not create a new `prime.db` at the pre-move path. `chat --local` and the other commands that open the database check `.migration.lock` the same way. Migration takes the flock exclusively, and only then removes or replaces `.migration.lock`. A busy database leaves that lock file in place. `--force` does not override an open `prime.db`. A published daemon is refused as well. The daemon refuses to start while `.migration.lock` exists. That file records the migrating pid and its start time. An empty file, garbage, a dead pid, or a reused pid (same number, different start time) is stale: `praxis-prime profile migrate` replaces it and finishes the move. A lock that still matches a live process needs `praxis-prime profile migrate --force`. The error names `.migration.lock`. The command does nothing if the marker is already there.

This process runs one profile. Chat, approvals, `model.set`, and `session.drop` require that profile plus a membership (owner and admin are not limited to memberships). A chat whose profile is not the one the daemon opened is refused. The audit `profile` column is that runtime profile.

## Auditors

An auditor does not chat and does not receive approval content. `GET /v1/approvals` stays 403 for that role. A WebSocket is subscribed only after `connect` succeeds. Approval events are filtered the same way as the HTTP list: owner and admin receive the card, members receive only their own profile's cards, auditors receive at most the meta fields, and every other socket receives nothing. A disabled or revoked account is dropped on the next publish.

`GET /v1/approvals/meta` is the content-free view: `id`, `tool`, `risk`, `createdAt`, and `decision`, plus a `count`. It has no arguments, summary, reason, or mount line. Auditors, the owner, and admins see every profile. Other accounts see only profiles they belong to. Pending rows use `decision` `pending`. `GET /v1/approvals` omits another account's `sessionId`.

## Loopback bearer token

The token file is `$XDG_RUNTIME_DIR/praxis-prime/gateway.token` (mode 0600). It is not in `config.toml` and it is not logged.

Once an account exists, a valid bearer token is an **owner-equivalent** credential. It acts as the owner account: it can chat, approve, and administer, on loopback only. With no accounts yet, the same file is the operator credential the single-user gateway already used.

Rotate it by replacing the file, then restarting the daemon so the process drops the old value:

```bash
praxis-prime daemon rotate-token
praxis-prime daemon stop
praxis-prime daemon start
```

`rotate-token` does not print the new token. It writes a temporary file in the same directory and replaces `gateway.token`, so a reader does not see a half-written secret. Clients that read the file (the CLI, after restart) pick it up from disk. Delete the file and start the daemon if you want `praxis-primed` to create one itself.

The session cookie is `HttpOnly`, `Secure`, and `SameSite=Strict`. Browsers send it to `http://127.0.0.1`. `httpx` and `urllib` cookie jars drop `Secure` cookies on `http://` URLs, including loopback. Non-browser clients should send the `Cookie` and `x-csrf-token` headers themselves, or use the bearer token.

`account passwd`, `account disable`, and `account role` revoke that account's sessions and WebSocket tickets. A ticket is bound to the session that minted it, so logout invalidates a ticket that was issued before the logout. An open WebSocket is checked again on the next frame. `profile unassign` removes a membership; the next chat on that profile is refused.

`gateway.bearer` defaults to `true`. After an account exists, set `bearer = false` in `config.toml` and restart to refuse the token. Cookie sessions and WebSocket tickets still work. Before any account exists the flag does not apply, so the gateway is not left open and the first-run token still works.
