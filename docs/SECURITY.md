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

Stop `praxis-primed` before the first `account create`. That command moves `prime.db` into `profiles/default/`. Every process that opens `prime.db` takes a shared flock on `prime.db.lock` without waiting. If migration holds that file, the open fails with `migration in progress` and does not create a new `prime.db` at the pre-move path. Once the migration marker is in place, local commands open `profiles/default/prime.db`. Opening the old top-level file fails with `this database moved to <path> after migration` and does not create a new file there. `chat --local` and the other commands that open the database check `.migration.lock` the same way. Migration takes the flock exclusively, and only then removes or replaces `.migration.lock`. A busy database leaves that lock file in place. `--force` does not override an open `prime.db`. A published daemon is refused as well. The daemon refuses to start while `.migration.lock` exists. That file records the migrating pid and its start time. An empty file, garbage, a dead pid, or a reused pid (same number, different start time) is stale: `praxis-prime profile migrate` replaces it and finishes the move. A lock that still matches a live process needs `praxis-prime profile migrate --force`. The error names `.migration.lock`. The command does nothing if the marker is already there.

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

## Passkeys and TOTP

Sign-in factors are local. Nothing in this path calls a hosted WebAuthn service or an identity provider.

A password alone opens a session until that account confirms TOTP. After that, `POST /v1/auth/login` returns a short-lived `mfaToken` and no session cookie. `POST /v1/auth/login/totp` exchanges the token plus a 6-digit code or a recovery code for the session. A passkey skips that second step: `POST /v1/auth/passkey/options` then `POST /v1/auth/passkey/verify` opens the session. The `mfaToken` is not a session cookie and not a bearer token.

Passkey registration, passkey removal, and TOTP enrollment require a step-up on top of the session. `POST /v1/auth/step-up` checks the current password and, once TOTP is confirmed, a current code or a recovery code. `POST /v1/auth/step-up/passkey/options` and `.../verify` accept a passkey assertion instead. Either path returns a `stepUpToken` that lasts five minutes, is bound to that session, and is sent back as `stepUpToken` on the factor-change request. A confirmed TOTP cannot be replaced through enroll; that route answers 409 and returns no secret. Turning TOTP off still requires the password on `POST /v1/auth/totp/disable`.

Open the daemon as `http://localhost:18790` to enroll a passkey. The relying party id is `localhost` for that origin and `127.0.0.1` for `http://127.0.0.1:18790`. A credential from one does not work on the other. The process still binds `127.0.0.1` only. Passkey ceremonies require user verification, so a tap without a PIN or biometric is refused. Anonymous `POST /v1/auth/passkey/options` does not list credential ids, including when a username is supplied. The username still binds the challenge to that account. A sixth open challenge for the same account is refused; older challenges are left in place until they expire or are used.

TOTP uses SHA-1, 6 digits, and a 30-second step, with one step of clock drift. The step that was accepted is stored. Presenting it again fails, including the code just used to confirm enrollment. Ten recovery codes are returned once at enrollment and when regenerated. Only their SHA-256 hashes are stored. Each code works once.

Five failures lock the account for 15 minutes. Password failures and second-factor failures add up. A correct password does not reset the second-factor count, so a known password cannot be used to guess codes without limit. The lock looks like any other rejected sign-in.

The TOTP seed is encrypted in `accounts.db`. The AES-GCM key is in that same file, and the associated data is the account id. A ciphertext copied onto another account does not decrypt. A seed written by an earlier revision of this change used a fixed label with no account id. The next successful read rewrites that blob under the account id. The file is mode 0600, and shell commands and sandboxes already cannot read it. Passkey public keys and signature counters are in the same database. They are not secrets. The private key stays on the authenticator. `account passwd` deletes that account's passkeys and step-up tokens and revokes its sessions, and the CLI writes an audit event for the change.

The loopback bearer token is not checked with a passkey or TOTP. It remains the owner-equivalent credential described above, on loopback only. HTTP factor changes made with that token still need a step-up. `praxis-prime account totp` and `account passkey` write `accounts.db` as the OS user who can read that file, the same trust as `account passwd`, and they append an audit event that does not contain the secret. Passkey enrollment itself is the HTTP ceremony; the CLI can list and remove credentials. Telegram Approve and Deny do not call these routes. A paired chat is its own credential.

OIDC is not in this build. Neither is a rule that turns MFA on for every role above viewer when the gateway leaves loopback, or a second passkey prompt on SEND and SPEND. Those wait for M1e and M6.

## Shell and the data directory

Bubblewrap mounts that contain the account data directory get an empty tmpfs over that directory, matched by path and by device and inode, so a bind-mount alias of a parent cannot read `profiles/`, `backups/`, or `accounts.db` at that path. The tmpfs does not hide a hard link of one of those files planted outside the mount. The command walk does not refuse every such read before bubblewrap runs. A bind that is inside the data directory is refused. The exception is one coding task worktree, `worktrees/<repo>/<task>` or `worktrees/<profile>/<repo>/<task>` after a profile exists, and the bind source is resolved first so a symlink cannot mount `profiles/`. `worktrees/` itself is not bindable. A `cd` that stays inside that worktree is allowed; a `cd` that leaves it is still refused. Without bubblewrap, shell commands are refused when any account or profile data exists (`accounts.db`, `profiles/`, `backups/`, `prime.db`, or `SOUL.md`), including account data in the default data directory when `--data-dir` points somewhere else. The card says `install bubblewrap to run shell commands` and the command is not run. Host shell remains only for a fresh install with no account data. The token check still splits `;` and `&&` and treats `cd -` as a refusal, as defence in depth. `read_file` of `org/policy.toml` stays allowed.
