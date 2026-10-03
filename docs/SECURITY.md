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

## Supervisor and profile workers

`praxis-primed` listens on loopback only. When `profiles/` exists it is the supervisor: it does not open a profile `prime.db`. Each profile runs in its own worker process. That process holds the profile's memory, skills, routines, and approval queue, under `profiles/<id>/`. A crash in one worker does not open another profile's database.

An install with no profile directory still runs the agent inside the daemon. The first start after profiles exist writes `supervisor/m1c.json` once. That marker does not move databases again and does not copy session grants into a worker. A second start sees the marker and leaves it.

### Trust boundary

The supervisor holds:

- the 32-byte master key at `$XDG_RUNTIME_DIR/praxis-prime/worker-master.key` (mode 0600)
- per-profile generation counters in the state directory
- `accounts.db` and `audit.db`
- the Telegram bot token

A worker is started with its profile id, its data root, the socket paths, and its generation. The derived credential is written to the worker's stdin and the pipe is closed. The master key is not an environment variable. The worker environment also drops `PRAXIS_PRIME_TELEGRAM_BOT_TOKEN` and `PRAXIS_PRIME_SECRETS_FILE`.

The credential is `HMAC-SHA256(master, "praxis-prime-worker:" + profile + ":" + generation)`. The profile id is checked before the HMAC is computed, so a string that is not a profile id is not a credential. Bumping one profile's generation rejects that profile's old credential and leaves the others valid. The generation file is locked and replaced atomically. A corrupt or empty generation file is refused, which does not bring a revoked credential back. Rotating the master key invalidates every derived credential. Comparison is constant-time, and an empty token never matches.

IPC is a Unix socket, mode 0600, with a 4-byte length and one JSON object, capped at 4 MiB. The socket directory is mode 0700. The directory is chosen so the supervisor socket and every current profile socket fit, including a 64-character profile id when a directory can hold one. When the runtime directory cannot hold those paths, the directory is a private `mkdtemp` directory, not a path under `/tmp`. A profile whose socket still cannot be created does not stop the daemon from starting the others. A private socket directory left by a crashed supervisor is removed on the next start when its supervisor socket is not accepting a connection. Both ends check `SO_PEERCRED` and refuse a different uid before a credential is written. A worker authenticates, and every later frame on that connection is checked against the current generation. A connection opened before a bump stops being accepted. The worker holds the read end of a pipe whose write end stays open in the supervisor process, so the worker exits when that process exits. The request thread that started the worker can return without closing the pipe. A worker started with `systemd-run` does not receive the pipe. It exits when `PRAXIS_PRIME_SUPERVISOR_PID` is no longer a live process. The profile lock records the supervisor pid, that process's start time, and a token. A new worker refuses to start when that supervisor is still alive and its `/proc` start time matches, including when this worker belongs to a different supervisor with a different token. It clears the lock only when the recorded supervisor is gone, when the pid is alive but the start time does not match, or when the stamp has no start time. Two supervisors on one data root do not signal each other's live worker. The socket sweep lock is `socks.lock` in that supervisor's runtime directory. Supervisors that use different runtime directories do not share it. A private socket directory younger than five seconds is not removed, and that age is what keeps a second supervisor from deleting a directory the first one is still starting. When `XDG_RUNTIME_DIR` is unset, the runtime path is `/tmp/praxis-prime-<uid>`. Startup refuses that path when another user already created it, so the fallback is not used as a directory this user does not own.

A worker may ask the supervisor for only two things:

| Method | What it may do |
|---|---|
| `grant.check` | Ask whether one account may still act on **this** profile. The supervisor reads accounts and memberships. The worker does not. |
| `event` | Record an `approval`, `audit`, or `routine` event. The supervisor stamps the authenticated profile and ignores a claimed profile that differs. Secrets in the payload are redacted. |

Anything else (`spawn`, `stop`, reading another profile, reading accounts) is refused. The supervisor calls the worker for chat, approvals, memory, routines, revoke, health, and shutdown. Profile A's credential is rejected on profile B's socket.

The gateway stays in the supervisor. `praxis-prime chat` and `ask` keep working. `--profile` selects the worker. With no `--profile`, `default` is used when it exists, otherwise the only profile. Looking up a session owner asks running workers first. When none of them has the session, idle profiles are started until one reports it. Telegram Approve and Deny go to the chat bound to that profile and requester (`telegram-bindings.json`, mode 0600). With no bindings, the paired owner chat still receives cards for `default` and for an unscoped queue. Once any chat is bound, a decision needs both the profile and the requester, and the bound account must be that requester. An empty profile or requester is refused, and a card with no requester is not sent to a bound chat.

Grants are checked again on every tool call. A revoked grant is stored as revoked in that profile's database and is not loaded on the next start. The one-time `grants-v1` migration does not copy still-active legacy entries. A routine run holds a lease stored with wall-clock time and renews it while the run is still going, so a run longer than the lease interval is not started a second time. A live lease is not taken again, including by the same process. A crash leaves the lease; after it expires the run may retry once, and a second expiry does not start another run. A lease whose end is further ahead than a fresh lease is treated as expired, so a clock that moved backwards does not skip that retry. Losing a membership, or a change to `profile.toml`, cancels the in-flight turn. Worker audit events are recorded on the supervisor audit log as well as in the profile database.

Upstream reads use a short read and an idle timeout. A peer that keeps sending is not cut off because the whole reply took longer than the socket timeout. A peer that closes with unread data can reset the connection; that is reported as an upstream failure.

### What this boundary is not

Workers run as the same Unix user as the daemon. A process that can `ptrace` that user, or `open()` a file outside the worker's `StateDB` check, can still read another profile's files. The path guard covers databases opened through `StateDB`, and the worker freezes its profile and data root at startup so a later environment change does not point that check at a different profile. Sandboxed tools keep the existing data-root tmpfs masks. `worker-master.key` is on that filename denylist. This is process isolation plus IPC authentication, not Landlock and not a hostile multi-tenant boundary. The worker path check does not by itself stop one worker from reading another's files through a same-user `open()` outside `StateDB`. Landlock remains M4. A Linux user per profile is unscheduled. Per-profile provider keys are M2. The SPA route client is M1d. OIDC is M1e.

Chat, approvals, `model.set`, and `session.drop` still require a membership when accounts are enforced (owner and admin are not limited to memberships). The audit `profile` column is the profile the supervisor authenticated, not a profile the worker claimed.

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

Passkey registration, passkey removal, TOTP enrollment, and TOTP disable require a step-up on top of the session. `POST /v1/auth/step-up` checks the current password and, once TOTP is confirmed, a current code or a recovery code. `POST /v1/auth/step-up/passkey/options` and `.../verify` accept a passkey assertion instead. Either path returns a `stepUpToken` that lasts five minutes, is bound to that session, and is sent back as `stepUpToken` on the factor-change request. The first factor change deletes it. Passkey enrollment spends it when registration options are issued; verify finishes that one session-bound ceremony and does not take a second token. A rejected Origin, including a missing or non-loopback Origin, is checked before that spend, so a bad origin leaves the token in place. A loopback bearer login has no session id. It cannot enroll a passkey; open a cookie session at `http://localhost:18790` for that ceremony. A later change, such as removing the passkey or enrolling TOTP, needs a new token. Logout deletes that session's step-up rows. Confirming TOTP deletes step-up rows minted before that confirmation. A confirmed TOTP cannot be replaced through enroll; that route answers 409 and returns no secret. `praxis-prime account totp disable` still asks for the password only, because that command is the OS user who can already read `accounts.db`.

Open the daemon as `http://localhost:18790` to enroll a passkey. The relying party id is `localhost` for that origin and `127.0.0.1` for `http://127.0.0.1:18790`. A credential from one does not work on the other. The process still binds `127.0.0.1` only. Passkey ceremonies require user verification, so a tap without a PIN or biometric is refused. Anonymous `POST /v1/auth/passkey/options` does not list credential ids, including when a username is supplied. The username is sealed inside the challenge, which is a fixed-size AES-GCM blob under an HKDF subkey of the account-data key, separate from the TOTP seed key, so the response does not show whether that username exists and the challenge is not written down until a verify spends it. Anonymous option calls cannot fill a cap or block another person's sign-in or step-up. A spent challenge cannot be replayed. Registration and step-up still store at most five challenges per account, and those routes require a session, so an anonymous caller cannot exhaust them. Older stored challenges stay until they expire or are used.

TOTP uses SHA-1, 6 digits, and a 30-second step, with one step of clock drift. The step that was accepted is stored. Presenting it again fails, including the code just used to confirm enrollment. Ten recovery codes are returned once at enrollment and when regenerated. Only their SHA-256 hashes are stored. Each code works once.

Five failures lock the account for 15 minutes. Password failures and second-factor failures add up. A correct password does not reset the second-factor count, so a known password cannot be used to guess codes without limit. The lock looks like any other rejected sign-in.

The TOTP seed is encrypted in `accounts.db`. The AES-GCM key is in that same file, and the associated data is the account id. A ciphertext copied onto another account does not decrypt. A seed written by an earlier revision of this change used a fixed label with no account id. The next successful read rewrites that blob under the account id. The file is mode 0600, and shell commands and sandboxes already cannot read it. Passkey public keys and signature counters are in the same database. They are not secrets. The private key stays on the authenticator. `account passwd` deletes that account's passkeys and step-up tokens and revokes its sessions, and the CLI writes an audit event for the change.

The loopback bearer token is not checked with a passkey or TOTP. It remains the owner-equivalent credential described above, on loopback only. HTTP factor changes made with that token still need a step-up. `praxis-prime account totp` and `account passkey` write `accounts.db` as the OS user who can read that file, the same trust as `account passwd`, and they append an audit event that does not contain the secret. Passkey enrollment itself is the HTTP ceremony; the CLI can list and remove credentials. Telegram Approve and Deny do not call these routes. A paired chat is its own credential.

OIDC is not in this build. Neither is a rule that turns MFA on for every role above viewer when the gateway leaves loopback, or a second passkey prompt on SEND and SPEND. Those wait for M1e and M6.

## Local web app

The daemon serves the SPA when `ui/dist` or `PRAXIS_PRIME_UI_DIR` contains `index.html`. `GET /` and `GET /assets/…` are public so the sign-in page can load. Every other route stays on the allowlist and the same session, bearer, and CSRF checks. The HTML and asset responses set:

```
Content-Security-Policy: default-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
```

There is no `unsafe-inline` and no `unsafe-eval`.

A browser `Sec-Fetch-Site: cross-site` is 403. A mutating request whose content type is not `application/json` is 415. A body over 1 MiB is 413 and is not read. The CLI and Telegram do not send `Sec-Fetch-Site`. They use the WebSocket, so those two HTTP checks do not apply to them.

`GET /v1/auth/session` returns that session's `csrfToken` so a reload can keep sending `x-csrf-token`. The cookie stays `HttpOnly`. `GET /v1/memory`, `GET /v1/skills`, and `GET /v1/routines` read the profile named by `x-praxis-profile` through that profile's worker. A missing grant is 403 and the other worker is not called. `GET /v1/admin/directory` is owner and admin only and leaves out email and secrets. A web approval is `POST /v1/approvals/<id>` with `allow_once`, `allow_session`, or `deny`. A second decide for that id fails. The turn writes the same approval audit row it writes for a Telegram decision.

## Shell and the data directory

Bubblewrap mounts that contain the account data directory get an empty tmpfs over that directory, matched by path and by device and inode, so a bind-mount alias of a parent cannot read `profiles/`, `backups/`, or `accounts.db` at that path. A regular file in another mount whose inode is account data and whose link count is greater than one is covered with `/dev/null`. That inode set is the same denylist: every regular file under `profiles/` and `backups/`, `accounts.db`, `audit.db`, and the root `prime.db`, each SQLite sidecar of those databases (`-wal`, `-shm`, and `-journal`, so a live `accounts.db-wal` is included), `SOUL.md`, `worker-master.key` (including the copy in the runtime directory), and `gateway.token` in the runtime directory. If none of those files has another name, the workspace is not walked. A hard link is covered only while its link count is greater than one. After the other name is deleted or replaced, the name that remains has a link count of one and is not covered. An old `accounts.db-wal` left behind when SQLite removes its sidecar is that case: it behaves like a copy of those bytes. `.git/objects` and `node_modules` are walked when an extra name exists, and a hard link inside them is still covered. If that scan cannot finish, the command is not launched. A directory that cannot be listed (including mode `0300`, where the directory can be entered but not read), a workspace entry that is still missing after a short retry, and a tree deeper than the scan limit are unfinished scans. A file that disappears inside the account data directory during the scan, such as a SQLite journal or a temporary file, is not a failure. The hard-link cap error is the one that says the cap was hit and to remove the extra links or use a smaller directory. Every other unfinished scan names the folder and the reason, for example permission denied. The folder is a workspace path, or a path relative to the account data directory. A folder under another profile is reported as another profile's data. The link count decides only whether to walk. There is no early stop: when a protected file has another name, every mount is walked to the end and every name whose device and inode match that file is covered, including a name in a working directory and a name in a write scope inside it. A directory inside the masked account-data root is not walked, because the tmpfs already hides it, except an approved worktree that was mounted again. The check runs when the sandbox is launched. A hard link created after that scan and before bubblewrap starts is not covered, and creating it takes code running as the same user. The command walk does not parse every such read before bubblewrap runs. A bind that is inside the data directory is refused. The exception is one coding task worktree, `worktrees/<repo>/<task>` or `worktrees/<profile>/<repo>/<task>` after a profile exists, and the bind source is resolved first so a symlink cannot mount `profiles/`. `worktrees/` itself is not bindable. A `cd` that stays inside that worktree is allowed; a `cd` that leaves it is still refused. Without bubblewrap, shell commands are refused when any account or profile data exists (`accounts.db`, `profiles/`, `backups/`, `prime.db`, or `SOUL.md`), including account data in the default data directory when `--data-dir` points somewhere else. The card says `install bubblewrap to run shell commands` and the command is not run. Host shell remains only for a fresh install with no account data. The token check still splits `;` and `&&` and treats `cd -` as a refusal, as defence in depth. `read_file` of `org/policy.toml` stays allowed.
