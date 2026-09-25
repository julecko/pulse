# Pulse

Pulse is a lightweight host-monitoring system: a single **server** collects
metrics (CPU, memory, disk, host info, ...) reported by one or more **agents**
running on the machines you want to watch. Right now the agent only collects
metrics locally and the server exposes a minimal HTTPS API backed by SQLite;
the agent → server transport and a mobile app to view everything remotely are
planned next.

Workspace layout:

```
crates/
  agent/         binary: runs on a monitored host, collects metrics
  server/        binary: HTTPS API + SQLite storage, runs on the central server
  protocol/      shared wire types (metrics payloads) used by agent and server
  pulse-shared/  shared config loading + logging setup used by both binaries
config/          default TOML configs used in debug builds (server.toml, agent.toml)
certs/           TLS cert/key for the server (gitignored, generate locally)
data/            SQLite database file (gitignored, created automatically)
```

## Prerequisites

- Rust toolchain, edition 2024 (tested with `rustc 1.94`) — install via [rustup](https://rustup.rs)
- `openssl` CLI, to generate a local dev TLS cert
- [`sqlx-cli`](https://github.com/launchbadge/sqlx/tree/main/sqlx-cli) — only needed if you're writing/reverting migrations by hand:
  ```sh
  cargo install sqlx-cli --no-default-features --features rustls,sqlite
  ```

## Quickstart

```sh
git clone <repo-url> pulse
cd pulse

# 1. TLS cert (see below)
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=localhost"

# 2. Run the server (creates data/server.db and applies migrations automatically)
cargo run -p server

# 3. In another terminal, run the agent
cargo run -p agent
```

The server listens on `https://0.0.0.0:8443` by default (see `config/server.toml`)
and serves a self-signed cert, so `curl` needs `-k`:

```sh
curl -k https://localhost:8443/healthz
curl -k https://localhost:8443/hosts
```

## TLS certs

`certs/` is gitignored — everyone generates their own local dev cert. The
server looks for `certs/cert.pem` and `certs/key.pem` (relative to cwd) in
debug builds, or `/etc/pulse/certs/{cert,key}.pem` in release builds, unless
overridden by `[web.tls]` in the config file.

Generate a self-signed cert valid for local dev:

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=localhost"
```

Regenerate any time — just re-run the command above (it overwrites both files).

## Database / working with sqlx

The server uses SQLite via `sqlx`, with migrations embedded into the binary
at compile time (`sqlx::migrate!("./migrations")` in `crates/server/src/db/mod.rs`).
**Just running `cargo run -p server` applies pending migrations automatically
— you don't need `DATABASE_URL` for normal development.**

You only need `DATABASE_URL` set when invoking `sqlx-cli` directly (adding or
reverting migrations by hand, or using `sqlx migrate` subcommands). The DB
file lives at `data/server.db` (debug) or `/var/lib/pulse/server.db`
(release) by default, and migrations live in `crates/server/migrations/`, not
in the repo root — pass `--source` or `cd crates/server` first.

```sh
# from the repo root
export DATABASE_URL="sqlite://$(pwd)/data/server.db"

# add a new reversible migration
sqlx migrate add -r -s --source crates/server/migrations <name>

# apply pending migrations manually
sqlx migrate run --source crates/server/migrations

# check migration status
sqlx migrate info --source crates/server/migrations

# revert the most recent migration (only works for reversible migrations
# created with -r, i.e. with a paired .down.sql)
sqlx migrate revert --source crates/server/migrations
```

Alternatively, run everything from inside `crates/server` and drop the
`--source` flag:

```sh
cd crates/server
export DATABASE_URL="sqlite://$(pwd)/../../data/server.db"
sqlx migrate revert
```

Tip: `cp .env.example .env` at the repo root instead of exporting by hand —
`.env` is gitignored and `sqlx-cli` picks it up automatically every shell
session.

## Configuration

Both binaries load TOML config on startup via `pulse_shared::config::load`:

- **debug build**: `config/<app>.toml` (the checked-in defaults, e.g.
  `config/server.toml`, `config/agent.toml`)
- **release build**: `/etc/pulse/<app>.toml`
- either build: the `PULSE_CONFIG` env var, if set, overrides the path

Any field not present in the file falls back to its default (see each
`config.rs` for the defaults). Notable settings:

- `config/server.toml`: `[web] bind/session_ttl_hours`, `[web.tls] cert/key`, `[db] path`,
  `[retention] metrics_days/auth_events_days` (default 14, `0` = keep forever), `[log] ...`
- `config/agent.toml`: `server_addr`, `interval_secs`, `pam_socket`, `[log] ...`

Logging goes to stdout in debug builds by default (or `log.file` if set), and
to `/var/log/pulse/<app>.log` in release builds. `RUST_LOG` overrides
`log.level` when set.

## Tracking logins (PAM)

The agent can report SSH logins, `sudo`/`su` sessions and failed password
attempts. PAM calls `agent pam-hook` through `pam_exec.so`. The hook writes
the event to the agent's local Unix socket (`pam_socket`: `data/agent.sock`
in debug, `/run/pulse/agent.sock` in release) and exits. The agent then
forwards events to the server with its bearer token
(`POST /agents/me/auth-events`), so the server links each event to its host
from the token. The hook never sees the token.

The socket only accepts events from root (which pam_exec runs as for
sshd/sudo/su) or from the agent's own user, so other local users can't
forge events. The agent keeps no history: each event is sent on its own as
it arrives. If the agent isn't approved, or the server can't be reached,
the event is dropped.

Nothing is installed automatically. Add these lines by hand (paths assume
the agent binary is at `/usr/local/bin/pulse-agent`):

**Sessions**: add to `/etc/pam.d/sshd`, `/etc/pam.d/sudo`, `/etc/pam.d/su`:

```
session optional pam_exec.so quiet /usr/local/bin/pulse-agent pam-hook
```

**Failed authentication** (Debian/Ubuntu `/etc/pam.d/common-auth`): put the
hook between `pam_unix` and `pam_deny`, and bump `success=1` to `success=2`
so a successful login skips both:

```
auth [success=2 default=ignore] pam_unix.so nullok
auth optional pam_exec.so quiet /usr/local/bin/pulse-agent pam-hook
auth requisite pam_deny.so
```

Keep a root shell open while editing PAM files, so a mistake can't lock you
out. The hook always exits 0 and the lines are `optional`, so a stopped or
broken agent never blocks a login.

Caveats:
- The `success=N` skip counts differ between distros. Check your own
  `common-auth` / `system-auth` before copying the snippet.
- Failed SSH **public-key** attempts are handled by sshd without going
  through PAM auth, so they aren't reported. Successful key logins are still
  reported as sessions.

View an agent's events with `server-cli agents events <id>`.

## Users

User accounts can only be created with `server-cli users`. There is no
registration endpoint and no HTTP route that creates users. Unlike the other
`server-cli` commands, `users` doesn't talk to the server's API. It opens the
server's SQLite file directly, so it only works on the server host for someone
with write access to that file (root or the service user):

```sh
cargo run -p server-cli -- users add alice      # prompts for the password twice
echo "$PASSWORD" | server-cli users add alice   # or read it from stdin (scripts)
cargo run -p server-cli -- users list
cargo run -p server-cli -- users remove alice   # also ends all of alice's sessions
```

The database is found the same way the server finds it: `[db] path` from the
server config (`PULSE_CONFIG`, else `config/server.toml` in debug or
`/etc/pulse/server.toml` in release), else the default location. Override it
with `--db <path>`. The server must have run once so the database and its
tables exist; `server-cli` never creates the database or runs migrations.

Passwords are never accepted as command-line arguments, so they don't end up
in shell history or `ps`. They must be at least 8 characters and are stored as
argon2id hashes.

Clients log in with `POST /auth/login` (`{"username": ..., "password": ...}`)
and get back a session token. They send it as `Authorization: Bearer <token>`
to user routes such as `GET /users/me`, and `POST /auth/logout` ends the
session. Only a SHA-256 hash of each token is stored. Sessions expire after
`[web] session_ttl_hours` (default 168, one week), and expired ones are
cleaned up hourly.

## Development

```sh
cargo check --all-targets   # fast type-check
cargo fmt --all              # format
cargo build --release        # optimized build
```

Git hooks live in `.githooks/` (formatting + `cargo check` on commit). Point
git at them once per clone:

```sh
git config core.hooksPath .githooks
```
