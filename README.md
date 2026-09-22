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
sqlx migrate add -r --source crates/server/migrations <name>

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

- `config/server.toml`: `[web] bind`, `[web.tls] cert/key`, `[db] path`, `[log] ...`
- `config/agent.toml`: `server_addr`, `interval_secs`, `[log] ...`

Logging goes to stdout in debug builds by default (or `log.file` if set), and
to `/var/log/pulse/<app>.log` in release builds. `RUST_LOG` overrides
`log.level` when set.

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
