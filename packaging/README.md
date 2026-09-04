# Packaging

## Debian packages (recommended)

```sh
cargo install cargo-deb          # one-time

packaging/build-deb.sh           # both roles
packaging/build-deb.sh agent     # just pulse-agent  (agentd + agent CLI)
packaging/build-deb.sh server    # just pulse-server (serverd + server CLI)

sudo apt install ./target/debian/pulse-agent_0.1.0-1_amd64.deb
```

The two packages are fully independent — `pulse-agent.deb` has no server binary
and `pulse-server.deb` has no agent binary. Building one role never compiles the
other's crates.

Each package installs:

| path | what |
|---|---|
| `/usr/lib/pulse/pulse-<app>d` | the daemon — not on `$PATH`, started by systemd only |
| `/usr/bin/pulse-<app>` | the config/control front-end (what you run) |
| `/etc/pulse/<app>.toml` | config — a dpkg conffile, survives upgrades |
| `/usr/lib/systemd/system/pulse-<app>.service` | unit (`ExecStart=/usr/lib/pulse/pulse-<app>d`) |

The service is **not** enabled automatically:

```sh
sudoedit /etc/pulse/agent.toml
sudo systemctl enable --now pulse-agent
```

Per-package `[package.metadata.deb]` lives in `crates/server/Cargo.toml` and
`crates/agent/Cargo.toml`. Use `build-deb.sh` rather than bare `cargo deb -p
agent` — each package needs a binary from its `*-cli` crate too, which the
script builds before `cargo deb --no-build`.

## Install from a build tree (no packaging tools)

```sh
cargo build --release
sudo packaging/postinstall.sh            # install binaries, config, units
sudo packaging/postinstall.sh --enable   # ... and enable --now both services
```

`postinstall.sh` is idempotent: existing `/etc/pulse/*.toml` are kept, binaries
and unit files are overwritten. Daemons go to `/usr/lib/pulse/`, front-ends to
`/usr/bin/`. Runtime dirs are created by systemd on first start
(`ConfigurationDirectory` / `StateDirectory` / `LogsDirectory` = `pulse`).

## Config file location

| Build            | server                    | agent                    |
|------------------|---------------------------|--------------------------|
| debug (`cargo`)  | `<exe dir>/server.toml`   | `<exe dir>/agent.toml`   |
| release          | `/etc/pulse/server.toml`  | `/etc/pulse/agent.toml`  |

Override with `PULSE_SERVER_CONFIG` / `PULSE_AGENT_CONFIG` (full path). A missing
file is fine (defaults + a log line); a malformed file is fatal.

Settings: server `bind`, `[storage]` and `[api]` (see below); agent `server`,
`interval_secs`; both take a `[log]` table (`level`, `file`, `ansi`, `rotation`,
`keep_files`) and a `tls` flag (see below).

## TLS / authentication

`tls = false` → plaintext, unauthenticated. `tls = true` → **mutual TLS 1.3
with certificate pinning both ways**:

- the agent pins the server's cert — it only talks to that server;
- the server pins a set of approved agent certs — it only accepts those agents.

A wrong/missing/unapproved certificate on either side aborts the handshake, and
both ends log the rejection. There is no CA.

### Files (in a `tls/` subfolder of the config directory)

`cert generate` creates `/etc/pulse/tls/` and puts everything there:

| host | files | role |
|---|---|---|
| server | `tls/server.crt` + `tls/server.key` | the server's own identity |
| server | `tls/trusted-agents/*.crt` | one file per approved agent |
| agent | `tls/agent.crt` + `tls/agent.key` | the agent's own identity |
| agent | `tls/trusted-server.crt` | pinned copy of the server's cert |

Deployments created before the `tls/` layout (cert files flat in `/etc/pulse/`)
keep working — the daemons and `cert` commands fall back to the flat location
when `tls/` is absent. To adopt the new layout on such a host:

```sh
sudo mkdir /etc/pulse/tls
sudo mv /etc/pulse/{server,agent}.crt /etc/pulse/{server,agent}.key \
        /etc/pulse/trusted-agents /etc/pulse/trusted-server.crt /etc/pulse/tls/ 2>/dev/null
sudo chown -R pulse:pulse /etc/pulse/tls
```

### Setup

```sh
# --- server host ---
sudo pulse-server cert generate --dns pulse.example.com --ip 10.0.0.5
sudo pulse-server cert pem                 # -> copy this to each agent as server.crt

# --- each agent host ---
sudo pulse-agent cert generate
sudo pulse-agent cert trust ./server.crt   # pin the server; turns tls on
sudo pulse-agent cert pem                  # -> send this to the server admin

# --- server host: approve each agent ---
sudo pulse-server cert approve ./agent-box1.crt --name box1   # turns tls on
sudo pulse-server cert list

sudo systemctl restart pulse-server        # and pulse-agent on each agent
```

`cert fingerprint` prints this host's own cert hash; `cert revoke <name|fp>`
removes an approved agent. Enabling `tls` happens automatically on the first
`cert trust` (agent) / `cert approve` (server).

Rejection is confirmed: the agent logs `failed to send report … AccessDenied`
and the server logs `TLS handshake failed … invalid peer certificate` when an
unapproved agent connects.

**Users:** both daemons run as a static `pulse` system user (deb postinst
creates it), needed so each can read its own private key. `cert generate` chowns
the generated files to it.

## Rate limiting (server)

The `[limits]` table caps `max_connections` (concurrent, excess dropped),
`per_ip_per_minute` (new connections per source IP, sliding 60s window), and
`connection_timeout_secs` (handshake + one report, guards slow-loris). Checks
run on the raw TCP accept, before the TLS handshake.

## History storage (server)

With `[storage] enabled = true` (the default) the server writes every received
report to a SQLite database — `[storage] path`, or `/var/lib/pulse/history.db`
when unset. Everything is keyed by the agent's `machine_id`: the `hosts` table
is the agent registry and `reports` references it `ON DELETE CASCADE`, so an
agent and all of its data are removed together (room to add tables like
`ssh_logins` the same way later).

`[storage] retention_days` (default 7) of history is kept; a background task
prunes older rows and reclaims space every `prune_interval_secs`. The data
survives restarts. Set `enabled = false` to run stateless (the API is then
unavailable).

## HTTP API (for the pulse app)

`[api] enabled = true` starts a JSON API on `[api] bind` (default
`127.0.0.1:9100`) with live host state and queryable history. It speaks **plain
HTTP** — keep it on loopback and put a TLS-terminating reverse proxy
(nginx/Caddy) in front for remote access. Requires `[storage] enabled` and at
least one account.

**Accounts** are managed on the server host (never over the API):

```sh
sudo pulse-server user add <name>      # prompts for a password (no echo)
sudo pulse-server user list
sudo pulse-server user passwd <name>
sudo pulse-server user rm <name>       # also drops that user's sessions
```

Passwords must be ≥ 12 characters with a lowercase letter, an uppercase letter,
a digit and a symbol, ≥ 5 distinct characters, and must not contain the
username. Hashed with Argon2id. In a script, pipe the password on stdin:
`printf '%s' "$pw" | sudo pulse-server user add ci`.

**Auth flow:** `POST /api/v1/login` with `{"username","password"}` returns
`{"token","expires_at_ms"}`. Send the token as `Authorization: Bearer <token>`
(the SSE endpoint also accepts `?token=<token>`). Only `sha256(token)` is stored
server-side; sessions last `[api] session_ttl_secs` (default 7 days) and are
revoked by `POST /api/v1/logout`.

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/v1/healthz` | liveness (no auth) |
| POST | `/api/v1/login` / `/api/v1/logout` | session lifecycle |
| GET  | `/api/v1/hosts` | all hosts + online flag + latest cpu/mem/load |
| GET  | `/api/v1/hosts/{machine_id}` | host detail + latest full report |
| GET  | `/api/v1/hosts/{machine_id}/history?from=&to=&bucket=` | downsampled series for charts (ms; `bucket` auto-picked) |
| GET  | `/api/v1/hosts/{machine_id}/reports?from=&to=&limit=` | raw full reports |
| GET  | `/api/v1/live` | SSE stream — snapshot then one event per new report |

`scripts/api_smoke_test.py` (stdlib only) exercises the whole surface:

```sh
scripts/api_smoke_test.py --url http://127.0.0.1:9100 --user alice --password '…'
```

## Logs

| Build   | `log.file` set | `log.file` unset          |
|---------|----------------|---------------------------|
| debug   | that file      | stdout (terminal)         |
| release | that file      | `/var/log/pulse/<app>.log`|

If a configured file can't be opened, it warns and falls back to stderr. ANSI
colour is auto-disabled when the terminal isn't a TTY. `RUST_LOG` overrides
`log.level`. With systemd, stdout is also captured: `journalctl -u pulse-agent -f`.

When logging to a file, `[log] rotation` (`daily`/`hourly`/`minutely`/`never`)
starts a new dated file (`server.2026-09-03.log`) and `[log] keep_files` deletes
the oldest beyond that count — so `rotation = "daily"`, `keep_files = 10` keeps
~10 days. No `logrotate` config needed. Rotation is re-checked on every write, so
a long-lived process rolls over at each period boundary (UTC), not just at
startup.

The server's full per-report device dump (host / CPU per-core / memory / disks /
load) is printed to the **terminal in debug builds only**. Release builds emit
just a one-line structured `report received` event (host, machine id, cpu %,
mem, disk count) to the log.

## Crates & binaries

| crate | produces | kind |
|---|---|---|
| `protocol` | — | wire format (lib) |
| `pulse-config` | — | config file loading + logging setup (lib) |
| `pulse-cli` | — | generic `config`/`systemctl` front-end engine (lib) |
| `server` | `pulse-serverd` | daemon — thin `main` over `pulse_server::run()` |
| `agent` | `pulse-agentd` | daemon — thin `main` over `pulse_agent::run()` |
| `server-cli` | `pulse-server` | front-end — `pulse_cli::run::<pulse_server::Config>()` |
| `agent-cli` | `pulse-agent` | front-end — `pulse_cli::run::<pulse_agent::Config>()` |

Each `.deb` bundles the daemon + its front-end (`build-deb.sh` builds the whole
workspace, then `cargo deb --no-build` assembles).

Front-end commands: `config <path|show|check|init|edit|set>`, `cert <…>`,
`start|stop|restart|status|enable|disable` (→ `systemctl`), `run` (daemon in the
foreground). `pulse-server` also has `user <add|list|passwd|rm>` for API
accounts.

## Dev

```sh
cp packaging/agent.toml target/debug/agent.toml   # tweak as needed
cargo run -p agent                # the daemon
cargo run -p agent-cli -- config show
```
