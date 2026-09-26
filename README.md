# Pulse

Pulse is a lightweight host-monitoring system: a single **server** collects
metrics (CPU, memory, disk, host info, ...) reported by one or more **agents**
running on the machines you want to watch. Agents send a metrics snapshot every
`interval_secs` (agent config) over HTTPS, and the server stores them in
SQLite for `[retention] metrics_days`. A mobile app to view everything
remotely is planned next.

Workspace layout:

```
crates/
  agentd/        pulse-agentd: runs on a monitored host, collects metrics
  serverd/       pulse-serverd: HTTPS API + SQLite storage, runs on the central server
  server-cli/    pulse-server-cli: admin CLI (agents, users) for the server host
  protocol/      shared wire types (metrics payloads) used by agent and server
  pulse-shared/  shared config loading + logging setup used by all binaries
config/          default TOML configs used in debug builds (server.toml, agent.toml)
packaging/       Debian packaging: systemd units, maintainer scripts, release configs
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
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"

# 2. Run the server (creates data/server.db and applies migrations automatically)
cargo run -p serverd

# 3. In another terminal, run the agent
cargo run -p agentd
```

The server listens on `https://0.0.0.0:8443` by default (see `config/server.toml`)
and serves a self-signed cert, so tell `curl` to trust it:

```sh
curl --cacert certs/cert.pem https://localhost:8443/healthz
```

## TLS certs

`certs/` is gitignored — everyone generates their own local dev cert. The
server looks for `certs/cert.pem` and `certs/key.pem` (relative to cwd) in
debug builds, or `/etc/pulse-server/certs/{cert,key}.pem` in release builds, unless
overridden by `[web.tls]` in the config file.

Generate a self-signed cert valid for local dev:

```sh
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

Regenerate any time — just re-run the command above (it overwrites both files).

The agent and `pulse-server-cli` always verify the server's cert, so a
cert made without the `-addext` lines above (e.g. by an older version of
this README) is rejected: rustls needs a `subjectAltName` matching the
address you connect to, and refuses certs marked `CA:TRUE` as server certs.
In debug builds the agent trusts `certs/cert.pem` via `ca_cert` in
`config/agent.toml`, and `pulse-server-cli` trusts the server's cert
automatically (see [Verifying the server's cert](#verifying-the-servers-cert)).

## Database / working with sqlx

The server uses SQLite via `sqlx`, with migrations embedded into the binary
at compile time (`sqlx::migrate!("./migrations")` in `crates/serverd/src/db/mod.rs`).
**Just running `cargo run -p serverd` applies pending migrations automatically
— you don't need `DATABASE_URL` for normal development.**

You only need `DATABASE_URL` set when invoking `sqlx-cli` directly (adding or
reverting migrations by hand, or using `sqlx migrate` subcommands). The DB
file lives at `data/server.db` (debug) or `/var/lib/pulse-server/server.db`
(release) by default, and migrations live in `crates/serverd/migrations/`, not
in the repo root — pass `--source` or `cd crates/serverd` first.

```sh
# from the repo root
export DATABASE_URL="sqlite://$(pwd)/data/server.db"

# add a new reversible migration
sqlx migrate add -r -s --source crates/serverd/migrations <name>

# apply pending migrations manually
sqlx migrate run --source crates/serverd/migrations

# check migration status
sqlx migrate info --source crates/serverd/migrations

# revert the most recent migration (only works for reversible migrations
# created with -r, i.e. with a paired .down.sql)
sqlx migrate revert --source crates/serverd/migrations
```

Alternatively, run everything from inside `crates/serverd` and drop the
`--source` flag:

```sh
cd crates/serverd
export DATABASE_URL="sqlite://$(pwd)/../../data/server.db"
sqlx migrate revert
```

Tip: `cp .env.example .env` at the repo root instead of exporting by hand —
`.env` is gitignored and `sqlx-cli` picks it up automatically every shell
session.

## Configuration

All binaries load TOML config on startup via `pulse_shared::config::load`:

- **debug build**: `config/<app>.toml` (the checked-in defaults, e.g.
  `config/server.toml`, `config/agent.toml`)
- **release build**: `/etc/pulse-<app>/<app>.toml`, i.e. `/etc/pulse-server/server.toml`
  and `/etc/pulse-agent/agent.toml` (not `/etc/pulse`, which is PulseAudio's)
- either build: the `PULSE_CONFIG` env var, if set, overrides the path

Any field not present in the file falls back to its default (see each
`config.rs` for the defaults). Notable settings:

- `config/server.toml`: `[web] bind/session_ttl_hours`, `[web.tls] cert/key`, `[db] path`,
  `[retention] metrics_days/auth_events_days` (default 14, `0` = keep forever), `[log] ...`
- `config/agent.toml`: `server_addr`, `interval_secs`, `pam_socket`, `[log] ...`

Logging goes to stdout in debug builds by default (or `log.file` if set), and
to `/var/log/pulse-<app>/<app>.log` in release builds. `RUST_LOG` overrides
`log.level` when set.

## Installing (Debian/Ubuntu packages)

Build both packages into `target/debian/` (needs
[`cargo-deb`](https://github.com/kornelski/cargo-deb): `cargo install cargo-deb`):

```sh
./packaging/build-debs.sh
```

| Package | Contains | Install on |
|---|---|---|
| `pulse-server_<ver>_<arch>.deb` | `pulse-serverd` (daemon), `pulse-server-cli` | the central server |
| `pulse-agent_<ver>_<arch>.deb` | `pulse-agentd` (daemon + PAM hook) | every monitored host |

They require glibc 2.34+ (Ubuntu 22.04 / Debian 12 or newer). Both can be
installed on the same host.

```sh
sudo apt install ./target/debian/pulse-server_*.deb
sudo apt install ./target/debian/pulse-agent_*.deb
```

The daemons aren't commands to run by hand, so they're installed outside
every user's `PATH`, in a private directory per package (like Postfix's
`/usr/lib/postfix/sbin/`): `/usr/lib/pulse-server/pulse-serverd` and
`/usr/lib/pulse-agent/pulse-agentd`. Manage them with `systemctl`
(`systemctl status|restart pulse-serverd`, logs in `/var/log/pulse-*/`).
The only command meant for users is `pulse-server-cli`, in `/usr/bin`; the
admin tool `pulse-server-gen-cert` is in `/usr/sbin`.

Installing creates a system user for each daemon. The server's unit is
enabled and started right away. The agent's is installed **disabled**, since
it first needs to know which server to report to (see below). Neither daemon
runs as root:

| | `pulse-serverd.service` | `pulse-agentd.service` |
|---|---|---|
| Runs as | `pulse-server` | `pulse-agent` |
| Config | `/etc/pulse-server/server.toml` | `/etc/pulse-agent/agent.toml` |
| State | `/var/lib/pulse-server/server.db` | `/var/lib/pulse-agent/identity.toml` |
| Logs | `/var/log/pulse-server/` | `/var/log/pulse-agent/` |
| Other | TLS cert in `/etc/pulse-server/certs/` | PAM socket `/run/pulse-agent/agent.sock` |

On first install the server package generates a self-signed TLS cert in
`/etc/pulse-server/certs/` with `pulse-server-gen-cert`. To use your own,
replace `cert.pem` and `key.pem` there, keeping the key readable by the
`pulse-server` group (`root:pulse-server`, mode `0640`), then run
`systemctl restart pulse-serverd`. Agents verify this cert, so read
[Verifying the server's cert](#verifying-the-servers-cert) before setting
them up.

After installing:

```sh
# on the server host: copy the server's cert somewhere agents can fetch it
cat /etc/pulse-server/certs/cert.pem          # public, safe to copy around

# on each agent host: install the server's cert, point the agent at the
# server, then start it
sudo install -m 0644 cert.pem /etc/pulse-agent/server.pem
sudoedit /etc/pulse-agent/agent.toml          # server_addr = "your-server:8443"
                                              # ca_cert = "/etc/pulse-agent/server.pem"
sudo systemctl enable --now pulse-agentd

# on the server host: create your admin user first (needs write access to the DB)
sudo pulse-server-cli users add alice

# then let agents pair (closed by default) and approve them; `agents`
# commands log in and ask for the password
pulse-server-cli -u alice agents pairing open --minutes 15
pulse-server-cli -u alice agents list
# check the fingerprint first: on the agent host,
#   sudo /usr/lib/pulse-agent/pulse-agentd fingerprint
pulse-server-cli -u alice agents approve <id>
pulse-server-cli -u alice agents pairing close
pulse-server-cli -u alice agents metrics <id>  # latest snapshots (--limit N)
```

To set up login tracking, see [Tracking logins (PAM)](#tracking-logins-pam).

### Pairing window

New agents can only send pairing requests while pairing is **open**. It's
closed by default (also after upgrading), so strangers who can reach the
server can't fill the agent list with fake requests. Open it while you add
agents, then close it again:

```sh
pulse-server-cli -u alice agents pairing open --minutes 15   # closes by itself
pulse-server-cli -u alice agents pairing open                # until you close it
pulse-server-cli -u alice agents pairing close
pulse-server-cli -u alice agents pairing status
```

While it's closed, `POST /agents/pair` refuses unknown agents with `403`
(they log why and retry every 5 minutes). Agents the server already knows
(pending, approved or revoked) can always poll their status, so approved
agents keep working and still notice being revoked. While it's open, at most
100 requests can be pending at once; more get `503` until you approve or
remove some. Hostnames must be unique: a second agent reporting a taken
hostname gets `409`.

Agents poll `/agents/pair` once a minute.

### Agent identity

On first start each agent generates a random **secret** (32 bytes) and
derives its public **fingerprint** from it; both are stored in
`/var/lib/pulse-agent/identity.toml` (mode 0600, agent's user only).

- The agent sends the secret with every pairing poll, proving it owns the
  fingerprint. A poll for a known fingerprint with the wrong secret gets
  `401`, and a new fingerprint must be the one derived from its secret, so
  nobody can register or take over a fingerprint that isn't theirs.
- Once approved, the secret itself is the agent's bearer token. The server
  never sends a credential back and stores only the secret's SHA-256, so a
  leaked database, log or `agents list` output gives nothing away. The
  fingerprint is public.
- Compare fingerprints before approving: `agents list` on the server,
  `sudo /usr/lib/pulse-agent/pulse-agentd fingerprint` on the host.

Revoking an agent is final for its secret (it may be compromised), so a
revoked agent can't be approved again. To bring the host back:

```sh
pulse-server-cli -u alice agents remove <id>             # on the server
sudo /usr/lib/pulse-agent/pulse-agentd reset-identity   # on the host: new secret
sudo systemctl restart pulse-agentd                     # pairs as a new request
```

Upgrading from a version where the server handed out tokens: approved
agents keep working (the server converts their stored token, and the agent
adopts it as its secret). Pending requests are dropped; those agents
request again, with a secret, next time pairing is open.

### Rate limiting

The routes anyone can reach are rate-limited per client IP (IPv6: per /64),
configurable under `[web.rate_limit]` in the server config:

| Route | Default | Counts |
|---|---|---|
| `POST /auth/login` | 5 per minute | failed logins only |
| `POST /agents/pair` | 30 per minute | every request |

Over the limit, the server answers `429` with `Retry-After` (the agent waits
that long; `pulse-server-cli` says how long). Five wrong passwords lock
that address out briefly, even for the right password, so guesses can't
continue. The pairing limit also caps how many agents can share one public
IP (e.g. behind NAT); raise it if you have more. Behind a reverse proxy,
every client shares the proxy's IP: set the limits to `0` and rate-limit at
the proxy. Password checks are also limited to a few at a time (each takes
~19 MiB), so a flood of logins can't exhaust the server's memory.

### Verifying the server's cert

The agent and `pulse-server-cli` always verify the server's TLS cert; there
is no option to skip it. Without it, anyone on the network path could pose
as the server and collect agent secrets or your login password, or tell
agents they've been revoked.

A cert is accepted if it chains to a public CA (e.g. Let's Encrypt), or to
the extra cert you give the client:

- agent: `ca_cert = "/etc/pulse-agent/server.pem"` in `agent.toml`
- `pulse-server-cli`: `--ca-cert <file>`. Without it, it trusts the server's
  own cert (`[web.tls] cert`, default `/etc/pulse-server/certs/cert.pem`)
  when it can read it, so on the server host it just works.

Either way, the cert must be valid for the host you connect to (the host in
the agent's `server_addr`, or the CLI's `--server`). The self-signed cert
from `pulse-server-gen-cert` covers the server's hostname, FQDN, its IPs at
generation time, and `localhost`/`127.0.0.1`. If agents reach the server by
another name (a public DNS name, a NAT address), or its IP changes,
regenerate it with those names and redistribute it:

```sh
sudo pulse-server-gen-cert --force pulse.example.com 203.0.113.7
sudo systemctl restart pulse-serverd
# then copy the new cert.pem to every agent's /etc/pulse-agent/server.pem
# and restart pulse-agentd there
```

Upgrading from a version that generated certs without a `subjectAltName`?
The package warns about it on upgrade; regenerate the cert as above.

If verification fails, the agent logs `pairing request failed` with the
reason after `invalid peer certificate:`
- `UnknownIssuer` / `BadSignature`: `ca_cert` unset or not the server's
  current cert
- `certificate not valid for name ...`: the cert doesn't cover the host in
  `server_addr`; regenerate it with that name
- `CaUsedAsEndEntity`: an old-style self-signed cert; regenerate it

`apt remove` stops the service and keeps config and data. `apt purge` also
deletes the database or agent identity, the logs and the generated certs. The
system users are left in place, as Debian policy recommends.

## Tracking logins (PAM)

The agent can report SSH logins, `sudo`/`su` sessions and failed password
attempts. PAM calls `pulse-agentd pam-hook` through `pam_exec.so`. The hook writes
the event to the agent's local Unix socket (`pam_socket`: `data/agent.sock`
in debug, `/run/pulse-agent/agent.sock` in release) and exits. The agent then
forwards events to the server with its bearer token (its secret)
(`POST /agents/me/auth-events`), so the server links each event to its host
from the token. The hook never sees the token.

The socket only accepts events from root (which pam_exec runs as for
sshd/sudo/su) or from the agent's own user, so other local users can't
forge events. The agent keeps no history: each event is sent on its own as
it arrives. If the agent isn't approved, or the server can't be reached,
the event is dropped.

Neither the package nor anything else edits PAM config automatically. Add
these lines by hand (paths assume the `pulse-agent` package, which installs
`/usr/lib/pulse-agent/pulse-agentd`):

**Sessions**: add to `/etc/pam.d/sshd`, `/etc/pam.d/sudo`, `/etc/pam.d/su`:

```
session optional pam_exec.so quiet /usr/lib/pulse-agent/pulse-agentd pam-hook
```

**Failed authentication** (Debian/Ubuntu `/etc/pam.d/common-auth`): put the
hook between `pam_unix` and `pam_deny`, and bump `success=1` to `success=2`
so a successful login skips both:

```
auth [success=2 default=ignore] pam_unix.so nullok
auth optional pam_exec.so quiet /usr/lib/pulse-agent/pulse-agentd pam-hook
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

View an agent's events with `pulse-server-cli -u <user> agents events <id>`.

## Users

User accounts can only be created with `pulse-server-cli users`. There is no
registration endpoint and no HTTP route that creates users. Unlike the other
`pulse-server-cli` commands, `users` doesn't talk to the server's API. It opens the
server's SQLite file directly, so it only works on the server host for someone
with write access to that file (root or the service user):

```sh
cargo run -p server-cli -- users add alice      # prompts for the password twice
echo "$PASSWORD" | pulse-server-cli users add alice   # or from stdin (scripts)
cargo run -p server-cli -- users list
cargo run -p server-cli -- users remove alice   # also ends all of alice's sessions
```

The database is found the same way the server finds it: `[db] path` from the
server config (`PULSE_CONFIG`, else `config/server.toml` in debug or
`/etc/pulse-server/server.toml` in release), else the default location. Override it
with `--db <path>`. The server must have run once so the database and its
tables exist; `pulse-server-cli` never creates the database or runs migrations.

Passwords are never accepted as command-line arguments, so they don't end up
in shell history or `ps`. They must be at least 8 characters and are stored as
argon2id hashes.

### Logging in from `pulse-server-cli`

Every server route except `/healthz`, `/auth/login` and the agents' own
routes requires a logged-in user. That covers everything `pulse-server-cli
agents` does (list, approve, revoke, remove, events, metrics). So each
`agents` command logs in first:

```sh
pulse-server-cli -u alice agents list          # prompts for the password, no echo
pulse-server-cli agents list                   # prompts for the username too
echo "$PASSWORD" | pulse-server-cli -u alice agents list   # scripts: password on stdin
```

The password is typed without echo and never taken as an argument, so it
doesn't show up in shell history or `ps`. Each run logs out when it's done,
so it leaves no session behind. `health` and `users` don't log in: `health`
is public, and `users` works on the database directly.

### HTTP API

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
