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

Settings: server `bind`; agent `server`, `interval_secs`; both take a `[log]`
table (`level`, `file`, `ansi`, `rotation`, `keep_files`).

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

Front-end commands: `config <path|show|check|init|edit|set>`,
`start|stop|restart|status|enable|disable` (→ `systemctl`), `run` (daemon in the
foreground).

## Dev

```sh
cp packaging/agent.toml target/debug/agent.toml   # tweak as needed
cargo run -p agent                # the daemon
cargo run -p agent-cli -- config show
```
