# Packaging

## Install (release)

```sh
cargo build --release
sudo packaging/postinstall.sh            # install binaries, config, units
sudo packaging/postinstall.sh --enable   # ... and enable --now both services
```

`postinstall.sh` is idempotent: existing `/etc/pulse/*.toml` are kept, binaries
and unit files are overwritten. Runtime dirs are created by systemd on first
start (`ConfigurationDirectory` / `StateDirectory` / `LogsDirectory` = `pulse`).

## Config file location

| Build            | server                    | agent                    |
|------------------|---------------------------|--------------------------|
| debug (`cargo`)  | `<exe dir>/server.toml`   | `<exe dir>/agent.toml`   |
| release          | `/etc/pulse/server.toml`  | `/etc/pulse/agent.toml`  |

Override with `PULSE_SERVER_CONFIG` / `PULSE_AGENT_CONFIG` (full path). A missing
file is fine (defaults + a log line); a malformed file is fatal.

Settings: server `bind`; agent `server`, `interval_secs`; both take a `[log]`
table (`level`, `file`, `ansi`).

## Logs

| Build   | `log.file` set | `log.file` unset          |
|---------|----------------|---------------------------|
| debug   | that file      | stdout (terminal)         |
| release | that file      | `/var/log/pulse/<app>.log`|

`RUST_LOG` overrides `log.level` when set. With systemd, stdout is also captured:
`journalctl -u pulse-agent -f`.

## Dev

```sh
cp packaging/agent.toml target/debug/agent.toml   # tweak as needed
cargo run -p agent
```
