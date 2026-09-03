# Packaging

## Config file locations

| Build            | server                      | agent                      |
|------------------|-----------------------------|----------------------------|
| debug (`cargo`)  | `<exe dir>/server.toml`     | `<exe dir>/agent.toml`     |
| release          | `/etc/pulse/server.toml`    | `/etc/pulse/agent.toml`    |

Override either with an env var: `PULSE_SERVER_CONFIG=/path/to.toml`,
`PULSE_AGENT_CONFIG=/path/to.toml`.

A missing file is fine — the binary logs it and runs on built-in defaults. A
file that exists but fails to parse is a fatal error.

## Install (release)

```sh
install -Dm755 target/release/server /usr/local/bin/pulse-server
install -Dm755 target/release/agent  /usr/local/bin/pulse-agent

install -Dm644 packaging/server.toml /etc/pulse/server.toml
install -Dm644 packaging/agent.toml  /etc/pulse/agent.toml

install -Dm644 packaging/pulse-server.service /etc/systemd/system/pulse-server.service
install -Dm644 packaging/pulse-agent.service  /etc/systemd/system/pulse-agent.service

systemctl daemon-reload
systemctl enable --now pulse-server   # or pulse-agent
```

## Dev

```sh
cp packaging/agent.toml target/debug/agent.toml   # tweak as needed
cargo run -p agent
```
