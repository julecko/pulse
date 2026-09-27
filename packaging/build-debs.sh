#!/bin/sh
# Builds the two Debian packages into target/debian/:
#   pulse-server_<version>_<arch>.deb  (pulse-serverd + pulse-server-cli)
#   pulse-agent_<version>_<arch>.deb   (pulse-agentd + pulse-agent-cli)
# Requires cargo-deb: cargo install cargo-deb
set -eu
cd "$(dirname "$0")/.."

# One build for all four binaries; pulse-server-cli and pulse-agent-cli
# belong to different crates than their packages, so cargo-deb can't build
# them itself.
cargo build --release -p serverd -p server-cli -p agentd -p agent-cli

cargo deb -p serverd --no-build
cargo deb -p agentd --no-build
