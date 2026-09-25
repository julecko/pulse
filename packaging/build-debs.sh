#!/bin/sh
# Builds the two Debian packages into target/debian/:
#   pulse-server_<version>_<arch>.deb  (pulse-serverd + pulse-server-cli)
#   pulse-agent_<version>_<arch>.deb   (pulse-agentd)
# Requires cargo-deb: cargo install cargo-deb
set -eu
cd "$(dirname "$0")/.."

# One build for all three binaries; pulse-server-cli belongs to a different
# crate than the pulse-server package, so cargo-deb can't build it itself.
cargo build --release -p serverd -p server-cli -p agentd

cargo deb -p serverd --no-build
cargo deb -p agentd --no-build
