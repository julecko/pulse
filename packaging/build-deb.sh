#!/usr/bin/env bash
#
# Build the pulse .deb packages — one per role, fully independent.
#
#   packaging/build-deb.sh                 # both: pulse-agent + pulse-server
#   packaging/build-deb.sh agent           # just pulse-agent  (agentd + agent CLI)
#   packaging/build-deb.sh server          # just pulse-server (serverd + server CLI)
#   packaging/build-deb.sh agent --target x86_64-unknown-linux-musl
#
# Each package's binaries come from two crates (daemon + front-end), so we build
# exactly those two crates and let `cargo deb --no-build` assemble. Building the
# agent package never compiles the server crates, and vice versa.
#
# Requires: cargo install cargo-deb

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v cargo-deb >/dev/null || {
    echo "cargo-deb not found — run: cargo install cargo-deb" >&2
    exit 1
}

roles=()
cargo_args=()
for arg in "$@"; do
    case "$arg" in
        agent | server) roles+=("$arg") ;;
        *) cargo_args+=("$arg") ;;
    esac
done
[ ${#roles[@]} -eq 0 ] && roles=(agent server)

for role in "${roles[@]}"; do
    echo "==> building pulse-$role"
    cargo build --release ${cargo_args[@]+"${cargo_args[@]}"} -p "$role" -p "${role}-cli"
    cargo deb --no-build ${cargo_args[@]+"${cargo_args[@]}"} -p "$role"
done

echo
echo "built:"
ls -1 target/debian/*.deb
