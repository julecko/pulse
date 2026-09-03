#!/usr/bin/env bash
#
# Build the pulse-server and pulse-agent .deb packages.
#
#   packaging/build-deb.sh                 # native (host glibc)
#   packaging/build-deb.sh --target ...    # cross / musl, passed through
#
# Requires: cargo install cargo-deb

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v cargo-deb >/dev/null; then
    echo "cargo-deb not found — run: cargo install cargo-deb" >&2
    exit 1
fi

cargo deb -p server "$@"
cargo deb -p agent "$@"

echo
echo "built:"
ls -1 target/debian/*.deb
