#!/usr/bin/env bash
#
# Set up pulse as systemd services. Run as root after `cargo build --release`.
#
#   sudo packaging/postinstall.sh            # install both, enable nothing
#   sudo packaging/postinstall.sh --enable   # ... and `enable --now` both
#
# Idempotent: existing /etc/pulse/*.toml files are kept, everything else is
# overwritten. Runtime dirs (/etc/pulse, /var/lib/pulse, /var/log/pulse) are
# created by systemd on first start via the unit's *Directory= settings.

set -euo pipefail

# /usr/bin to match the unit files' ExecStart= and the .deb layout.
PREFIX="${PREFIX:-/usr}"
CONF_DIR="/etc/pulse"
UNIT_DIR="/etc/systemd/system"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

enable=0
[ "${1:-}" = "--enable" ] && enable=1

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root" >&2
    exit 1
fi

for bin in server agent; do
    if [ ! -x "$root/target/release/$bin" ]; then
        echo "error: $root/target/release/$bin missing — run 'cargo build --release'" >&2
        exit 1
    fi
done

echo "==> binaries -> $PREFIX/bin"
install -Dm755 "$root/target/release/server" "$PREFIX/bin/pulse-server"
install -Dm755 "$root/target/release/agent"  "$PREFIX/bin/pulse-agent"

echo "==> config -> $CONF_DIR"
install -d -m755 "$CONF_DIR"
for app in server agent; do
    dest="$CONF_DIR/$app.toml"
    if [ -e "$dest" ]; then
        echo "    keeping existing $dest"
    else
        install -Dm644 "$here/$app.toml" "$dest"
        echo "    wrote $dest"
    fi
done

echo "==> units -> $UNIT_DIR"
install -Dm644 "$here/pulse-server.service" "$UNIT_DIR/pulse-server.service"
install -Dm644 "$here/pulse-agent.service"  "$UNIT_DIR/pulse-agent.service"

echo "==> systemctl daemon-reload"
systemctl daemon-reload

if [ "$enable" -eq 1 ]; then
    echo "==> enabling services"
    systemctl enable --now pulse-server.service
    systemctl enable --now pulse-agent.service
fi

cat <<'EOF'

Done. Next steps:
  - edit /etc/pulse/server.toml and /etc/pulse/agent.toml
  - start:   systemctl enable --now pulse-agent    (or pulse-server)
  - logs:    journalctl -u pulse-agent -f
             tail -f /var/log/pulse/agent.log
EOF
