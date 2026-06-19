#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Please run as root:"
  echo "  sudo bash install-full.sh"
  exit 1
fi

if [ ! -f "./install-lite.sh" ]; then
  echo "install-lite.sh not found. Run from repository root."
  exit 1
fi

echo "===== Golden VPN Max Full Installer ====="
echo
echo "Full mode will install:"
echo "- Lite stack: WireGuard + Dashboard + Agent + optional Telegram"
echo "- Pi-hole"
echo "- Unbound"
echo "- Backup scaffold"
echo "- Restore rehearsal scaffold"
echo
echo "Use this only on a fresh Ubuntu/Debian VPS."
echo

read -r -p "Continue with Full install? Type FULL: " confirm
if [ "$confirm" != "FULL" ]; then
  echo "Canceled."
  exit 1
fi

echo
echo "Step 1/4: running Lite installer..."
bash ./install-lite.sh

echo
echo "Step 2/4: installing Pi-hole and Unbound packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  unbound \
  curl \
  ca-certificates \
  dnsutils

if command -v pihole >/dev/null 2>&1; then
  echo "Pi-hole already installed."
else
  echo
  echo "Installing Pi-hole using official installer."
  echo "You may be asked interactive Pi-hole setup questions."
  curl -fsSL https://install.pi-hole.net | bash
fi

echo
echo "Step 3/4: configuring Unbound scaffold..."
install -d -m 755 /etc/unbound/unbound.conf.d

cat > /etc/unbound/unbound.conf.d/golden-vpn-max.conf <<'EOF_UNBOUND'
server:
  verbosity: 0
  interface: 127.0.0.1
  port: 5335
  do-ip4: yes
  do-udp: yes
  do-tcp: yes
  do-ip6: no
  prefer-ip6: no
  harden-glue: yes
  harden-dnssec-stripped: yes
  use-caps-for-id: no
  edns-buffer-size: 1232
  prefetch: yes
  num-threads: 1
  so-rcvbuf: 1m
  private-address: 10.0.0.0/8
  private-address: 172.16.0.0/12
  private-address: 192.168.0.0/16
EOF_UNBOUND

systemctl enable unbound
systemctl restart unbound

echo
echo "Step 4/4: creating backup and restore scaffold..."
install -d -m 700 /opt/wg-golden/backups
install -d -m 700 /opt/wg-golden/offsite
install -d -m 700 /opt/wg-golden/restore-rehearsal

cat > /opt/wg-golden/backup-now.sh <<'EOF_BACKUP'
#!/usr/bin/env bash
set -Eeuo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
OUT="/opt/wg-golden/backups/golden-vpn-full-$TS.tgz"

tar -czf "$OUT" \
  /etc/wireguard \
  /etc/wg-golden.env \
  /opt/wg-golden \
  /etc/systemd/system/wg-golden.service \
  /etc/systemd/system/wg-golden-agent.service \
  /etc/systemd/system/wg-golden-telegram.service \
  2>/tmp/golden-backup-warnings.log || true

sha256sum "$OUT" > "$OUT.sha256"

echo "BACKUP_CREATED $OUT"
echo "SHA256_CREATED $OUT.sha256"
EOF_BACKUP

chmod +x /opt/wg-golden/backup-now.sh

cat > /opt/wg-golden/restore-rehearsal.sh <<'EOF_RESTORE'
#!/usr/bin/env bash
set -Eeuo pipefail

LATEST="$(ls -1t /opt/wg-golden/backups/*.tgz 2>/dev/null | head -1 || true)"

if [ -z "$LATEST" ]; then
  echo "RESTORE_REHEARSAL_FAIL no backup found"
  exit 1
fi

TMP="/opt/wg-golden/restore-rehearsal/test"
rm -rf "$TMP"
mkdir -p "$TMP"

tar -tzf "$LATEST" >/dev/null
tar -xzf "$LATEST" -C "$TMP" >/dev/null 2>&1 || true

echo "RESTORE_REHEARSAL_OK $LATEST"
EOF_RESTORE

chmod +x /opt/wg-golden/restore-rehearsal.sh

echo
echo "Creating full helper command..."
cat > /usr/local/bin/golden-vpn-full <<'EOF_FULL_BIN'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-status}" in
  status)
    golden-vpn status
    systemctl --no-pager --plain status pihole-FTL unbound 2>/dev/null || true
    ;;
  backup-now)
    bash /opt/wg-golden/backup-now.sh
    ;;
  restore-rehearsal)
    bash /opt/wg-golden/restore-rehearsal.sh
    ;;
  logs)
    journalctl -u wg-golden -u wg-golden-agent -u wg-golden-telegram -u pihole-FTL -u unbound -n 160 --no-pager
    ;;
  *)
    echo "Usage: golden-vpn-full {status|backup-now|restore-rehearsal|logs}"
    exit 1
    ;;
esac
EOF_FULL_BIN

chmod +x /usr/local/bin/golden-vpn-full

echo
echo "Running first backup scaffold..."
bash /opt/wg-golden/backup-now.sh || true

echo
echo "===== FULL INSTALL COMPLETE ====="
echo
echo "Useful commands:"
echo "  sudo golden-vpn status"
echo "  sudo golden-vpn doctor"
echo "  sudo golden-vpn-full status"
echo "  sudo golden-vpn-full backup-now"
echo "  sudo golden-vpn-full restore-rehearsal"
echo
echo "Recommended Pi-hole upstream DNS:"
echo "  127.0.0.1#5335"
