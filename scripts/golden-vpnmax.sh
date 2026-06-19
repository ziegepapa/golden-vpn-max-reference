#!/usr/bin/env bash
set -Eeuo pipefail

CMD="${1:-status}"

case "$CMD" in
  status)
    exec /opt/wg-golden/golden-vpnmax-status.sh
    ;;
  repair-safe)
    exec /opt/wg-golden/golden-vpnmax-repair-safe.sh
    ;;
  verify-backup)
    exec /opt/wg-golden/golden-vpnmax-verify-backup.sh
    ;;
  backup-now)
    exec /opt/wg-golden/golden-vpnmax-backup-now.sh
    ;;
  offsite-encrypt)
    exec /opt/wg-golden/golden-vpnmax-offsite-encrypt.sh
    ;;
  restore-rehearsal)
    exec /opt/wg-golden/golden-vpnmax-restore-rehearsal.sh
    ;;
  migration-pack)
    exec /opt/wg-golden/golden-vpnmax-migration-pack.sh
    ;;
  prune-old)
    exec /opt/wg-golden/golden-vpnmax-prune-old.sh
    ;;
  doctor)
    exec /opt/wg-golden/golden-final-doctor.sh
    ;;
  hygiene)
    /opt/wg-golden/golden-peer-hygiene.sh
    exec cat /opt/wg-golden/PEER_HYGIENE_REVIEW.txt
    ;;
  help|-h|--help)
    cat <<'EOF'
VPN MAX CONTROL COMMANDS

sudo /opt/wg-golden/golden-vpnmax.sh status
sudo /opt/wg-golden/golden-vpnmax.sh repair-safe
sudo /opt/wg-golden/golden-vpnmax.sh verify-backup
sudo /opt/wg-golden/golden-vpnmax.sh backup-now
sudo /opt/wg-golden/golden-vpnmax.sh offsite-encrypt
sudo /opt/wg-golden/golden-vpnmax.sh restore-rehearsal
sudo /opt/wg-golden/golden-vpnmax.sh migration-pack
sudo /opt/wg-golden/golden-vpnmax.sh prune-old
sudo /opt/wg-golden/golden-vpnmax.sh doctor
sudo /opt/wg-golden/golden-vpnmax.sh hygiene
EOF
    ;;
  *)
    echo "Unknown command: $CMD"
    echo "Run: sudo /opt/wg-golden/golden-vpnmax.sh help"
    exit 1
    ;;
esac
