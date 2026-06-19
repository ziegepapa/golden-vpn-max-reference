#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/wg-golden"
KEEP="/home/ubuntu/FINAL_BACKUPS_KEEP"
OLD="$KEEP/OLD_SUPERSEDED"
LOG="$APP_DIR/control/repair-safe-last.log"

mkdir -p "$APP_DIR/control" "$KEEP" "$OLD"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

FAIL=0
WARN=0
CHANGED=0

ok(){ echo "OK: $*"; }
warn(){ echo "WARN: $*"; WARN=$((WARN+1)); }
fail(){ echo "FAIL: $*"; FAIL=$((FAIL+1)); }
changed(){ echo "FIXED: $*"; CHANGED=$((CHANGED+1)); }

echo "===== VPN MAX REPAIR SAFE ====="
echo "Time: $(date -Is)"
echo

repair_service_if_down() {
  local svc="$1"
  local action="${2:-restart}"

  if systemctl is-active --quiet "$svc"; then
    ok "$svc active"
    return 0
  fi

  echo "REPAIR: $svc is inactive, trying $action..."
  if [ "$action" = "start" ]; then
    systemctl start "$svc" || true
  else
    systemctl restart "$svc" || true
  fi

  sleep 3

  if systemctl is-active --quiet "$svc"; then
    changed "$svc repaired"
  else
    fail "$svc still not active"
  fi
}

echo "[Services]"
repair_service_if_down "wg-quick@wg0" "start"
repair_service_if_down "wg-golden" "restart"
repair_service_if_down "wg-golden-agent" "restart"
repair_service_if_down "pihole-FTL" "restart"
repair_service_if_down "unbound" "restart"

echo
echo "[Dashboard API]"
if curl -fsS --max-time 8 http://127.0.0.1:8888/healthz >/tmp/vpnmax-health.$$ 2>/dev/null; then
  ok "dashboard healthz"
else
  echo "REPAIR: dashboard API failed, restarting wg-golden..."
  systemctl restart wg-golden || true
  sleep 3
  if curl -fsS --max-time 8 http://127.0.0.1:8888/healthz >/tmp/vpnmax-health.$$ 2>/dev/null; then
    changed "dashboard API repaired"
  else
    fail "dashboard API still failed"
  fi
fi
rm -f /tmp/vpnmax-health.$$

echo
echo "[DNS]"
if dig @127.0.0.1 -p 5335 google.com +short >/tmp/vpnmax-unbound.$$ 2>/dev/null && [ -s /tmp/vpnmax-unbound.$$ ]; then
  ok "unbound recursive DNS"
else
  echo "REPAIR: unbound DNS failed, restarting unbound..."
  systemctl restart unbound || true
  sleep 3
  if dig @127.0.0.1 -p 5335 google.com +short >/tmp/vpnmax-unbound.$$ 2>/dev/null && [ -s /tmp/vpnmax-unbound.$$ ]; then
    changed "unbound DNS repaired"
  else
    fail "unbound DNS still failed"
  fi
fi
rm -f /tmp/vpnmax-unbound.$$

if pihole status 2>/dev/null | grep -qi "blocking is enabled"; then
  ok "Pi-hole blocking enabled"
else
  echo "REPAIR: Pi-hole blocking not enabled, enabling..."
  pihole enable >/dev/null 2>&1 || true
  sleep 2
  if pihole status 2>/dev/null | grep -qi "blocking is enabled"; then
    changed "Pi-hole blocking enabled"
  else
    warn "Pi-hole blocking state unclear"
  fi
fi

if dig @127.0.0.1 google.com +short >/tmp/vpnmax-pihole.$$ 2>/dev/null && [ -s /tmp/vpnmax-pihole.$$ ]; then
  ok "Pi-hole DNS google.com"
else
  echo "REPAIR: Pi-hole DNS failed, restarting pihole-FTL..."
  systemctl restart pihole-FTL || true
  pihole restartdns >/dev/null 2>&1 || true
  sleep 3
  if dig @127.0.0.1 google.com +short >/tmp/vpnmax-pihole.$$ 2>/dev/null && [ -s /tmp/vpnmax-pihole.$$ ]; then
    changed "Pi-hole DNS repaired"
  else
    fail "Pi-hole DNS still failed"
  fi
fi
rm -f /tmp/vpnmax-pihole.$$

if dig @127.0.0.1 doubleclick.net +short 2>/dev/null | grep -q '^0\.0\.0\.0$'; then
  ok "Pi-hole block doubleclick.net"
else
  echo "REPAIR: Pi-hole block check failed, restarting DNS..."
  pihole restartdns >/dev/null 2>&1 || true
  sleep 3
  if dig @127.0.0.1 doubleclick.net +short 2>/dev/null | grep -q '^0\.0\.0\.0$'; then
    changed "Pi-hole block repaired"
  else
    warn "Pi-hole block check still not returning 0.0.0.0"
  fi
fi

echo
echo "[Firewall DNS check only]"
if ufw status verbose | grep -q "53/tcp on ens3.*DENY IN" && \
   ufw status verbose | grep -q "53/udp on ens3.*DENY IN" && \
   ufw status verbose | grep -q "53/tcp on wg0.*ALLOW IN" && \
   ufw status verbose | grep -q "53/udp on wg0.*ALLOW IN"; then
  ok "public DNS blocked and VPN DNS allowed"
else
  warn "firewall DNS rule needs manual review; repair-safe does not rewrite UFW"
fi

echo
echo "[Backup folder permissions]"
mkdir -p "$KEEP" "$OLD"
chown -R ubuntu:ubuntu "$KEEP" || true
chmod 700 "$KEEP" "$OLD" || true
find "$KEEP" -maxdepth 1 -type f -exec chmod 600 {} \; 2>/dev/null || true
find "$OLD" -maxdepth 1 -type f -exec chmod 600 {} \; 2>/dev/null || true
ok "backup folder permissions normalized"

echo
echo "[Backup verification]"
if [ -x "$APP_DIR/golden-vpnmax-verify-backup.sh" ]; then
  if "$APP_DIR/golden-vpnmax-verify-backup.sh" >/tmp/vpnmax-verify.$$ 2>&1; then
    ok "latest backup verified"
  else
    cat /tmp/vpnmax-verify.$$ || true
    fail "latest backup verification failed"
  fi
  rm -f /tmp/vpnmax-verify.$$
else
  warn "backup verifier not found"
fi

echo
echo "[Client config checker]"
if [ -x "$APP_DIR/golden-client-config-check.sh" ]; then
  "$APP_DIR/golden-client-config-check.sh" || true
else
  warn "client config checker not found"
fi

echo
echo "[Summary]"
echo "changed: $CHANGED"
echo "warnings: $WARN"
echo "failures: $FAIL"
echo "log: $LOG"

if [ "$FAIL" -eq 0 ]; then
  echo "REPAIR_SAFE_OK"
  exit 0
else
  echo "REPAIR_SAFE_CHECK_NEEDED"
  exit 2
fi
