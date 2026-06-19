#!/usr/bin/env bash
set -u

FAIL=0
pass(){ echo "PASS $1"; }
warn(){ echo "WARN $1"; }
fail(){ echo "FAIL $1"; FAIL=1; }

echo "===== GOLDEN VPN DOCTOR ====="
date -Is
echo

echo "1) Services"
for svc in wg-quick@wg0 wg-golden wg-golden-agent; do
  if systemctl is-active --quiet "$svc"; then
    pass "$svc active"
  else
    fail "$svc not active"
  fi
done

if systemctl list-unit-files | grep -q '^wg-golden-telegram.service'; then
  if systemctl is-active --quiet wg-golden-telegram; then
    pass "wg-golden-telegram active"
  else
    warn "wg-golden-telegram not active"
  fi
fi

echo
echo "2) Files"
for f in /etc/wireguard/wg0.conf /etc/wg-golden.env /opt/wg-golden/app_lts.py /opt/wg-golden/agent.py; do
  [ -f "$f" ] && pass "$f exists" || fail "$f missing"
done

echo
echo "3) WireGuard"
if command -v wg >/dev/null 2>&1; then
  wg show wg0 >/tmp/golden-doctor-wg.txt 2>&1 && pass "wg show wg0 OK" || fail "wg show wg0 failed"
else
  fail "wg command missing"
fi

echo
echo "4) Dashboard"
if curl -fsS http://127.0.0.1:8888/healthz >/tmp/golden-doctor-health.txt 2>&1; then
  pass "dashboard health OK"
  cat /tmp/golden-doctor-health.txt
  echo
else
  fail "dashboard health failed"
fi

echo
echo "5) Secret sanity"
if grep -RInE 'CHANGE_ME|YOUR_SERVER_IP' /etc/wg-golden.env /etc/wireguard/wg0.conf 2>/dev/null; then
  warn "placeholder values found"
else
  pass "no obvious placeholders in env/wg config"
fi

echo
if [ "$FAIL" = "0" ]; then
  echo "DOCTOR_PASS"
else
  echo "DOCTOR_FAIL"
fi

exit "$FAIL"
