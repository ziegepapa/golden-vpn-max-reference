#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Please run as root:"
  echo "  sudo bash uninstall.sh"
  exit 1
fi

echo "===== Golden VPN Max Uninstaller ====="
echo
echo "This can remove Golden VPN Max services and app files."
echo
echo "WARNING:"
echo "- Stopping WireGuard may disconnect VPN users."
echo "- Removing Pi-hole/Unbound may affect DNS."
echo "- Review before using on production systems."
echo

echo "Choose uninstall mode:"
echo
echo "1) App only       - remove Golden services and /opt/wg-golden"
echo "2) App + WG       - also remove wg0 config and WireGuard service"
echo "3) Full cleanup   - also try to remove Pi-hole/Unbound packages"
echo "4) Exit"
echo

read -r -p "Select [1-4]: " choice

case "$choice" in
  1|2|3) ;;
  4)
    echo "Exit."
    exit 0
    ;;
  *)
    echo "Invalid choice."
    exit 1
    ;;
esac

echo
read -r -p "Type DELETE to continue: " confirm

if [ "$confirm" != "DELETE" ]; then
  echo "Canceled."
  exit 1
fi

echo
echo "Stopping Golden services..."
systemctl disable --now wg-golden 2>/dev/null || true
systemctl disable --now wg-golden-agent 2>/dev/null || true
systemctl disable --now wg-golden-telegram 2>/dev/null || true

echo "Removing Golden systemd services..."
rm -f /etc/systemd/system/wg-golden.service
rm -f /etc/systemd/system/wg-golden-agent.service
rm -f /etc/systemd/system/wg-golden-telegram.service
systemctl daemon-reload

echo "Removing Golden app files..."
rm -rf /opt/wg-golden
rm -f /etc/wg-golden.env
rm -f /usr/local/bin/golden-vpn
rm -f /usr/local/bin/golden-vpn-full

if [ "$choice" = "2" ] || [ "$choice" = "3" ]; then
  echo
  echo "Stopping WireGuard wg0..."
  systemctl disable --now wg-quick@wg0 2>/dev/null || true

  echo "Removing WireGuard wg0 config and generated clients..."
  rm -f /etc/wireguard/wg0.conf
  rm -rf /etc/wireguard/clients
fi

if [ "$choice" = "3" ]; then
  echo
  echo "Stopping Pi-hole and Unbound..."
  systemctl disable --now pihole-FTL 2>/dev/null || true
  systemctl disable --now unbound 2>/dev/null || true

  echo "Removing Unbound Golden config..."
  rm -f /etc/unbound/unbound.conf.d/golden-vpn-max.conf

  echo
  echo "Pi-hole removal is intentionally not forced here."
  echo "If you want to remove Pi-hole completely, run:"
  echo "  sudo pihole uninstall"
  echo
  echo "Unbound package can be removed manually with:"
  echo "  sudo apt-get remove --purge unbound"
fi

echo
echo "UNINSTALL_DONE"
