#!/usr/bin/env bash
set -Eeuo pipefail

echo "===== Golden VPN Max AIO Installer ====="
echo
echo "Choose install mode:"
echo
echo "1) Lite  - WireGuard + Dashboard + Agent + optional Telegram"
echo "2) Full  - Lite + Pi-hole + Unbound + backup scaffold"
echo "3) Doctor"
echo "4) Exit"
echo

read -r -p "Select [1-4]: " choice

case "$choice" in
  1)
    echo "Starting Lite installer..."
    bash ./install-lite.sh
    ;;
  2)
    echo "Starting Full installer..."
    if [ ! -f ./install-full.sh ]; then
      echo "install-full.sh is not available yet."
      echo "Full mode will be added in the next release."
      exit 1
    fi
    bash ./install-full.sh
    ;;
  3)
    echo "Running doctor..."
    bash ./doctor.sh
    ;;
  4)
    echo "Exit."
    exit 0
    ;;
  *)
    echo "Invalid choice."
    exit 1
    ;;
esac
