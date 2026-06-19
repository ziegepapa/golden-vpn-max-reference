#!/usr/bin/env bash
set -Eeuo pipefail

echo "===== Golden VPN Max AIO Installer ====="
echo
echo "Choose action:"
echo
echo "1) Lite install   - WireGuard + Dashboard + Agent + optional Telegram"
echo "2) Full install   - Lite + Pi-hole + Unbound + backup scaffold"
echo "3) Doctor         - run local checks"
echo "4) Uninstall      - remove Golden VPN Max components"
echo "5) Exit"
echo

read -r -p "Select [1-5]: " choice

case "$choice" in
  1)
    echo "Starting Lite installer..."
    if [ ! -f ./install-lite.sh ]; then
      echo "install-lite.sh not found."
      exit 1
    fi
    bash ./install-lite.sh
    ;;

  2)
    echo "Starting Full installer..."
    if [ ! -f ./install-full.sh ]; then
      echo "install-full.sh not found."
      exit 1
    fi
    bash ./install-full.sh
    ;;

  3)
    echo "Running doctor..."
    if [ ! -f ./doctor.sh ]; then
      echo "doctor.sh not found."
      exit 1
    fi
    bash ./doctor.sh
    ;;

  4)
    echo "Starting uninstaller..."
    if [ ! -f ./uninstall.sh ]; then
      echo "uninstall.sh not found."
      exit 1
    fi
    bash ./uninstall.sh
    ;;

  5)
    echo "Exit."
    exit 0
    ;;

  *)
    echo "Invalid choice."
    exit 1
    ;;
esac
