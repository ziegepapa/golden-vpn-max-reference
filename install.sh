#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="Golden VPN Max"
INSTALL_DIR="/opt/wg-golden"
ENV_FILE="/etc/wg-golden.env"
WG_IF="wg0"

if [ "${1:-}" = "--help" ]; then
  echo "Golden VPN Max Lite Installer"
  echo
  echo "Usage:"
  echo "  sudo bash install.sh"
  echo
  echo "Installs:"
  echo "  - WireGuard"
  echo "  - Golden VPN dashboard"
  echo "  - Agent"
  echo "  - Optional Telegram bot"
  echo
  echo "Pi-hole/Unbound/full offsite backup are not included in Lite mode."
  exit 0
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "Please run as root:"
  echo "  sudo bash install.sh"
  exit 1
fi

if [ ! -f "app/app_lts.py" ] || [ ! -f "app/agent.py" ]; then
  echo "Please run this installer from the repository root."
  exit 1
fi

ask() {
  local prompt="$1"
  local default="$2"
  local value
  read -r -p "$prompt [$default]: " value
  echo "${value:-$default}"
}

yesno() {
  local prompt="$1"
  local default="$2"
  local value
  read -r -p "$prompt [$default]: " value
  value="${value:-$default}"
  case "$value" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

detect_public_ip() {
  curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || echo "YOUR_SERVER_IP"
}

echo "===== $APP_NAME Lite Installer ====="
echo
echo "Lite mode installs WireGuard, dashboard, agent, optional Telegram."
echo "Use this on a fresh Ubuntu/Debian VPS."
echo

DEFAULT_ENDPOINT="$(detect_public_ip)"
WG_ENDPOINT_HOST="$(ask "WireGuard endpoint domain/IP" "$DEFAULT_ENDPOINT")"
WG_PORT="$(ask "WireGuard UDP port" "51820")"
VPN_SUBNET="$(ask "VPN subnet CIDR" "10.99.0.0/24")"
WG_SERVER_IP="$(ask "VPN server IP" "10.99.0.1")"
DASHBOARD_BIND="$(ask "Dashboard bind IP" "$WG_SERVER_IP")"
DASHBOARD_PORT="$(ask "Dashboard port" "8888")"

TELEGRAM_ENABLED="no"
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

if yesno "Enable Telegram bot?" "no"; then
  TELEGRAM_ENABLED="yes"
  read -r -p "Telegram bot token: " TELEGRAM_BOT_TOKEN
  read -r -p "Telegram chat ID: " TELEGRAM_CHAT_ID
fi

echo
echo "Installing packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  wireguard wireguard-tools \
  python3 python3-flask python3-requests \
  curl jq qrencode iptables iproute2

echo
echo "Creating directories..."
install -d -m 700 "$INSTALL_DIR"
install -d -m 700 /etc/wireguard
install -d -m 700 /etc/wireguard/clients
install -d -m 700 "$INSTALL_DIR/state"

echo
echo "Copying files..."
install -m 755 app/app_lts.py "$INSTALL_DIR/app_lts.py"
install -m 755 app/agent.py "$INSTALL_DIR/agent.py"
install -m 755 app/telegram_agent.py "$INSTALL_DIR/telegram_agent.py"
install -m 755 scripts/golden-vpnmax.sh "$INSTALL_DIR/golden-vpnmax.sh"
install -m 755 scripts/golden-vpnmax-repair-safe.sh "$INSTALL_DIR/golden-vpnmax-repair-safe.sh"

if [ -f doctor.sh ]; then
  install -m 755 doctor.sh "$INSTALL_DIR/doctor.sh"
fi

echo
echo "Writing env file..."
cat > "$ENV_FILE" <<EOF_ENV
WG_INTERFACE="$WG_IF"
WG_ENDPOINT="$WG_ENDPOINT_HOST:$WG_PORT"
WG_VPN_NET="$VPN_SUBNET"
WG_SERVER_IP="$WG_SERVER_IP"
WG_PORT="$WG_PORT"
DASHBOARD_BIND="$DASHBOARD_BIND"
DASHBOARD_PORT="$DASHBOARD_PORT"
TELEGRAM_ENABLED="$TELEGRAM_ENABLED"
TELEGRAM_BOT_TOKEN="$TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID"
EOF_ENV
chmod 600 "$ENV_FILE"

echo
echo "Creating WireGuard config..."
if [ -f "/etc/wireguard/$WG_IF.conf" ]; then
  echo "Existing /etc/wireguard/$WG_IF.conf found. Keeping existing config."
else
  SERVER_PRIV="$(wg genkey)"
  SERVER_PUB="$(printf '%s' "$SERVER_PRIV" | wg pubkey)"
  OUT_IF="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
  OUT_IF="${OUT_IF:-eth0}"

  cat > "/etc/wireguard/$WG_IF.conf" <<EOF_WG
[Interface]
Address = $WG_SERVER_IP/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV

PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null; iptables -A FORWARD -i $WG_IF -j ACCEPT; iptables -A FORWARD -o $WG_IF -j ACCEPT; iptables -t nat -A POSTROUTING -o $OUT_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_IF -j ACCEPT; iptables -D FORWARD -o $WG_IF -j ACCEPT; iptables -t nat -D POSTROUTING -o $OUT_IF -j MASQUERADE

# ServerPublicKey = $SERVER_PUB
EOF_WG
  chmod 600 "/etc/wireguard/$WG_IF.conf"
fi

echo
echo "Creating systemd services..."
cat > /etc/systemd/system/wg-golden.service <<EOF_SVC
[Unit]
Description=Golden VPN Max Dashboard
After=network-online.target wg-quick@$WG_IF.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=$ENV_FILE
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app_lts.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF_SVC

cat > /etc/systemd/system/wg-golden-agent.service <<EOF_SVC
[Unit]
Description=Golden VPN Max Agent
After=network-online.target wg-quick@$WG_IF.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=$ENV_FILE
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF_SVC

cat > /etc/systemd/system/wg-golden-telegram.service <<EOF_SVC
[Unit]
Description=Golden VPN Max Telegram Bot
After=network-online.target wg-quick@$WG_IF.service wg-golden.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=$ENV_FILE
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/telegram_agent.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF_SVC

echo
echo "Creating helper command..."
cat > /usr/local/bin/golden-vpn <<'EOF_BIN'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-status}" in
  status)
    systemctl --no-pager --plain status wg-quick@wg0 wg-golden wg-golden-agent 2>/dev/null || true
    curl -fsS http://127.0.0.1:8888/healthz 2>/dev/null || true
    echo
    ;;
  doctor)
    if [ -x /opt/wg-golden/doctor.sh ]; then
      bash /opt/wg-golden/doctor.sh
    else
      echo "doctor.sh not installed"
      exit 1
    fi
    ;;
  logs)
    journalctl -u wg-golden -u wg-golden-agent -u wg-golden-telegram -n 120 --no-pager
    ;;
  *)
    echo "Usage: golden-vpn {status|doctor|logs}"
    exit 1
    ;;
esac
EOF_BIN
chmod +x /usr/local/bin/golden-vpn

echo
echo "Starting services..."
systemctl daemon-reload
systemctl enable "wg-quick@$WG_IF" wg-golden wg-golden-agent
systemctl restart "wg-quick@$WG_IF"
systemctl restart wg-golden
systemctl restart wg-golden-agent

if [ "$TELEGRAM_ENABLED" = "yes" ]; then
  systemctl enable wg-golden-telegram
  systemctl restart wg-golden-telegram
fi

echo
echo "Opening WireGuard port if UFW is active..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then
  ufw allow "$WG_PORT"/udp || true
fi

echo
echo "===== INSTALL COMPLETE ====="
echo "WireGuard endpoint: $WG_ENDPOINT_HOST:$WG_PORT"
echo "Dashboard inside VPN: http://$DASHBOARD_BIND:$DASHBOARD_PORT"
echo
echo "Commands:"
echo "  sudo golden-vpn status"
echo "  sudo golden-vpn doctor"
echo "  sudo golden-vpn logs"
