Golden VPN Max — Troubleshooting Guide

This guide lists common problems and safe ways to debug a Golden VPN Max installation.

The recommended rule is:

Do not patch many things at once.
Find the failing layer first.
Fix one layer.
Restart only the affected service.
Check again.

Quick triage

Start with:

sudo golden-vpn status
sudo golden-vpn doctor
sudo golden-vpn logs

For Full Mode:

sudo golden-vpn-full status
sudo golden-vpn-full logs

Check Git repository status if you are editing the reference repo:

git status --short

Common shell mistakes

Problem: terminal shows >

Example:

>

This usually means a heredoc or quote was not closed.

Common cause:

cat > README.md <<'EOF'

but EOF was never entered.

Fix:

Ctrl + C

Then check repo state:

cd /path/to/repo
git status --short

If a file was partially written, open it with nano and fix it:

nano README.md

Problem: fatal: not a git repository

Example:

fatal: not a git repository (or any of the parent directories): .git

You are in the wrong directory.

Fix:

cd /home/ubuntu/golden-vpn-max-reference
git status --short

Problem: accidentally created wrong filename

Example:

install.s

Check files:

ls -l install.s install.sh

Preview:

sed -n '1,80p' install.s

If it is correct, move it:

mv install.s install.sh
chmod +x install.sh
bash -n install.sh

Installer problems

Problem: installer says run as root

Example:

Please run as root

Fix:

sudo bash install.sh

or direct mode:

sudo bash install-lite.sh
sudo bash install-full.sh

Problem: installer says run from repository root

Example:

Please run this installer from the repository root.

Fix:

cd golden-vpn-max-reference
sudo bash install.sh

Check required files:

ls -l app/app_lts.py app/agent.py install.sh install-lite.sh

Problem: package install fails

Run:

sudo apt-get update
sudo apt-get install -f

Then retry the installer.

Check network:

ping -c 3 1.1.1.1
curl -I https://github.com

WireGuard problems

Problem: WireGuard service not active

Check:

systemctl status wg-quick@wg0
journalctl -u wg-quick@wg0 -n 120 --no-pager

Check config syntax manually:

sudo wg-quick strip wg0

Check file exists:

sudo ls -l /etc/wireguard/wg0.conf

Check permissions:

sudo chmod 600 /etc/wireguard/wg0.conf

Restart:

sudo systemctl restart wg-quick@wg0

Problem: client cannot connect

Check server:

sudo wg show wg0
sudo ss -lunp | grep 51820

Check cloud firewall:

UDP 51820 must be open.

Check UFW:

sudo ufw status
sudo ufw allow 51820/udp

Check client config:

Endpoint must be correct.
Server public key must be correct.
Client private key must match client public key on server.
AllowedIPs must be correct.
PersistentKeepalive should usually be 25 for mobile/NAT clients.

Problem: no handshake

Check latest handshakes:

sudo wg show wg0 latest-handshakes

If handshake is empty:

1. Check endpoint domain/IP.
2. Check UDP port.
3. Check cloud firewall.
4. Check server peer public key.
5. Check client private key.
6. Check client network connection.

Problem: handshake exists but no internet

Check forwarding:

sysctl net.ipv4.ip_forward

Expected:

net.ipv4.ip_forward = 1

Enable temporarily:

sudo sysctl -w net.ipv4.ip_forward=1

Check NAT rules:

sudo iptables -t nat -S
sudo iptables -S FORWARD

Restart WireGuard:

sudo systemctl restart wg-quick@wg0

Dashboard problems

Problem: dashboard service not active

Check:

systemctl status wg-golden
journalctl -u wg-golden -n 120 --no-pager

Restart:

sudo systemctl restart wg-golden

Problem: dashboard health check fails

Try localhost:

curl -fsS http://127.0.0.1:8888/healthz

Try VPN server IP:

curl -fsS http://10.99.0.1:8888/healthz

Replace 10.99.0.1 with your configured VPN server IP.

Check bind and port in:

sudo cat /etc/wg-golden.env

Do not publish this file.

Problem: dashboard works on server but not from client

Check:

1. Client is connected to VPN.
2. Client can ping VPN server IP.
3. Dashboard binds to VPN IP or appropriate interface.
4. Firewall does not block dashboard port over VPN.

Useful commands:

ip addr show wg0
sudo ss -tulpen | grep 8888

Agent problems

Problem: agent service not active

Check:

systemctl status wg-golden-agent
journalctl -u wg-golden-agent -n 120 --no-pager

Restart:

sudo systemctl restart wg-golden-agent

Problem: agent reports wrong state

Check state files:

sudo ls -lh /opt/wg-golden/state

Check logs:

sudo journalctl -u wg-golden-agent -n 200 --no-pager

Do not delete state files unless you know what they contain.

Telegram problems

Problem: Telegram bot not responding

Check service:

systemctl status wg-golden-telegram
journalctl -u wg-golden-telegram -n 120 --no-pager

Check environment:

sudo grep -E 'TELEGRAM_ENABLED|TELEGRAM_CHAT_ID' /etc/wg-golden.env

Do not print or publish the bot token.

Restart:

sudo systemctl restart wg-golden-telegram

Problem: wrong chat ID

Recheck your Telegram chat ID.

Then update:

sudo nano /etc/wg-golden.env
sudo systemctl restart wg-golden-telegram

Problem: token leaked

Immediately revoke the token in BotFather and create a new one.

Then update:

sudo nano /etc/wg-golden.env
sudo systemctl restart wg-golden-telegram

DNS problems in Full Mode

Problem: Pi-hole not active

Check:

systemctl status pihole-FTL
journalctl -u pihole-FTL -n 120 --no-pager

Restart DNS:

sudo pihole restartdns

or:

sudo systemctl restart pihole-FTL

Problem: Unbound not active

Check:

systemctl status unbound
journalctl -u unbound -n 120 --no-pager

Check config:

sudo unbound-checkconf

Restart:

sudo systemctl restart unbound

Problem: Pi-hole cannot resolve through Unbound

Test Unbound directly:

dig @127.0.0.1 -p 5335 example.com

If this fails, fix Unbound first.

If this works, check Pi-hole upstream DNS:

127.0.0.1#5335

Problem: VPN client DNS does not filter

Check client config:

DNS should point to the VPN DNS server.

Example:

DNS = 10.99.0.1

Check client is using VPN DNS:

nslookup example.com

or:

dig example.com

Backup problems

Problem: backup command missing

Full Mode should create:

/usr/local/bin/golden-vpn-full
/opt/wg-golden/backup-now.sh

Check:

ls -l /usr/local/bin/golden-vpn-full
sudo ls -l /opt/wg-golden/backup-now.sh

Problem: backup fails

Run directly:

sudo bash /opt/wg-golden/backup-now.sh

Check warnings:

sudo cat /tmp/golden-backup-warnings.log

Check disk space:

df -h

Check backup directory:

sudo ls -lh /opt/wg-golden/backups

Problem: restore rehearsal fails

Run:

sudo golden-vpn-full restore-rehearsal

If no backup found:

sudo golden-vpn-full backup-now
sudo golden-vpn-full restore-rehearsal

Check archive manually:

sudo tar -tzf /opt/wg-golden/backups/YOUR_BACKUP_FILE.tgz

GitHub / repo problems

Problem: push asks for username and password

GitHub HTTPS push requires a token, not your account password.

Use a Personal Access Token.

After pushing, revoke the token if you do not need it anymore.

Problem: accidental secret committed

Do not continue pushing.

Immediate steps:

1. Revoke leaked token/key.
2. Remove secret from current files.
3. Rotate affected credentials.
4. Consider cleaning Git history if needed.

Search:

grep -RInE 'PRIVATE|TOKEN|SECRET|BEGIN .*PRIVATE' . --exclude-dir=.git

Port checks

List listening ports:

sudo ss -tulpen

Check WireGuard UDP:

sudo ss -lunp | grep 51820

Check dashboard:

sudo ss -tulpen | grep 8888

Check Unbound:

sudo ss -tulpen | grep 5335

Check Pi-hole DNS:

sudo ss -tulpen | grep ':53'

Logs checklist

Core:

sudo journalctl -u wg-quick@wg0 -n 120 --no-pager
sudo journalctl -u wg-golden -n 120 --no-pager
sudo journalctl -u wg-golden-agent -n 120 --no-pager

Telegram:

sudo journalctl -u wg-golden-telegram -n 120 --no-pager

Full Mode:

sudo journalctl -u pihole-FTL -n 120 --no-pager
sudo journalctl -u unbound -n 120 --no-pager

System errors:

sudo journalctl -p err -b --no-pager

Safe rollback mindset

Before changing production-like systems:

1. Take backup.
2. Change one file.
3. Restart one service.
4. Check status.
5. Check logs.
6. Run doctor.

Avoid this:

Patch dashboard, WireGuard, DNS, Telegram, backup all at once.

If a patch fails, restore the previous file and re-check before continuing.

Emergency commands

Stop dashboard:

sudo systemctl stop wg-golden

Stop agent:

sudo systemctl stop wg-golden-agent

Stop Telegram:

sudo systemctl stop wg-golden-telegram

Stop WireGuard:

sudo systemctl stop wg-quick@wg0

Warning: stopping WireGuard may disconnect VPN clients.

When to rebuild from scratch

For a test VPS, rebuilding is often faster than debugging.

Rebuild when:

Fresh test install failed badly.
Multiple unrelated services are broken.
You do not need to preserve clients or state.
You are still evaluating the project.

Do not rebuild a real production server unless you have verified backups and restore steps.
