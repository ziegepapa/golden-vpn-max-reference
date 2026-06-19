Golden VPN Max — Operations Guide

This guide explains how to operate a Golden VPN Max installation after setup.

It covers daily commands, service checks, logs, backup, restore rehearsal, WireGuard checks, dashboard access, Telegram checks, and DNS checks for Full Mode.

Main commands

After installation, the main helper command is:

sudo golden-vpn status
sudo golden-vpn doctor
sudo golden-vpn logs

If Full Mode was installed, an additional helper is available:

sudo golden-vpn-full status
sudo golden-vpn-full backup-now
sudo golden-vpn-full restore-rehearsal
sudo golden-vpn-full logs

Daily health check

Run:

sudo golden-vpn status

Then run:

sudo golden-vpn doctor

A healthy system should show:

DOCTOR_PASS

If doctor fails, check the failed section first. Do not patch unrelated parts before understanding the failed check.

Service overview

Core services:

wg-quick@wg0
wg-golden
wg-golden-agent

Optional Telegram service:

wg-golden-telegram

Full Mode services:

pihole-FTL
unbound

Check all core services:

systemctl status wg-quick@wg0
systemctl status wg-golden
systemctl status wg-golden-agent

Check Telegram service:

systemctl status wg-golden-telegram

Check Full Mode services:

systemctl status pihole-FTL
systemctl status unbound

Restart services

Restart WireGuard:

sudo systemctl restart wg-quick@wg0

Restart dashboard:

sudo systemctl restart wg-golden

Restart agent:

sudo systemctl restart wg-golden-agent

Restart Telegram bot:

sudo systemctl restart wg-golden-telegram

Restart Pi-hole:

sudo systemctl restart pihole-FTL

Restart Unbound:

sudo systemctl restart unbound

Logs

Core logs:

sudo journalctl -u wg-golden -n 120 --no-pager
sudo journalctl -u wg-golden-agent -n 120 --no-pager
sudo journalctl -u wg-quick@wg0 -n 120 --no-pager

Telegram logs:

sudo journalctl -u wg-golden-telegram -n 120 --no-pager

Full Mode logs:

sudo journalctl -u pihole-FTL -n 120 --no-pager
sudo journalctl -u unbound -n 120 --no-pager

Combined helper:

sudo golden-vpn logs

Full combined helper:

sudo golden-vpn-full logs

Dashboard access

The dashboard should be accessed over VPN.

Default Lite example:

http://10.99.0.1:8888

Do not expose the dashboard publicly unless you have added your own authentication, firewall restrictions, and reverse proxy hardening.

Check local dashboard health from the server:

curl -fsS http://127.0.0.1:8888/healthz

If dashboard is bound only to the VPN IP, local 127.0.0.1 health may not work depending on the app configuration. In that case, check the VPN IP:

curl -fsS http://10.99.0.1:8888/healthz

Replace 10.99.0.1 with your configured VPN server IP.

WireGuard checks

Show WireGuard status:

sudo wg show

Show specific interface:

sudo wg show wg0

Show interface IP:

ip addr show wg0

Show routes:

ip route

Show listening UDP port:

sudo ss -lunp | grep 51820

Replace 51820 if you used a different WireGuard port.

WireGuard client checks

On the server, check peers:

sudo wg show wg0 peers

Check latest handshakes:

sudo wg show wg0 latest-handshakes

Check transfer counters:

sudo wg show wg0 transfer

A client that has never connected may show no recent handshake.

Firewall checks

Cloud firewall must allow the WireGuard UDP port.

Default:

UDP 51820

If UFW is active, check:

sudo ufw status

Allow WireGuard manually:

sudo ufw allow 51820/udp

Do not publicly allow the dashboard port unless you understand the security impact.

Telegram operation

If Telegram is enabled, check the service:

sudo systemctl status wg-golden-telegram

View logs:

sudo journalctl -u wg-golden-telegram -n 120 --no-pager

Common Telegram checks:

Bot token exists in environment file
Chat ID is correct
Server can reach Telegram API
Service is active

The environment file is usually:

/etc/wg-golden.env

Do not publish this file.

Environment file

Main environment file:

/etc/wg-golden.env

It may contain:

WireGuard interface
WireGuard endpoint
VPN subnet
VPN server IP
Dashboard bind address
Dashboard port
Telegram bot token
Telegram chat ID

Protect this file:

sudo chmod 600 /etc/wg-golden.env

Do not commit it to GitHub.

Backup operation in Full Mode

Create backup:

sudo golden-vpn-full backup-now

Expected output:

BACKUP_CREATED ...
SHA256_CREATED ...

Backup location:

/opt/wg-golden/backups

List backups:

sudo ls -lh /opt/wg-golden/backups

Verify checksum manually:

cd /opt/wg-golden/backups
sha256sum -c *.sha256

If multiple backups exist, check the checksum file for the backup you want to verify.

Restore rehearsal

Run:

sudo golden-vpn-full restore-rehearsal

Expected output:

RESTORE_REHEARSAL_OK

A restore rehearsal checks that the backup archive can be read and extracted into a test directory.

It does not replace a full disaster recovery plan.

Offsite backup recommendation

Full Mode creates an offsite directory:

/opt/wg-golden/offsite

You should copy encrypted backups away from the VPS.

Examples of offsite locations:

Another server
Object storage
Encrypted external drive
Private backup storage

Never rely only on backups stored on the same VPS.

Pi-hole operation in Full Mode

Check Pi-hole service:

sudo systemctl status pihole-FTL

Pi-hole CLI examples:

pihole status
pihole -t
pihole restartdns

Pi-hole admin interface depends on your Pi-hole setup.

Keep Pi-hole reachable only over VPN/private network where possible.

Unbound operation in Full Mode

Check Unbound:

sudo systemctl status unbound

Test Unbound DNS directly:

dig @127.0.0.1 -p 5335 example.com

Expected: DNS answer is returned.

Recommended Pi-hole upstream DNS:

127.0.0.1#5335

DNS test from a VPN client

After connecting a VPN client, test:

nslookup example.com

or:

dig example.com

Confirm the DNS server is your VPN DNS server if you configured DNS through the VPN.

Updating from Git

On the server that contains the repository clone:

cd golden-vpn-max-reference
git pull

Do not blindly rerun installers on an existing production server.

Review changes first:

git log --oneline -5
git diff HEAD~1 HEAD

Safe change workflow

Recommended workflow for changes:

1. Read the change
2. Backup current config
3. Apply one change
4. Restart only the affected service
5. Check status
6. Check logs
7. Run doctor
8. Commit documentation or config changes separately

Avoid changing many unrelated parts at once.

Common maintenance commands

Disk usage:

df -h

Memory:

free -h

Listening ports:

sudo ss -tulpen

System logs:

sudo journalctl -n 200 --no-pager

Recent boot errors:

sudo journalctl -p err -b --no-pager

What not to publish

Do not publish:

/etc/wg-golden.env
/etc/wireguard/wg0.conf
/etc/wireguard/clients/*
/opt/wg-golden/state/*
/opt/wg-golden/backups/*
Telegram bot tokens
WireGuard private keys
real client configs
backup archives

Emergency stop

Stop dashboard:

sudo systemctl stop wg-golden

Stop agent:

sudo systemctl stop wg-golden-agent

Stop Telegram bot:

sudo systemctl stop wg-golden-telegram

Stop WireGuard:

sudo systemctl stop wg-quick@wg0

Warning: stopping WireGuard may disconnect VPN users.

Recovery basics

If dashboard fails:

sudo systemctl status wg-golden
sudo journalctl -u wg-golden -n 120 --no-pager

If WireGuard fails:

sudo wg show
sudo systemctl status wg-quick@wg0
sudo journalctl -u wg-quick@wg0 -n 120 --no-pager

If DNS fails in Full Mode:

sudo systemctl status pihole-FTL
sudo systemctl status unbound
dig @127.0.0.1 -p 5335 example.com

If Telegram fails:

sudo systemctl status wg-golden-telegram
sudo journalctl -u wg-golden-telegram -n 120 --no-pager

Recommended weekly routine

1. Run sudo golden-vpn doctor
2. Check WireGuard peers
3. Check service logs
4. Run backup-now if using Full Mode
5. Run restore-rehearsal if using Full Mode
6. Copy important backup offsite
7. Confirm dashboard is not public

Recommended before major changes

Before changing VPN, dashboard, DNS, or backup logic:

sudo golden-vpn-full backup-now

If Full Mode is not installed, manually back up:

/etc/wireguard
/etc/wg-golden.env
/opt/wg-golden
systemd service files

Then make one change at a time.
