Golden VPN Max — Full Mode

Full Mode is the extended installation path for Golden VPN Max Reference Build.

It starts with the Lite stack, then adds DNS filtering and backup scaffolding.

What Full Mode includes

Full Mode includes everything from Lite Mode:

* WireGuard VPN
* Private dashboard
* Golden VPN agent
* Optional Telegram bot
* Local status helper
* Doctor checker

Then Full Mode adds:

* Pi-hole
* Unbound
* Backup scaffold
* Restore rehearsal scaffold
* Full helper command

Lite vs Full

Lite Mode is best for a simple personal VPN.

Full Mode is best when you also want DNS filtering and a basic backup workflow.

Feature	Lite	Full
WireGuard	yes	yes
Dashboard	yes	yes
Agent	yes	yes
Telegram bot	optional	optional
Pi-hole	no	yes
Unbound	no	yes
Backup scaffold	no	yes
Restore rehearsal scaffold	no	yes
Full helper command	no	yes

How to install Full Mode

Recommended entry point:

sudo bash install.sh

Then choose:

2) Full

Or run Full directly:

sudo bash install-full.sh

Full Mode will ask for confirmation:

Continue with Full install? Type FULL:

Type:

FULL

to continue.

What Full Mode changes

Full Mode may install or modify:

/opt/wg-golden
/etc/wg-golden.env
/etc/wireguard/wg0.conf
/etc/unbound/unbound.conf.d/golden-vpn-max.conf
/usr/local/bin/golden-vpn
/usr/local/bin/golden-vpn-full

It may also create or restart these services:

wg-quick@wg0
wg-golden
wg-golden-agent
wg-golden-telegram
pihole-FTL
unbound

Pi-hole

Pi-hole provides DNS filtering.

Full Mode uses the official Pi-hole installer.

Pi-hole may ask interactive setup questions.

Recommended role:

VPN clients -> Pi-hole -> Unbound -> Internet DNS root recursion

Recommended Pi-hole upstream DNS after Unbound is installed:

127.0.0.1#5335

Unbound

Unbound is installed as a local recursive DNS resolver.

Full Mode creates:

/etc/unbound/unbound.conf.d/golden-vpn-max.conf

Default Unbound listener:

127.0.0.1:5335

Pi-hole should use this as upstream DNS:

127.0.0.1#5335

Backup scaffold

Full Mode creates backup directories:

/opt/wg-golden/backups
/opt/wg-golden/offsite
/opt/wg-golden/restore-rehearsal

It also creates:

/opt/wg-golden/backup-now.sh
/opt/wg-golden/restore-rehearsal.sh

Create a backup:

sudo golden-vpn-full backup-now

Run a restore rehearsal:

sudo golden-vpn-full restore-rehearsal

The backup scaffold is intentionally simple. It is a starting point, not a full enterprise backup system.

Full helper command

Full Mode adds:

sudo golden-vpn-full status
sudo golden-vpn-full backup-now
sudo golden-vpn-full restore-rehearsal
sudo golden-vpn-full logs

Expected Full Mode services

After Full install, check:

systemctl status wg-quick@wg0
systemctl status wg-golden
systemctl status wg-golden-agent
systemctl status pihole-FTL
systemctl status unbound

If Telegram was enabled:

systemctl status wg-golden-telegram

Recommended post-install checks

Run:

sudo golden-vpn status
sudo golden-vpn doctor
sudo golden-vpn-full status

Then test backup:

sudo golden-vpn-full backup-now
sudo golden-vpn-full restore-rehearsal

Security notes

Do not expose the dashboard publicly.

Recommended:

WireGuard UDP port open to clients
Dashboard only reachable over VPN
SSH restricted if possible
Pi-hole reachable only from VPN/private network

Do not publish:

* real WireGuard private keys
* real client configs
* Telegram bot tokens
* backup archives
* environment files

Limitations

Full Mode is experimental.

Current Full Mode is a scaffold. It does not yet provide:

* automatic offsite upload
* automatic encrypted backup rotation
* complete client wizard
* complete Pi-hole policy tuning
* production SLA
* guaranteed compatibility with every VPS image

Use it first on a disposable VPS.

Recommended test order

1. Create fresh VPS
2. Clone repo
3. Run sudo bash install.sh
4. Choose Full
5. Complete Lite questions
6. Complete Pi-hole setup
7. Confirm Unbound is active
8. Set Pi-hole upstream DNS to 127.0.0.1#5335
9. Connect one VPN client
10. Confirm DNS filtering works
11. Run doctor
12. Run backup-now
13. Run restore-rehearsal

When to choose Lite instead

Choose Lite if:

* you only need VPN access
* you do not need Pi-hole
* you want fewer moving parts
* you are testing the project for the first time

Choose Full only when you want VPN plus DNS filtering and backup scaffolding.
