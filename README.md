# Golden VPN Max — Reference Build

Personal reference build for a self-hosted VPN stack:

- WireGuard VPN
- Private dashboard
- Telegram bot notifications
- Pi-hole DNS filtering concept
- Health checks
- Backup / restore rehearsal concept
- Offsite encrypted backup concept

This repository is for learning/reference use.

No production keys, tokens, backups, or client configs are included.

## Quick Install — Lite Mode

Experimental Lite installer:

```bash
git clone https://github.com/ziegepapa/golden-vpn-max-reference.git
cd golden-vpn-max-reference
sudo bash install.sh
```

Lite mode currently targets:

- WireGuard
- Golden VPN dashboard
- Golden VPN agent
- Optional Telegram bot
- Local status/doctor helper

Full Pi-hole, Unbound, offsite encrypted backup, and restore rehearsal are not included in Lite mode yet.

## Check installation

```bash
sudo golden-vpn status
sudo golden-vpn doctor
sudo golden-vpn logs
```

## Important

This is not a managed service and not a guaranteed production installer.

Review the scripts before running them. You are responsible for server security, firewall rules, WireGuard keys, client configs, backups, and restore testing.

See:

- `SECURITY.md`
- `DISCLAIMER.md`
- `INSTALL.md`
