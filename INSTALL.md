# Golden VPN Max — Installation Guide

This guide explains how to install Golden VPN Max Reference Build using the AIO installer.

Golden VPN Max is a reference self-hosted VPN stack built around WireGuard, a private dashboard, Telegram notifications, and optional Full Mode components such as Pi-hole, Unbound, and backup scaffolding.

## Important warning

Use a fresh Ubuntu/Debian VPS.

Do not run the installer on an existing production VPN server unless you understand what it will change.

The installer may create or modify:

- `/opt/wg-golden`
- `/etc/wg-golden.env`
- `/etc/wireguard/wg0.conf`
- systemd services
- WireGuard service
- Pi-hole and Unbound components in Full Mode

This repository does not include real private keys, tokens, backups, or client configs.

## Supported modes

Golden VPN Max includes three install paths:

### 1. AIO menu

Recommended entry point.

```bash
sudo bash install.sh
