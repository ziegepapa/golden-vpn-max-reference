#!/usr/bin/env python3
# GOLDEN_LTS_2026

import os, re, json, time, shutil, subprocess, ipaddress
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, Response, send_file, render_template, session

APP = Path("/opt/wg-golden")
STATE = APP / "state"
CLIENTS = Path("/etc/wireguard/clients")
DELETED = CLIENTS / "deleted"
BACKUPS = APP / "backups" / "lts"
ENV = Path("/etc/wg-golden.env")
DB = STATE / "lts_state.json"
AUDIT = STATE / "audit.jsonl"

for d in [STATE, CLIENTS, DELETED, BACKUPS]:
    d.mkdir(parents=True, exist_ok=True)

def load_env():
    if ENV.exists():
        for raw in ENV.read_text(errors="ignore").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

load_env()

WG = os.environ.get("WG_INTERFACE", "wg0")
WGCONF = os.environ.get("WG_CONF", "/etc/wireguard/wg0.conf")
VPNNET = os.environ.get("WG_VPN_NET", "10.99.0.0/24")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8888"))

SECRET = STATE / "lts_secret.key"
if not SECRET.exists():
    SECRET.write_text(os.urandom(32).hex())
    SECRET.chmod(0o600)

app = Flask(__name__)

# ===== GOLDEN_DNS_SINGLE_FINAL_CLEANER_2026 =====
@app.after_request
def golden_dns_single_final_cleaner_2026(resp):
    """
    Final WireGuard config cleaner.
    Registered immediately after app creation, so Flask runs it last.
    It guarantees downloaded/API config text has exactly one DNS line:
    DNS = <VPN_SERVER_IP>
    """
    try:
        import re as _dns_re
        import json as _dns_json

        def _clean_text(text):
            if not isinstance(text, str):
                return text

            marker_hit = (
                "PrivateKey" in text and
                "PublicKey" in text and
                ("[Interface]" in text or "Interface]" in text) and
                ("[Peer]" in text or "Peer]" in text)
            )
            if not marker_hit:
                return text

            t = text.replace("\r\n", "\n").replace("\r", "\n")
            t = _dns_re.sub(r"(?m)^Interface\]", "[Interface]", t)
            t = _dns_re.sub(r"(?m)^Peer\]", "[Peer]", t)

            lines = t.splitlines()
            out = []
            inserted = False

            for line in lines:
                if _dns_re.match(r"^\s*DNS\s*=", line):
                    continue
                out.append(line)
                if not inserted and _dns_re.match(r"^\s*Address\s*=", line):
                    out.append("DNS = <VPN_SERVER_IP>")
                    inserted = True

            if not inserted:
                # Fallback: insert after [Interface] if Address was not found.
                final = []
                inserted2 = False
                for line in out:
                    final.append(line)
                    if not inserted2 and line.strip() == "[Interface]":
                        final.append("DNS = <VPN_SERVER_IP>")
                        inserted2 = True
                out = final

            t = "\n".join(out).strip() + "\n"
            t = _dns_re.sub(r"\n{3,}", "\n\n", t)
            return t

        def _walk(obj):
            if isinstance(obj, dict):
                return {k: _walk(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_walk(x) for x in obj]
            if isinstance(obj, str):
                return _clean_text(obj)
            return obj

        data = resp.get_data(as_text=True)

        if not data or "PrivateKey" not in data:
            return resp

        ctype = resp.content_type or ""

        if "application/json" in ctype:
            obj = _dns_json.loads(data)
            obj = _walk(obj)
            new = _dns_json.dumps(obj, ensure_ascii=False)
        else:
            new = _clean_text(data)

        if new != data:
            resp.set_data(new)
            resp.headers["Content-Length"] = str(len(new.encode("utf-8")))
    except Exception:
        pass

    return resp
# ===== END GOLDEN_DNS_SINGLE_FINAL_CLEANER_2026 =====


app.secret_key = SECRET.read_text().strip()

def now():
    return datetime.now().isoformat(timespec="seconds")

def sh(cmd, input_text=None, timeout=10):
    return subprocess.check_output(
        list(cmd), input=input_text, text=True,
        stderr=subprocess.STDOUT, timeout=timeout
    ).strip()

def read(path):
    return Path(path).read_text(errors="ignore")

def write(path, text):
    Path(path).write_text(text.rstrip() + "\n")

def jload(path, default):
    try:
        d = json.loads(Path(path).read_text())
        return d if isinstance(d, dict) else default
    except Exception:
        return default

def jsave(path, data):
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    tmp.replace(path)

def db():
    d = jload(DB, {})
    for k in ["disabled", "exposed", "expiry", "trusted", "mutes", "peer_names"]:
        d.setdefault(k, {})
    return d

def save_db(d):
    jsave(DB, d)

def audit(action, target="", detail="", extra=None, severity="info"):
    item = {
        "ts": int(time.time()),
        "time": now(),
        "severity": severity,
        "action": action,
        "target": target,
        "detail": detail,
        "remote": getattr(request, "remote_addr", "") if request else "system",
        "extra": extra or {},
    }
    with AUDIT.open("a") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

def audit_tail(n=120):
    try:
        out = []
        for line in AUDIT.read_text(errors="ignore").splitlines()[-int(n):]:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return list(reversed(out))
    except Exception:
        return []

def safe_name(name):
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(name or "").strip()).strip(".-_")
    if not name:
        raise ValueError("Name required")
    if len(name) > 48:
        raise ValueError("Name too long")
    return name

def human_bytes(n):
    try:
        n = float(n)
    except Exception:
        n = 0
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{int(n)} {units[i]}" if i == 0 else f"{n:.2f} {units[i]}"

def human_age(ts):
    try:
        ts = int(ts)
    except Exception:
        ts = 0
    if ts <= 0:
        return "Never"
    diff = max(0, int(time.time()) - ts)
    if diff < 60:
        return f"{diff}s"
    if diff < 3600:
        return f"{diff // 60}m"
    if diff < 86400:
        return f"{diff // 3600}h"
    return f"{diff // 86400}d"

def wgconf():
    return read(WGCONF)

def backup_wg(reason):
    f = BACKUPS / f"wg0.conf.{reason}.{time.strftime('%Y-%m-%d_%H%M%S')}"
    f.write_text(wgconf())
    f.chmod(0o600)
    return str(f)

def endpoint_host():
    h = os.environ.get("WG_PUBLIC_HOST", "vpn.example.com").strip() or "vpn.example.com"
    h = re.sub(r"^https?://", "", h).strip("/")
    if h.count(":") == 1 and h.rsplit(":", 1)[1].isdigit():
        h = h.rsplit(":", 1)[0]
    return h

def listen_port():
    try:
        return sh(["wg", "show", WG, "listen-port"], timeout=5)
    except Exception:
        m = re.search(r"(?im)^\s*ListenPort\s*=\s*(\d+)", wgconf())
        return m.group(1) if m else "51820"

def server_public_key():
    return sh(["wg", "show", WG, "public-key"], timeout=5)

def server_net4():
    m = re.search(r"(?im)^\s*Address\s*=\s*(.+)", wgconf())
    if m:
        for part in m.group(1).split(","):
            try:
                i = ipaddress.ip_interface(part.strip())
                if i.version == 4:
                    return i.network
            except Exception:
                pass
    return ipaddress.ip_network(VPNNET, strict=False)

def clean_deleted_name(path):
    name = path.stem
    name = re.sub(r"\.rotated\.\d{4}-\d{2}-\d{2}_\d{6}$", "", name)
    name = re.sub(r"\.\d{4}-\d{2}-\d{2}_\d{6}$", "", name)
    return name

def pub_from_client_file(path):
    raw = Path(path).read_text(errors="ignore")
    m = re.search(r"(?im)^\s*PrivateKey\s*=\s*(\S+)", raw)
    if not m:
        return ""
    return sh(["wg", "pubkey"], input_text=m.group(1), timeout=5)

def peer_name_map():
    d = db()
    names = dict(d.get("peer_names", {}))

    cur = None
    try:
        for line in wgconf().splitlines():
            m = re.match(r"\s*#+\s*Client:\s*(.+)", line, re.I)
            if m:
                cur = m.group(1).strip()
                continue
            m = re.match(r"\s*PublicKey\s*=\s*(\S+)", line, re.I)
            if m and cur:
                names.setdefault(m.group(1).strip(), cur)
                cur = None
    except Exception:
        pass

    for base in [CLIENTS, DELETED]:
        try:
            files = sorted(base.glob("*.conf"), key=lambda x: x.stat().st_mtime, reverse=True)
            for f in files:
                try:
                    pub = pub_from_client_file(f)
                    name = f.stem if base == CLIENTS else clean_deleted_name(f)
                    if pub and name and not name.lower().startswith("test"):
                        names.setdefault(pub, name)
                except Exception:
                    pass
        except Exception:
            pass

    return names

def used_ips():
    used = set()
    for m in re.finditer(r"(?im)^\s*AllowedIPs\s*=\s*(.+)", wgconf()):
        for part in m.group(1).split(","):
            try:
                i = ipaddress.ip_interface(part.strip())
                if i.version == 4:
                    used.add(str(i.ip))
            except Exception:
                pass
    m = re.search(r"(?im)^\s*Address\s*=\s*(.+)", wgconf())
    if m:
        for part in m.group(1).split(","):
            try:
                i = ipaddress.ip_interface(part.strip())
                if i.version == 4:
                    used.add(str(i.ip))
            except Exception:
                pass
    for f in CLIENTS.glob("*.conf"):
        try:
            m = re.search(r"(?im)^\s*Address\s*=\s*([^,\n]+)", f.read_text(errors="ignore"))
            if m:
                used.add(str(ipaddress.ip_interface(m.group(1).strip()).ip))
        except Exception:
            pass
    return used

def next_ip():
    used = used_ips()
    for ip in server_net4().hosts():
        if str(ip) not in used:
            return str(ip)
    raise RuntimeError("No free IP")

def gen_keys():
    priv = sh(["wg", "genkey"], timeout=5)
    pub = sh(["wg", "pubkey"], input_text=priv, timeout=5)
    psk = sh(["wg", "genpsk"], timeout=5)
    return priv, pub, psk

def cpath(name):
    return CLIENTS / f"{safe_name(name)}.conf"

def qpath(name):
    return CLIENTS / f"{safe_name(name)}.png"

def make_qr(name):
    try:
        if not cpath(name).exists():
            return False
        subprocess.run(
            ["qrencode", "-t", "PNG", "-o", str(qpath(name))],
            input=cpath(name).read_text(errors="ignore"),
            text=True, timeout=8, check=True
        )
        qpath(name).chmod(0o600)
        return True
    except Exception:
        return False

def parse_client(name_or_path):
    if isinstance(name_or_path, Path):
        path = name_or_path
        name = path.stem
    else:
        name = safe_name(name_or_path)
        path = cpath(name)

    if not path.exists():
        raise FileNotFoundError(str(path))

    raw = path.read_text(errors="ignore")
    priv = re.search(r"(?im)^\s*PrivateKey\s*=\s*(\S+)", raw)
    psk = re.search(r"(?im)^\s*PresharedKey\s*=\s*(\S+)", raw)
    addr = re.search(r"(?im)^\s*Address\s*=\s*([^,\n]+)", raw)
    allowed = re.search(r"(?im)^\s*AllowedIPs\s*=\s*(.+)", raw)
    endpoint = re.search(r"(?im)^\s*Endpoint\s*=\s*(.+)", raw)

    if not priv or not psk or not addr:
        raise RuntimeError("Invalid client config")

    pub = sh(["wg", "pubkey"], input_text=priv.group(1), timeout=5)
    ip = str(ipaddress.ip_interface(addr.group(1).strip()).ip)
    mode = "full" if allowed and "0.0.0.0/0" in allowed.group(1) else "split"
    D = db()
    exp = int(D.get("expiry", {}).get(name, 0) or 0)

    return {
        "name": name,
        "ip": ip,
        "public_key": pub,
        "psk": psk.group(1),
        "mode": mode,
        "endpoint": endpoint.group(1).strip() if endpoint else "",
        "expires_at": exp,
        "expired": bool(exp and exp <= int(time.time())),
        "disabled": bool(D.get("disabled", {}).get(name)),
        "exposed": bool(D.get("exposed", {}).get(name)),
        "conf_url": f"/client/{name}.conf",
        "qr_url": f"/client/{name}.png" if qpath(name).exists() else "",
    }

def expiry_ts(value):
    v = str(value or "").strip().lower()
    if v in ["", "forever", "never", "none"]:
        return 0
    m = re.match(r"^(\d+)(m|h|d)?$", v)
    if not m:
        raise ValueError("Invalid expiry")
    n = int(m.group(1))
    u = m.group(2) or "d"
    return int(time.time()) + (n * 60 if u == "m" else n * 3600 if u == "h" else n * 86400)

def expiry_label(ts):
    ts = int(ts or 0)
    if not ts:
        return "forever"
    diff = ts - int(time.time())
    if diff <= 0:
        return "expired"
    if diff >= 86400:
        return f"{diff // 86400}d"
    if diff >= 3600:
        return f"{diff // 3600}h"
    return f"{max(1, diff // 60)}m"

def remove_peer_block(pub):
    blocks = re.split(r"(?m)(?=^\[Peer\]\s*$)", wgconf())
    kept = []
    removed = False
    for b in blocks:
        if "[Peer]" in b and re.search(r"(?im)^\s*PublicKey\s*=\s*" + re.escape(pub) + r"\s*$", b):
            removed = True
            continue
        kept.append(b)
    write(WGCONF, "".join(kept))
    return removed

def append_peer(name, pub, psk, ip):
    write(WGCONF, wgconf().rstrip() + f"""

### Client: {name}
[Peer]
PublicKey = {pub}
PresharedKey = {psk}
AllowedIPs = {ip}/32
""")

def live_add(pub, psk, ip):
    sh(["wg", "set", WG, "peer", pub, "preshared-key", "/dev/stdin", "allowed-ips", f"{ip}/32"], input_text=psk + "\n", timeout=8)

def live_remove(pub):
    try:
        sh(["wg", "set", WG, "peer", pub, "remove"], timeout=8)
    except Exception:
        pass

def live_peer_keys():
    return {p["public_key"] for p in get_peers()}

def create_client(name, mode, expiry):
    name = safe_name(name)
    mode = "full" if mode == "full" else "split"
    if cpath(name).exists():
        raise ValueError("Client already exists")

    ip = next_ip()
    priv, pub, psk = gen_keys()
    allowed = "0.0.0.0/0, ::/0" if mode == "full" else str(server_net4())
    conf = f"""[Interface]
PrivateKey = {priv}
Address = {ip}/32
DNS = <VPN_SERVER_IP>

[Peer]
PublicKey = {server_public_key()}
PresharedKey = {psk}
Endpoint = {endpoint_host()}:{listen_port()}
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""
    b = backup_wg("create")
    append_peer(name, pub, psk, ip)
    cpath(name).write_text(conf)
    cpath(name).chmod(0o600)
    make_qr(name)
    live_add(pub, psk, ip)

    D = db()
    exp = expiry_ts(expiry)
    if exp:
        D["expiry"][name] = exp
    else:
        D["expiry"].pop(name, None)
    D["disabled"].pop(name, None)
    D["exposed"].pop(name, None)
    D["peer_names"][pub] = name
    save_db(D)

    audit("client.create", name, f"{mode} {ip}", {"backup": b})
    return client_detail(name)

def client_detail(name):
    c = parse_client(name)
    peers = {p["public_key"]: p for p in get_peers()}
    p = peers.get(c["public_key"], {})
    if not qpath(c["name"]).exists():
        make_qr(c["name"])
    c.update({
        "online": bool(p.get("online")),
        "endpoint_live": p.get("endpoint", "N/A"),
        "last_seen": p.get("last_seen", "N/A"),
        "traffic": p.get("total_h", "0 B"),
        "expiry_label": expiry_label(c["expires_at"]),
        "qr_url": f"/client/{c['name']}.png" if qpath(c["name"]).exists() else "",
    })
    return c

def disable_client(name, reason="manual"):
    c = parse_client(name)
    b = backup_wg("disable")
    remove_peer_block(c["public_key"])
    live_remove(c["public_key"])
    D = db()
    D["disabled"][c["name"]] = {"time": int(time.time()), "reason": reason}
    save_db(D)
    audit("client.disable", c["name"], reason, {"backup": b})

def enable_client(name):
    c = parse_client(name)
    if c["exposed"]:
        raise RuntimeError("Client marked exposed. Rotate first.")
    if c["expired"]:
        raise RuntimeError("Client expired.")
    b = backup_wg("enable")
    append_peer(c["name"], c["public_key"], c["psk"], c["ip"])
    live_add(c["public_key"], c["psk"], c["ip"])
    D = db()
    D["disabled"].pop(c["name"], None)
    save_db(D)
    audit("client.enable", c["name"], "enabled", {"backup": b})

def delete_client(name):
    c = parse_client(name)
    b = backup_wg("delete")
    remove_peer_block(c["public_key"])
    live_remove(c["public_key"])
    ts = time.strftime("%Y-%m-%d_%H%M%S")
    if cpath(name).exists():
        shutil.move(str(cpath(name)), str(DELETED / f"{safe_name(name)}.{ts}.conf"))
    if qpath(name).exists():
        shutil.move(str(qpath(name)), str(DELETED / f"{safe_name(name)}.{ts}.png"))
    D = db()
    for k in ["disabled", "exposed", "expiry"]:
        D[k].pop(c["name"], None)
    save_db(D)
    audit("client.delete", c["name"], "deleted", {"backup": b})

def expose_client(name):
    c = parse_client(name)
    D = db()
    D["exposed"][c["name"]] = {"time": int(time.time()), "public_key": c["public_key"]}
    save_db(D)
    disable_client(name, "exposed")
    audit("client.exposed", c["name"], "marked exposed", severity="warning")

def rotate_client(name):
    c = parse_client(name)
    b = backup_wg("rotate")
    ts = time.strftime("%Y-%m-%d_%H%M%S")
    (DELETED / f"{c['name']}.rotated.{ts}.conf").write_text(cpath(name).read_text(errors="ignore"))

    remove_peer_block(c["public_key"])
    live_remove(c["public_key"])

    priv, pub, psk = gen_keys()
    allowed = "0.0.0.0/0, ::/0" if c["mode"] == "full" else str(server_net4())
    conf = f"""[Interface]
PrivateKey = {priv}
Address = {c["ip"]}/32
DNS = {os.environ.get("WG_CLIENT_DNS", "<VPN_SERVER_IP>")}

[Peer]
PublicKey = {server_public_key()}
PresharedKey = {psk}
Endpoint = {endpoint_host()}:{listen_port()}
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""
    cpath(name).write_text(conf)
    cpath(name).chmod(0o600)
    make_qr(name)
    append_peer(c["name"], pub, psk, c["ip"])
    live_add(pub, psk, c["ip"])

    D = db()
    D["disabled"].pop(c["name"], None)
    D["exposed"].pop(c["name"], None)
    D["peer_names"].pop(c["public_key"], None)
    D["peer_names"][pub] = c["name"]
    save_db(D)

    audit("client.rotate", c["name"], "rotated keys", {"old": c["public_key"], "new": pub, "backup": b}, "warning")
    return client_detail(name)

def get_peers():
    D = db()
    names = peer_name_map()
    trusted = D.get("trusted", {})
    mutes = D.get("mutes", {})
    now_ts = int(time.time())
    out = []

    try:
        dump = sh(["wg", "show", WG, "dump"], timeout=8)
    except Exception as e:
        audit("wg.dump.error", WG, str(e), severity="error")
        return []

    for line in dump.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue

        key = parts[0]
        endpoint = parts[2] if parts[2] != "(none)" else "N/A"
        allowed = parts[3]
        hs = int(parts[4] or 0)
        rx = int(parts[5] or 0)
        tx = int(parts[6] or 0)

        ip = allowed.split(",")[0].split("/")[0] if allowed else ""
        online = bool(hs and now_ts - hs <= 180)

        name = names.get(key, "")
        if not name:
            if ip == "<VPN_CLIENT_IP>":
                name = "Example Laptop"
            elif ip == "<VPN_CLIENT_IP>":
                name = "iPhone"
            elif ip:
                name = f"Device {ip}"
            else:
                name = f"Peer {key[:8]}"

        score = 0
        reasons = []
        tr = trusted.get(key, "")

        if endpoint != "N/A" and not tr:
            score += 12
            reasons.append("endpoint not trusted")
        if tr and endpoint != "N/A" and endpoint != tr:
            score += 55
            reasons.append("endpoint changed")
        if not hs:
            score += 15
            reasons.append("never connected")
        elif now_ts - hs > 86400:
            score += 30
            reasons.append("stale")
        elif not online:
            score += 8
            reasons.append("sleeping")

        mu = mutes.get(key, 0)
        muted = bool(mu == -1 or mu > time.time())
        if muted:
            score = max(0, score - 20)
            reasons.append("muted")

        if not reasons:
            reasons = ["normal"]

        out.append({
            "name": name,
            "public_key": key,
            "kid": key[:12],
            "endpoint": endpoint,
            "allowed_ips": allowed,
            "primary_ip": ip,
            "handshake": hs,
            "last_seen": human_age(hs),
            "online": online,
            "status": "LIVE" if online else "STALE" if hs else "NEVER",
            "rx": rx,
            "tx": tx,
            "rx_h": human_bytes(rx),
            "tx_h": human_bytes(tx),
            "total_h": human_bytes(rx + tx),
            "risk": min(100, score),
            "risk_level": "Critical" if score >= 80 else "Warning" if score >= 50 else "Watch" if score >= 25 else "Normal",
            "reasons": reasons,
            "trusted_endpoint": tr,
            "muted": muted,
        })

    return sorted(out, key=lambda x: (not x["online"], -x["risk"], x["name"].lower()))

def get_clients():
    out = []
    for f in sorted(CLIENTS.glob("*.conf")):
        try:
            out.append(client_detail(f.stem))
        except Exception as e:
            audit("client.parse.error", f.name, str(e), severity="error")
    return out

def get_devices():
    clients = get_clients()
    peers = get_peers()
    by_pub = {c["public_key"]: c for c in clients}
    devices = []

    for c in clients:
        devices.append({
            **c,
            "kind": "managed",
            "title": c["name"],
            "subtitle": f'{c["ip"]} · {c["mode"]} · {c.get("endpoint_live","N/A")}',
            "can_config": True,
        })

    for p in peers:
        if p["public_key"] in by_pub:
            continue
        devices.append({
            "kind": "peer-only",
            "title": p["name"],
            "name": p["name"],
            "ip": p["primary_ip"],
            "public_key": p["public_key"],
            "subtitle": f'{p["primary_ip"]} · peer-only · {p["endpoint"]}',
            "online": p["online"],
            "last_seen": p["last_seen"],
            "traffic": p["total_h"],
            "risk": p["risk"],
            "risk_level": p["risk_level"],
            "reasons": p["reasons"],
            "endpoint_live": p["endpoint"],
            "can_config": False,
            "note": "Không còn file .conf/private key live. Muốn QR/config thì tạo client mới hoặc restore file deleted phù hợp.",
        })

    return devices

def recovery_files():
    out = []
    for f in sorted(DELETED.glob("*.conf"), key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
        item = {
            "file": f.name,
            "size": f.stat().st_size,
            "mtime": datetime.fromtimestamp(f.stat().st_mtime).isoformat(timespec="seconds"),
        }
        try:
            raw = f.read_text(errors="ignore")
            m = re.search(r"(?im)^\s*Address\s*=\s*([^,\n]+)", raw)
            item["ip"] = str(ipaddress.ip_interface(m.group(1).strip()).ip) if m else ""
            item["name_guess"] = clean_deleted_name(f)
            item["public_key"] = pub_from_client_file(f)
        except Exception:
            pass
        out.append(item)
    return out

def recovery_preview(file):
    file = Path(str(file)).name
    path = DELETED / file
    if not path.exists():
        raise FileNotFoundError(file)
    raw = path.read_text(errors="ignore")
    m = re.search(r"(?im)^\s*Address\s*=\s*([^,\n]+)", raw)
    ip = str(ipaddress.ip_interface(m.group(1).strip()).ip) if m else ""
    pub = pub_from_client_file(path)
    return {"file": file, "name_guess": clean_deleted_name(path), "ip": ip, "public_key": pub, "config": raw}

def recovery_restore(file, name=None):
    prev = recovery_preview(file)
    name = safe_name(name or prev["name_guess"])
    dst = cpath(name)
    if dst.exists():
        raise ValueError("Client name already exists")

    src = DELETED / Path(file).name
    shutil.copy2(src, dst)
    dst.chmod(0o600)
    info = parse_client(name)

    live = live_peer_keys()
    if info["public_key"] not in live:
        b = backup_wg("restore")
        append_peer(name, info["public_key"], info["psk"], info["ip"])
        live_add(info["public_key"], info["psk"], info["ip"])
    else:
        b = ""

    make_qr(name)
    D = db()
    D["peer_names"][info["public_key"]] = name
    D["disabled"].pop(name, None)
    D["exposed"].pop(name, None)
    save_db(D)
    audit("recovery.restore", name, Path(file).name, {"backup": b})
    return client_detail(name)

def peer_trust(key):
    P = {p["public_key"]: p for p in get_peers()}
    if key not in P:
        raise ValueError("Peer not found")
    ep = P[key]["endpoint"]
    if ep == "N/A":
        raise ValueError("Peer has no endpoint")
    D = db()
    D["trusted"][key] = ep
    save_db(D)
    audit("peer.trust", P[key]["name"], ep)

def peer_mute(key, duration):
    sec = {"1h": 3600, "24h": 86400, "forever": -1}.get(str(duration), 86400)
    D = db()
    D["mutes"][key] = -1 if sec == -1 else time.time() + sec
    save_db(D)
    audit("peer.mute", key[:12], str(duration))

def peer_unmute(key):
    D = db()
    D["mutes"].pop(key, None)
    save_db(D)
    audit("peer.unmute", key[:12], "unmuted")

def peer_rename(key, name):
    name = str(name or "").strip()
    if not name:
        raise ValueError("Name required")
    if len(name) > 40:
        raise ValueError("Name too long")
    D = db()
    D["peer_names"][key] = name
    save_db(D)
    audit("peer.rename", key[:12], name)
    return {"public_key": key, "name": name}

def trusted_remote():
    r = request.remote_addr or ""
    if r in ["127.0.0.1", "::1"]:
        return True
    try:
        return ipaddress.ip_address(r) in ipaddress.ip_network(VPNNET, strict=False)
    except Exception:
        return False

@app.before_request
def gate():
    if request.path.startswith("/healthz") or request.path.startswith("/static/"):
        return None
    if trusted_remote():
        session["auth"] = True
        return None
    if session.get("auth"):
        return None
    if request.path.startswith("/api"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return Response("VPN only. Connect WireGuard and open http://<VPN_SERVER_IP>:8888", 401)

@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/")
def home():
    return render_template("lts.html")

@app.route("/studio")
def studio():
    return render_template("lts.html")

@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "app": "GOLDEN_LTS_2026", "time": now()})

@app.route("/api/state")
@app.route("/api/studio/state")
def api_state():
    clients = get_clients()
    peers = get_peers()
    devices = get_devices()
    recovery = recovery_files()
    return jsonify({
        "ok": True,
        "app": "GOLDEN_LTS_2026",
        "clients": clients,
        "peers": peers,
        "devices": devices,
        "recovery": recovery,
        "audit": audit_tail(120),
        "summary": {
            "clients": len(clients),
            "devices": len(devices),
            "peer_only": sum(1 for d in devices if d.get("kind") == "peer-only"),
            "peers": len(peers),
            "online": sum(1 for p in peers if p["online"]),
            "highrisk": sum(1 for p in peers if p["risk"] >= 50),
            "disabled": sum(1 for c in clients if c["disabled"]),
            "exposed": sum(1 for c in clients if c["exposed"]),
            "recovery": len(recovery),
        }
    })

def apiwrap(fn):
    try:
        return jsonify({"ok": True, "result": fn(request.get_json(silent=True) or {})})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/client/create", methods=["POST"])
def api_create():
    return apiwrap(lambda d: create_client(d.get("name"), d.get("mode", "split"), d.get("expiry", "forever")))

@app.route("/api/client/config", methods=["POST"])
def api_config():
    def f(d):
        name = safe_name(d.get("name"))
        if not cpath(name).exists():
            raise FileNotFoundError(name)
        make_qr(name)
        audit("client.config", name, "viewed")
        return {
            "name": name,
            "config": cpath(name).read_text(errors="ignore"),
            "conf_url": f"/client/{name}.conf",
            "qr_url": f"/client/{name}.png" if qpath(name).exists() else "",
        }
    return apiwrap(f)

@app.route("/api/client/disable", methods=["POST"])
def api_disable():
    return apiwrap(lambda d: disable_client(d.get("name")) or True)

@app.route("/api/client/enable", methods=["POST"])
def api_enable():
    return apiwrap(lambda d: enable_client(d.get("name")) or True)

@app.route("/api/client/delete", methods=["POST"])
def api_delete():
    return apiwrap(lambda d: delete_client(d.get("name")) or True)

@app.route("/api/client/expose", methods=["POST"])
def api_expose():
    return apiwrap(lambda d: expose_client(d.get("name")) or True)

@app.route("/api/client/rotate", methods=["POST"])
def api_rotate():
    return apiwrap(lambda d: rotate_client(d.get("name")))

@app.route("/api/peer/trust", methods=["POST"])
def api_peer_trust():
    return apiwrap(lambda d: peer_trust(d.get("key")) or True)

@app.route("/api/peer/mute", methods=["POST"])
def api_peer_mute():
    return apiwrap(lambda d: peer_mute(d.get("key"), d.get("duration", "24h")) or True)

@app.route("/api/peer/unmute", methods=["POST"])
def api_peer_unmute():
    return apiwrap(lambda d: peer_unmute(d.get("key")) or True)

@app.route("/api/peer/rename", methods=["POST"])
def api_peer_rename():
    return apiwrap(lambda d: peer_rename(d.get("key"), d.get("name")))

@app.route("/api/recovery/preview", methods=["POST"])
def api_recovery_preview():
    return apiwrap(lambda d: recovery_preview(d.get("file")))

@app.route("/api/recovery/restore", methods=["POST"])
def api_recovery_restore():
    return apiwrap(lambda d: recovery_restore(d.get("file"), d.get("name")))

@app.route("/client/<name>.conf")
def dl_conf(name):
    name = safe_name(name)
    if not cpath(name).exists():
        return Response("not found", 404)
    return Response(
        cpath(name).read_text(errors="ignore"),
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}.conf"'}
    )

@app.route("/client/<name>.png")
def dl_qr(name):
    name = safe_name(name)
    if not qpath(name).exists():
        make_qr(name)
    if not qpath(name).exists():
        return Response("not found", 404)
    return send_file(str(qpath(name)), mimetype="image/png")


# ===== GOLDEN_SYSTEMINFO_LTS_V1 =====
import os as _sys_os
import json as _sys_json
import time as _sys_time
import shutil as _sys_shutil
import subprocess as _sys_subprocess

def _lts_human_bytes(num):
    try:
        num = float(num)
    except Exception:
        num = 0.0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while num >= 1024 and i < len(units) - 1:
        num /= 1024.0
        i += 1
    return f"{num:.2f}{units[i]}" if i else f"{int(num)}{units[i]}"

def _lts_bar(percent, width=24):
    try:
        p = max(0.0, min(100.0, float(percent)))
    except Exception:
        p = 0.0
    filled = int(round((p / 100.0) * width))
    return "█" * filled + "░" * max(0, width - filled)

def _lts_cpu_percent():
    def read_cpu():
        with open("/proc/stat", "r") as f:
            line = f.readline().strip()
        nums = [int(x) for x in line.split()[1:8]]
        idle = nums[3] + nums[4]
        total = sum(nums)
        return idle, total

    try:
        idle1, total1 = read_cpu()
        _sys_time.sleep(0.12)
        idle2, total2 = read_cpu()
        didle = idle2 - idle1
        dtotal = total2 - total1
        if dtotal <= 0:
            return 0.0
        return round((1.0 - didle / dtotal) * 100.0, 1)
    except Exception:
        return 0.0

def _lts_mem_swap():
    data = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                k, v = line.split(":", 1)
                data[k.strip()] = int(v.strip().split()[0]) * 1024
    except Exception:
        pass

    mem_total = data.get("MemTotal", 0)
    mem_avail = data.get("MemAvailable", 0)
    mem_used = max(0, mem_total - mem_avail)
    mem_pct = round((mem_used / mem_total) * 100.0, 1) if mem_total else 0.0

    swap_total = data.get("SwapTotal", 0)
    swap_free = data.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)
    swap_pct = round((swap_used / swap_total) * 100.0, 1) if swap_total else 0.0

    return {
        "mem_total": mem_total,
        "mem_used": mem_used,
        "mem_pct": mem_pct,
        "swap_total": swap_total,
        "swap_used": swap_used,
        "swap_pct": swap_pct,
    }

def _lts_disk():
    try:
        total, used, free = _sys_shutil.disk_usage("/")
        pct = round((used / total) * 100.0, 1) if total else 0.0
        return {"total": total, "used": used, "free": free, "pct": pct}
    except Exception:
        return {"total": 0, "used": 0, "free": 0, "pct": 0.0}

def _lts_vnstat():
    try:
        raw = _sys_subprocess.check_output(
            ["vnstat", "--json"],
            stderr=_sys_subprocess.DEVNULL,
            timeout=2
        ).decode("utf-8", "ignore")

        j = _sys_json.loads(raw)
        interfaces = j.get("interfaces") or []
        if not interfaces:
            return {"month": "N/A", "all": "N/A"}

        iface = interfaces[0]
        traffic = iface.get("traffic", {})
        months = traffic.get("month", []) or []
        total = traffic.get("total", {}) or {}

        month_val = 0
        if months:
            cur = months[-1]
            month_val = (cur.get("rx", 0) or 0) + (cur.get("tx", 0) or 0)

        all_val = (total.get("rx", 0) or 0) + (total.get("tx", 0) or 0)

        return {
            "month": _lts_human_bytes(month_val),
            "all": _lts_human_bytes(all_val),
        }
    except Exception:
        return {"month": "N/A", "all": "N/A"}

@app.get("/api/system/info")
def api_system_info_lts():
    cpu_pct = _lts_cpu_percent()
    ms = _lts_mem_swap()
    dk = _lts_disk()
    vn = _lts_vnstat()

    lines = [
        f"CPU  [{_lts_bar(cpu_pct)}]  {cpu_pct:.0f}%",
        f"RAM  [{_lts_bar(ms['mem_pct'])}]  {ms['mem_pct']:.0f}%",
        f"DISK [{_lts_bar(dk['pct'])}]  {dk['pct']:.0f}%",
        f"SWAP [{_lts_bar(ms['swap_pct'])}]  {ms['swap_pct']:.0f}%",
        f"DATA {vn['month']} (month)  {vn['all']} (all)",
        "──────────────────────────────────────────────────",
    ]

    return jsonify({
        "ok": True,
        "cpu": {"percent": cpu_pct, "bar": _lts_bar(cpu_pct)},
        "ram": {
            "percent": ms["mem_pct"],
            "bar": _lts_bar(ms["mem_pct"]),
            "used": _lts_human_bytes(ms["mem_used"]),
            "total": _lts_human_bytes(ms["mem_total"]),
        },
        "disk": {
            "percent": dk["pct"],
            "bar": _lts_bar(dk["pct"]),
            "used": _lts_human_bytes(dk["used"]),
            "total": _lts_human_bytes(dk["total"]),
        },
        "swap": {
            "percent": ms["swap_pct"],
            "bar": _lts_bar(ms["swap_pct"]),
            "used": _lts_human_bytes(ms["swap_used"]),
            "total": _lts_human_bytes(ms["swap_total"]),
        },
        "data": vn,
        "lines": lines,
        "time": now(),
    })
# ===== END GOLDEN_SYSTEMINFO_LTS_V1 =====



# ===== GOLDEN_AGENT_DASHBOARD_API_2026 =====
from pathlib import Path as _agent_Path
import json as _agent_json
import subprocess as _agent_subprocess
from flask import jsonify as _agent_jsonify, request as _agent_request

_AGENT_STATE_FILE = _agent_Path("/opt/wg-golden/state/agent_state.json")
_AGENT_EVENTS_FILE = _agent_Path("/opt/wg-golden/state/agent_events.jsonl")
_AGENT_FINAL_FILE = _agent_Path("/opt/wg-golden/AGENT_2026_FINAL_LOCKED.txt")
_AGENT_ACTIVE_RELEASE = _agent_Path("/opt/wg-golden/AGENT_FINAL_ACTIVE_RELEASE")

def _agent_read_json(path, default):
    try:
        return _agent_json.loads(_agent_Path(path).read_text(errors="ignore"))
    except Exception:
        return default

def _agent_read_text(path, default=""):
    try:
        return _agent_Path(path).read_text(errors="ignore").strip()
    except Exception:
        return default

def _agent_service():
    try:
        r = _agent_subprocess.run(
            ["systemctl", "is-active", "wg-golden-agent"],
            capture_output=True,
            text=True,
            timeout=2
        )
        active = (r.stdout or "").strip()
    except Exception:
        active = "unknown"

    try:
        r2 = _agent_subprocess.run(
            ["systemctl", "is-enabled", "wg-golden-agent"],
            capture_output=True,
            text=True,
            timeout=2
        )
        enabled = (r2.stdout or "").strip()
    except Exception:
        enabled = "unknown"

    return {
        "active": active,
        "enabled": enabled,
        "ok": active == "active",
    }

@app.get("/api/agent/state")
def api_agent_state():
    state = _agent_read_json(_AGENT_STATE_FILE, {})
    service = _agent_service()

    return _agent_jsonify({
        "ok": bool(state),
        "service": service,
        "agent": state,
        "final_marker": _agent_read_text(_AGENT_FINAL_FILE, ""),
        "active_release": _agent_read_text(_AGENT_ACTIVE_RELEASE, ""),
        "time": now(),
    })

@app.get("/api/agent/events")
def api_agent_events():
    try:
        limit = int(_agent_request.args.get("limit", "50"))
    except Exception:
        limit = 50

    limit = max(1, min(300, limit))
    events = []

    try:
        lines = _AGENT_EVENTS_FILE.read_text(errors="ignore").splitlines()[-limit:]
        for line in lines:
            try:
                events.append(_agent_json.loads(line))
            except Exception:
                pass
    except Exception:
        pass

    return _agent_jsonify({
        "ok": True,
        "events": events,
        "count": len(events),
        "time": now(),
    })
# ===== END GOLDEN_AGENT_DASHBOARD_API_2026 =====



# ===== GOLDEN_AGENT_COMPLETE_CONTROL_API_2026 =====
from pathlib import Path as _agentc_Path
import json as _agentc_json
import subprocess as _agentc_subprocess
from flask import request as _agentc_request, jsonify as _agentc_jsonify

_AGENTC_CONFIG = _agentc_Path("/opt/wg-golden/state/agent_config.json")

def _agentc_json_load(path, default):
    try:
        return _agentc_json.loads(_agentc_Path(path).read_text(errors="ignore"))
    except Exception:
        return default

def _agentc_json_save(path, data):
    tmp = _agentc_Path(str(path) + ".tmp")
    tmp.write_text(_agentc_json.dumps(data, ensure_ascii=False, indent=2))
    tmp.replace(path)

@app.post("/api/agent/control")
def api_agent_control():
    data = _agentc_request.get_json(silent=True) or {}
    action = str(data.get("action", "")).strip()

    if action == "run_once":
        r = _agentc_subprocess.run(
            ["/opt/wg-golden/golden-agentctl.sh", "once"],
            capture_output=True,
            text=True,
            timeout=25
        )
        return _agentc_jsonify({
            "ok": r.returncode == 0,
            "action": action,
            "stdout": r.stdout[-4000:],
            "stderr": r.stderr[-4000:],
            "time": now(),
        })

    if action == "test_telegram":
        r = _agentc_subprocess.run(
            ["/opt/wg-golden/golden-agentctl.sh", "test-telegram"],
            capture_output=True,
            text=True,
            timeout=25
        )
        return _agentc_jsonify({
            "ok": r.returncode == 0,
            "action": action,
            "stdout": r.stdout[-4000:],
            "stderr": r.stderr[-4000:],
            "time": now(),
        })


    if action == "backup_now":
        import subprocess as _gw_backup_subprocess
        from flask import jsonify as _gw_backup_jsonify
        r = _gw_backup_subprocess.run(
            ["/opt/wg-golden/golden-agentctl.sh", "backup-now"],
            capture_output=True,
            text=True,
            timeout=45
        )
        return _gw_backup_jsonify({
            "ok": r.returncode == 0,
            "action": action,
            "stdout": r.stdout[-4000:],
            "stderr": r.stderr[-4000:],
            "time": now(),
        })

    if action == "set_interval":
        try:
            seconds = int(data.get("seconds", 10))
        except Exception:
            seconds = 10

        seconds = max(5, min(300, seconds))
        cfg = _agentc_json_load(_AGENTC_CONFIG, {})
        cfg["interval_seconds"] = seconds
        _agentc_json_save(_AGENTC_CONFIG, cfg)

        return _agentc_jsonify({
            "ok": True,
            "action": action,
            "interval_seconds": seconds,
            "time": now(),
        })

    return _agentc_jsonify({
        "ok": False,
        "error": "Unsupported Agent control action",
        "time": now(),
    }), 400
# ===== END GOLDEN_AGENT_COMPLETE_CONTROL_API_2026 =====
















# ===== GOLDEN_DASHBOARD_VPNMAX_CONTROL_LITE_FINAL_2026 =====
from flask import request as _vmax_req, jsonify as _vmax_jsonify
import subprocess as _vmax_subprocess
import pathlib as _vmax_pathlib
import json as _vmax_json
import time as _vmax_time

def _vmax_job_status():
    p = _vmax_pathlib.Path("/opt/wg-golden/control/dashboard-vpnmax-job.json")
    if not p.exists():
        return {
            "ok": True,
            "state": "idle",
            "message": "No VPN Max dashboard job yet",
        }
    try:
        return _vmax_json.loads(p.read_text(errors="ignore"))
    except Exception as e:
        return {
            "ok": False,
            "state": "unknown",
            "error": str(e),
        }

def _vmax_latest_backup():
    keep = _vmax_pathlib.Path("/home/ubuntu/FINAL_BACKUPS_KEEP")
    files = sorted(
        keep.glob("WG_GOLDEN_VPN_MAX_FINAL_2026_*.tgz"),
        key=lambda x: x.stat().st_mtime if x.exists() else 0,
        reverse=True,
    )
    if not files:
        return None
    f = files[0]
    sha = _vmax_pathlib.Path(str(f) + ".sha256")
    return {
        "path": str(f),
        "sha256": str(sha) if sha.exists() else None,
        "size_bytes": f.stat().st_size,
        "mtime": f.stat().st_mtime,
    }

@app.route("/api/vpnmax/dashboard/status", methods=["GET"])
def golden_vpnmax_dashboard_status_2026():
    return _vmax_jsonify({
        "ok": True,
        "job": _vmax_job_status(),
        "latest_backup": _vmax_latest_backup(),
        "actions": [
            "status",
            "repair-safe",
            "backup-now",
            "verify-backup",
            "restore-rehearsal",
            "hygiene",
        ],
    })

@app.route("/api/vpnmax/dashboard/run", methods=["POST"])
def golden_vpnmax_dashboard_run_2026():
    try:
        data = _vmax_req.get_json(silent=True) or {}
        action = str(data.get("action") or "").strip().lower().replace("_", "-")

        allowed = {
            "status",
            "repair-safe",
            "backup-now",
            "verify-backup",
            "restore-rehearsal",
            "hygiene",
        }

        if action not in allowed:
            return _vmax_jsonify({
                "ok": False,
                "error": "unsupported action",
                "allowed": sorted(allowed),
            }), 400

        st = _vmax_job_status()
        if st.get("state") == "running":
            return _vmax_jsonify({
                "ok": True,
                "state": "already_running",
                "job": st,
            })

        _vmax_subprocess.Popen(
            ["/opt/wg-golden/golden-dashboard-vpnmax-runner.sh", action],
            stdout=_vmax_subprocess.DEVNULL,
            stderr=_vmax_subprocess.DEVNULL,
            start_new_session=True,
        )

        _vmax_time.sleep(0.3)

        return _vmax_jsonify({
            "ok": True,
            "state": "started",
            "action": action,
            "message": "VPN Max action started in background",
        })

    except Exception as e:
        return _vmax_jsonify({
            "ok": False,
            "error": str(e),
        }), 500

@app.before_request
def golden_vpnmax_intercept_old_backup_button_2026():
    """
    Preserve compatibility with the existing Agent 'Backup now' button.
    It now starts the real VPN Max backup asynchronously.
    """
    try:
        if _vmax_req.method != "POST":
            return None

        if _vmax_req.path not in ("/api/agent/control", "/api/vpnmax/control"):
            return None

        data = _vmax_req.get_json(silent=True) or {}
        action = str(
            data.get("action")
            or data.get("cmd")
            or data.get("command")
            or data.get("control")
            or ""
        ).strip().lower().replace("_", "-")

        backup_actions = {
            "backup",
            "backup-now",
            "backupnow",
            "run-backup",
            "create-backup",
            "vpnmax-backup",
            "vpnmax-backup-now",
        }

        if action not in backup_actions:
            return None

        st = _vmax_job_status()
        if st.get("state") == "running":
            return _vmax_jsonify({
                "ok": True,
                "action": "backup-now",
                "state": "already_running",
                "job": st,
            })

        _vmax_subprocess.Popen(
            ["/opt/wg-golden/golden-dashboard-vpnmax-runner.sh", "backup-now"],
            stdout=_vmax_subprocess.DEVNULL,
            stderr=_vmax_subprocess.DEVNULL,
            start_new_session=True,
        )

        _vmax_time.sleep(0.3)

        return _vmax_jsonify({
            "ok": True,
            "action": "backup-now",
            "state": "started",
            "message": "VPN Max backup started in background",
        })

    except Exception as e:
        return _vmax_jsonify({
            "ok": False,
            "action": "backup-now",
            "error": str(e),
        }), 500
# ===== END GOLDEN_DASHBOARD_VPNMAX_CONTROL_LITE_FINAL_2026 =====
















# ===== GOLDEN_DEVICE_MANAGER_FINAL_2026 =====
from flask import request as _dm_req, jsonify as _dm_jsonify
import subprocess as _dm_subprocess
import pathlib as _dm_pathlib
import json as _dm_json
import time as _dm_time
import shutil as _dm_shutil

_DM_STATE = _dm_pathlib.Path("/opt/wg-golden/state/lts_state.json")
_DM_WGCONF = _dm_pathlib.Path("/etc/wireguard/wg0.conf")

_DM_FALLBACK_NAMES = {
    "qU5RfG/50jGLRvF/4oXrCFss+jnuRbG1/8FjeLbtW3o=": "Example Laptop",
    "F28scYjegm/e6lItQ+3Z0kcYuEtTk/AL49gnIVE/6Ak=": "iPhone",
}

def _dm_host(endpoint):
    endpoint = str(endpoint or "").strip()
    if not endpoint or endpoint == "(none)":
        return ""
    if endpoint.startswith("[") and "]" in endpoint:
        return endpoint[1:].split("]", 1)[0]
    return endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint

def _dm_load():
    try:
        return _dm_json.loads(_DM_STATE.read_text(errors="ignore"))
    except Exception:
        return {}

def _dm_save(db):
    _DM_STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _DM_STATE.with_suffix(".tmp")
    tmp.write_text(_dm_json.dumps(db, ensure_ascii=False, indent=2))
    tmp.replace(_DM_STATE)

def _dm_bytes(n):
    try:
        n = float(n)
    except Exception:
        n = 0
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.2f} {units[i]}"

def _dm_age(ts):
    try:
        ts = int(ts)
    except Exception:
        ts = 0
    if ts <= 0:
        return "Never"
    sec = max(0, int(_dm_time.time()) - ts)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m"
    if sec < 86400:
        return f"{sec // 3600}h"
    return f"{sec // 86400}d"

def _dm_name(pub, allowed, db):
    if pub in _DM_FALLBACK_NAMES:
        return _DM_FALLBACK_NAMES[pub]

    for key in ("peer_names", "names", "client_names"):
        val = db.get(key)
        if isinstance(val, dict) and val.get(pub):
            return str(val[pub])

    ip = (allowed or "").split(",")[0].strip().split("/")[0]
    if ip == "<VPN_CLIENT_IP>":
        return "Example Laptop"
    if ip == "<VPN_CLIENT_IP>":
        return "iPhone"
    return f"Device {ip}" if ip else pub[:10]

def _dm_set_name(pub, name, db):
    if not isinstance(db.get("peer_names"), dict):
        db["peer_names"] = {}
    db["peer_names"][pub] = name[:80]

def _dm_trusted(pub, db):
    for key in ("trusted_hosts", "trusted", "trusted_endpoints", "peer_trusted_endpoints"):
        val = db.get(key)
        if isinstance(val, dict) and pub in val:
            x = val.get(pub)
            if isinstance(x, dict):
                x = x.get("host") or x.get("endpoint") or x.get("value") or ""
            return str(x or "")
    return ""

def _dm_set_trusted(pub, endpoint, db):
    host = _dm_host(endpoint)

    if not isinstance(db.get("trusted_hosts"), dict):
        db["trusted_hosts"] = {}
    db["trusted_hosts"][pub] = host

    # Compatibility with older dashboard/agent state readers.
    for key in ("trusted", "trusted_endpoints", "peer_trusted_endpoints"):
        if not isinstance(db.get(key), dict):
            db[key] = {}
        db[key][pub] = endpoint

def _dm_backup_devices(db):
    val = db.get("backup_devices")
    return val if isinstance(val, dict) else {}

def _dm_set_backup(pub, enabled, db):
    if not isinstance(db.get("backup_devices"), dict):
        db["backup_devices"] = {}
    if enabled:
        db["backup_devices"][pub] = True
    else:
        db["backup_devices"].pop(pub, None)

def _dm_peers():
    out = _dm_subprocess.check_output(["wg", "show", "wg0", "dump"], text=True)
    lines = [x for x in out.splitlines() if x.strip()]
    db = _dm_load()
    backup_devices = _dm_backup_devices(db)
    now = int(_dm_time.time())
    peers = []

    for line in lines:
        parts = line.split("\t")

        # Interface row has 4 columns. Peer rows normally have 8 columns here.
        if len(parts) < 8:
            continue

        pub, _psk, endpoint, allowed, latest, rx, tx, _ka = parts[:8]
        endpoint = "" if endpoint == "(none)" else endpoint
        latest_i = int(latest or 0)
        rx_i = int(rx or 0)
        tx_i = int(tx or 0)

        if latest_i <= 0:
            status = "NEVER"
        else:
            age = now - latest_i
            if age <= 300:
                status = "LIVE"
            elif age <= 86400:
                status = "RECENT"
            else:
                status = "STALE"

        trusted = _dm_trusted(pub, db)
        endpoint_host = _dm_host(endpoint)
        trusted_host = _dm_host(trusted)
        endpoint_changed = bool(endpoint and trusted and endpoint_host != trusted_host)

        is_backup = bool(backup_devices.get(pub))

        risk = 0
        reasons = []

        if status == "NEVER":
            risk += 15
            reasons.append("never connected")
        elif status == "STALE":
            risk += 30
            reasons.append("stale")

        if endpoint_changed:
            risk += 55
            reasons.append("endpoint changed")

        peers.append({
            "public_key": pub,
            "name": _dm_name(pub, allowed, db),
            "allowed_ips": allowed,
            "ip": (allowed or "").split(",")[0].strip().split("/")[0],
            "endpoint": endpoint,
            "endpoint_host": endpoint_host,
            "trusted_endpoint": trusted,
            "trusted_host": trusted_host,
            "endpoint_changed": endpoint_changed,
            "status": status,
            "risk": risk,
            "reasons": reasons,
            "last_seen": _dm_age(latest_i),
            "traffic": _dm_bytes(rx_i + tx_i),
            "rx": rx_i,
            "tx": tx_i,
            "is_backup": is_backup,
            "can_trust": bool(endpoint and endpoint_host != trusted_host),
            "can_delete": status in ("STALE", "NEVER"),
        })

    order = {"LIVE": 0, "RECENT": 1, "STALE": 2, "NEVER": 3}
    peers.sort(key=lambda x: (order.get(x["status"], 9), -x["risk"], x["name"]))
    return peers

@app.route("/api/device-manager/final", methods=["GET"])
def golden_device_manager_final_list_2026():
    try:
        peers = _dm_peers()
        return _dm_jsonify({
            "ok": True,
            "peers": peers,
            "summary": {
                "peers": len(peers),
                "live": sum(1 for p in peers if p["status"] == "LIVE"),
                "recent": sum(1 for p in peers if p["status"] == "RECENT"),
                "stale": sum(1 for p in peers if p["status"] == "STALE"),
                "never": sum(1 for p in peers if p["status"] == "NEVER"),
                "backup": sum(1 for p in peers if p.get("is_backup")),
                "highrisk": sum(1 for p in peers if p["risk"] >= 50),
            },
        })
    except Exception as e:
        return _dm_jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/device-manager/final/trust", methods=["POST"])
def golden_device_manager_final_trust_2026():
    try:
        data = _dm_req.get_json(silent=True) or {}
        pub = str(data.get("public_key") or "").strip()
        peer = next((x for x in _dm_peers() if x["public_key"] == pub), None)
        if not peer:
            return _dm_jsonify({"ok": False, "error": "peer not found"}), 404
        if not peer.get("endpoint"):
            return _dm_jsonify({"ok": False, "error": "peer has no endpoint"}), 400

        db = _dm_load()
        _dm_set_trusted(pub, peer["endpoint"], db)
        _dm_save(db)

        return _dm_jsonify({
            "ok": True,
            "message": "trusted endpoint saved",
            "trusted_host": _dm_host(peer["endpoint"]),
            "trusted_endpoint": peer["endpoint"],
        })
    except Exception as e:
        return _dm_jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/device-manager/final/rename", methods=["POST"])
def golden_device_manager_final_rename_2026():
    try:
        data = _dm_req.get_json(silent=True) or {}
        pub = str(data.get("public_key") or "").strip()
        name = str(data.get("name") or "").strip()
        if not pub or not name:
            return _dm_jsonify({"ok": False, "error": "missing public_key or name"}), 400

        db = _dm_load()
        _dm_set_name(pub, name, db)
        _dm_save(db)

        return _dm_jsonify({"ok": True, "name": name[:80]})
    except Exception as e:
        return _dm_jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/device-manager/final/backup", methods=["POST"])
def golden_device_manager_final_backup_mark_2026():
    try:
        data = _dm_req.get_json(silent=True) or {}
        pub = str(data.get("public_key") or "").strip()
        enabled = bool(data.get("enabled"))
        if not pub:
            return _dm_jsonify({"ok": False, "error": "missing public_key"}), 400

        db = _dm_load()
        _dm_set_backup(pub, enabled, db)
        _dm_save(db)

        return _dm_jsonify({"ok": True, "public_key": pub, "is_backup": enabled})
    except Exception as e:
        return _dm_jsonify({"ok": False, "error": str(e)}), 500

def _dm_remove_from_conf(pub):
    if not _DM_WGCONF.exists():
        return False

    lines = _DM_WGCONF.read_text().splitlines(True)
    out = []
    i = 0
    removed = False

    while i < len(lines):
        if lines[i].strip() == "[Peer]":
            j = i + 1
            while j < len(lines) and not (
                lines[j].strip().startswith("[") and lines[j].strip().endswith("]")
            ):
                j += 1

            block = lines[i:j]
            has_pub = False
            for ln in block:
                if ln.strip().startswith("PublicKey") and "=" in ln:
                    if ln.split("=", 1)[1].strip() == pub:
                        has_pub = True
                        break

            if has_pub:
                removed = True
            else:
                out.extend(block)

            i = j
        else:
            out.append(lines[i])
            i += 1

    if removed:
        _DM_WGCONF.write_text("".join(out))

    return removed

@app.route("/api/device-manager/final/delete", methods=["POST"])
def golden_device_manager_final_delete_2026():
    try:
        data = _dm_req.get_json(silent=True) or {}
        pub = str(data.get("public_key") or "").strip()
        confirm = str(data.get("confirm") or "").strip()

        if confirm != "DELETE":
            return _dm_jsonify({"ok": False, "error": "confirmation required"}), 400

        peer = next((x for x in _dm_peers() if x["public_key"] == pub), None)
        if not peer:
            return _dm_jsonify({"ok": False, "error": "peer not found"}), 404

        if peer["status"] == "LIVE":
            return _dm_jsonify({"ok": False, "error": "refusing to delete LIVE peer"}), 409

        ts = _dm_time.strftime("%Y%m%d_%H%M%S")
        bdir = _dm_pathlib.Path(f"/opt/wg-golden/backups/device_manager_delete_{ts}")
        bdir.mkdir(parents=True, exist_ok=True)

        if _DM_WGCONF.exists():
            _dm_shutil.copy2(_DM_WGCONF, bdir / "wg0.conf.before")
        if _DM_STATE.exists():
            _dm_shutil.copy2(_DM_STATE, bdir / "lts_state.json.before")

        _dm_subprocess.run(["wg", "set", "wg0", "peer", pub, "remove"], check=False)
        removed_conf = _dm_remove_from_conf(pub)

        db = _dm_load()
        for key in (
            "peer_names", "names", "client_names",
            "trusted_hosts", "trusted", "trusted_endpoints", "peer_trusted_endpoints",
            "backup_devices", "mutes", "disabled", "exposed", "expiry",
        ):
            val = db.get(key)
            if isinstance(val, dict):
                val.pop(pub, None)
            elif isinstance(val, list):
                db[key] = [x for x in val if x != pub]

        _dm_save(db)

        return _dm_jsonify({
            "ok": True,
            "message": "peer deleted permanently",
            "deleted": peer,
            "removed_from_wg0_conf": removed_conf,
            "backup_dir": str(bdir),
        })
    except Exception as e:
        return _dm_jsonify({"ok": False, "error": str(e)}), 500
# ===== END GOLDEN_DEVICE_MANAGER_FINAL_2026 =====




# ===== GOLDEN_DEVICE_MANAGER_PAGE_FINAL_2026 =====
from flask import render_template as _dm_page_render_template

@app.route("/devices")
@app.route("/device-manager")
def golden_device_manager_page_final_2026():
    return _dm_page_render_template("device_manager_final.html")
# ===== END GOLDEN_DEVICE_MANAGER_PAGE_FINAL_2026 =====


if __name__ == "__main__":
    app.run(host=HOST, port=PORT)

# GOLDEN_FINAL_BACKUP_NOW_API_2026


# GOLDEN_CLIENT_DNS_10_66_66_1_2026
