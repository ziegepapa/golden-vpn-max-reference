#!/usr/bin/env python3
import os, re, time, json, socket, shutil, subprocess, urllib.parse, urllib.request, ipaddress, tarfile
from pathlib import Path
from collections import deque

WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_CONF = os.environ.get("WG_CONF", "/etc/wireguard/wg0.conf")
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = str(os.environ.get("TELEGRAM_CHAT_ID", "")).strip()
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://<VPN_SERVER_IP>:8888")
PUBLIC_IFACE = os.environ.get("TELEGRAM_PUBLIC_IFACE", "ens3")

DIGEST_MINUTES = int(os.environ.get("TELEGRAM_DIGEST_MINUTES", "10"))
WATCHDOG_MINUTES = int(os.environ.get("TELEGRAM_WATCHDOG_MINUTES", "5"))
DAILY_BACKUP_HOUR = int(os.environ.get("TELEGRAM_DAILY_BACKUP_HOUR", "3"))
TRAFFIC_SPIKE_BYTES = int(os.environ.get("TELEGRAM_TRAFFIC_SPIKE_BYTES", "10485760"))

ALERT_ENDPOINT = os.environ.get("TELEGRAM_ALERT_ENDPOINT", "1") == "1"
ALERT_LOGIN_FAILED = os.environ.get("TELEGRAM_ALERT_LOGIN_FAILED", "1") == "1"
ALERT_LOGIN_SUCCESS = os.environ.get("TELEGRAM_ALERT_LOGIN_SUCCESS", "0") == "1"
ALERT_TRAFFIC_SPIKE = os.environ.get("TELEGRAM_ALERT_TRAFFIC_SPIKE", "0") == "1"

STATE_DIR = Path("/opt/wg-golden/state")
BACKUP_DIR = Path("/opt/wg-golden/backups")
CLIENT_DIR = Path("/etc/wireguard/clients")
CLIENT_DELETED_DIR = CLIENT_DIR / "deleted"
EVENT_FILE = STATE_DIR / "events.json"
AGENT_STATE = STATE_DIR / "telegram_roadmap_state.json"

for d in [STATE_DIR, BACKUP_DIR, CLIENT_DIR, CLIENT_DELETED_DIR]:
    d.mkdir(parents=True, exist_ok=True)

COMMANDS = {
    "/start", "/menu", "/help",
    "/status", "/peers", "/online", "/events", "/top", "/report",
    "/clients", "/newclient", "/add_split", "/add_full", "/delete_client", "/config_client",
    "/risk", "/mute", "/unmute", "/trust", "/muted",
    "/quiet", "/digest", "/watchdog", "/backup", "/dashboard",
    "/lockdown", "/unlock", "/restart_dashboard", "/whoami", "/cancel",
}

def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default

def save_json(path, data):
    try:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        tmp.replace(path)
    except Exception:
        pass

state = load_json(AGENT_STATE, {
    "offset": 0,
    "peers": {},
    "mutes": {},
    "trusted": {},
    "digest": [],
    "seen_events": [],
    "baseline_done": False,
    "quiet": False,
    "last_digest": 0,
    "last_watchdog": 0,
    "last_backup_date": "",
    "observed_hours": {},
    "watchdog_last": {},
    "wizard": {},
})

def sh(cmd, timeout=8, input_text=None):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=timeout, input=input_text).strip()

def sh_run(cmd, timeout=8, input_text=None):
    r = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        input=input_text,
        check=True,
    )
    return (r.stdout or "").strip()

def tg_api(method, data=None):
    if not BOT_TOKEN:
        return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    encoded = None
    headers = {}
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=encoded, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def send(text, keyboard=None):
    if not BOT_TOKEN or not CHAT_ID:
        return
    data = {"chat_id": CHAT_ID, "text": text[:3900], "disable_web_page_preview": "true"}
    if keyboard and not is_main_menu_keyboard(keyboard):
        data["reply_markup"] = json.dumps({"inline_keyboard": keyboard}, ensure_ascii=False)
    else:
        data["reply_markup"] = json.dumps(active_reply_keyboard_markup(), ensure_ascii=False)
    try:
        tg_api("sendMessage", data)
    except Exception as e:
        print("send error:", repr(e), flush=True)

def edit(chat_id, message_id, text, keyboard=None):
    data = {"chat_id": chat_id, "message_id": message_id, "text": text[:3900], "disable_web_page_preview": "true"}
    if keyboard and not is_main_menu_keyboard(keyboard):
        data["reply_markup"] = json.dumps({"inline_keyboard": keyboard}, ensure_ascii=False)
    elif keyboard and is_main_menu_keyboard(keyboard):
        data["reply_markup"] = json.dumps({"inline_keyboard": []}, ensure_ascii=False)
    try:
        tg_api("editMessageText", data)
    except Exception:
        send(text, keyboard)

def answer_callback(callback_id, text="OK"):
    try:
        tg_api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})
    except Exception:
        pass


def make_client_qr_file(name, config_text):
    safe = safe_name(name)
    qr_path = CLIENT_DIR / f"{safe}.png"

    if not shutil.which("qrencode"):
        return None

    subprocess.check_call(
        ["qrencode", "-t", "PNG", "-o", str(qr_path)],
        input=config_text,
        text=True,
        timeout=6,
    )
    qr_path.chmod(0o600)
    return qr_path

def send_file_path(method, field_name, path, mime_type, caption=""):
    path = Path(path)
    if not path.exists():
        send(f"File not found: {path}")
        return

    tg_upload_file(
        method,
        field_name,
        path.name,
        path.read_bytes(),
        mime_type,
        caption,
    )

def send_client_package_from_disk(name):
    safe = safe_name(name)
    conf_path = CLIENT_DIR / f"{safe}.conf"
    qr_path = CLIENT_DIR / f"{safe}.png"

    if not conf_path.exists():
        send(f"Client config file not found: {conf_path}")
        return

    cfg = conf_path.read_text(errors="ignore")

    # Gửi text để copy nhanh
    if len(cfg) <= 3400:
        send(f"📄 WireGuard config for {safe}\n\n{cfg}")
    else:
        send(f"📄 WireGuard config for {safe}\nSending as file.")

    # Gửi file .conf thật
    send_file_path(
        "sendDocument",
        "document",
        conf_path,
        "application/octet-stream",
        f"WireGuard config: {safe}"
    )

    # Gửi QR file thật nếu có; nếu chưa có thì tạo
    if not qr_path.exists():
        try:
            make_client_qr_file(safe, cfg)
        except Exception as e:
            print("make QR failed:", repr(e), flush=True)

    if qr_path.exists():
        send_file_path(
            "sendPhoto",
            "photo",
            qr_path,
            "image/png",
            f"QR code: {safe}"
        )
    else:
        send("QR unavailable: qrencode is not installed or failed.")


# STEP6C_TELEGRAM_PERSISTENT_MENU_2026
REPLY_BUTTON_MAP = {
    "📊 Status": "/status",
    "🧠 Risk": "/risk",
    "🧩 Clients": "/clients_menu",
    "➕ New": "/newclient",
    "➕ New Client": "/newclient",
    "🏆 Top": "/top",
    "📜 Events": "/events",
    "📦 Digest": "/digest",
    "🩺 Watch": "/watchdog",
    "🩺 Watchdog": "/watchdog",
    "🔕 Quiet": "/quiet",
    "💾 Backup": "/backup",
    "🌐 Dash": "/dashboard",
    "🌐 Dashboard": "/dashboard",
    "⬅️ Back": "/menu",
    "⬅️ Back / Menu": "/menu",
    "Back": "/menu",
    "Menu": "/menu",
    "📋 List": "/clients_list",
    "📄 Config": "/client_config_help",
    "🗑 Delete": "/client_delete_help",
}

def reply_keyboard_markup():
    return {
        "keyboard": [
            [{"text": "📊 Status"}, {"text": "🧠 Risk"}],
            [{"text": "🧩 Clients"}, {"text": "➕ New"}],
            [{"text": "🏆 Top"}, {"text": "📜 Events"}],
            [{"text": "📦 Digest"}, {"text": "🩺 Watch"}],
            [{"text": "🔕 Quiet"}, {"text": "💾 Backup"}],
            [{"text": "⬅️ Back"}, {"text": "🌐 Dash"}],
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False,
        "is_persistent": True,
        "input_field_placeholder": "Golden VPN command…",
    }


# STEP6E_CLIENTS_SUBMENU_2026
def clients_reply_keyboard_markup():
    return {
        "keyboard": [
            [{"text": "📋 List"}, {"text": "➕ New"}],
            [{"text": "📄 Config"}, {"text": "🗑 Delete"}],
            [{"text": "⬅️ Back"}],
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False,
        "is_persistent": True,
        "input_field_placeholder": "Clients menu…",
    }

def active_reply_keyboard_markup():
    if state.get("reply_menu") == "clients":
        return clients_reply_keyboard_markup()
    return reply_keyboard_markup()
# END STEP6E_CLIENTS_SUBMENU_2026

def normalize_reply_button(text):
    t = (text or "").strip()
    return REPLY_BUTTON_MAP.get(t, t)
# END STEP6C_TELEGRAM_PERSISTENT_MENU_2026



# STEP6C3_NO_DUP_MAIN_INLINE_2026
def is_main_menu_keyboard(keyboard):
    try:
        items = []
        for row in keyboard or []:
            for btn in row:
                items.append(btn.get("callback_data") or btn.get("url") or btn.get("text"))
        must = {"status", "risk", "clients", "newclient", "top", "events", "digest", "watchdog", "quiet_toggle", "backup"}
        return must.issubset(set(items))
    except Exception:
        return False
# END STEP6C3_NO_DUP_MAIN_INLINE_2026


def menu_keyboard():
    return [
        [{"text": "📊 Status", "callback_data": "status"}, {"text": "🧠 Risk", "callback_data": "risk"}],
        [{"text": "🧩 Clients", "callback_data": "clients"}, {"text": "➕ New Client", "callback_data": "newclient"}],
        [{"text": "🏆 Top", "callback_data": "top"}, {"text": "📜 Events", "callback_data": "events"}],
        [{"text": "📦 Digest", "callback_data": "digest"}, {"text": "🩺 Watchdog", "callback_data": "watchdog"}],
        [{"text": "🔕 Quiet", "callback_data": "quiet_toggle"}, {"text": "💾 Backup", "callback_data": "backup"}],
        [{"text": "🌐 Dashboard", "url": DASHBOARD_URL}],
    ]

def back_keyboard():
    return [[{"text": "⬅️ Menu", "callback_data": "menu"}]]

def newclient_keyboard():
    return [
        [{"text": "Split tunnel", "callback_data": "wiz_mode:split"}, {"text": "Full tunnel", "callback_data": "wiz_mode:full"}],
        [{"text": "Cancel", "callback_data": "wiz_cancel"}],
    ]

def clients_keyboard():
    rows = []
    for c in list_clients()[:8]:
        name = c["name"]
        rows.append([
            {"text": f"📄 {name}", "callback_data": f"config:{name}"},
            {"text": f"🗑 {name}", "callback_data": f"delete_confirm:{name}"},
        ])
    rows.append([{"text": "➕ New Client", "callback_data": "newclient"}])
    rows.append([{"text": "⬅️ Menu", "callback_data": "menu"}])
    return rows

def delete_keyboard(name):
    return [
        [{"text": f"✅ Delete {name}", "callback_data": f"delete_do:{name}"}],
        [{"text": "Cancel", "callback_data": "clients"}],
    ]

def human_bytes(n):
    try:
        n = float(n)
    except Exception:
        n = 0.0
    units = ["B","KB","MB","GB","TB","PB"]
    i = 0
    while n >= 1024 and i < len(units)-1:
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
    m, s = divmod(diff, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h{m:02d}m"
    d, h = divmod(h, 24)
    return f"{d}d{h}h"

def safe_name(name):
    name = str(name or "").strip()
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name)
    name = name.strip(".-_")
    if not name:
        raise ValueError("Client name is required")
    if len(name) > 48:
        raise ValueError("Client name is too long")
    return name

def peer_names():
    names = {}
    try:
        lines = Path(WG_CONF).read_text(errors="ignore").splitlines()
    except Exception:
        return names
    current = None
    for raw in lines:
        line = raw.strip()
        m = re.match(r"#+\s*Client:\s*(.+)", line, re.I)
        if m:
            current = m.group(1).strip()
            continue
        m = re.match(r"#+\s*(.+)", line)
        if m and "peer" not in m.group(1).lower():
            current = m.group(1).strip()
            continue
        m = re.match(r"PublicKey\s*=\s*(\S+)", line)
        if m and current:
            names[m.group(1).strip()] = current
            current = None
    return names

def get_peers():
    names = peer_names()
    peers = []
    try:
        dump = sh(["sudo", "wg", "show", WG_INTERFACE, "dump"])
    except Exception as e:
        print("wg dump error:", repr(e), flush=True)
        return []
    now = time.time()
    lines = [x for x in dump.splitlines() if x.strip()]
    for line in lines[1:]:
        p = line.split("\t")
        if len(p) < 8:
            continue
        key = p[0]
        endpoint = p[2] if p[2] != "(none)" else "N/A"
        allowed = p[3]
        try:
            hs = int(p[4])
        except Exception:
            hs = 0
        try:
            rx = int(p[5]); tx = int(p[6])
        except Exception:
            rx = tx = 0
        online = hs > 0 and now - hs <= 180
        peers.append({
            "key": key, "kid": key[:12], "name": names.get(key, "Unknown"),
            "endpoint": endpoint, "allowed": allowed, "hs": hs, "online": online,
            "rx": rx, "tx": tx, "total": rx + tx,
        })
    peers.sort(key=lambda x: (not x["online"], -x["total"], x["name"].lower()))
    return peers

def match_peer(q):
    q = str(q or "").lower().strip()
    if not q:
        return None
    for p in get_peers():
        if q in p["name"].lower() or q in p["key"].lower() or q in p["allowed"].lower() or q in p["kid"].lower():
            return p
    return None

def is_muted(peer):
    m = state.setdefault("mutes", {}).get(peer["key"])
    if not m:
        return False
    until = float(m.get("until", 0))
    if until < 0:
        return True
    if until > time.time():
        return True
    state["mutes"].pop(peer["key"], None)
    save_json(AGENT_STATE, state)
    return False

def parse_duration(s):
    s = str(s or "24h").strip().lower()
    if s in ["forever", "permanent", "perm"]:
        return -1
    m = re.match(r"^(\d+)(m|h|d)?$", s)
    if not m:
        return 24 * 3600
    n = int(m.group(1)); unit = m.group(2) or "h"
    return n * 60 if unit == "m" else n * 86400 if unit == "d" else n * 3600

def add_digest(kind, title, body, severity=1, peer_key=None):
    if state.get("quiet"):
        return
    item_id = f"{kind}:{peer_key or ''}:{title}:{body}"
    now = int(time.time())
    for x in state.setdefault("digest", []):
        if x.get("id") == item_id and now - int(x.get("ts", 0)) < 1800:
            return
    state.setdefault("digest", []).append({
        "id": item_id, "ts": now, "time": time.strftime("%H:%M:%S"),
        "kind": kind, "title": title, "body": body,
        "severity": severity, "peer_key": peer_key,
    })
    state["digest"] = state["digest"][-80:]
    save_json(AGENT_STATE, state)

def flush_digest(force=False):
    now = time.time()
    interval = max(60, DIGEST_MINUTES * 60)
    if not force and now - float(state.get("last_digest", 0)) < interval:
        return
    items = state.get("digest", [])
    if not items:
        state["last_digest"] = now
        save_json(AGENT_STATE, state)
        return
    high = [x for x in items if int(x.get("severity", 1)) >= 3]
    medium = [x for x in items if int(x.get("severity", 1)) == 2]
    lines = ["📦 Golden VPN Digest", f"Items: {len(items)} · High: {len(high)} · Medium: {len(medium)}", ""]
    for x in sorted(items, key=lambda a: int(a.get("severity", 1)), reverse=True)[:18]:
        icon = "🚨" if int(x.get("severity", 1)) >= 3 else "⚠️" if int(x.get("severity", 1)) == 2 else "•"
        lines.append(f"{icon} {x.get('time','')} · {x.get('title','')}")
        if x.get("body"):
            lines.append(str(x.get("body"))[:220])
        lines.append("")
    send("\n".join(lines).strip(), menu_keyboard())
    state["digest"] = []
    state["last_digest"] = now
    save_json(AGENT_STATE, state)

def wg_listen_port():
    try:
        return sh(["sudo", "wg", "show", WG_INTERFACE, "listen-port"], timeout=3)
    except Exception:
        pass
    try:
        txt = Path(WG_CONF).read_text(errors="ignore")
        m = re.search(r"(?im)^\s*ListenPort\s*=\s*(\d+)", txt)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "51820"

def server_private_key():
    txt = Path(WG_CONF).read_text(errors="ignore")
    m = re.search(r"(?im)^\s*PrivateKey\s*=\s*(\S+)", txt)
    if not m:
        raise RuntimeError("Cannot read server PrivateKey from wg0.conf")
    return m.group(1).strip()

def server_public_key():
    return sh(["wg", "pubkey"], input_text=server_private_key(), timeout=3)

def server_addresses():
    txt = Path(WG_CONF).read_text(errors="ignore")
    m = re.search(r"(?im)^\s*Address\s*=\s*(.+)", txt)
    if not m:
        return [ipaddress.ip_interface("<VPN_SERVER_IP>/24")]
    out = []
    for part in m.group(1).split(","):
        try:
            out.append(ipaddress.ip_interface(part.strip()))
        except Exception:
            pass
    return out or [ipaddress.ip_interface("<VPN_SERVER_IP>/24")]

def vpn_ipv4_network():
    for addr in server_addresses():
        if addr.version == 4:
            return addr.network
    return ipaddress.ip_network("10.99.0.0/24")

def used_ipv4s():
    used = set()
    try:
        txt = Path(WG_CONF).read_text(errors="ignore")
    except Exception:
        txt = ""
    for m in re.finditer(r"(?im)^\s*AllowedIPs\s*=\s*(.+)", txt):
        for part in m.group(1).split(","):
            try:
                iface = ipaddress.ip_interface(part.strip())
                if iface.version == 4:
                    used.add(str(iface.ip))
            except Exception:
                pass
    for addr in server_addresses():
        if addr.version == 4:
            used.add(str(addr.ip))
    return used

def next_client_ipv4():
    net = vpn_ipv4_network()
    used = used_ipv4s()
    for ip in net.hosts():
        s = str(ip)
        if s not in used:
            return s
    raise RuntimeError(f"No free IPv4 left in {net}")

def client_allowed_ips(mode):
    return "0.0.0.0/0, ::/0" if mode == "full" else str(vpn_ipv4_network())

def gen_keypair():
    private = sh(["wg", "genkey"], timeout=3)
    public = sh(["wg", "pubkey"], input_text=private, timeout=3)
    psk = sh(["wg", "genpsk"], timeout=3)
    return private, public, psk

def backup_wg_conf(reason):
    ts = time.strftime("%Y-%m-%d_%H%M%S")
    dst = BACKUP_DIR / f"wg0.conf.{reason}.{ts}"
    dst.write_text(Path(WG_CONF).read_text(errors="ignore"))
    return str(dst)

def endpoint_host():
    host = os.environ.get("WG_PUBLIC_HOST", "vpn.example.com").strip()
    host = re.sub(r"^https?://", "", host).strip().strip("/")
    if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]
    return host or "vpn.example.com"

def client_conf_path(name):
    return CLIENT_DIR / f"{safe_name(name)}.conf"

def create_client(name, mode):
    name = safe_name(name)
    mode = "full" if mode == "full" else "split"
    path = client_conf_path(name)
    if path.exists():
        raise ValueError(f"Client already exists: {name}")

    ip = next_client_ipv4()
    endpoint = f"{endpoint_host()}:{wg_listen_port()}"
    dns = os.environ.get("WG_CLIENT_DNS", "<VPN_SERVER_IP>").strip() or "<VPN_SERVER_IP>"
    server_pub = server_public_key()
    client_priv, client_pub, psk = gen_keypair()
    allowed = client_allowed_ips(mode)

    client_conf = f"""[Interface]
PrivateKey = {client_priv}
Address = {ip}/32
DNS = {dns}

[Peer]
PublicKey = {server_pub}
PresharedKey = {psk}
Endpoint = {endpoint}
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""
    server_peer = f"""

### Client: {name}
[Peer]
PublicKey = {client_pub}
PresharedKey = {psk}
AllowedIPs = {ip}/32
"""
    backup = backup_wg_conf("before_create_client")
    with open(WG_CONF, "a") as f:
        f.write(server_peer)
    path.write_text(client_conf)
    path.chmod(0o600)

    try:
        make_client_qr_file(name, client_conf)
    except Exception as e:
        print("create QR file failed:", repr(e), flush=True)

    sh_run(
        ["sudo", "wg", "set", WG_INTERFACE, "peer", client_pub, "preshared-key", "/dev/stdin", "allowed-ips", f"{ip}/32"],
        input_text=psk + "\n",
        timeout=6,
    )

    add_digest("client", "Client created", f"{name} · {mode} · {ip}", 1)
    return {"name": name, "mode": mode, "ip": ip, "endpoint": endpoint, "public_key": client_pub, "file": str(path), "backup": backup, "config": client_conf}

def remove_peer_block(public_key):
    txt = Path(WG_CONF).read_text(errors="ignore")
    blocks = re.split(r"(?m)(?=^\[Peer\]\s*$)", txt)
    kept = []
    removed = False
    for b in blocks:
        if "[Peer]" in b and re.search(r"(?im)^\s*PublicKey\s*=\s*" + re.escape(public_key) + r"\s*$", b):
            removed = True
            continue
        kept.append(b)
    if not removed:
        raise RuntimeError("Peer public key not found in wg0.conf")
    Path(WG_CONF).write_text("".join(kept).rstrip() + "\n")

def delete_client(name):
    name = safe_name(name)
    path = client_conf_path(name)
    if not path.exists():
        raise ValueError(f"Client config not found: {name}")
    txt = path.read_text(errors="ignore")
    m = re.search(r"(?im)^\s*PrivateKey\s*=\s*(\S+)", txt)
    if not m:
        raise RuntimeError("Cannot read client private key")
    client_pub = sh(["wg", "pubkey"], input_text=m.group(1).strip(), timeout=3)
    backup = backup_wg_conf("before_delete_client")
    remove_peer_block(client_pub)
    try:
        sh(["sudo", "wg", "set", WG_INTERFACE, "peer", client_pub, "remove"], timeout=5)
    except Exception:
        pass
    ts = time.strftime("%Y-%m-%d_%H%M%S")
    deleted = CLIENT_DELETED_DIR / f"{name}.{ts}.conf"
    path.rename(deleted)
    add_digest("client", "Client deleted", name, 1)
    return {"name": name, "public_key": client_pub, "deleted_file": str(deleted), "backup": backup}

def list_clients():
    peers = get_peers()
    by_ip = {}
    for p in peers:
        ip = p.get("allowed", "").split(",")[0].split("/")[0].strip()
        by_ip[ip] = p
    out = []
    for f in sorted(CLIENT_DIR.glob("*.conf")):
        if f.name == "wg0.conf":
            continue
        txt = f.read_text(errors="ignore")
        ip = ""
        mode = "unknown"
        m = re.search(r"(?im)^\s*Address\s*=\s*([^,\n]+)", txt)
        if m:
            ip = m.group(1).strip().split("/")[0]
        m = re.search(r"(?im)^\s*AllowedIPs\s*=\s*(.+)", txt)
        if m:
            mode = "full" if "0.0.0.0/0" in m.group(1) else "split"
        peer = by_ip.get(ip, {})
        out.append({"name": f.stem, "ip": ip, "mode": mode, "online": bool(peer.get("online")), "endpoint": peer.get("endpoint", "N/A"), "last_seen": human_age(peer.get("hs", 0)) if peer else "N/A", "total": peer.get("total", 0), "file": str(f)})
    return out

def get_client_config(name):
    path = client_conf_path(name)
    if not path.exists():
        raise ValueError(f"Client config not found: {name}")
    return path.read_text(errors="ignore")

def peer_risk(peer):
    score = 0
    reasons = []
    now = time.time()
    trusted_ep = state.setdefault("trusted", {}).get(peer["key"], {}).get("endpoint")
    if peer["endpoint"] != "N/A" and trusted_ep and peer["endpoint"] != trusted_ep:
        score += 40; reasons.append("Endpoint differs from trusted endpoint")
    elif peer["endpoint"] != "N/A" and not trusted_ep:
        score += 8; reasons.append("No trusted endpoint saved")
    if peer["hs"] <= 0:
        score += 10; reasons.append("Never connected")
    else:
        age = now - peer["hs"]
        if age > 14 * 86400:
            score += 25; reasons.append("Stale for more than 14 days")
        elif age > 7 * 86400:
            score += 15; reasons.append("Stale for more than 7 days")
        elif age > 86400:
            score += 6; reasons.append("Not seen for more than 24h")
    hours = state.setdefault("observed_hours", {}).setdefault(peer["key"], [])
    current_hour = int(time.strftime("%H"))
    if peer["online"]:
        if current_hour not in hours:
            if len(hours) >= 4:
                score += 12; reasons.append("Online at unusual hour")
            hours.append(current_hour)
            state["observed_hours"][peer["key"]] = sorted(list(set(hours)))[-24:]
    if is_muted(peer):
        score = max(0, score - 20); reasons.append("Muted peer")
    return min(100, score), reasons

def status_text():
    peers = get_peers()
    online = sum(1 for p in peers if p["online"])
    rx = sum(p["rx"] for p in peers); tx = sum(p["tx"] for p in peers)
    try:
        load = os.getloadavg()
        load_s = f"{load[0]:.2f} {load[1]:.2f} {load[2]:.2f}"
    except Exception:
        load_s = "N/A"
    try:
        svc = sh(["systemctl", "is-active", "wg-golden"], timeout=3)
    except Exception:
        svc = "unknown"
    try:
        tsvc = sh(["systemctl", "is-active", "wg-golden-telegram"], timeout=3)
    except Exception:
        tsvc = "unknown"
    return (
        "🛡 Golden VPN\n\n"
        f"Dashboard: {svc}\nTelegram: {tsvc}\nHost: {socket.gethostname()}\n"
        f"Peers: {len(peers)} · Online: {online}\n"
        f"Traffic: ↓ {human_bytes(rx)} · ↑ {human_bytes(tx)}\n"
        f"Load: {load_s}\nQuiet: {'ON' if state.get('quiet') else 'OFF'}\n"
        f"Digest pending: {len(state.get('digest', []))}\nURL: {DASHBOARD_URL}"
    )

def peers_text(only_online=False):
    peers = get_peers()
    if only_online:
        peers = [p for p in peers if p["online"]]
    if not peers:
        return "No peers found."
    lines = ["🟢 Online peers" if only_online else "🧩 All peers"]
    for p in peers[:15]:
        icon = "🟢" if p["online"] else "⚫"
        risk, _ = peer_risk(p)
        mute = " · muted" if is_muted(p) else ""
        lines.append(f"{icon} {p['name']} · risk {risk}/100{mute}\nIP: {p['allowed']}\nEndpoint: {p['endpoint']}\nLast: {human_age(p['hs'])}\nTraffic: ↓ {human_bytes(p['rx'])} · ↑ {human_bytes(p['tx'])}")
    return "\n\n".join(lines)

def risk_text():
    scored = []
    for p in get_peers():
        score, reasons = peer_risk(p)
        scored.append((score, p, reasons))
    scored.sort(key=lambda x: x[0], reverse=True)
    lines = ["🧠 Peer Risk Score"]
    for score, p, reasons in scored[:12]:
        icon = "🚨" if score >= 60 else "⚠️" if score >= 30 else "✅"
        reason = "; ".join(reasons[:3]) if reasons else "Normal"
        lines.append(f"{icon} {p['name']} — {score}/100\n{reason}")
    return "\n\n".join(lines)

def dashboard_devices_for_telegram():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8888/api/state", timeout=5) as r:
            d = json.loads(r.read().decode("utf-8", "ignore"))
        devices = d.get("devices") or []
        return devices
    except Exception:
        return []

def clients_text():
    clients = list_clients()
    if not clients:
        return "🧩 Clients — 0\n\nNo managed client found.\nUse ➕ New to create one."

    lines = [f"🧩 Clients — {len(clients)}", ""]

    for c in clients[:12]:
        icon = "🟢" if c.get("online") else "⚫"
        name = c.get("name", "unknown")
        ip = c.get("ip") or "no-ip"
        mode = c.get("mode") or "unknown"
        last = c.get("last_seen") or "N/A"

        flags = []
        if str(c.get("disabled", "")).lower() in ["true", "1", "yes"] or "disabled" in str(c).lower():
            flags.append("disabled")
        if "expired" in str(c).lower():
            flags.append("expired")
        if last == "Never":
            flags.append("never")

        suffix = (" · " + " · ".join(flags)) if flags else ""
        lines.append(f"{icon} {name} · {ip} · {mode} · {last}{suffix}")

    if len(clients) > 12:
        lines.append(f"… +{len(clients)-12} more")

    lines.append("")
    lines.append("Use buttons below for New / Config / Delete.")
    return "\n".join(lines)


def top_text():
    peers = sorted(get_peers(), key=lambda p: p["total"], reverse=True)
    if not peers:
        return "No peers found."
    lines = ["🏆 Top traffic"]
    for i, p in enumerate(peers[:8], 1):
        icon = "🟢" if p["online"] else "⚫"
        lines.append(f"{i}. {icon} {p['name']} — {human_bytes(p['total'])}")
    return "\n".join(lines)

def events_text():
    events = load_json(EVENT_FILE, [])
    if not events:
        return "No events yet."
    lines = ["📜 Recent events"]
    for e in events[:5]:
        lines.append(f"{e.get('time','')} · {e.get('peer','')}\n{e.get('message','')}")
    return "\n\n".join(lines)

def report_text():
    peers = get_peers()
    clients = list_clients()
    online = [p for p in peers if p["online"]]
    stale = [p for p in peers if p["hs"] > 0 and time.time() - p["hs"] > 86400]
    never = [p for p in peers if p["hs"] <= 0]
    top = sorted(peers, key=lambda p: p["total"], reverse=True)[:3]
    high_risk = [p for p in peers if peer_risk(p)[0] >= 40]
    rx = sum(p["rx"] for p in peers); tx = sum(p["tx"] for p in peers)
    lines = ["📅 Golden VPN Report", "", f"Peers: {len(peers)}", f"Managed clients: {len(clients)}", f"Online: {len(online)}", f"Stale >24h: {len(stale)}", f"Never connected: {len(never)}", f"High risk: {len(high_risk)}", f"Traffic: ↓ {human_bytes(rx)} · ↑ {human_bytes(tx)}", "", "Top:"]
    for i, p in enumerate(top, 1):
        lines.append(f"{i}. {p['name']} — {human_bytes(p['total'])}")
    return "\n".join(lines)

def mute_text():
    mutes = state.setdefault("mutes", {})
    if not mutes:
        return "No muted peers."
    peers = {p["key"]: p for p in get_peers()}
    lines = ["🔕 Muted peers"]
    for k, m in list(mutes.items()):
        p = peers.get(k)
        name = p["name"] if p else k[:12]
        until = float(m.get("until", 0))
        left = "forever" if until < 0 else time.strftime("%Y-%m-%d %H:%M", time.localtime(until))
        lines.append(f"{name} · until {left}")
    return "\n".join(lines)

def watchdog_text():
    issues = run_watchdog(return_only=True)
    if not issues:
        return "🩺 Watchdog OK\nNo current issue detected."
    return "🩺 Watchdog issues\n\n" + "\n".join(f"⚠️ {x}" for x in issues)

def lockdown():
    try:
        sh(["sudo", "ufw", "allow", "in", "on", "wg0", "to", "any", "port", "8888", "proto", "tcp"], timeout=8)
    except Exception:
        pass
    try:
        sh(["sudo", "ufw", "insert", "1", "deny", "in", "on", PUBLIC_IFACE, "to", "any", "port", "8888", "proto", "tcp"], timeout=8)
        sh(["sudo", "ufw", "reload"], timeout=8)
        return "🔒 Lockdown applied. Dashboard should remain available over WireGuard."
    except Exception as e:
        return f"Lockdown failed: {e}"

def unlock():
    try:
        for _ in range(5):
            subprocess.run(["sudo", "ufw", "delete", "deny", "in", "on", PUBLIC_IFACE, "to", "any", "port", "8888", "proto", "tcp"], text=True, input="y\n", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sh(["sudo", "ufw", "allow", "8888/tcp"], timeout=8)
        sh(["sudo", "ufw", "reload"], timeout=8)
        return "🔓 Public dashboard port 8888 allowed again."
    except Exception as e:
        return f"Unlock failed: {e}"

def restart_dashboard():
    try:
        sh(["sudo", "systemctl", "restart", "wg-golden"], timeout=12)
        time.sleep(1)
        svc = sh(["systemctl", "is-active", "wg-golden"], timeout=3)
        return f"🔁 Dashboard restarted.\nService: {svc}"
    except Exception as e:
        return f"Restart failed: {e}"

def daily_backup(force=False):
    today = time.strftime("%Y-%m-%d")
    if not force and state.get("last_backup_date") == today:
        return "Backup already done today."
    ts = time.strftime("%Y-%m-%d_%H%M%S")
    dst = BACKUP_DIR / f"golden-daily-{ts}.tgz"
    with tarfile.open(dst, "w:gz") as tar:
        for path in [WG_CONF, "/etc/wireguard/clients", "/opt/wg-golden/app.py", "/opt/wg-golden/telegram_agent.py", "/etc/wg-golden.env"]:
            p = Path(path)
            if p.exists():
                tar.add(str(p), arcname=str(p).lstrip("/"))
    state["last_backup_date"] = today
    save_json(AGENT_STATE, state)
    return f"✅ Backup created:\n{dst}"

def run_watchdog(return_only=False):
    issues = []
    try:
        svc = sh(["systemctl", "is-active", "wg-golden"], timeout=3)
        if svc != "active":
            issues.append(f"wg-golden service is {svc}")
            if not return_only:
                try:
                    sh(["sudo", "systemctl", "restart", "wg-golden"], timeout=12)
                    issues.append("Action: restarted wg-golden")
                except Exception as e:
                    issues.append(f"Restart failed: {e}")
    except Exception as e:
        issues.append(f"Cannot check wg-golden: {e}")

    try:
        wg = sh(["sudo", "wg", "show", WG_INTERFACE], timeout=4)
        if not wg:
            issues.append(f"{WG_INTERFACE} returned empty status")
    except Exception as e:
        issues.append(f"WireGuard {WG_INTERFACE} issue: {e}")

    try:
        ports = sh(["ss", "-ltn"], timeout=3)
        if ":8888" not in ports:
            issues.append("Dashboard port 8888 is not listening")
    except Exception as e:
        issues.append(f"Cannot check port 8888: {e}")

    try:
        disk = shutil.disk_usage("/")
        pct = disk.used / disk.total * 100
        if pct >= 85:
            issues.append(f"Disk usage high: {pct:.1f}%")
    except Exception:
        pass

    if issues and not return_only:
        last = state.setdefault("watchdog_last", {})
        joined = "\n".join(issues)
        key = str(hash(joined))
        now = time.time()
        if now - float(last.get(key, 0)) > 1800:
            add_digest("watchdog", "Watchdog issue", joined, 3)
            last[key] = now
            save_json(AGENT_STATE, state)
    return issues

def menu_text():
    return "🛡 Golden VPN\nUse the keyboard below."


def start_wizard(mode=None):
    wiz = state.setdefault("wizard", {})
    if mode:
        wiz["stage"] = "name"
        wiz["mode"] = mode
        save_json(AGENT_STATE, state)
        return f"➕ New {mode} client\n\nSend client name now.\nExample: iphone-guest"
    wiz.clear()
    wiz["stage"] = "mode"
    save_json(AGENT_STATE, state)
    return "➕ New WireGuard client\n\nChoose tunnel mode:"

def cancel_wizard():
    state.setdefault("wizard", {}).clear()
    save_json(AGENT_STATE, state)
    return "Cancelled."

def handle_wizard_text(text):
    wiz = state.setdefault("wizard", {})
    if wiz.get("stage") != "name":
        return False
    try:
        name = safe_name(text.strip())
        mode = wiz.get("mode", "split")
        r = create_client(name, mode)
        # AUTO PACKAGE AFTER WIZARD CREATE
        try:
            send_client_package_from_disk(r["name"])
        except Exception as e:
            send(f"⚠️ Client created, but sending .conf/QR failed: {e}")
        wiz.clear()
        save_json(AGENT_STATE, state)
        send(
            f"✅ Created {mode} client\n\n"
            f"Name: {r['name']}\n"
            f"IP: {r['ip']}\n"
            f"Endpoint: {r['endpoint']}\n\n"
            f"Config:\n/config_client {r['name']}",
            clients_keyboard()
        )
    except Exception as e:
        send(f"Create failed: {e}", newclient_keyboard())
    return True


# ===== FORCE_CLIENT_FILE_QR_V1 =====
def tg_upload_path(method, field_name, path, mime_type, caption=""):
    path = Path(path)
    if not path.exists():
        send(f"File not found: {path}")
        return

    boundary = "----GoldenBoundary" + str(int(time.time() * 1000000))
    parts = []

    def field(name, value):
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        parts.append(str(value).encode())
        parts.append(b"\r\n")

    def filefield(name, filename, data, mime):
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode())
        parts.append(f"Content-Type: {mime}\r\n\r\n".encode())
        parts.append(data)
        parts.append(b"\r\n")

    field("chat_id", CHAT_ID)
    if caption:
        field("caption", caption[:900])

    filefield(field_name, path.name, path.read_bytes(), mime_type)
    parts.append(f"--{boundary}--\r\n".encode())

    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )

    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

def ensure_client_qr_file(name):
    safe = safe_name(name)
    conf_path = CLIENT_DIR / f"{safe}.conf"
    qr_path = CLIENT_DIR / f"{safe}.png"

    if not conf_path.exists():
        raise FileNotFoundError(str(conf_path))

    if shutil.which("qrencode"):
        subprocess.check_call(
            ["qrencode", "-t", "PNG", "-o", str(qr_path), str(conf_path)],
            timeout=8,
        )
        qr_path.chmod(0o600)

    return conf_path, qr_path

def send_client_package_from_disk(name):
    safe = safe_name(name)
    conf_path, qr_path = ensure_client_qr_file(safe)

    cfg = conf_path.read_text(errors="ignore")

    # Gửi text để copy nhanh
    if len(cfg) <= 3400:
        send(f"📄 WireGuard config for {safe}\n\n{cfg}")
    else:
        send(f"📄 WireGuard config for {safe}\nConfig is long, sending as file.")

    # Gửi file .conf thật
    tg_upload_path(
        "sendDocument",
        "document",
        conf_path,
        "application/octet-stream",
        f"WireGuard config file: {safe}.conf"
    )

    # Gửi QR code ảnh thật
    if qr_path.exists():
        tg_upload_path(
            "sendPhoto",
            "photo",
            qr_path,
            "image/png",
            f"WireGuard QR code: {safe}"
        )
    else:
        send("QR unavailable: qrencode failed or is not installed.")
# ===== END FORCE_CLIENT_FILE_QR_V1 =====


# ===== AUTO_SEND_PACKAGE_ON_CREATE_V2 =====
def auto_upload_path_v2(method, field_name, path, mime_type, caption=""):
    path = Path(path)
    if not path.exists():
        send(f"File not found: {path}")
        return

    boundary = "----GoldenBoundary" + str(int(time.time() * 1000000))
    parts = []

    def field(name, value):
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        parts.append(str(value).encode())
        parts.append(b"\r\n")

    def filefield(name, filename, data, mime):
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode())
        parts.append(f"Content-Type: {mime}\r\n\r\n".encode())
        parts.append(data)
        parts.append(b"\r\n")

    field("chat_id", CHAT_ID)
    if caption:
        field("caption", caption[:900])

    filefield(field_name, path.name, path.read_bytes(), mime_type)
    parts.append(f"--{boundary}--\r\n".encode())

    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )

    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

def make_qr_for_client_v2(name):
    safe = safe_name(name)
    conf_path = CLIENT_DIR / f"{safe}.conf"
    qr_path = CLIENT_DIR / f"{safe}.png"

    if not conf_path.exists():
        raise FileNotFoundError(str(conf_path))

    cfg = conf_path.read_text(errors="ignore")

    if shutil.which("qrencode"):
        subprocess.run(
            ["qrencode", "-t", "PNG", "-o", str(qr_path)],
            input=cfg,
            text=True,
            timeout=8,
            check=True,
        )
        qr_path.chmod(0o600)

    return conf_path, qr_path

def send_client_package_from_disk(name):
    safe = safe_name(name)
    conf_path, qr_path = make_qr_for_client_v2(safe)
    cfg = conf_path.read_text(errors="ignore")

    # 1. Gửi nội dung config để copy nhanh
    send(f"📄 WireGuard config for {safe}\n\n{cfg}")

    # 2. Gửi file .conf thật
    auto_upload_path_v2(
        "sendDocument",
        "document",
        conf_path,
        "application/octet-stream",
        f"WireGuard config file: {safe}.conf"
    )

    # 3. Gửi QR thật
    if qr_path.exists():
        auto_upload_path_v2(
            "sendPhoto",
            "photo",
            qr_path,
            "image/png",
            f"WireGuard QR code: {safe}"
        )
    else:
        send("QR unavailable: qrencode failed or is not installed.")
# ===== END AUTO_SEND_PACKAGE_ON_CREATE_V2 =====

def handle_action(action, chat_id=None, message_id=None, callback_id=None):
    if callback_id:
        answer_callback(callback_id)

    # AUTO PACKAGE CONFIG BUTTON OVERRIDE
    if action.startswith("config:"):
        name = action.split(":", 1)[1]
        try:
            send_client_package_from_disk(name)
            text = f"✅ Sent .conf file and QR for {name}"
        except Exception as e:
            text = f"Config file/QR failed: {e}"
        kb = clients_keyboard()
        if chat_id and message_id:
            edit(chat_id, message_id, text, kb)
        else:
            send(text, kb)
        return

    # FORCE: config button must send real .conf file and QR image
    if action.startswith("config:"):
        name = action.split(":", 1)[1]
        try:
            send_client_package_from_disk(name)
            text = f"✅ Sent .conf file and QR for {name}"
        except Exception as e:
            text = f"Config file/QR failed: {e}"
        kb = clients_keyboard()
        if chat_id and message_id:
            edit(chat_id, message_id, text, kb)
        else:
            send(text, kb)
        return

    kb = back_keyboard()

    if action == "menu":
        text, kb = menu_text(), menu_keyboard()
    elif action == "status":
        text, kb = status_text(), menu_keyboard()
    elif action == "risk":
        text, kb = risk_text(), menu_keyboard()
    elif action == "peers":
        text = peers_text(False)
    elif action == "online":
        text = peers_text(True)
    elif action == "events":
        text = events_text()
    elif action == "top":
        text = top_text()
    elif action == "report":
        text, kb = report_text(), menu_keyboard()
    elif action == "clients":
        text, kb = clients_text(), clients_keyboard()
    elif action == "newclient":
        text, kb = start_wizard(), newclient_keyboard()
    elif action.startswith("wiz_mode:"):
        mode = action.split(":", 1)[1]
        text, kb = start_wizard(mode), [[{"text": "Cancel", "callback_data": "wiz_cancel"}]]
    elif action == "wiz_cancel":
        text, kb = cancel_wizard(), menu_keyboard()
    elif action == "digest":
        flush_digest(force=True)
        text, kb = "📦 Digest flushed.", menu_keyboard()
    elif action == "watchdog":
        text, kb = watchdog_text(), menu_keyboard()
    elif action == "backup":
        try:
            text = daily_backup(force=True)
        except Exception as e:
            text = f"Backup failed: {e}"
        kb = menu_keyboard()
    elif action == "quiet_toggle":
        state["quiet"] = not bool(state.get("quiet"))
        save_json(AGENT_STATE, state)
        text, kb = f"🔕 Quiet mode is now {'ON' if state['quiet'] else 'OFF'}", menu_keyboard()
    elif action.startswith("config:"):
        name = action.split(":", 1)[1]
        try:
            cfg = get_client_config(name)
            text = f"📄 Config for {name}\n\n{cfg}"
        except Exception as e:
            text = f"Error: {e}"
        kb = clients_keyboard()
    elif action.startswith("delete_confirm:"):
        name = action.split(":", 1)[1]
        text = f"⚠️ Delete client {name}?\n\nThis removes peer from WireGuard and moves .conf to deleted folder."
        kb = delete_keyboard(name)
    elif action.startswith("delete_do:"):
        name = action.split(":", 1)[1]
        try:
            r = delete_client(name)
            text = f"🗑 Deleted client: {r['name']}\nBackup: {r['backup']}"
        except Exception as e:
            text = f"Delete failed: {e}"
        kb = clients_keyboard()
    else:
        text, kb = menu_text(), menu_keyboard()

    if chat_id and message_id:
        edit(chat_id, message_id, text, kb)
    else:
        send(text, kb)

def handle_message(text, chat_id):
    if str(chat_id) != CHAT_ID:
        return

    # STEP6C4: map reply-keyboard button text to real slash commands.
    text = normalize_reply_button(text)

    if not text.startswith("/") and state.setdefault("wizard", {}).get("stage"):
        if handle_wizard_text(text):
            return

    parts = text.strip().split()
    cmd = parts[0].lower() if parts else ""

    # STEP6E clients submenu command handlers
    if cmd in ["/start", "/menu", "/help"]:
        state["reply_menu"] = "main"
        save_json(AGENT_STATE, state)
        send(menu_text())
        return

    if cmd == "/clients_menu":
        state["reply_menu"] = "clients"
        save_json(AGENT_STATE, state)
        send("🧩 Clients\nChoose an action.")
        return

    if cmd == "/clients_list":
        state["reply_menu"] = "clients"
        save_json(AGENT_STATE, state)
        send(clients_text())
        return

    if cmd == "/client_config_help":
        state["reply_menu"] = "clients"
        save_json(AGENT_STATE, state)
        send("📄 Config\nSend:\n/config_client client-name")
        return

    if cmd == "/client_delete_help":
        state["reply_menu"] = "clients"
        save_json(AGENT_STATE, state)
        send("🗑 Delete\nSend:\n/delete_client client-name\n\nDelete still requires confirmation.")
        return

    if cmd == "/cancel":
        send(cancel_wizard(), menu_keyboard())
        return

    if cmd not in COMMANDS:
        send(menu_text(), menu_keyboard())
        return

    if cmd in ["/start", "/menu", "/help"]:
        send("🛡️ Golden VPN\nMenu opened. Use the keyboard below.")
    elif cmd == "/newclient":
        send(start_wizard(), newclient_keyboard())
    elif cmd == "/status":
        send(status_text(), menu_keyboard())
    elif cmd == "/peers":
        send(peers_text(False), back_keyboard())
    elif cmd == "/online":
        send(peers_text(True), back_keyboard())
    elif cmd == "/events":
        send(events_text(), back_keyboard())
    elif cmd == "/top":
        send(top_text(), back_keyboard())
    elif cmd == "/report":
        send(report_text(), menu_keyboard())
    elif cmd == "/risk":
        send(risk_text(), menu_keyboard())
    elif cmd == "/watchdog":
        send(watchdog_text(), menu_keyboard())
    elif cmd == "/digest":
        flush_digest(force=True)
        send("📦 Digest flushed.", menu_keyboard())
    elif cmd == "/backup":
        try:
            send(daily_backup(force=True), menu_keyboard())
        except Exception as e:
            send(f"Backup failed: {e}", menu_keyboard())
    elif cmd == "/clients":
        send(clients_text(), clients_keyboard())
    elif cmd == "/dashboard":
        send(f"🌐 Dashboard:\n{DASHBOARD_URL}", [[{"text": "Open Dashboard", "url": DASHBOARD_URL}]])
    elif cmd == "/whoami":
        send(f"Your chat_id:\n{chat_id}")
    elif cmd == "/quiet":
        state["quiet"] = not bool(state.get("quiet"))
        save_json(AGENT_STATE, state)
        send(f"🔕 Quiet mode is now {'ON' if state['quiet'] else 'OFF'}", menu_keyboard())
    elif cmd == "/muted":
        send(mute_text(), menu_keyboard())
    elif cmd == "/mute":
        if len(parts) < 2:
            send("Usage:\n/mute peer 24h\n/mute peer forever", menu_keyboard())
            return
        peer = match_peer(parts[1])
        if not peer:
            send("Peer not found.", menu_keyboard())
            return
        dur = parse_duration(parts[2] if len(parts) >= 3 else "24h")
        until = -1 if dur < 0 else time.time() + dur
        state.setdefault("mutes", {})[peer["key"]] = {"until": until, "name": peer["name"]}
        save_json(AGENT_STATE, state)
        send(f"🔕 Muted {peer['name']}.", menu_keyboard())
    elif cmd == "/unmute":
        if len(parts) < 2:
            send("Usage:\n/unmute peer", menu_keyboard())
            return
        peer = match_peer(parts[1])
        if not peer:
            send("Peer not found.", menu_keyboard())
            return
        state.setdefault("mutes", {}).pop(peer["key"], None)
        save_json(AGENT_STATE, state)
        send(f"🔔 Unmuted {peer['name']}.", menu_keyboard())
    elif cmd == "/trust":
        if len(parts) < 2:
            send("Usage:\n/trust peer", menu_keyboard())
            return
        peer = match_peer(parts[1])
        if not peer:
            send("Peer not found.", menu_keyboard())
            return
        if peer["endpoint"] == "N/A":
            send("Peer has no endpoint to trust.", menu_keyboard())
            return
        state.setdefault("trusted", {})[peer["key"]] = {"name": peer["name"], "endpoint": peer["endpoint"], "time": int(time.time())}
        save_json(AGENT_STATE, state)
        send(f"✅ Trusted endpoint for {peer['name']}:\n{peer['endpoint']}", menu_keyboard())
    elif cmd in ["/add_split", "/add_full"]:
        if len(parts) < 2:
            mode = "split" if cmd == "/add_split" else "full"
            send(start_wizard(mode), [[{"text": "Cancel", "callback_data": "wiz_cancel"}]])
            return
        mode = "split" if cmd == "/add_split" else "full"
        try:
            r = create_client(parts[1], mode)
            # AUTO PACKAGE AFTER QUICK CREATE
            try:
                send_client_package_from_disk(r["name"])
            except Exception as e:
                send(f"⚠️ Client created, but sending .conf/QR failed: {e}")
            send(f"✅ Created {mode} client\n\nName: {r['name']}\nIP: {r['ip']}\nEndpoint: {r['endpoint']}\n\nGet config:\n/config_client {r['name']}", clients_keyboard())
        except Exception as e:
            send(f"Create failed: {e}", clients_keyboard())
    elif cmd == "/delete_client":
        if len(parts) < 2:
            send("Usage:\n/delete_client ten-client", clients_keyboard())
            return
        name = safe_name(parts[1])
        send(f"⚠️ Delete client {name}?", delete_keyboard(name))
    elif cmd == "/config_client":
        if len(parts) < 2:
            send("Usage:\n/config_client ten-client", clients_keyboard())
            return
        name = safe_name(parts[1])
        try:
            cfg = get_client_config(name)
            send(f"📄 Config for {name}\n\n{cfg}", clients_keyboard())
        except Exception as e:
            send(f"Config failed: {e}", clients_keyboard())
    elif cmd == "/lockdown":
        send("⚠️ Confirm lockdown?", [[{"text": "✅ Lockdown", "callback_data": "lockdown_do"}], [{"text": "Cancel", "callback_data": "menu"}]])
    elif cmd == "/unlock":
        send(unlock(), menu_keyboard())
    elif cmd == "/restart_dashboard":
        send(restart_dashboard(), menu_keyboard())

def poll_updates():
    try:
        res = tg_api("getUpdates", {"offset": state.get("offset", 0), "timeout": 1, "allowed_updates": json.dumps(["message", "callback_query"])})
        for upd in res.get("result", []):
            state["offset"] = max(state.get("offset", 0), upd["update_id"] + 1)
            if "message" in upd:
                msg = upd["message"]
                txt = msg.get("text") or ""
                chat = msg.get("chat") or {}
                if txt:
                    handle_message(txt, chat.get("id"))
            if "callback_query" in upd:
                cb = upd["callback_query"]
                msg = cb.get("message") or {}
                chat = msg.get("chat") or {}
                if str(chat.get("id")) != CHAT_ID:
                    continue
                handle_action(cb.get("data", "menu"), chat_id=chat.get("id"), message_id=msg.get("message_id"), callback_id=cb.get("id"))
        save_json(AGENT_STATE, state)
    except Exception as e:
        print("poll error:", repr(e), flush=True)

def monitor_peers():
    peers = get_peers()
    old = state.setdefault("peers", {})
    baseline_done = state.get("baseline_done", False)
    now = time.time()
    for p in peers:
        k = p["key"]
        prev = old.get(k)
        if prev and baseline_done and not is_muted(p):
            if ALERT_ENDPOINT and p["endpoint"] != "N/A" and prev.get("endpoint") not in [None, "N/A", p["endpoint"]]:
                trusted = state.setdefault("trusted", {}).get(k, {}).get("endpoint")
                severity = 3 if trusted and trusted != p["endpoint"] else 2
                add_digest("endpoint", f"New endpoint: {p['name']}", f"Old: {prev.get('endpoint')}\nNew: {p['endpoint']}\nTrusted: {trusted or 'N/A'}", severity, k)

            if ALERT_TRAFFIC_SPIKE:
                prev_total = int(prev.get("total", p["total"]))
                prev_t = float(prev.get("t", now))
                dt = max(1, now - prev_t)
                rate = max(0, (p["total"] - prev_total) / dt)
                last_spike = float(prev.get("last_spike", 0))
                if rate >= TRAFFIC_SPIKE_BYTES and now - last_spike > 900:
                    add_digest("traffic", f"Traffic spike: {p['name']}", f"Rate: {human_bytes(rate)}/s", 2, k)
                    prev["last_spike"] = now

            score, reasons = peer_risk(p)
            last_risk = int(prev.get("last_risk", 0))
            if score >= 60 and score - last_risk >= 20:
                add_digest("risk", f"Risk spike: {p['name']}", f"Risk: {score}/100\n" + "; ".join(reasons[:3]), 3, k)

        old[k] = {"name": p["name"], "online": p["online"], "endpoint": p["endpoint"], "allowed": p["allowed"], "hs": p["hs"], "total": p["total"], "t": now, "last_spike": float((prev or {}).get("last_spike", 0)), "last_risk": peer_risk(p)[0]}
    state["baseline_done"] = True
    save_json(AGENT_STATE, state)

def monitor_login_events():
    if state.get("quiet"):
        return
    events = load_json(EVENT_FILE, [])
    seen = set(state.setdefault("seen_events", []))
    new_seen = deque(maxlen=100)
    for x in state.get("seen_events", []):
        new_seen.append(x)
    for e in reversed(events[:40]):
        kind = e.get("kind", "")
        if kind == "login_failed" and not ALERT_LOGIN_FAILED:
            continue
        if kind == "login_success" and not ALERT_LOGIN_SUCCESS:
            continue
        if kind not in ["login_failed", "login_success"]:
            continue
        ident = f"{e.get('ts')}:{kind}:{e.get('message')}"
        if ident in seen:
            continue
        severity = 3 if kind == "login_failed" else 1
        add_digest("login", f"Dashboard {kind.replace('_',' ')}", f"{e.get('message','')}\nTime: {e.get('time','')}", severity)
        new_seen.append(ident)
    state["seen_events"] = list(new_seen)
    save_json(AGENT_STATE, state)

def maybe_daily_backup():
    hour = int(time.strftime("%H"))
    if hour != DAILY_BACKUP_HOUR:
        return
    try:
        msg = daily_backup(force=False)
        if "created" in msg.lower():
            add_digest("backup", "Daily backup created", msg, 1)
    except Exception as e:
        add_digest("backup", "Daily backup failed", str(e), 2)

def main():
    last_peer = 0
    last_login = 0
    last_watchdog = 0
    last_backup = 0
    while True:
        poll_updates()
        now = time.time()
        if now - last_peer >= 10:
            monitor_peers()
            last_peer = now
        if now - last_login >= 10:
            monitor_login_events()
            last_login = now
        if now - last_watchdog >= WATCHDOG_MINUTES * 60:
            run_watchdog(return_only=False)
            last_watchdog = now
        if now - last_backup >= 900:
            maybe_daily_backup()
            last_backup = now
        flush_digest(force=False)
        time.sleep(1)

# ===== EXPIRY_PACK_D_V1 =====

_original_create_client_expiry_pack = create_client
_original_handle_message_expiry_pack = handle_message
_original_handle_action_expiry_pack = handle_action
_original_start_wizard_expiry_pack = start_wizard if "start_wizard" in globals() else None
_original_handle_wizard_text_expiry_pack = handle_wizard_text if "handle_wizard_text" in globals() else None

def expiry_parse_duration(v):
    v = str(v or "").strip().lower()
    if v in ["", "none", "no", "forever", "perm", "permanent", "never"]:
        return None

    m = re.match(r"^(\d+)(m|h|d)?$", v)
    if not m:
        raise ValueError("Invalid expiry. Use 1d, 7d, 30d, 90d, or forever.")

    n = int(m.group(1))
    unit = m.group(2) or "d"

    if unit == "m":
        return int(time.time()) + n * 60
    if unit == "h":
        return int(time.time()) + n * 3600
    return int(time.time()) + n * 86400

def expiry_label(ts):
    if not ts:
        return "forever"

    try:
        ts = int(ts)
    except Exception:
        return "unknown"

    now = int(time.time())
    if ts <= now:
        return "expired"

    diff = ts - now
    d, r = divmod(diff, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)

    if d > 0:
        return f"{d}d {h}h"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"

def set_client_expiry(name, duration):
    name = safe_name(name)
    expires_at = expiry_parse_duration(duration)

    st = state
    st.setdefault("client_expiry", {})

    if expires_at is None:
        st["client_expiry"].pop(name, None)
        save_json(AGENT_STATE, st)
        return {
            "name": name,
            "expires_at": None,
            "label": "forever",
        }

    st["client_expiry"][name] = {
        "expires_at": int(expires_at),
        "label": expiry_label(expires_at),
        "created_at": int(time.time()),
        "notified_24h": False,
        "expired_handled": False,
    }
    save_json(AGENT_STATE, st)

    return {
        "name": name,
        "expires_at": int(expires_at),
        "label": expiry_label(expires_at),
    }

def get_client_expiry(name):
    name = safe_name(name)
    item = state.setdefault("client_expiry", {}).get(name)
    if not item:
        return {
            "expires_at": None,
            "label": "forever",
            "expired": False,
        }

    ts = int(item.get("expires_at", 0) or 0)
    return {
        "expires_at": ts,
        "label": expiry_label(ts),
        "expired": bool(ts and ts <= time.time()),
    }

def disable_client_for_expiry(name):
    name = safe_name(name)
    info = sec_like_client_info_for_bot(name)

    backup = backup_wg_conf("before_expire_disable_client")

    txt = Path(WG_CONF).read_text(errors="ignore")
    new_txt, removed = remove_peer_block_for_expiry(txt, info["public_key"])
    if removed:
        Path(WG_CONF).write_text(new_txt)

    try:
        subprocess.run(
            ["sudo", "wg", "set", WG_INTERFACE, "peer", info["public_key"], "remove"],
            timeout=5,
        )
    except Exception:
        pass

    state.setdefault("disabled_clients", {})[name] = {
        "time": int(time.time()),
        "reason": "expired",
        "ip": info["ip"],
        "public_key": info["public_key"],
        "backup": backup,
    }

    save_json(AGENT_STATE, state)

    return {
        "name": name,
        "backup": backup,
    }

def remove_peer_block_for_expiry(txt, public_key):
    blocks = re.split(r"(?m)(?=^\[Peer\]\s*$)", txt)
    kept = []
    removed = False

    for b in blocks:
        if "[Peer]" in b and re.search(r"(?im)^\s*PublicKey\s*=\s*" + re.escape(public_key) + r"\s*$", b):
            removed = True
            continue
        kept.append(b)

    return "".join(kept).rstrip() + "\n", removed

def sec_like_client_info_for_bot(name):
    name = safe_name(name)
    f = CLIENT_DIR / f"{name}.conf"
    if not f.exists():
        raise FileNotFoundError(str(f))

    txt = f.read_text(errors="ignore")

    priv_m = re.search(r"(?im)^\s*PrivateKey\s*=\s*(\S+)", txt)
    psk_m = re.search(r"(?im)^\s*PresharedKey\s*=\s*(\S+)", txt)
    addr_m = re.search(r"(?im)^\s*Address\s*=\s*([^,\n]+)", txt)

    if not priv_m or not psk_m or not addr_m:
        raise RuntimeError("Client config is incomplete")

    pub = sh(["wg", "pubkey"], input_text=priv_m.group(1).strip(), timeout=3)
    ip = addr_m.group(1).strip().split("/")[0]

    return {
        "name": name,
        "public_key": pub,
        "psk": psk_m.group(1).strip(),
        "ip": ip,
        "allowed_server": f"{ip}/32",
    }

def create_client(name, mode, expiry=None):
    result = _original_create_client_expiry_pack(name, mode)

    if expiry not in [None, "", "forever", "none"]:
        ex = set_client_expiry(result["name"], expiry)
        result["expiry"] = ex
    else:
        result["expiry"] = {
            "expires_at": None,
            "label": "forever",
        }

    return result

def clients_text():
    devices = dashboard_devices_for_telegram()

    if devices:
        lines = [f"🧩 Devices — {len(devices)}", ""]

        for d in devices[:12]:
            name = d.get("name") or d.get("title") or "Unknown"
            ip = d.get("ip") or d.get("primary_ip") or ""
            kind = d.get("kind") or d.get("mode") or ""
            last = d.get("last_seen") or ""
            traffic = d.get("traffic") or d.get("total_h") or ""

            online = bool(d.get("online"))
            icon = "🟢" if online else "⚫"

            badges = []
            status = str(d.get("status") or "").lower()
            risk = int(d.get("risk") or 0)
            if "backup" in str(d).lower():
                badges.append("backup")
            if risk >= 50:
                badges.append("attention")
            if status and status not in ["live", "online"]:
                badges.append(status)

            right = " · ".join(x for x in [ip, kind, last, traffic] if x)
            suffix = (" · " + " · ".join(badges[:2])) if badges else ""

            if right:
                lines.append(f"{icon} {name} · {right}{suffix}")
            else:
                lines.append(f"{icon} {name}{suffix}")

        if len(devices) > 12:
            lines.append(f"… +{len(devices)-12} more")

        lines.append("")
        lines.append("Use buttons below for New / Config / Delete.")
        return "\n".join(lines)

    # Fallback if dashboard API is unavailable.
    clients = list_clients()
    if not clients:
        return "🧩 Devices — 0\n\nNo device found."

    lines = [f"🧩 Clients — {len(clients)}", ""]
    for c in clients[:12]:
        icon = "🟢" if c.get("online") else "⚫"
        lines.append(f"{icon} {c.get('name')} · {c.get('ip') or 'no-ip'} · {c.get('mode')} · {c.get('last_seen') or 'N/A'}")
    return "\n".join(lines)


def expiring_text():
    items = []
    now = int(time.time())

    for name, item in state.setdefault("client_expiry", {}).items():
        ts = int(item.get("expires_at", 0) or 0)
        if not ts:
            continue
        items.append((ts, name))

    if not items:
        return "No expiring clients."

    items.sort()
    lines = ["⏳ Expiring clients"]

    for ts, name in items[:20]:
        status = "expired" if ts <= now else expiry_label(ts)
        lines.append(f"{name} — {status}")

    return "\n".join(lines)

def start_wizard(mode=None):
    wiz = state.setdefault("wizard", {})

    if mode:
        wiz.clear()
        wiz["stage"] = "name"
        wiz["mode"] = mode
        save_json(AGENT_STATE, state)
        return (
            f"➕ New {mode} client\n\n"
            "Send client name now.\n"
            "Example: iphone-guest"
        )

    wiz.clear()
    wiz["stage"] = "mode"
    save_json(AGENT_STATE, state)
    return "➕ New WireGuard client\n\nChoose tunnel mode:"

def expiry_keyboard():
    return [
        [
            {"text": "1 day", "callback_data": "wiz_expiry:1d"},
            {"text": "7 days", "callback_data": "wiz_expiry:7d"},
        ],
        [
            {"text": "30 days", "callback_data": "wiz_expiry:30d"},
            {"text": "90 days", "callback_data": "wiz_expiry:90d"},
        ],
        [
            {"text": "Forever", "callback_data": "wiz_expiry:forever"},
        ],
        [
            {"text": "Cancel", "callback_data": "wiz_cancel"},
        ],
    ]

def handle_wizard_text(text):
    wiz = state.setdefault("wizard", {})
    stage = wiz.get("stage")

    if stage == "name":
        try:
            name = safe_name(text.strip())
        except Exception as e:
            send(f"Invalid name: {e}")
            return True

        wiz["name"] = name
        wiz["stage"] = "expiry"
        save_json(AGENT_STATE, state)

        send(
            f"⏳ Expiry for {name}\n\n"
            "Choose expiry, or type manually: 1d / 7d / 30d / forever",
            expiry_keyboard()
        )
        return True

    if stage == "expiry":
        name = wiz.get("name")
        mode = wiz.get("mode", "split")
        duration = text.strip() or "forever"

        try:
            r = create_client(name, mode, duration)
            try:
                send_client_package_from_disk(r["name"])
            except Exception as e:
                send(f"⚠️ Client created, but sending .conf/QR failed: {e}")

            ex = r.get("expiry", {})
            send(
                f"✅ Created {mode} client\n\n"
                f"Name: {r['name']}\n"
                f"IP: {r['ip']}\n"
                f"Endpoint: {r['endpoint']}\n"
                f"Expiry: {ex.get('label','forever')}",
                clients_keyboard()
            )
        except Exception as e:
            send(f"Create failed: {e}", clients_keyboard())

        wiz.clear()
        save_json(AGENT_STATE, state)
        return True

    return False

def handle_action(action, chat_id=None, message_id=None, callback_id=None):
    if action.startswith("wiz_expiry:"):
        if callback_id:
            answer_callback(callback_id)

        duration = action.split(":", 1)[1]
        wiz = state.setdefault("wizard", {})
        name = wiz.get("name")
        mode = wiz.get("mode", "split")

        if not name:
            text = "Wizard expired. Start again with /newclient."
            kb = menu_keyboard()
        else:
            try:
                r = create_client(name, mode, duration)
                try:
                    send_client_package_from_disk(r["name"])
                except Exception as e:
                    send(f"⚠️ Client created, but sending .conf/QR failed: {e}")

                ex = r.get("expiry", {})
                text = (
                    f"✅ Created {mode} client\n\n"
                    f"Name: {r['name']}\n"
                    f"IP: {r['ip']}\n"
                    f"Endpoint: {r['endpoint']}\n"
                    f"Expiry: {ex.get('label','forever')}"
                )
                kb = clients_keyboard()
            except Exception as e:
                text = f"Create failed: {e}"
                kb = clients_keyboard()

        wiz.clear()
        save_json(AGENT_STATE, state)

        if chat_id and message_id:
            edit(chat_id, message_id, text, kb)
        else:
            send(text, kb)
        return

    return _original_handle_action_expiry_pack(action, chat_id, message_id, callback_id)

def handle_message(text, chat_id):
    if str(chat_id) != CHAT_ID:
        return

    if not text.startswith("/") and state.setdefault("wizard", {}).get("stage"):
        if handle_wizard_text(text):
            return

    parts = text.strip().split()
    cmd = parts[0].lower() if parts else ""

    if cmd == "/newclient":
        send(start_wizard(), newclient_keyboard())
        return

    if cmd in ["/add_split", "/add_full"]:
        if len(parts) < 2:
            mode = "split" if cmd == "/add_split" else "full"
            send(start_wizard(mode), [[{"text": "Cancel", "callback_data": "wiz_cancel"}]])
            return

        mode = "split" if cmd == "/add_split" else "full"
        name = parts[1]
        expiry = parts[2] if len(parts) >= 3 else "forever"

        try:
            r = create_client(name, mode, expiry)
            try:
                send_client_package_from_disk(r["name"])
            except Exception as e:
                send(f"⚠️ Client created, but sending .conf/QR failed: {e}")

            ex = r.get("expiry", {})
            send(
                f"✅ Created {mode} client\n\n"
                f"Name: {r['name']}\n"
                f"IP: {r['ip']}\n"
                f"Endpoint: {r['endpoint']}\n"
                f"Expiry: {ex.get('label','forever')}",
                clients_keyboard()
            )
        except Exception as e:
            send(f"Create failed: {e}", clients_keyboard())
        return

    if cmd == "/expiry_client":
        if len(parts) < 3:
            send("Usage:\n/expiry_client client-name 7d", clients_keyboard())
            return
        try:
            r = set_client_expiry(parts[1], parts[2])
            send(f"⏳ Expiry set\n\nClient: {r['name']}\nExpiry: {r['label']}", clients_keyboard())
        except Exception as e:
            send(f"Set expiry failed: {e}", clients_keyboard())
        return

    if cmd == "/clear_expiry":
        if len(parts) < 2:
            send("Usage:\n/clear_expiry client-name", clients_keyboard())
            return
        try:
            r = set_client_expiry(parts[1], "forever")
            send(f"✅ Expiry cleared\n\nClient: {r['name']}", clients_keyboard())
        except Exception as e:
            send(f"Clear expiry failed: {e}", clients_keyboard())
        return

    if cmd == "/expiring":
        send(expiring_text(), clients_keyboard())
        return

    return _original_handle_message_expiry_pack(text, chat_id)

def check_client_expiry():
    now = int(time.time())
    expiry = state.setdefault("client_expiry", {})
    changed = False

    for name, item in list(expiry.items()):
        ts = int(item.get("expires_at", 0) or 0)
        if not ts:
            continue

        if ts <= now and not item.get("expired_handled"):
            try:
                result = disable_client_for_expiry(name)
                item["expired_handled"] = True
                changed = True
                add_digest(
                    "expiry",
                    f"Client expired: {name}",
                    f"Client disabled automatically.\nBackup: {result.get('backup')}",
                    3,
                )
            except Exception as e:
                add_digest(
                    "expiry",
                    f"Client expiry failed: {name}",
                    str(e),
                    3,
                )

        elif 0 < ts - now <= 86400 and not item.get("notified_24h"):
            item["notified_24h"] = True
            changed = True
            add_digest(
                "expiry",
                f"Client expiring soon: {name}",
                f"Expires in {expiry_label(ts)}",
                2,
            )

    if changed:
        save_json(AGENT_STATE, state)

def main():
    last_peer = 0
    last_login = 0
    last_watchdog = 0
    last_backup = 0
    last_expiry = 0

    while True:
        poll_updates()
        now = time.time()

        if now - last_peer >= 10:
            monitor_peers()
            last_peer = now

        if now - last_login >= 10:
            monitor_login_events()
            last_login = now

        if now - last_watchdog >= WATCHDOG_MINUTES * 60:
            run_watchdog(return_only=False)
            last_watchdog = now

        if now - last_backup >= 900:
            maybe_daily_backup()
            last_backup = now

        if now - last_expiry >= 60:
            check_client_expiry()
            last_expiry = now

        flush_digest(force=False)
        time.sleep(1)
# ===== END EXPIRY_PACK_D_V1 =====

if __name__ == "__main__":
    main()
