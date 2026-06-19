#!/usr/bin/env python3
# GOLDEN_VPN_AGENT_2026_LTS

import os
import re
import json
import time
import tarfile
import shutil
import signal
import socket
import urllib.parse
import urllib.request
import subprocess
from pathlib import Path
from datetime import datetime

APP = Path("/opt/wg-golden")
STATE = APP / "state"
LOGS = APP / "logs"
BACKUPS = APP / "backups" / "agent"

ENV_FILE = Path("/etc/wg-golden.env")
WG_CONF = Path(os.environ.get("WG_CONF", "/etc/wireguard/wg0.conf"))
CLIENTS = Path("/etc/wireguard/clients")
DELETED = CLIENTS / "deleted"

AGENT_STATE = STATE / "agent_state.json"
AGENT_EVENTS = STATE / "agent_events.jsonl"
AGENT_CONFIG = STATE / "agent_config.json"
LTS_STATE = STATE / "lts_state.json"
LOG_FILE = LOGS / "agent.log"

for d in [STATE, LOGS, BACKUPS]:
    d.mkdir(parents=True, exist_ok=True)

RUNNING = True

DEFAULT_CONFIG = {
    "interval_seconds": 60,
    "stale_seconds": 86400,
    "offline_seconds": 300,
    "risk_alert_threshold": 50,
    "traffic_spike_bytes": 10485760,
    "telegram_enabled": True,
    "alert_endpoint_change": True,
    "alert_online_offline": True,
    "alert_stale": True,
    "alert_traffic_spike": False,
    "daily_report_enabled": True,
    "daily_report_hour": 8,
    "daily_backup_enabled": True,
    "daily_backup_hour": 3,
    "auto_mode": False,
    "event_throttle_seconds": 1800
}

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def log(msg):
    line = f"{now_iso()} {msg}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def load_env():
    if ENV_FILE.exists():
        for raw in ENV_FILE.read_text(errors="ignore").splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

def jload(path, default):
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else default
    except Exception:
        return default

def jsave(path, data):
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    tmp.replace(path)

def config():
    cfg = DEFAULT_CONFIG.copy()
    disk = jload(AGENT_CONFIG, {})
    cfg.update(disk)
    if not AGENT_CONFIG.exists():
        jsave(AGENT_CONFIG, cfg)
    return cfg

def sh(cmd, input_text=None, timeout=10):
    return subprocess.check_output(
        list(cmd),
        input=input_text,
        text=True,
        stderr=subprocess.STDOUT,
        timeout=timeout
    ).strip()

def human_bytes(n):
    try:
        n = float(n)
    except Exception:
        n = 0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
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

def read_wg_conf():
    try:
        return WG_CONF.read_text(errors="ignore")
    except Exception:
        return ""

def pub_from_client_file(path):
    try:
        raw = Path(path).read_text(errors="ignore")
        m = re.search(r"(?im)^\s*PrivateKey\s*=\s*(\S+)", raw)
        if not m:
            return ""
        return sh(["wg", "pubkey"], input_text=m.group(1), timeout=5)
    except Exception:
        return ""

def clean_deleted_name(path):
    name = path.stem
    name = re.sub(r"\.rotated\.\d{4}-\d{2}-\d{2}_\d{6}$", "", name)
    name = re.sub(r"\.\d{4}-\d{2}-\d{2}_\d{6}$", "", name)
    return name

def peer_name_map():
    out = {}

    lts = jload(LTS_STATE, {})
    out.update(lts.get("peer_names", {}) or {})

    cur = None
    for line in read_wg_conf().splitlines():
        m = re.match(r"\s*#+\s*Client:\s*(.+)", line, re.I)
        if m:
            cur = m.group(1).strip()
            continue
        m = re.match(r"\s*PublicKey\s*=\s*(\S+)", line, re.I)
        if m and cur:
            out.setdefault(m.group(1).strip(), cur)
            cur = None

    for base in [CLIENTS, DELETED]:
        try:
            files = sorted(base.glob("*.conf"), key=lambda x: x.stat().st_mtime, reverse=True)
            for f in files:
                pub = pub_from_client_file(f)
                if not pub:
                    continue
                name = f.stem if base == CLIENTS else clean_deleted_name(f)
                if name and not name.lower().startswith("test"):
                    out.setdefault(pub, name)
        except Exception:
            pass

    return out

def trusted_map():
    return (jload(LTS_STATE, {}).get("trusted", {}) or {})

def muted_map():
    return (jload(LTS_STATE, {}).get("mutes", {}) or {})

def get_peers():
    names = peer_name_map()
    trusted = trusted_map()
    muted = muted_map()
    now_ts = int(time.time())
    peers = []

    try:
        dump = sh(["wg", "show", "wg0", "dump"], timeout=8)
    except Exception as e:
        log(f"wg dump error: {e}")
        return []

    lines = dump.splitlines()
    if len(lines) <= 1:
        return []

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue

        key = parts[0]
        endpoint = parts[2] if parts[2] != "(none)" else "N/A"
        allowed = parts[3]
        hs = int(parts[4] or 0)
        rx = int(parts[5] or 0)
        tx = int(parts[6] or 0)
        keepalive = parts[7]

        ip = allowed.split(",")[0].split("/")[0] if allowed else ""
        age = now_ts - hs if hs else None
        offline_limit = int(config().get("offline_seconds", 300))
        stale_limit = int(config().get("stale_seconds", 86400))

        if not hs:
            status = "NEVER"
            online = False
        elif age <= 180:
            status = "LIVE"
            online = True
        elif age <= offline_limit:
            status = "RECENT"
            online = False
        elif age <= stale_limit:
            status = "SLEEPING"
            online = False
        else:
            status = "STALE"
            online = False

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

        reasons = []
        risk = 0
        tr = trusted.get(key, "")

        if endpoint != "N/A" and not tr:
            risk += 12
            reasons.append("endpoint not trusted")

        if tr and endpoint != "N/A" and not same_endpoint_host(endpoint, tr):
            risk += 35
            reasons.append("endpoint host changed from trusted")

        if status == "NEVER":
            risk += 15
            reasons.append("never connected")
        elif status == "STALE":
            risk += 35
            reasons.append("stale over threshold")
        elif status == "SLEEPING":
            risk += 8
            reasons.append("sleeping/offline")
        elif status == "RECENT":
            reasons.append("recently seen")

        mu = muted.get(key, 0)
        is_muted = bool(mu == -1 or mu > time.time())
        if is_muted:
            risk = max(0, risk - 20)
            reasons.append("muted")

        if not reasons:
            reasons = ["normal"]

        peers.append({
            "name": name,
            "public_key": key,
            "kid": key[:12],
            "endpoint": endpoint,
            "allowed_ips": allowed,
            "primary_ip": ip,
            "handshake": hs,
            "last_seen": human_age(hs),
            "online": online,
            "status": status,
            "rx": rx,
            "tx": tx,
            "total": rx + tx,
            "rx_h": human_bytes(rx),
            "tx_h": human_bytes(tx),
            "total_h": human_bytes(rx + tx),
            "risk": min(100, risk),
            "risk_level": "Critical" if risk >= 80 else "Warning" if risk >= 50 else "Watch" if risk >= 25 else "Normal",
            "reasons": reasons,
            "trusted_endpoint": tr,
            "muted": is_muted,
            "keepalive": keepalive,
        })

    return sorted(peers, key=lambda p: (not p["online"], -p["risk"], p["name"].lower()))


# STEP6B1_AGENT_HOST_ONLY_2026
def endpoint_host(endpoint):
    if not endpoint or endpoint == "N/A":
        return ""
    ep = str(endpoint).strip()
    if ep.startswith("[") and "]" in ep:
        return ep[1:ep.index("]")]
    if ":" in ep:
        return ep.rsplit(":", 1)[0]
    return ep

def same_endpoint_host(a, b):
    ha = endpoint_host(a)
    hb = endpoint_host(b)
    return bool(ha and hb and ha == hb)
# END STEP6B1_AGENT_HOST_ONLY_2026


def send_telegram(text):
    cfg = config()
    if not cfg.get("telegram_enabled"):
        return False

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    if not token or not chat:
        return False

    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat,
            "text": text,
            "disable_web_page_preview": "true"
        }).encode()
        urllib.request.urlopen(url, data=data, timeout=12).read()
        return True
    except Exception as e:
        log(f"telegram error: {e}")
        return False

def event_key(kind, peer):
    return f"{kind}:{peer.get('public_key','')[:16]}"

def should_throttle(state, key):
    cfg = config()
    now_ts = int(time.time())
    last = state.setdefault("throttle", {}).get(key, 0)
    if now_ts - int(last or 0) < int(cfg["event_throttle_seconds"]):
        return True
    state["throttle"][key] = now_ts
    return False

def add_event(state, kind, severity, title, detail="", peer=None, notify=True):
    ev = {
        "ts": int(time.time()),
        "time": now_iso(),
        "kind": kind,
        "severity": severity,
        "title": title,
        "detail": detail,
        "peer": peer or {},
    }

    with AGENT_EVENTS.open("a") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    state.setdefault("events_recent", []).insert(0, ev)
    state["events_recent"] = state["events_recent"][:100]

    log(f"EVENT {severity} {kind}: {title} {detail}")

    if notify:
        text = f"🟡 Golden VPN Agent\n{severity.upper()} · {kind}\n{title}"
        if detail:
            text += f"\n{detail}"
        send_telegram(text)

def summarize(peers):
    return {
        "peers": len(peers),
        "online": sum(1 for p in peers if p["online"]),
        "recent": sum(1 for p in peers if p["status"] == "RECENT"),
        "sleeping": sum(1 for p in peers if p["status"] == "SLEEPING"),
        "stale": sum(1 for p in peers if p["status"] == "STALE"),
        "never": sum(1 for p in peers if p["status"] == "NEVER"),
        "highrisk": sum(1 for p in peers if p["risk"] >= config()["risk_alert_threshold"]),
        "traffic_total": sum(p["total"] for p in peers),
        "traffic_total_h": human_bytes(sum(p["total"] for p in peers)),
    }

def analyze(prev_state, peers):
    cfg = config()
    previous = {p["public_key"]: p for p in prev_state.get("peers", [])}
    state = prev_state

    for p in peers:
        old = previous.get(p["public_key"])
        key = p["public_key"]

        if old:
            if cfg.get("alert_online_offline"):
                if not old.get("online") and p["online"]:
                    ek = event_key("peer_online", p)
                    if not should_throttle(state, ek):
                        add_event(state, "peer_online", "info", f"{p['name']} online", f"{p['primary_ip']} · {p['endpoint']}", p)

                if old.get("online") and not p["online"]:
                    ek = event_key("peer_offline", p)
                    if not should_throttle(state, ek):
                        add_event(state, "peer_offline", "info", f"{p['name']} offline", f"Last seen {p['last_seen']}", p)

            if cfg.get("alert_endpoint_change"):
                old_ep = old.get("endpoint")
                new_ep = p.get("endpoint")
                if old_ep and new_ep and old_ep != "N/A" and new_ep != "N/A" and not same_endpoint_host(old_ep, new_ep):
                    ek = event_key("endpoint_changed", p)
                    if not should_throttle(state, ek):
                        add_event(state, "endpoint_changed", "warning", f"{p['name']} endpoint host changed", f"{endpoint_host(old_ep)} → {endpoint_host(new_ep)}", p)

            if cfg.get("alert_traffic_spike"):
                delta = int(p.get("total", 0)) - int(old.get("total", 0))
                if delta >= int(cfg["traffic_spike_bytes"]):
                    ek = event_key("traffic_spike", p)
                    if not should_throttle(state, ek):
                        add_event(state, "traffic_spike", "warning", f"{p['name']} traffic spike", f"+{human_bytes(delta)} in interval", p)
        else:
            ek = event_key("peer_seen", p)
            if not should_throttle(state, ek):
                add_event(state, "peer_seen", "info", f"{p['name']} detected", f"{p['primary_ip']} · {p['endpoint']}", p, notify=False)

        # STEP6B1: avoid duplicate critical spam. Host/IP change is handled once by endpoint_changed.
        if False and cfg.get("alert_endpoint_change") and p.get("trusted_endpoint") and p.get("endpoint") != "N/A" and p["endpoint"] != p["trusted_endpoint"]:
            ek = event_key("trusted_endpoint_mismatch", p)
            if not should_throttle(state, ek):
                add_event(state, "trusted_endpoint_mismatch", "critical", f"{p['name']} endpoint differs from trusted", f"trusted={p['trusted_endpoint']} current={p['endpoint']}", p)

        if cfg.get("alert_stale") and p["status"] in ["STALE", "NEVER"]:
            ek = event_key("peer_stale", p)
            if not should_throttle(state, ek):
                add_event(state, "peer_stale", "warning", f"{p['name']} {p['status']}", f"Last seen {p['last_seen']} · risk {p['risk']}", p)

        if p["risk"] >= int(cfg["risk_alert_threshold"]):
            ek = event_key("high_risk", p)
            if not should_throttle(state, ek):
                add_event(state, "high_risk", "warning", f"{p['name']} high risk", f"risk={p['risk']} · {', '.join(p['reasons'])}", p)

def daily_backup(state):
    cfg = config()
    if not cfg.get("daily_backup_enabled"):
        return

    hour = int(cfg.get("daily_backup_hour", 3))
    now = datetime.now()
    today_key = now.strftime("%Y-%m-%d")

    if now.hour != hour:
        return

    if state.get("last_backup_day") == today_key:
        return

    name = f"agent_backup_{today_key}_{now.strftime('%H%M%S')}.tgz"
    dest = BACKUPS / name

    try:
        with tarfile.open(dest, "w:gz") as tar:
            if WG_CONF.exists():
                tar.add(WG_CONF, arcname="wg0.conf")
            if CLIENTS.exists():
                tar.add(CLIENTS, arcname="clients")
            if LTS_STATE.exists():
                tar.add(LTS_STATE, arcname="lts_state.json")
            if AGENT_STATE.exists():
                tar.add(AGENT_STATE, arcname="agent_state.json")
            if AGENT_CONFIG.exists():
                tar.add(AGENT_CONFIG, arcname="agent_config.json")

        dest.chmod(0o600)
        state["last_backup_day"] = today_key

        # STEP6B2: keep latest 7 agent backups only.
        try:
            old_backups = sorted(BACKUPS.glob("*agent_backup_*.tgz"), key=lambda x: x.stat().st_mtime, reverse=True)
            for old_file in old_backups[7:]:
                old_file.unlink(missing_ok=True)
        except Exception as e:
            log(f"agent backup prune warning: {e}")

        add_event(state, "daily_backup", "info", "Daily backup created", str(dest), notify=False)
        # STEP6B2: quiet daily backup success; no Telegram spam.
    except Exception as e:
        add_event(state, "daily_backup_error", "error", "Daily backup failed", str(e))

def daily_report(state, peers):
    cfg = config()
    if not cfg.get("daily_report_enabled"):
        return

    hour = int(cfg.get("daily_report_hour", 8))
    now = datetime.now()
    today_key = now.strftime("%Y-%m-%d")

    if now.hour != hour:
        return

    if state.get("last_report_day") == today_key:
        return

    s = summarize(peers)
    top = sorted(peers, key=lambda p: p["total"], reverse=True)[:5]
    top_lines = "\n".join([f"- {p['name']}: {p['total_h']} · {p['status']} · risk {p['risk']}" for p in top])

    text = (
        "📅 Golden VPN Agent Daily Report\n"
        f"Peers: {s['peers']}\n"
        f"Online: {s['online']}\n"
        f"High risk: {s['highrisk']}\n"
        f"Stale: {s['stale']}\n"
        f"Never: {s['never']}\n"
        f"Traffic total: {s['traffic_total_h']}\n\n"
        f"Top traffic:\n{top_lines or 'No peers'}"
    )

    send_telegram(text)
    state["last_report_day"] = today_key
    add_event(state, "daily_report", "info", "Daily report sent", notify=False)


# ===== GOLDEN_VPN_AGENT_COMPLETE_2026 =====
def _complete_service_status(name):
    try:
        active = _final = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=2
        ).stdout.strip()
    except Exception:
        active = "unknown"

    try:
        enabled = subprocess.run(
            ["systemctl", "is-enabled", name],
            capture_output=True,
            text=True,
            timeout=2
        ).stdout.strip()
    except Exception:
        enabled = "unknown"

    return {"name": name, "active": active, "enabled": enabled, "ok": active == "active"}

def _complete_recommendations(peers):
    recs = []

    for p in peers:
        name = p.get("name", "Unknown")
        status = p.get("status", "")
        risk = int(p.get("risk", 0) or 0)
        reasons = ", ".join(p.get("reasons", []) or [])
        endpoint = p.get("endpoint", "N/A")
        trusted = p.get("trusted_endpoint", "")

        if risk >= 80:
            recs.append({
                "level": "critical",
                "title": f"Review {name} immediately",
                "detail": f"Risk {risk}. Reasons: {reasons}",
                "action": "Manual review before any change"
            })
        elif risk >= 50:
            recs.append({
                "level": "warning",
                "title": f"Watch {name}",
                "detail": f"Risk {risk}. Reasons: {reasons}",
                "action": "Check endpoint, trust only if expected"
            })

        if endpoint != "N/A" and not trusted and status in ["LIVE", "RECENT"]:
            recs.append({
                "level": "info",
                "title": f"{name} endpoint not trusted yet",
                "detail": endpoint,
                "action": "Use Trust in Security Center if this endpoint is expected"
            })

        if status == "STALE":
            recs.append({
                "level": "warning",
                "title": f"{name} is stale",
                "detail": f"Last seen {p.get('last_seen')}. Traffic {p.get('total_h')}",
                "action": "Keep if backup device, otherwise rotate/delete manually"
            })

        if status == "NEVER":
            recs.append({
                "level": "info",
                "title": f"{name} never connected",
                "detail": p.get("allowed_ips", ""),
                "action": "Check if this device is still needed"
            })

    if not recs:
        recs.append({
            "level": "ok",
            "title": "VPN looks healthy",
            "detail": "No urgent Agent recommendation.",
            "action": "Keep monitoring"
        })

    return recs[:12]

def _complete_agent_health(peers):
    dash = _complete_service_status("wg-golden")
    agent = _complete_service_status("wg-golden-agent")
    wgquick = _complete_service_status("wg-quick@wg0")

    high = sum(1 for p in peers if int(p.get("risk", 0) or 0) >= 50)
    online = sum(1 for p in peers if p.get("online"))
    stale = sum(1 for p in peers if p.get("status") == "STALE")
    never = sum(1 for p in peers if p.get("status") == "NEVER")

    score = 100
    if not dash["ok"]: score -= 35
    if not agent["ok"]: score -= 35
    if not wgquick["ok"]: score -= 35
    score -= min(30, high * 10)
    score -= min(20, stale * 5)
    score -= min(10, never * 3)
    score = max(0, min(100, score))

    return {
        "score": score,
        "level": "excellent" if score >= 90 else "good" if score >= 75 else "watch" if score >= 55 else "critical",
        "services": {
            "dashboard": dash,
            "agent": agent,
            "wireguard": wgquick,
        },
        "online": online,
        "highrisk": high,
        "stale": stale,
        "never": never,
    }
# ===== END GOLDEN_VPN_AGENT_COMPLETE_2026 =====

def write_state(state, peers):
    state["app"] = "GOLDEN_VPN_AGENT_2026_LTS"
    state["hostname"] = socket.gethostname()
    state["updated_at"] = now_iso()
    state["updated_ts"] = int(time.time())
    state["safe_mode"] = not bool(config().get("auto_mode"))
    state["config"] = config()
    state["summary"] = summarize(peers)
    state["recommendations"] = _complete_recommendations(peers)
    state["health"] = _complete_agent_health(peers)
    state["agent_version"] = "GOLDEN_VPN_AGENT_COMPLETE_2026"
    state["peers"] = peers
    jsave(AGENT_STATE, state)

def one_cycle():
    load_env()
    state = jload(AGENT_STATE, {})
    peers = get_peers()

    analyze(state, peers)
    daily_backup(state)
    daily_report(state, peers)
    write_state(state, peers)

def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False
    log(f"signal {signum}, stopping")

def main():
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    load_env()
    cfg = config()
    log("Golden VPN Agent 2026 LTS started")
    add_start = not AGENT_STATE.exists()

    if add_start:
        st = jload(AGENT_STATE, {})
        add_event(st, "agent_start", "info", "Golden VPN Agent started", "Safe Mode", notify=False)
        jsave(AGENT_STATE, st)

    while RUNNING:
        try:
            one_cycle()
        except Exception as e:
            log(f"cycle error: {e}")
            try:
                st = jload(AGENT_STATE, {})
                add_event(st, "agent_error", "error", "Agent cycle error", str(e))
                jsave(AGENT_STATE, st)
            except Exception:
                pass

        sleep_for = int(config().get("interval_seconds", 60))
        for _ in range(max(1, sleep_for)):
            if not RUNNING:
                break
            time.sleep(1)

    log("Golden VPN Agent stopped")

if __name__ == "__main__":
    main()

# GOLDEN_VPN_AGENT_FINAL_POLISH_2026
