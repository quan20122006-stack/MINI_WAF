import json
import time
import httpx
import threading
from collections import defaultdict
from security.ip_filter import ban_ip, unban_ip , list_banned_ips

from config.settings import (
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    TELEGRAM_ALERT_ENABLED,
    TELEGRAM_SUMMARY_ENABLED,
    TELEGRAM_SUMMARY_INTERVAL,
)
SUMMARY_RUNTIME_ENABLED = TELEGRAM_SUMMARY_ENABLED

# =========================
# FILE LOGGING
# =========================
def _now_iso():
    from datetime import datetime
    return datetime.utcnow().isoformat() + "Z"


def _write_json(file, data):
    with open(file, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")


ACCESS_LOG = "logs/waf_access.log"
SECURITY_LOG = "logs/waf_security.log"
INCIDENT_LOG = "logs/waf_incidents.log"

# =========================
# TELEGRAM
# =========================
def send_telegram_alert(text: str):
    if not TELEGRAM_ALERT_ENABLED:
        return

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[TELEGRAM] missing config")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    try:
        with httpx.Client(timeout=5) as client:
            resp = client.post(url, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
            })
        print("[TELEGRAM]", resp.status_code, resp.text)
    except Exception as e:
        print("[TELEGRAM ERROR]", e)


# =========================
# ANTI-SPAM
# =========================
LAST_ALERT_TIME = {}
ALERT_COOLDOWN = 60  # seconds


def should_alert(key: str):
    now = time.time()
    last = LAST_ALERT_TIME.get(key, 0)

    if now - last < ALERT_COOLDOWN:
        return False

    LAST_ALERT_TIME[key] = now
    return True


# =========================
# SUMMARY DATA
# =========================
SUMMARY = {
    "start": time.time(),
    "ip_hits": defaultdict(int),
    "rule_hits": defaultdict(int),
    "blocked": 0,
    "detected": 0,
}


def update_summary(client_ip, rule_hit, action):
    if client_ip:
        SUMMARY["ip_hits"][client_ip] += 1

    if rule_hit and rule_hit != "None":
        SUMMARY["rule_hits"][rule_hit] += 1

    if action == "BLOCKED":
        SUMMARY["blocked"] += 1

    elif action == "DETECTED":
        SUMMARY["detected"] += 1

def build_summary_text():
    duration = int(time.time() - SUMMARY["start"])

    top_ips = sorted(SUMMARY["ip_hits"].items(), key=lambda x: x[1], reverse=True)[:3]
    top_rules = sorted(SUMMARY["rule_hits"].items(), key=lambda x: x[1], reverse=True)[:3]

    text = f"📊 WAF Summary ({duration}s)\n\n"

    text += "Top IP:\n"
    for ip, count in top_ips:
        text += f"- {ip}: {count}\n"

    text += "\nTop Rule:\n"
    for rule, count in top_rules:
        text += f"- {rule}: {count}\n"

    text += f"\nBlocked: {SUMMARY['blocked']}"
    text += f"\nDetected: {SUMMARY['detected']}"

    return text


def reset_summary():
    SUMMARY["start"] = time.time()
    SUMMARY["ip_hits"].clear()
    SUMMARY["rule_hits"].clear()
    SUMMARY["blocked"] = 0
    SUMMARY["detected"] = 0


# =========================
# TELEGRAM POLLING (/stats)
# =========================
LAST_UPDATE_ID = 0


def telegram_polling():
    global LAST_UPDATE_ID
    global SUMMARY_RUNTIME_ENABLED

    if not TELEGRAM_ALERT_ENABLED:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"

    try:
        with httpx.Client(timeout=5) as client:
            resp = client.get(url, params={"offset": LAST_UPDATE_ID + 1})
            data = resp.json()

        for update in data.get("result", []):
            LAST_UPDATE_ID = update["update_id"]

            msg = update.get("message", {})
            text = msg.get("text", "").strip()
            chat_id = str(msg.get("chat", {}).get("id", ""))

            # chỉ nhận lệnh từ đúng chat_id của bạn
            if chat_id != str(TELEGRAM_CHAT_ID):
                continue

            if text == "/stats":
                send_telegram_alert(build_summary_text())

            elif text == "/summary_on":
                SUMMARY_RUNTIME_ENABLED = True
                send_telegram_alert("✅ Đã bật WAF summary định kỳ")

            elif text == "/summary_off":
                SUMMARY_RUNTIME_ENABLED = False
                send_telegram_alert("🔕 Đã tắt WAF summary định kỳ")

            elif text.startswith("/ban "):
                ip = text.split(" ", 1)[1].strip()
                ban_ip(ip)
                send_telegram_alert(f"🚫 Đã ban IP: {ip}")

            elif text.startswith("/unban "):
                ip = text.split(" ", 1)[1].strip()
                unban_ip(ip)
                send_telegram_alert(f"✅ Đã unban IP: {ip}")

            elif text == "/bans":
                banned = list_banned_ips()
                if banned:
                    send_telegram_alert("🚫 Banned IPs:\n" + "\n".join(banned))
                else:
                    send_telegram_alert("✅ Không có IP runtime nào đang bị ban")

            elif text == "/help":
                send_telegram_alert(
                    "Mini-WAF commands:\n"
                    "/stats - xem thống kê hiện tại\n"
                    "/summary_on - bật summary định kỳ\n"
                    "/summary_off - tắt summary định kỳ\n"
                    "/ban <ip> - ban IP\n"
                    "/unban <ip> - gỡ ban IP\n"
                    "/bans - xem IP đang bị ban\n"
                    "/help - xem lệnh"
                )

    except Exception as e:
        print("[TELEGRAM POLL ERROR]", e)

# =========================
# BACKGROUND TASKS
# =========================
def start_background_tasks():
    def summary_loop():
        while True:
            time.sleep(TELEGRAM_SUMMARY_INTERVAL)

            if SUMMARY_RUNTIME_ENABLED:
                send_telegram_alert(build_summary_text())
                reset_summary()

    def command_loop():
        while True:
            time.sleep(2)
            telegram_polling()

    threading.Thread(target=summary_loop, daemon=True).start()
    threading.Thread(target=command_loop, daemon=True).start()

# =========================
# MAIN LOG FUNCTION
# =========================
def log_event(request_id, client_ip, action, rule_hit, message, **kwargs):
    data = {
        "timestamp": _now_iso(),
        "request_id": request_id,
        "client_ip": client_ip,
        "action": action,
        "rule_hit": rule_hit,
        "message": message,
        **kwargs
    }

    # write log
    _write_json(ACCESS_LOG, data)

    if action in ["BLOCKED", "DETECTED"]:
        _write_json(SECURITY_LOG, data)

    update_summary(client_ip, rule_hit, action)

    # ALERT logic
    if action == "BLOCKED":
        key = f"{client_ip}:{rule_hit}"

        if should_alert(key):
            send_telegram_alert(
                f"🚨 BLOCKED\nIP: {client_ip}\nRule: {rule_hit}\nPath: {kwargs.get('path')}"
            )

def log_alert(request_id, client_ip, rule_hit, message, severity="error", path=None):
    data = {
        "timestamp": _now_iso(),
        "request_id": request_id,
        "client_ip": client_ip,
        "action": "ALERT",
        "rule_hit": rule_hit,
        "message": message,
        "severity": severity,
        "path": path,
    }

    _write_json(SECURITY_LOG, data)
    _write_json(INCIDENT_LOG, data)

    key = f"alert:{rule_hit}:{client_ip}"

    if should_alert(key):
        send_telegram_alert(
            f"🚨 WAF ALERT\n"
            f"Severity: {severity}\n"
            f"IP: {client_ip}\n"
            f"Rule: {rule_hit}\n"
            f"Path: {path}\n"
            f"Message: {message}"
        )