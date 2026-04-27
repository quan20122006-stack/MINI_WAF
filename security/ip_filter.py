from fastapi import Request
from pathlib import Path
import json


TRUSTED_PROXIES = {"10.0.0.254", "192.168.1.100"}
BLACKLIST_IPS = {"192.168.1.50", "10.0.0.5"}

BANNED_FILE = Path("config/banned_ips.json")

WAF_STATE = {
    "banned_ips": set()
}


def get_real_ip(request: Request) -> str:
    physical_ip = request.client.host

    if physical_ip in TRUSTED_PROXIES:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return physical_ip


def load_banned_ips():
    if BANNED_FILE.exists():
        with open(BANNED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        WAF_STATE["banned_ips"] = set(data.get("blocked", []))
    else:
        WAF_STATE["banned_ips"] = set()
        _save_banned_ips()


def _save_banned_ips():
    BANNED_FILE.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "blocked": sorted(WAF_STATE["banned_ips"])
    }

    with open(BANNED_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def ban_ip(ip: str):
    WAF_STATE["banned_ips"].add(ip)
    _save_banned_ips()


def unban_ip(ip: str):
    WAF_STATE["banned_ips"].discard(ip)
    _save_banned_ips()


def list_banned_ips():
    return sorted(WAF_STATE["banned_ips"])


def is_ip_blocked(ip: str) -> bool:
    return ip in BLACKLIST_IPS or ip in WAF_STATE["banned_ips"]


load_banned_ips()