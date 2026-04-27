import os
from dotenv import load_dotenv
load_dotenv(override=True)


def get_env(name: str, default: str = None, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(f"Thiếu biến môi trường bắt buộc: {name}")
    return value


WAF_BACKEND_URL = get_env("WAF_BACKEND_URL", "http://127.0.0.1:8000")
WAF_SHARED_SECRET = get_env("WAF_SHARED_SECRET", required=True)
WAF_ADMIN_TOKEN = get_env("WAF_ADMIN_TOKEN", required=True)

WAF_SSL_KEYFILE = get_env("WAF_SSL_KEYFILE", "key.pem")
WAF_SSL_CERTFILE = get_env("WAF_SSL_CERTFILE", "cert.pem")

WAF_HOST = get_env("WAF_HOST", "127.0.0.1")
WAF_PORT = int(get_env("WAF_PORT", "5000"))
BACKEND_HOST = get_env("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(get_env("BACKEND_PORT", "8000"))

TELEGRAM_BOT_TOKEN = get_env("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = get_env("TELEGRAM_CHAT_ID", "")
TELEGRAM_ALERT_ENABLED = get_env("TELEGRAM_ALERT_ENABLED", "false").lower() == "true"

WAF_DRY_RUN_MODE = get_env("WAF_DRY_RUN_MODE", "true").lower() == "true"

TELEGRAM_SUMMARY_ENABLED = get_env("TELEGRAM_SUMMARY_ENABLED", "false").lower() == "true"
TELEGRAM_SUMMARY_INTERVAL = int(get_env("TELEGRAM_SUMMARY_INTERVAL", "60"))