import os #os dùng để xử lý đường dẫn file/thư mục
import json
import time
import logging
from logging.handlers import RotatingFileHandler #logging và RotatingFileHandler dùng để ghi log ra file
from collections import defaultdict, deque
from datetime import datetime

# =========================
# PATHS
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs") #tạo đường dẫn tới thư mục logs
os.makedirs(LOG_DIR, exist_ok=True)

ACCESS_LOG_FILE = os.path.join(LOG_DIR, "waf_access.log") #waf_access.log dành cho request bình thường, ví dụ request được allow.
SECURITY_LOG_FILE = os.path.join(LOG_DIR, "waf_security.log") #waf_security.log dành cho sự kiện bảo mật, ví dụ detect rule, block, warning, error.
INCIDENT_LOG_FILE = os.path.join(LOG_DIR, "waf_incidents.log") #dành cho incident/alert, tức là sự kiện đáng chú ý hơn log thường.

# =========================
# LOGGER SETUP
# =========================
def _build_logger(name: str, file_path: str):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = RotatingFileHandler(
            file_path,
            maxBytes=2 * 1024 * 1024,   # 2MB
            backupCount=3,
            encoding="utf-8"
        )
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


access_logger = _build_logger("waf_access", ACCESS_LOG_FILE)
security_logger = _build_logger("waf_security", SECURITY_LOG_FILE)
incident_logger = _build_logger("waf_incident", INCIDENT_LOG_FILE)

# =========================
# ALERT MEMORY
# =========================
recent_blocks = deque()
recent_rule_hits = defaultdict(deque)

BLOCK_ALERT_THRESHOLD = 5
RULE_ALERT_THRESHOLD = 5
ALERT_WINDOW_SECONDS = 60


def _now_iso(): #Tạo timestamp ISO : 2026-04-26T12:30:45.123456
    return datetime.utcnow().isoformat() + "Z"


def _cleanup_old_events(queue_obj, now_ts: float):
    while queue_obj and now_ts - queue_obj[0] > ALERT_WINDOW_SECONDS:
        queue_obj.popleft()


def _write_json(logger_obj, payload: dict):
    logger_obj.info(json.dumps(payload, ensure_ascii=False))


def trigger_webhook(event_type: str, payload: dict):
    """
    Lab mode: hiện tại ghi ra incident log + print.
    Sau này có thể thay bằng Telegram / Discord / Slack webhook thật.
    """
    incident_record = {
        "timestamp": _now_iso(),
        "event_type": event_type,
        "payload": payload
    }
    _write_json(incident_logger, incident_record)
    print(f"[ALERT] {event_type}: {json.dumps(payload, ensure_ascii=False)}")


def maybe_alert_on_block(client_ip: str, rule_hit: str, path: str = None):
    now_ts = time.time()

    recent_blocks.append(now_ts)
    _cleanup_old_events(recent_blocks, now_ts)

    if len(recent_blocks) >= BLOCK_ALERT_THRESHOLD:
        trigger_webhook(
            "HIGH_BLOCK_RATE",
            {
                "client_ip": client_ip,
                "rule_hit": rule_hit,
                "path": path,
                "window_seconds": ALERT_WINDOW_SECONDS,
                "count": len(recent_blocks),
            }
        )

    if rule_hit:
        dq = recent_rule_hits[rule_hit]
        dq.append(now_ts)
        _cleanup_old_events(dq, now_ts)

        if len(dq) >= RULE_ALERT_THRESHOLD:
            trigger_webhook(
                "RULE_HIT_SPIKE",
                {
                    "client_ip": client_ip,
                    "rule_hit": rule_hit,
                    "path": path,
                    "window_seconds": ALERT_WINDOW_SECONDS,
                    "count": len(dq),
                }
            )


def log_event(
    request_id: str,
    client_ip: str,
    action: str,
    rule_hit: str,
    message: str,
    upstream_status: int = None,
    level: str = "info",
    path: str = None,
    method: str = None,
    user_agent: str = None,
    fingerprint: str = None,
    surface: str = None,
    decision: str = None,
    dry_run_mode: bool = None,
    latency_ms: float = None,
):
    payload = {
        "timestamp": _now_iso(),
        "request_id": request_id,
        "client_ip": client_ip,
        "action": action,              # PASSED / DETECTED / BLOCKED
        "rule_hit": rule_hit,
        "message": message,
        "upstream_status": upstream_status,
        "level": level,
        "path": path,
        "method": method,
        "user_agent": user_agent,
        "fingerprint": fingerprint,
        "surface": surface,            # url/query/header/cookie/value/filename/metadata/anomaly/file/response
        "decision": decision,          # allow/detect/block/mask/challenge/ban
        "dry_run_mode": dry_run_mode,
        "latency_ms": latency_ms,
    }

    is_security_event = action in {"DETECTED", "BLOCKED"} or level in {"warning", "error"}

    if is_security_event:
        _write_json(security_logger, payload)
    else:
        _write_json(access_logger, payload)

    if action == "BLOCKED":
        maybe_alert_on_block(client_ip, rule_hit, path)


def log_admin_event(
    request_id: str,
    client_ip: str,
    action: str,
    message: str,
    admin_path: str = None,
    success: bool = True,
):
    payload = {
        "timestamp": _now_iso(),
        "request_id": request_id,
        "client_ip": client_ip,
        "action": action,
        "message": message,
        "admin_path": admin_path,
        "success": success,
        "category": "admin_audit"
    }

    _write_json(security_logger, payload)

    if not success:
        trigger_webhook(
            "ADMIN_AUDIT_FAILURE",
            {
                "client_ip": client_ip,
                "admin_path": admin_path,
                "message": message,
            }
        )


def log_alert(request_id: str, client_ip: str, rule_hit: str, message: str, severity: str = "error", path: str = None):
    payload = {
        "timestamp": _now_iso(),
        "request_id": request_id,
        "client_ip": client_ip,
        "rule_hit": rule_hit,
        "message": message,
        "severity": severity,
        "path": path,
        "category": "explicit_alert"
    }

    _write_json(security_logger, payload)
    trigger_webhook(
        "EXPLICIT_ALERT",
        {
            "client_ip": client_ip,
            "rule_hit": rule_hit,
            "message": message,
            "severity": severity,
            "path": path,
        }
    )