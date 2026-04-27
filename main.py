import uvicorn
import uuid
import time
import asyncio

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from utils.fetch_threat_ips import fetch_and_block

from core.rules import WAF_STATE
from admin.api import admin_router
from security.ip_filter import get_real_ip , is_ip_blocked
from security.rate_limit import check_rate_limit
from core.analyzer import analyze_payload
from core.proxy import forward_request
from utils.logger import log_event

from core.request_inspector import collect_request_surfaces
from core.body_parser import inspect_uploaded_files
from security.abuse_defense import (
    make_fingerprint,
    is_temporarily_banned,
    record_suspicious_behavior,
)
from utils.logger import start_background_tasks


app = FastAPI(title="Mini-WAF")
app.include_router(admin_router)

@app.on_event("startup")
async def startup():
    start_background_tasks()

async def threat_updater():
    while True:
        fetch_and_block()
        await asyncio.sleep(1800)  # 30 phút


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def waf_entry_point(request: Request, path: str):
    # =========================
    # INIT
    # =========================
    start_time = time.perf_counter()

    req_id = str(uuid.uuid4())
    client_ip = get_real_ip(request)
    user_agent = request.headers.get("user-agent", "")
    fingerprint = make_fingerprint(client_ip, user_agent)
    dry_run = WAF_STATE.get("DRY_RUN_MODE", True)

    def get_latency_ms():
        return round((time.perf_counter() - start_time) * 1000, 2)

    def block_page(reason: str, code: int):
        html = f"""
        <div style='font-family: Arial; padding: 20px;'>
            <h1 style='color: red;'>[WAF] KẾT NỐI BỊ TỪ CHỐI</h1>
            <p>Lý do: <b>{reason}</b></p>
            <hr>
            <p style='color: gray; font-size: 12px;'>
                Nếu bạn cho rằng đây là sự nhầm lẫn, vui lòng liên hệ IT Helpdesk.<br>
                <b>Mã truy vết (Request ID):</b> {req_id}
            </p>
        </div>
        """
        return HTMLResponse(content=html, status_code=code)

    def waf_log(action, rule_hit, message, level="info", surface=None, decision=None, upstream_status=None):
        log_event(
            req_id,
            client_ip,
            action,
            rule_hit,
            message,
            upstream_status=upstream_status,
            level=level,
            path=request.url.path,
            method=request.method,
            user_agent=user_agent,
            fingerprint=fingerprint,
            surface=surface,
            decision=decision,
            dry_run_mode=dry_run,
            latency_ms=get_latency_ms(),
        )

    def suspicious_score():
        if record_suspicious_behavior(fingerprint):
            waf_log(
                "DETECTED",
                "Challenge_Required",
                "Fingerprint vượt ngưỡng nghi ngờ",
                level="warning",
                surface="behavior",
                decision="challenge"
            )

    # =========================
    # 1. LAYER 3/4 DEFENSE
    # =========================
    if is_ip_blocked(client_ip):
        waf_log(
            "BLOCKED",
            "IP_Blacklist",
            "Truy cập từ IP Blacklist",
            level="warning",
            surface="ip",
            decision="block"
        )
        return block_page("IP của bạn đã bị khóa!", 403)

    if is_temporarily_banned(client_ip) or is_temporarily_banned(fingerprint):
        waf_log(
            "BLOCKED",
            "Temporary_Ban",
            "IP/Fingerprint đang bị ban tạm thời",
            level="warning",
            surface="behavior",
            decision="ban"
        )
        return block_page("Bạn đang bị khóa tạm thời do hành vi bất thường", 403)

    user_key = None
    if request.url.path.startswith("/login"):
        user_key = request.query_params.get("username")

    if not check_rate_limit(client_ip, path=request.url.path, user_key=user_key):
        waf_log(
            "BLOCKED",
            "Rate_Limit",
            "Vượt quá giới hạn truy cập",
            level="warning",
            surface="rate_limit",
            decision="block"
        )
        return block_page("Vui lòng truy cập chậm lại!", 429)

    # =========================
    # 2. URL + QUERY
    # =========================
    if attack_type := analyze_payload(str(request.url), path=request.url.path, method=request.method):
        if dry_run:
            waf_log(
                "DETECTED",
                attack_type,
                "Phát hiện mã độc trên URL",
                level="warning",
                surface="url",
                decision="detect"
            )
            suspicious_score()
        else:
            waf_log(
                "BLOCKED",
                attack_type,
                "Phát hiện mã độc trên URL",
                level="warning",
                surface="url",
                decision="block"
            )
            return block_page(f"Tấn công {attack_type} qua URL", 403)

    for key, value in request.query_params.items():
        if attack_type := analyze_payload(value, path=request.url.path, method=request.method):
            if dry_run:
                waf_log(
                    "DETECTED",
                    attack_type,
                    f"Mã độc ở query param: {key}",
                    level="warning",
                    surface="query",
                    decision="detect"
                )
                suspicious_score()
            else:
                waf_log(
                    "BLOCKED",
                    attack_type,
                    f"Mã độc ở query param: {key}",
                    level="warning",
                    surface="query",
                    decision="block"
                )
                return block_page(f"Tấn công {attack_type} qua query", 403)

    # =========================
    # 3. COLLECT ALL SURFACES
    # =========================
    surfaces = await collect_request_surfaces(request)

    # HEADERS
    for name, value in surfaces["headers"]:
        if attack_type := analyze_payload(value, path=request.url.path, method=request.method):
            if dry_run:
                waf_log(
                    "DETECTED",
                    attack_type,
                    f"Mã độc trong header: {name}",
                    level="warning",
                    surface="header",
                    decision="detect"
                )
                suspicious_score()
            else:
                waf_log(
                    "BLOCKED",
                    attack_type,
                    f"Mã độc trong header: {name}",
                    level="warning",
                    surface="header",
                    decision="block"
                )
                return block_page(f"Tấn công {attack_type} qua header", 403)

    # COOKIES
    for name, value in surfaces["cookies"]:
        if attack_type := analyze_payload(value, path=request.url.path, method=request.method):
            if dry_run:
                waf_log(
                    "DETECTED",
                    attack_type,
                    f"Mã độc trong cookie: {name}",
                    level="warning",
                    surface="cookie",
                    decision="detect"
                )
                suspicious_score()
            else:
                waf_log(
                    "BLOCKED",
                    attack_type,
                    f"Mã độc trong cookie: {name}",
                    level="warning",
                    surface="cookie",
                    decision="block"
                )
                return block_page(f"Tấn công {attack_type} qua cookie", 403)

    # FIELD NAMES
    for field in surfaces["field_names"]:
        if attack_type := analyze_payload(field, path=request.url.path, method=request.method):
            if dry_run:
                waf_log(
                    "DETECTED",
                    attack_type,
                    f"Mã độc trong field name: {field}",
                    level="warning",
                    surface="field_name",
                    decision="detect"
                )
                suspicious_score()
            else:
                waf_log(
                    "BLOCKED",
                    attack_type,
                    f"Mã độc trong field name: {field}",
                    level="warning",
                    surface="field_name",
                    decision="block"
                )
                return block_page(f"Tấn công {attack_type} qua field name", 403)

    # VALUES
    for val in surfaces["values"]:
        if attack_type := analyze_payload(val, path=request.url.path, method=request.method):
            if dry_run:
                waf_log(
                    "DETECTED",
                    attack_type,
                    "Mã độc trong body/value",
                    level="warning",
                    surface="value",
                    decision="detect"
                )
                suspicious_score()
            else:
                waf_log(
                    "BLOCKED",
                    attack_type,
                    "Mã độc trong body/value",
                    level="warning",
                    surface="value",
                    decision="block"
                )
                return block_page(f"Tấn công {attack_type} qua dữ liệu", 403)

    # FILENAMES
    for filename in surfaces["filenames"]:
        if attack_type := analyze_payload(filename, path=request.url.path, method=request.method):
            if dry_run:
                waf_log(
                    "DETECTED",
                    attack_type,
                    f"Mã độc trong filename: {filename}",
                    level="warning",
                    surface="filename",
                    decision="detect"
                )
                suspicious_score()
            else:
                waf_log(
                    "BLOCKED",
                    attack_type,
                    f"Mã độc trong filename: {filename}",
                    level="warning",
                    surface="filename",
                    decision="block"
                )
                return block_page(f"Tấn công {attack_type} qua filename", 403)

    # METADATA
    for meta in surfaces["metadata"]:
        if attack_type := analyze_payload(meta, path=request.url.path, method=request.method):
            if dry_run:
                waf_log(
                    "DETECTED",
                    attack_type,
                    f"Mã độc trong metadata: {meta}",
                    level="warning",
                    surface="metadata",
                    decision="detect"
                )
                suspicious_score()
            else:
                waf_log(
                    "BLOCKED",
                    attack_type,
                    f"Mã độc trong metadata: {meta}",
                    level="warning",
                    surface="metadata",
                    decision="block"
                )
                return block_page(f"Tấn công {attack_type} qua metadata", 403)

    # ANOMALY
    for anomaly in surfaces["anomalies"]:
        if dry_run:
            waf_log(
                "DETECTED",
                anomaly,
                f"Request anomaly: {anomaly}",
                level="warning",
                surface="anomaly",
                decision="detect"
            )
            suspicious_score()
        else:
            waf_log(
                "BLOCKED",
                anomaly,
                f"Request anomaly: {anomaly}",
                level="warning",
                surface="anomaly",
                decision="block"
            )
            return block_page(f"Request bất thường: {anomaly}", 400)

    # =========================
    # 4. FILE SCAN RIÊNG
    # =========================
    file_threat = await inspect_uploaded_files(request)

    if file_threat:
        if dry_run:
            waf_log(
                "DETECTED",
                file_threat,
                "File upload đáng ngờ",
                level="warning",
                surface="file",
                decision="detect"
            )
            suspicious_score()
        else:
            waf_log(
                "BLOCKED",
                file_threat,
                "File upload đáng ngờ",
                level="warning",
                surface="file",
                decision="block"
            )
            return block_page(f"File bị từ chối: {file_threat}", 403)

    # =========================
    # 5. FORWARD
    # =========================
    response = await forward_request(request, path, client_ip)

    waf_log(
        "PASSED",
        "None",
        f"Truy cập thành công /{path}",
        upstream_status=response.status_code,
        level="info",
        surface="request",
        decision="allow"
    )

    return response


if __name__ == "__main__":
    print("[*] Khởi động WAF...")
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=5000,
        reload=True,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem"
    )