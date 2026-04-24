import uvicorn
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from core.rules import WAF_STATE
from admin.api import admin_router
from security.ip_filter import get_real_ip, is_ip_blocked
from security.rate_limit import check_rate_limit
from core.analyzer import analyze_payload
from core.proxy import forward_request
from utils.logger import log_event

from core.request_inspector import collect_request_surfaces
from core.body_parser import inspect_uploaded_files


app = FastAPI(title="Mini-WAF")
app.include_router(admin_router)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def waf_entry_point(request: Request, path: str):

    # =========================
    # INIT
    # =========================
    req_id = str(uuid.uuid4())
    client_ip = get_real_ip(request)

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

    # =========================
    # 1. LAYER 3/4 DEFENSE
    # =========================
    if is_ip_blocked(client_ip):
        log_event(req_id, client_ip, "BLOCKED", "IP_Blacklist", "Truy cập từ IP Blacklist", level="warning")
        return block_page("IP của bạn đã bị khóa!", 403)

    user_key = None

    # ví dụ đơn giản: nếu request login có query username
    if request.url.path.startswith("/login"):
        user_key = request.query_params.get("username")

    if not check_rate_limit(client_ip, path=request.url.path, user_key=user_key):
        log_event(req_id, client_ip, "BLOCKED", "Rate_Limit", "Vượt quá giới hạn truy cập", level="warning")
        return block_page("Vui lòng truy cập chậm lại!", 429)

    # =========================
    # 2. URL + QUERY
    # =========================
    if attack_type := analyze_payload(str(request.url), path=request.url.path, method=request.method):
        if WAF_STATE.get("DRY_RUN_MODE", True):
            log_event(req_id, client_ip, "DETECTED", attack_type, "URL (Dry-run)", level="warning")
        else:
            log_event(req_id, client_ip, "BLOCKED", attack_type, "URL", level="warning")
            return block_page(f"Tấn công {attack_type} qua URL", 403)

    for key, value in request.query_params.items():
        if attack_type := analyze_payload(value, path=request.url.path, method=request.method):
            if WAF_STATE.get("DRY_RUN_MODE", True):
                log_event(req_id, client_ip, "DETECTED", attack_type, f"Query: {key} (Dry-run)", level="warning")
            else:
                log_event(req_id, client_ip, "BLOCKED", attack_type, f"Query: {key}", level="warning")
                return block_page(f"Tấn công {attack_type} qua query", 403)

    # =========================
    # 3. COLLECT ALL SURFACES
    # =========================
    surfaces = await collect_request_surfaces(request)

    # HEADERS
    for name, value in surfaces["headers"]:
        if attack_type := analyze_payload(value, path=request.url.path, method=request.method):
            if WAF_STATE.get("DRY_RUN_MODE", True):
                log_event(req_id, client_ip, "DETECTED", attack_type, f"Header: {name}", level="warning")
            else:
                log_event(req_id, client_ip, "BLOCKED", attack_type, f"Header: {name}", level="warning")
                return block_page(f"Tấn công {attack_type} qua header", 403)

    # COOKIES
    for name, value in surfaces["cookies"]:
        if attack_type := analyze_payload(value, path=request.url.path, method=request.method):
            if WAF_STATE.get("DRY_RUN_MODE", True):
                log_event(req_id, client_ip, "DETECTED", attack_type, f"Cookie: {name}", level="warning")
            else:
                log_event(req_id, client_ip, "BLOCKED", attack_type, f"Cookie: {name}", level="warning")
                return block_page(f"Tấn công {attack_type} qua cookie", 403)

    # FIELD NAMES
    for field in surfaces["field_names"]:
        if attack_type := analyze_payload(field, path=request.url.path, method=request.method):
            if WAF_STATE.get("DRY_RUN_MODE", True):
                log_event(req_id, client_ip, "DETECTED", attack_type, "Field name", level="warning")
            else:
                log_event(req_id, client_ip, "BLOCKED", attack_type, "Field name", level="warning")
                return block_page(f"Tấn công {attack_type} qua field name", 403)

    # VALUES
    for val in surfaces["values"]:
        if attack_type := analyze_payload(val, path=request.url.path, method=request.method):
            if WAF_STATE.get("DRY_RUN_MODE", True):
                log_event(req_id, client_ip, "DETECTED", attack_type, "Body", level="warning")
            else:
                log_event(req_id, client_ip, "BLOCKED", attack_type, "Body", level="warning")
                return block_page(f"Tấn công {attack_type} qua dữ liệu", 403)

    # FILENAMES
    for filename in surfaces["filenames"]:
        if attack_type := analyze_payload(filename, path=request.url.path, method=request.method):
            if WAF_STATE.get("DRY_RUN_MODE", True):
                log_event(req_id, client_ip, "DETECTED", attack_type, "Filename", level="warning")
            else:
                log_event(req_id, client_ip, "BLOCKED", attack_type, "Filename", level="warning")
                return block_page(f"Tấn công {attack_type} qua filename", 403)

    # METADATA
    for meta in surfaces["metadata"]:
        if attack_type := analyze_payload(meta, path=request.url.path, method=request.method):
            if WAF_STATE.get("DRY_RUN_MODE", True):
                log_event(req_id, client_ip, "DETECTED", attack_type, "Metadata", level="warning")
            else:
                log_event(req_id, client_ip, "BLOCKED", attack_type, "Metadata", level="warning")
                return block_page(f"Tấn công {attack_type} qua metadata", 403)

    # ANOMALY
    for anomaly in surfaces["anomalies"]:
        if WAF_STATE.get("DRY_RUN_MODE", True):
            log_event(req_id, client_ip, "DETECTED", anomaly, "Request anomaly", level="warning")
        else:
            log_event(req_id, client_ip, "BLOCKED", anomaly, "Request anomaly", level="warning")
            return block_page(f"Request bất thường: {anomaly}", 400)

    # =========================
    # 4. FILE SCAN RIÊNG
    # =========================
    file_threat = await inspect_uploaded_files(request)

    if file_threat:
        if WAF_STATE.get("DRY_RUN_MODE", True):
            log_event(req_id, client_ip, "DETECTED", file_threat, "File upload", level="warning")
        else:
            log_event(req_id, client_ip, "BLOCKED", file_threat, "File upload", level="warning")
            return block_page(f"File bị từ chối: {file_threat}", 403)

    # =========================
    # 5. FORWARD
    # =========================
    response = await forward_request(request, path, client_ip)

    log_event(
        req_id,
        client_ip,
        "PASSED",
        "None",
        f"Truy cập thành công /{path}",
        upstream_status=response.status_code,
        level="info"
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