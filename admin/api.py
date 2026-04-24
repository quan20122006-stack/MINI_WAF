from fastapi import APIRouter, Header, HTTPException, Body
# Giả sử WAF_STATE được import từ core.rules
from core.rules import WAF_STATE, load_rules, save_rules
from config.settings import WAF_ADMIN_TOKEN
# Tạo một luồng API riêng không đụng hàng với WAF
admin_router = APIRouter(prefix="/admin/api/v1")

def verify_admin(x_admin_token: str):
    """Hàm kiểm tra quyền truy cập Admin"""
    if x_admin_token != WAF_ADMIN_TOKEN:
        raise HTTPException(
            status_code=403, 
            detail="[Admin] Sai Token! Cút ngay!"
        )

@admin_router.get("/status")
def get_status(x_admin_token: str = Header(None)):
    verify_admin(x_admin_token)
    return {
        "dry_run_mode": WAF_STATE.get("DRY_RUN_MODE", True),
        "disabled_rules": WAF_STATE.get("DISABLED_RULES", [])
    }

@admin_router.post("/mode")
def set_mode(dry_run: bool = Body(..., embed=True), x_admin_token: str = Header(None)):
    """API chuyển đổi giữa Dry-Run và Strict Mode"""
    verify_admin(x_admin_token)
    WAF_STATE["DRY_RUN_MODE"] = dry_run
    return {"message": f"Thành công! DRY_RUN_MODE = {dry_run}"}

@admin_router.post("/rules/toggle")
def toggle_rule(
    rule_name: str = Body(...), 
    enable: bool = Body(...), 
    x_admin_token: str = Header(None)
):
    """API Bật/Tắt luật và Hot-Reload"""
    verify_admin(x_admin_token)
    
    # Khởi tạo danh sách nếu chưa tồn tại
    if "DISABLED_RULES" not in WAF_STATE:
        WAF_STATE["DISABLED_RULES"] = []
    
    disabled = WAF_STATE["DISABLED_RULES"]

    if enable:
        # Nếu muốn Bật (enable=True) thì xóa khỏi danh sách cấm
        if rule_name in disabled:
            disabled.remove(rule_name)
    else:
        # Nếu muốn Tắt (enable=False) thì thêm vào danh sách cấm
        if rule_name not in disabled:
            disabled.append(rule_name)

    # Lưu xuống ổ cứng (File JSON)
    save_rules()
    # Nạp lại vào RAM ngay lập tức mà không cần tắt Server
    load_rules()
    
    status = "BẬT" if enable else "TẮT"
    return {"message": f"Đã {status} luật {rule_name}"}

@admin_router.post("/reload")
def hot_reload(x_admin_token: str = Header(None)):
    """API ép WAF đọc lại file config trên ổ cứng"""
    verify_admin(x_admin_token)
    success = load_rules()
    if success:
        return {"message": "Hot-Reload thành công!"}
    raise HTTPException(status_code=500, detail="Lỗi nạp luật từ file config!")