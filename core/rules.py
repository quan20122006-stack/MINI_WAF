import json
import os

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
config_path = os.path.join(base_dir, "config", "rules.json")

WAF_STATE = {
    "DRY_RUN_MODE": True,
    "RULES": {},
    "DISABLED_RULES": []
}


def load_rules():
    """Đọc file JSON và nạp vào RAM"""
    try:
        with open(config_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        WAF_STATE["RULES"] = data
        WAF_STATE["DISABLED_RULES"] = data.get("disabled_rules", [])
        return True
    except Exception as e:
        print(f"[!] Lỗi tải luật: {e}")
        return False


def save_rules():
    """Ghi trạng thái hiện tại từ RAM xuống file"""
    try:
        data_to_save = dict(WAF_STATE.get("RULES", {}))
        data_to_save["disabled_rules"] = WAF_STATE.get("DISABLED_RULES", [])

        with open(config_path, "w", encoding="utf-8") as file:
            json.dump(data_to_save, file, indent=4, ensure_ascii=False)

        return True
    except Exception as e:
        print(f"[!] Lỗi lưu luật: {e}")
        return False


load_rules()