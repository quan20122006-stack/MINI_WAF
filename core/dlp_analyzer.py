import re
import json
import os 

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
config_path = os.path.join(base_dir, 'config', 'dlp_rules.json')

try:
    with open(config_path, 'r' , encoding='utf-8') as file:
        DLP_RULES = json.load(file)
except Exception:
    DLP_RULES = {"fatal_leaks": {}, "masking": {}}

def inspect_and_mask(body: str)-> tuple[bool, str]:
    """
    Quét Response Body.
    Trả về: (Có chặn không?, Tên lỗi hoặc Body đã được che giấu)
    """
    if not body:
        return False,body
    
    #Quet loi , chan request
    fatal_rules = DLP_RULES.get("fatal_leaks", {})
    for leak_type, pattern in fatal_rules.items():
        if re.search(pattern , body):
            return True, leak_type# Trả về lệnh chặn và tên lỗi
    
    #Quet du lieu nhay cam de che giau
    masking_rules = DLP_RULES.get("masking",{})
    safe_body = body
    for data_type , pattern in masking_rules.items():
        # Dùng Regex để tìm và thay thế dữ liệu nhạy cảm bằng dấu *
        safe_body = re.sub(pattern, f"[{data_type} ĐÃ BỊ WAF CHE GIẤU]", safe_body)

    return False, safe_body # Cho phép đi tiếp với Body đã được làm sạch