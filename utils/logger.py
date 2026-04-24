import logging
import os
import json
import time 
from datetime import datetime

# 1. Tìm đường dẫn lưu file log
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_file = os.path.join(base_dir, 'waf_alerts.log')

# 2. Tạo Formatter định dạng JSON
class JsonFormatter(logging.Formatter):
    def format(self, record):
        # Tạo một dictionary chứa cấu trúc log
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "request_id": getattr(record,"request_id" , "N/A"),
            "action": getattr(record, "action", "UNKNOWN"),
            "rule_hit": getattr(record, "rule_hit", "None"),
            "upstream_status": getattr(record, "upstream_status", 0),
            "level": record.levelname,
            "client_ip": getattr(record, "client_ip", "Unknown"), # Lấy biến IP được truyền vào
            "message": record.getMessage()
        }
        # Chuyển đổi thành chuỗi JSON (giữ nguyên tiếng Việt với ensure_ascii=False)
        return json.dumps(log_data, ensure_ascii=False)

# 3. Khởi tạo Logger
logger = logging.getLogger("WAF_Logger")
logger.setLevel(logging.INFO)

# Cấu hình ghi ra file
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setFormatter(JsonFormatter(datefmt='%Y-%m-%d %H:%M:%S'))
# Tránh việc log bị nhân đôi khi FastAPI dùng chế độ reload
if not logger.handlers:
    logger.addHandler(file_handler)

# 4. Hàm tiện ích để gọi ở main.py
def log_alert(ip: str, message: str, level: str = 'info'):
    extra_data = {'client_ip': ip}
    
    if level == 'warning':
        logger.warning(message, extra=extra_data)
    elif level == 'error':
        logger.error(message, extra=extra_data)
    else:
        logger.info(message, extra=extra_data)

#5. He thong canh bao ra quet 
block_history = []
ALERT_THRESHOLD = 5  # Báo động nếu có 5 request bị chặn...
ALERT_WINDOW = 60    # ...trong vòng 60 giây.
def trigger_webhook():
    # Trong thực tế, bạn sẽ dùng requests.post() bắn API Telegram/Slack ở đây
    print("\n" + "="*60)
    print("[ALERT_FIRE] BÁO ĐỘNG ĐỎ TỪ WAF!")
    print(f"Phát hiện rà quét diện rộng: Vượt ngưỡng {ALERT_THRESHOLD} blocks/{ALERT_WINDOW}s.")
    print("-> Đã tự động gửi thông báo đến Telegram của đội Blue Team SOC.")
    print("="*60 + "\n")

# 3. Hàm ghi log trung tâm
def log_event(req_id: str, ip: str, action: str, rule_hit: str, message: str, upstream_status: int = 0, level: str = 'info'):
    extra_data = {
        'request_id': req_id,
        'client_ip': ip,
        'action': action,
        'rule_hit': rule_hit,
        'upstream_status': upstream_status
    }
    
    if level == 'warning' or action == 'BLOCKED':
        logger.warning(message, extra=extra_data)
        
        # --- Logic đếm Alert ---
        global block_history
        current_time = time.time()
        block_history.append(current_time)
        # Lọc bỏ các block đã cũ (quá 60 giây)
        block_history = [t for t in block_history if current_time - t < ALERT_WINDOW]
        
        # Chỉ báo động 1 lần khi vừa chạm ngưỡng để tránh spam tin nhắn
        if len(block_history) == ALERT_THRESHOLD:
            trigger_webhook()
            
    elif level == 'error':
        logger.error(message, extra=extra_data)
    else:
        logger.info(message, extra=extra_data)