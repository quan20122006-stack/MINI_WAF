from fastapi import Request

# Cấu hình danh sách IP (Sau này có thể chuyển vào config.json hoặc Database)
TRUSTED_PROXIES = {"10.0.0.254", "192.168.1.100"} 
BLACKLIST_IPS = {"192.168.1.50", "10.0.0.5"}

def get_real_ip(request: Request) -> str:
    """
    Lấy IP thật của người dùng, có cơ chế chống giả mạo IP (IP Spoofing)
    """
    physical_ip = request.client.host
    
    # Chỉ tin tưởng Header X-Forwarded-For nếu IP kết nối vật lý là một Proxy quen thuộc
    if physical_ip in TRUSTED_PROXIES:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Lấy IP đầu tiên trong chuỗi (IP của người dùng gốc)
            return forwarded_for.split(",")[0].strip()
            
    return physical_ip

def is_ip_blocked(ip: str) -> bool:
    """
    Kiểm tra xem IP có nằm trong danh sách đen không.
    """
    return ip in BLACKLIST_IPS

RUNTIME_BLACKLIST_IPS = set()


def ban_ip(ip: str):
    RUNTIME_BLACKLIST_IPS.add(ip)


def unban_ip(ip: str):
    RUNTIME_BLACKLIST_IPS.discard(ip)


def list_banned_ips():
    return sorted(RUNTIME_BLACKLIST_IPS)


def is_ip_blocked(ip: str) -> bool:
    return ip in BLACKLIST_IPS or ip in RUNTIME_BLACKLIST_IPS