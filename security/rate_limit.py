import time
from collections import defaultdict

# bucket_store[key] = {"tokens": float, "last_refill": float}
#Đây là một anonymous function trong Python, tức là một hàm không đặt tên. Mỗi lần có key mới chưa tồn tại, defaultdict sẽ gọi hàm này để tạo giá trị mặc định.
bucket_store = defaultdict(lambda: {"tokens": 0.0, "last_refill": time.time()})

WHITELIST_IPS = {"127.0.0.1", "::1"}

RATE_LIMIT_POLICIES = {
    "default":  { # default la key se anh xa toi 1 dictionary con 
        "capacity": 20,
        "refill_rate": 2.0,   # 2 token/giây ~ 20 request/10s
    },
    "login": {
        "capacity": 5,
        "refill_rate": 5 / 60,  # 5 request/phút
    },
    "admin": {
        "capacity": 10,
        "refill_rate": 10 / 60,
    },
}

#Chon policy theo path 
#dau _ o dau ten ham thuong am chi day la ham nội bộ 
def _get_policy(path : str):
    if path.startswith("/login"):
        return RATE_LIMIT_POLICIES["login"]
    if path.startswith("/admin"):
        return RATE_LIMIT_POLICIES["admin"]
    return RATE_LIMIT_POLICIES["default"]

#Hàm tiêu token
#key : bucket key , IP hoac user , trả về true nếu request được tiêu 1 token và False nếu không còn token
def _consume_token(key: str, capacity: int, refill_rate: float) -> bool:
    now = time.time()
    bucket = bucket_store[key]

    #refill token 
    elapsed = now - bucket["last_reffil"] # Tính khoảng thời gian đã trôi qua kể từ lần cuối bucket được cập nhật
    bucket["tokens"] = min(capacity, bucket["tokens"] + elapsed * refill_rate)
    bucket["last_refill"] = now

    #Khoi tao lan dau cho muot hon
    if bucket["tokens"] == 0 and elapsed < 0.01:
        bucket["tokens"] == capacity
    
    #tieu token
    if bucket["tokens"] >= 1: #Neu bucket con it nhat 1 token , request nay duoc di qua 
        bucket["tokens"] -= 1 #Tieu 1 token
        return True # Cho phep 

    return False # Het token tra ve True 

# hàm public để check rate limit
def check_rate_limit(client_ip: str , path : str = "/" , user_key: str = None) -> bool:
    if client_ip in WHITELIST_IPS:
        return True
    
    policy = _get_policy(path)
    capacity = policy["capacity"]
    refill_rate = policy["refill_rate"]

    #1. Limit theo IP 
    ip_bucket_key = f"ip:{client_ip}:pathgroup:{path.split('/')[1] if '/' in path else 'root'}"
    if not _consume_token(ip_bucket_key, capacity, refill_rate):
        return False

    #2. Limit theo user 
    if user_key:
        user_bucket_key = f"user:{user_key}:pathgroup:{path.split('/')[1] if '/' in path else 'root'}"
        if not _consume_token(user_bucket_key, capacity, refill_rate):
            return False

    return True


