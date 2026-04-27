import requests
import json
from security.ip_filter import ban_ip

THREAT_URL = "https://example.com/bad_ips.txt"  # danh sách IP mỗi dòng 1 IP

def fetch_and_block():
    resp = requests.get(THREAT_URL, timeout=10)
    if resp.status_code == 200:
        ips = resp.text.splitlines()
        for ip in ips:
            ban_ip(ip.strip())
    else:
        print("Cannot fetch threat IPs", resp.status_code)

if __name__ == "__main__":
    fetch_and_block()