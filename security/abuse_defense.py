import time
import hashlib
from collections import defaultdict

FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW = 300
TEMP_BAN_SECONDS = 600
CHALLENGE_AFTER = 3 # Neu client bi nhan hanh vi 3 lan dang ngo thi he thong se yeu cau challengence vi du nhu Capcha hay JAvascript

failed_logins = defaultdict(list) #nghĩa là mỗi key sẽ có một danh sách các timestamp login sai
# vd : failed_logins["abc"] = [1713830000.1, 1713830010.5]
temporary_bans = {} #là dictionary lưu key nào đang bị ban đến thời điểm nào
# vd : temporary_bans["abc"] = 1713830600.0
challenge_scores = defaultdict(int) #nghĩa là mỗi key có một điểm nghi ngờ dạng số nguyên, mặc định là 0. Mỗi lần có hành vi lạ, điểm tăng thêm 1


def make_fingerprint(client_ip: str , user_agent: str ="") -> str:
    raw = f"{client_ip}|{user_agent}" #dùng f-string để ghép IP và User-Agent thành một chuỗi
    #Vd : "1.2.3.4|Mozilla/5.0"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
    #raw.encode() chuyển string thành bytes , hashlib.sha256(...) tạo hash SHA-256 , .hexdigest() chuyển kết quả hash thành chuỗi hex , [:16] lấy 16 ký tự đầu

def is_temporarily_banned(key: str) -> bool:
    ban_until = temporary_bans.get(key) #Xem key nay co bi ban hay khong ?
    if not ban_until:
        return False 
    if time.time() > ban_until: #Nếu thời gian hiện tại đã vượt qua thời điểm hết ban, lệnh ban đã hết hiệu lực.
        del temporary_bans[key] #xoá luôn key khỏi temporary_bans
        return False
    
    return True

def temporary_ban(key: str):
    temporary_bans[key] = time.time() + TEMP_BAN_SECONDS
    #time.time() là thời gian hiện tại. Cộng thêm TEMP_BAN_SECONDS để ra thời điểm kết thúc ban.

#ham nay Nó ghi nhận một lần login thất bại cho key, đồng thời kiểm tra xem key đó đã vượt ngưỡng chưa.
def record_failed_login(key: str) -> bool:
    now = time.time()
    #Nó tạo một list mới chỉ giữ lại các timestamp còn nằm trong cửa sổ 300 giây.
    failed_logins[key] = [
    t for t in failed_logins[key]
    if now - t < FAILED_LOGIN_WINDOW
    ]
    failed_logins[key].append(now) #thêm lần login sai hiện tại vào danh sách.

    if len(failed_logins[key]) >= FAILED_LOGIN_LIMIT: #nếu số lần fail trong cửa sổ hiện tại đạt hoặc vượt 5
        temporary_ban(key) #ban key
        failed_logins[key].clear() #xoá danh sách lỗi login sau khi ban
        return True #trả về True để báo rằng hành động ban vừa được kích hoạt.
    
    return False

#nếu một người nhập sai vài lần rồi nhập đúng, ta không nên giữ mãi điểm xấu của họ. Xoá failure giúp tránh false positive.
def clear_login_failures(key : str):
    failed_logins.pop(key, None)

#Hàm này tăng điểm nghi ngờ cho key.
def record_suspicious_behavior(key: str) -> bool:
    challenge_scores[key] += 1
    return challenge_scores[key] >= CHALLENGE_AFTER
    #Nếu score đạt từ 3 trở lên, trả về True. Điều này có nghĩa là client nên bị challenge.

#Hàm này xoá điểm nghi ngờ của key.
def reset_suspicious_behavior(key: str):
    challenge_scores.pop(key, None)
