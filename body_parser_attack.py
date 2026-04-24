import requests
import json

WAF_URL = "http://localhost:5000/api/test"

print("BẮT ĐẦU CHIẾN DỊCH KIỂM TRA SMART PARSER")

#Ki thuat ep kieu unicode trong json 
json_payload = {"username": "admin", "bio": "\u003Cscript\u003Ealert(1)\u003C/script\u003E"}
res1 = requests.post(WAF_URL, json = json_payload)
print(f"-> Ket qua: {res1.status_code}")
if res1.status_code == 403:
    print("Tan cong that bai ")

#TEST 2 : Gui form data binh thuong
print("\n[Test 2] Gửi payload SQLi qua Form-Data truyền thống...")
form_payload = {"username": "admin", "password": "' OR 1=1 --"}
res2 = requests.post(WAF_URL, data=form_payload)
print(f"-> Kết quả: {res2.status_code}")
if res2.status_code == 403:
    print("WAF da chan SQLi")

#Test3: Gui file upload chua ma doc
#Nhet chu script vao 1 file .txt
print("\n[Test 3] Gửi File Upload chứa mã XSS bên trong nội dung file...")
files = {'profile_picture': ('malware.txt', '<script>Tôi là virus</script>', 'text/plain')}
data_fields = {'description': 'Đây là ảnh đại diện của tôi'}
res3 = requests.post(WAF_URL, files=files, data=data_fields)
print(f"-> Kết quả: {res3.status_code}")
# Nếu backend không có route /api/test nó sẽ trả về 404, hoặc 200 tùy bạn set.
# Điều quan trọng là WAF KHÔNG TRẢ VỀ 403!
if res3.status_code != 403:
    print("WAF quet thanh cong , ngan chan tan cong")



