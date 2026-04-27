from fastapi import FastAPI , Request , Header , HTTPException , Response
import uvicorn
from fastapi.responses import HTMLResponse 
from pydantic import BaseModel
import httpx 
from config.settings import WAF_SHARED_SECRET

app = FastAPI()

# Định nghĩa một mật khẩu bí mật chỉ WAF và Backend biết


#Dinh nghia cau truc Json 
class login_data(BaseModel):
    username: str
    password: str

@app.get("/")
async def home():
    return{"message" : "backend is running"}

@app.get("/search")
async def search(q: str = "", x_waf_secret: str = Header(None)):
    # KIỂM TRA BẢO VỆ CỬA SAU
    if x_waf_secret != WAF_SHARED_SECRET :
        # Nếu không có thẻ hoặc thẻ sai -> Đuổi cổ (403 Forbidden)
        raise HTTPException(status_code=403, detail="[Backend] LỖI: Truy cập trực tiếp bị từ chối! Vui lòng đi qua WAF.")
        
    # Trả về kết quả nếu hợp lệ
    return f"Bạn đang tìm kiếm: {q}"

@app.post("/login")
async def login(data: login_data, x_waf_secret: str = Header(None)):
    if x_waf_secret != WAF_SHARED_SECRET:
        raise HTTPException(status_code=403, detail="[Backend] LỖI: Đi cửa sau!")
    return {"status": "success", "message": f"Chào mừng {data.username} đã đăng nhập!"}

@app.get("/test-dlp", response_class=HTMLResponse)
async def test_dlp():
    return "Đây là mã thẻ của tôi: 1234-5678-9012-3456. Xin đừng nói cho ai biết. Lỗi tại thư mục /var/www/html/app.py" 

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)