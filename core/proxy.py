import httpx
from fastapi import Request , Response
from core.dlp_analyzer import inspect_and_mask
from utils.logger import log_alert
from fastapi.responses import HTMLResponse
from config.settings import WAF_BACKEND_URL, WAF_SHARED_SECRET


async def forward_request(request: Request, path = str ,client_ip = str )-> Response:
    """Nhận request từ Client, gắn thẻ Secret và chuyển tiếp xuống Backend.
    Trả về Response của Backend cho Client."""

    target_url = f"{WAF_BACKEND_URL}/{path}"

    #1. Keo toan bo du lieu body ve 
    body = await request.body()

    # 2. Xử lý Headers: Xóa 'host' cũ và nhét Secret Key vào để mở "cửa sau" Backend
    headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
    headers["X-WAF-Secret"] = WAF_SHARED_SECRET

    #3. Thuc hien goi xuong backend 
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                params=request.query_params,
                content=body,
                headers=headers
            )
            
            #Quy trinh kiem tra luong di ra 
            response_body = resp.content
            content_type = resp.headers.get("content-type","")

            #Chi soi cac response dang van ban (HTML , Json)
            if "text" in content_type or "json" in content_type:
                try:
                    body_str = response_body.decode('utf-8')

                    #Goi may quet DLP 
                    is_blocked , result = inspect_and_mask(body_str)
                    if is_blocked:
                        log_alert(client_ip, f"DLP BLOCK - Ngăn chặn lộ lọt dữ liệu: {result}", "error")
                        return HTMLResponse(
                            content="<h1>[WAF] Lỗi 500: Server gặp sự cố (Dữ liệu nhạy cảm đã bị chặn rò rỉ)!</h1>",
                            status_code=500
                        )
                    else:
                        #Cap nhat lai body bang du lieu da duoc masking
                        response_body = result.encode('utf-8')
                except UnicodeDecodeError:
                    pass
            
            #Don dep headers 
            safe_headers = dict(resp.headers)
            #Bo thong tin lo nen tang Backend
            safe_headers.pop("server" , None) #Xoa server: apache/nginx 
            safe_headers.pop("x-powered-by", None) #Xoa PHP/Express

            #Mask data lam thay doi do dai chuoi , tinh toan lai Content-Length
            if "content-length" in safe_headers:
                safe_headers['content-length'] = str(len(response_body))
            
            return Response(
                content=response_body, 
                status_code=resp.status_code, 
                headers=safe_headers
            )

            
        except httpx.RequestError as e:
            # Bắt lỗi nếu Backend bị sập hoặc chưa bật
            return HTMLResponse(
                content=f"<h1>[WAF Error] Mất kết nối đến Backend: {e}</h1>", 
                status_code=502
            )
        