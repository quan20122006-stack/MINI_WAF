import json
from fastapi import Request

SUSPICIOUS_HEADER = {
    "user-agent", #gia mao client
    "referer", #gia mao nguon truy cap 
    "x-forwarded-for", #nguon truy cap
    "x-original-url", # bypass routing
    "x-rewrite-url", #bypass routing
    "cookie", # du lieu trang thai , tojen
    "content-type", #kieu du lieu body
}

async def collect_request_surfaces(request: Request) -> dict:
    surfaces = {
        "headers": [],
        "cookies" : [],
        "field_names": [],
        "values": [],
        "filenames": [],
        "metadata": [],
        "anomalies": [],
    }
    content_type = request.headers.get("content-type","").lower()

    #1. Headers 
    for header_name, header_value in request.headers.items():
        if header_name.lower() in SUSPICIOUS_HEADER:
            surfaces["headers"].append((header_name, header_value))
    
    #2. Cookies 
    for cookie_name , cookie_value in request.cookies.items():
        surfaces["cookies"].append((cookie_name, cookie_value))
    
    #3 Content-Type
    if request.method in {"POST" , "PUT" , "PATCH"}:
        body = await request.body()
        if body and not content_type:
            surfaces["anomalies"].append("Missing_Content_Type_With_Body")
    
    if "multipart/form-data" in content_type and "boundary=" not in content_type:
        surfaces["anomalies"].append("Multipart_Missing_boundary")

    #4, Body parsing
    try: 
        if "application/json" in content_type:
            body = await request.body()
            if body:
                data = json.loads(body)
                _extract_json_surfaces(data, surfaces)
        
        elif "application/x-www-form-urlencoded" in content_type:
            form = await request.form()
            for key, value in form.multi_items():
                surfaces["field_names"].append(str(key))
                surfaces["values"].append(str(value))
        
        #multipart thuong dung cho upload file 
        elif "multipart/form-data" in content_type:
            form = await request.form()
            for key, value in form.multi_items():
                surfaces["field_names"].append(str(key))
        
                if isinstance(value,str):
                    surfaces["values"].append(value)
                else:
                    #Uploadfile metadata
                    if getattr(value, "filename" , None):
                        surfaces["filenames"].append(value.filename)
                    if getattr(value, "content_type" , None):
                        surfaces["metadata"].append(
                            f"part_content_type:{value.content_type}"
                        )
        
        else: 
            body = await request.body()
            if body:
                try:
                    surfaces["values"].append(body.decode("utf-8", errors="ignore"))
                except Exception:
                    surfaces["anomalies"].append("Body_Decode_Error")
    except json.JSONDecodeError:
        surfaces["anomalies"].append("Malformed_JSON")
    except Exception:
        surfaces["anomalies"].append("Body_Parse_Error")

    return surfaces

def _extract_json_surfaces(data, surfaces: dict):
    if isinstance(data , dict):
        for key, value in data.items():
            surfaces["field_names"].append(str(key))
            _extract_json_surfaces(value, surfaces)
    
    elif isinstance(data , list):
        for item in data:
            _extract_json_surfaces(item, surfaces)
    
    elif isinstance(data, str):
        surfaces["values"].append(data)

    elif data is not None:
        # số, bool... chuyển thành text để quét khi cần
        surfaces["values"].append(str(data))
                    