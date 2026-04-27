#Nhiệm vụ của nó hiện tại là lột lớp vỏ URL Encode (tối đa 3 lần để chống Double/Triple Encode)
import urllib.parse
import html
import re
import unicodedata

def normalize_payload(payload: str , max_url_decode_rounds: int = 3) -> str:
    if payload is None:
        return ""
    
    #1. Ep ve string
    if not isinstance(payload, str):
        payload = str(payload)
    
    #2. Unicode normaliztion
    #Giup cac ki tu nhin giong nhau va on dinh hon
    normalized = unicodedata.normalize("NFKC",payload)

    #3. html entity decode 
    normalized = html.unescape(normalized)

    #4. URL decode nhieu vong
    decoded_payload = normalized
    for _ in range(max_url_decode_rounds):
        new_payload = urllib.parse.unquote(decoded_payload)
        if new_payload == decoded_payload:
            break 
        decoded_payload = new_payload
    
    normalized = decoded_payload
    #5. Chuan hoa slash/backslash (Huu ich cho path traversal)
    normalized = normalized.replace("\\" , "/")

    #6. Loai null byte
    normalized = normalized.replace("\x00","")

    # 7. Gộp whitespace lạ
    normalized = re.sub(r"[\r\n\t]+", " ", normalized)
    normalized = re.sub(r"\s{2,}", " ", normalized)

    # 8. Strip đầu cuối
    normalized = normalized.strip()

    return normalized


