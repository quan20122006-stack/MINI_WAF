import re 

MAX_FILE_SIZE = 5 * 1024 * 1024

# whitelist extension va mime type
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf", ".txt"}
ALLOWED_MIMES = {"image/jpeg", "image/png", "application/pdf", "text/plain"}

# Magic bytes 
MAGIC_BYTES = {
    "image/jpeg": [b"\xFF\xD8\xFF"],
    "image/png": [b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"],
    "application/pdf": [b"\x25\x50\x44\x46"],
}

#Chong double extension
BAD_EXT_REGEX = re.compile(r'\.(php|phtml|exe|sh|jsp|cgi|pl|py|bat)([\.%]|$)', re.IGNORECASE)
def scan_file(filename: str, content_type: str, file_bytes: bytes) -> str:
    if len(file_bytes) > MAX_FILE_SIZE:
        return "Chi chap nhan file duoi 5MB"
    
    #Kiem tra double extension
    if BAD_EXT_REGEX.search(filename):
        return "extension khong phu hop"
    
    #kiem tra duoi file trong whitelist
    ext = "." + filename.split('.')[-1].lower() if '.' in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return "extension khong phu hop"
    
    #Kiem tra MIME TYPE 
    if content_type not in ALLOWED_MIMES:
        return "MIME khong hop le"
    
    #Kiem tra Magic bytes
    if content_type in MAGIC_BYTES:
        signatures = MAGIC_BYTES[content_type]
        is_valid = False
        for sig in signatures:
            if file_bytes.startswith(sig):  # So sánh byte đầu tiên của file với Hex chuẩn
                is_valid = True
                break
            if not is_valid:
                return "Fake_Magic_Bytes" # Bắt quả tang đổi đuôi file!
            
    return None # File sạch! Cho phép đi qua.