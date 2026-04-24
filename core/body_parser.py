from fastapi import Request
from security.file_scanner import scan_file


async def inspect_uploaded_files(request: Request):
    content_type = request.headers.get("content-type", "").lower()

    if "multipart/form-data" not in content_type:
        return None

    try:
        form = await request.form()

        for _, value in form.multi_items():
            if not isinstance(value, str):
                file_bytes = await value.read()
                threat = scan_file(value.filename, value.content_type, file_bytes)
                if threat:
                    return threat

        return None

    except Exception:
        return "File_Parse_Error"