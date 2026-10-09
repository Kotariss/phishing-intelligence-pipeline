import io
import re
from typing import List, Optional
from PIL import Image

def scan_qr_codes(image_bytes: bytes) -> List[str]:
    """
    Scans an image from raw bytes and extracts decoded QR code strings (URLs).
    Gracefully handles environments where pyzbar is not installed.
    """
    found_urls = []
    
    # Try pyzbar if available
    try:
        from pyzbar.pyzbar import decode
        pil_img = Image.open(io.BytesIO(image_bytes))
        decoded_objs = decode(pil_img)
        for obj in decoded_objs:
            data = obj.data.decode("utf-8", errors="ignore").strip()
            if data:
                found_urls.append(data)
        if found_urls:
            return found_urls
    except (ImportError, Exception):
        pass

    # Fallback: scan image text / metadata for URLs or URI payloads
    try:
        pil_img = Image.open(io.BytesIO(image_bytes))
        # Check EXIF / info tags
        info = pil_img.info
        for k, v in info.items():
            if isinstance(v, str):
                for match in re.findall(r'https?://[^\s<>"]+', v):
                    found_urls.append(match)
    except Exception:
        pass

    return list(set(found_urls))

def scan_qr_from_file_path(image_path: str) -> List[str]:
    try:
        with open(image_path, "rb") as f:
            return scan_qr_codes(f.read())
    except Exception:
        return []
