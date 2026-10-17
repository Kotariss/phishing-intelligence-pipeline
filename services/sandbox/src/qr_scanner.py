import io
import re
from typing import List

from PIL import Image

MAX_PIXELS = 25_000_000  # decompression-bomb guard


def _decode_with_pyzbar(pil_img: Image.Image) -> List[str]:
    from pyzbar.pyzbar import decode, ZBarSymbol
    return [obj.data.decode("utf-8", errors="ignore").strip()
            for obj in decode(pil_img, symbols=[ZBarSymbol.QRCODE])]


def _decode_with_opencv(pil_img: Image.Image) -> List[str]:
    import cv2
    import numpy as np
    arr = cv2.cvtColor(np.array(pil_img.convert("RGB")), cv2.COLOR_RGB2BGR)
    detector = cv2.QRCodeDetector()
    found: List[str] = []
    ok, decoded, _, _ = detector.detectAndDecodeMulti(arr)
    if ok:
        found.extend(d for d in decoded if d)
    if not found:
        data, _, _ = detector.detectAndDecode(arr)
        if data:
            found.append(data)
    return found


def scan_qr_codes(image_bytes: bytes) -> List[str]:
    """
    Decodes QR codes from raw image bytes.
    Backends: pyzbar (needs the zbar system library) -> OpenCV QRCodeDetector -> none.
    """
    try:
        pil_img = Image.open(io.BytesIO(image_bytes))
        if pil_img.width * pil_img.height > MAX_PIXELS:
            return []
        pil_img.load()
    except Exception:
        return []

    found: List[str] = []
    for backend in (_decode_with_pyzbar, _decode_with_opencv):
        try:
            found = [d for d in backend(pil_img) if d]
        except Exception:
            # Backend missing (ImportError / zbar DLL absent) or failed on this image.
            continue
        if found:
            break

    # Some generators also store the payload in PNG text chunks.
    if not found:
        for value in pil_img.info.values():
            if isinstance(value, str):
                found.extend(re.findall(r'https?://[^\s<>"]+', value))

    return sorted(set(found))

