"""
Text on images (OCR) with the local Tesseract engine: image lures often carry no links or markup, only a
rendered "enter your password to view the document" form. Nothing leaves the container.

Backend: pytesseract + the tesseract binary (languages eng, rus, chi_sim when installed).
When Tesseract is not installed the function returns ``None`` and the pipeline works without OCR.
"""
import io
import os
import re
import shutil
from functools import lru_cache
from typing import Optional

from PIL import Image, ImageOps

MAX_PIXELS = 25_000_000  # decompression-bomb guard
OCR_TIMEOUT = int(os.getenv("OCR_TIMEOUT", "15"))
WANTED_LANGS = ("eng", "rus", "chi_sim")
TARGET_SIDE = 2000
CJK = re.compile(r"[一-鿿]")


@lru_cache(maxsize=1)
def _langs() -> Optional[str]:
    try:
        import pytesseract
    except ImportError:
        return None
    cmd = os.getenv("TESSERACT_CMD") or shutil.which("tesseract")
    if not cmd:
        default = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        cmd = default if os.path.exists(default) else None
    if not cmd:
        return None
    pytesseract.pytesseract.tesseract_cmd = cmd
    try:
        available = set(pytesseract.get_languages(config=""))
    except Exception:
        return None
    langs = [l for l in WANTED_LANGS if l in available]
    return "+".join(langs) if langs else None


def _prepare(image_bytes: bytes) -> Optional[Image.Image]:
    img = Image.open(io.BytesIO(image_bytes))
    if img.width * img.height > MAX_PIXELS:
        return None
    img = ImageOps.autocontrast(ImageOps.grayscale(img.convert("RGB")))
    k = TARGET_SIDE / max(img.size)
    if k > 1:  # e-mail screenshots are small: upscale for small UI fonts
        img = img.resize((int(img.width * k), int(img.height * k)), Image.LANCZOS)
    return img


def ocr_image(image_bytes: bytes) -> Optional[str]:
    """Recognised text, or None when OCR is unavailable / the image cannot be read.

    Latin/Cyrillic and Chinese are recognised in separate passes: a single mixed-script model
    turns Chinese UI text into Cyrillic noise."""
    langs = _langs()
    if not langs:
        return None
    import pytesseract
    try:
        img = _prepare(image_bytes)
        if img is None:
            return None
        main = "+".join(l for l in langs.split("+") if l != "chi_sim") or langs
        parts = [pytesseract.image_to_string(img, lang=main, config="--psm 6", timeout=OCR_TIMEOUT)]
        if "chi_sim" in langs:
            zh = pytesseract.image_to_string(img, lang="chi_sim", config="--psm 6", timeout=OCR_TIMEOUT)
            if len(CJK.findall(zh)) >= 4:
                parts.append(zh)
    except Exception:
        return None
    return " ".join(" ".join(parts).split())[:4000]
