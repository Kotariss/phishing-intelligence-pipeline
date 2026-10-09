"""
Compact, engine-portable fingerprints and campaign linking.

* dhash64         perceptual hash of the landing-page screenshot (robust to small visual changes)
* dom hash        structural DOM skeleton hash (phishing-kit reuse)
* exfil channels  Telegram bot id / Discord webhook (one actor = one campaign)
* form host       registrable domain receiving the credentials
"""
import base64
import hashlib
import io
from typing import Any, Dict, Optional

MIN_TAGS_FOR_DOM_CAMPAIGN = 15


def dhash64(image_b64: Optional[str]) -> Optional[str]:
    """64-bit difference hash of an image (hex). None if the image cannot be decoded."""
    if not image_b64:
        return None
    try:
        from PIL import Image
        raw = base64.b64decode(image_b64.split("base64,")[-1])
        img = Image.open(io.BytesIO(raw)).convert("L").resize((9, 8), Image.LANCZOS)
    except Exception:
        return None
    pixels = list(img.tobytes())
    bits = 0
    for row in range(8):
        for col in range(8):
            left = pixels[row * 9 + col]
            right = pixels[row * 9 + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:016x}"


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def campaign_key(fp: Dict[str, Any]) -> Optional[str]:
    """Deterministic campaign identifier from the strongest available shared infrastructure."""
    if fp.get("telegram_bot_ids"):
        basis = "tg:" + sorted(fp["telegram_bot_ids"])[0]
    elif fp.get("discord_webhooks"):
        basis = "dc:" + sorted(fp["discord_webhooks"])[0]
    elif fp.get("dom_structural_hash") and (fp.get("dom_tags_count") or 0) >= MIN_TAGS_FOR_DOM_CAMPAIGN:
        basis = "dom:" + fp["dom_structural_hash"]
    elif fp.get("credential_post_domain"):
        basis = "post:" + fp["credential_post_domain"]
    elif fp.get("attachment_sha256"):
        basis = "att:" + fp["attachment_sha256"]
    else:
        return None
    return "CMP-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10].upper()
