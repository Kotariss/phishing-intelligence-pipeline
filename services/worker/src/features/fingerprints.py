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
from typing import Any, Dict, List, Optional, Tuple

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
    """Bits that differ between two 64-bit perceptual hashes (hex)."""
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def visual_clusters(items: List[Tuple[str, str]], max_distance: int = 8) -> List[List[str]]:
    """Groups objects whose screenshots look alike (dHash distance <= max_distance of 64 bits): the same kit
    on different domains / with a changed DOM still looks the same (ТЗ 4.1.2.5, 4.1.7.1)."""
    parent = {i: i for i, _ in items}

    def root(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for n, (a, ha) in enumerate(items):
        for b, hb in items[n + 1:]:
            if hamming(ha, hb) <= max_distance:
                parent[root(a)] = root(b)
    groups: Dict[str, List[str]] = {}
    for i, _ in items:
        groups.setdefault(root(i), []).append(i)
    return sorted((g for g in groups.values() if len(g) > 1), key=len, reverse=True)


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
        att = fp["attachment_sha256"]  # list of all attachments (a single string in older records)
        basis = "att:" + (att if isinstance(att, str) else att[0])
    else:
        return None
    return "CMP-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10].upper()
