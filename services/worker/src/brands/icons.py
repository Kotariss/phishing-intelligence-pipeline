"""Reference site icons of the target brands and matching by perceptual hash (ТЗ 4.1.2.1, 4.1.4.3 «по значку сайта»).

`brand_icons.json` is produced by scripts/collect_brand_icons.py from the brands' official sites. An icon found on a page (an inline
`data:` favicon, a small logo image) that is within `max_hamming` bits of a reference icon names the brand; brands of one corporate
family share icons, so the result is a list of candidates."""
import base64
import json
import os
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

try:
    from ..features.fingerprints import dhash64, hamming
except ImportError:
    from features.fingerprints import dhash64, hamming

ICONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand_icons.json")


@lru_cache(maxsize=1)
def load_icons() -> Tuple[Dict[str, Dict[str, str]], int]:
    try:
        with open(ICONS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("icons", {}), int(data.get("max_hamming", 4))
    except (OSError, ValueError):
        return {}, 4


def match_icon(image_b64: Optional[str]) -> List[Tuple[str, int]]:
    """Brands whose reference icon looks like this image: [(brand_id, hamming distance)], closest first."""
    icons, max_d = load_icons()
    h = dhash64(image_b64) if image_b64 else None
    if not h or not icons:
        return []
    bits = bin(int(h, 16)).count("1")
    if not 10 <= bits <= 54:  # near-blank / solid images match everything
        return []
    hits = [(bid, hamming(h, meta["dhash"])) for bid, meta in icons.items()]
    return sorted(((b, d) for b, d in hits if d <= max_d), key=lambda x: x[1])


def icon_from_data_uri(value: Optional[str]) -> Optional[str]:
    """Base64 payload of an inline `data:image/...` URI (an icon embedded in the page), else None."""
    if value and value.startswith("data:image") and "base64," in value:
        return value.split("base64,", 1)[1]
    return None
