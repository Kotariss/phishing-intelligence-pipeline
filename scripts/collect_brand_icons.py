"""Collects reference site icons of the target brands from their OFFICIAL domains (ТЗ 4.1.2.1: «эталонные логотипы, значки сайтов»).

Only public icons of the brands' own sites are fetched (favicon.ico and the <link rel=icon / apple-touch-icon> of the home page).
Result: services/worker/src/brands/icons/<brand_id>.png (≤ 128 px) and brands/brand_icons.json with the perceptual hash of every icon.

    python scripts/collect_brand_icons.py [--limit N]
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

import requests

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BRANDS = os.path.join(ROOT, "services", "worker", "src", "brands")
sys.path.insert(0, os.path.join(ROOT, "services", "worker", "src"))
from features.fingerprints import dhash64  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (compatible; dw2-brand-icons/1.0; research prototype)"}
LINK_ICON = re.compile(r'<link[^>]+rel=["\'][^"\']*(?:apple-touch-icon|icon)[^"\']*["\'][^>]*>', re.I)
HREF = re.compile(r'href=["\']([^"\']+)["\']', re.I)


def fetch(url, limit=400_000):
    try:
        r = requests.get(url, headers=UA, timeout=8, stream=True, allow_redirects=True)
        if r.status_code != 200:
            return None
        data = r.raw.read(limit + 1, decode_content=True)
        return data if 100 < len(data) <= limit else None
    except requests.RequestException:
        return None


def to_png(data):
    """Icon bytes -> (PNG bytes ≤128 px on white, dhash) or None if it is not a usable image."""
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data))
        if getattr(im, "n_frames", 1) > 1 or im.format == "ICO":
            sizes = getattr(im, "ico", None)
            if sizes is not None and sizes.sizes():
                im = sizes.getimage(max(sizes.sizes()))
        im = im.convert("RGBA")
        bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
        bg.alpha_composite(im)
        im = bg.convert("RGB")
        im.thumbnail((128, 128))
        if min(im.size) < 16:
            return None
        buf = io.BytesIO()
        im.save(buf, "PNG")
        png = buf.getvalue()
        return png, dhash64(base64.b64encode(png).decode())
    except Exception:
        return None


def candidates(domain):
    base = f"https://{domain}"
    yield base + "/favicon.ico"
    page = fetch(base + "/", 300_000)
    if page:
        for tag in LINK_ICON.findall(page.decode("utf-8", "ignore")):
            m = HREF.search(tag)
            if m:
                yield urljoin(base + "/", m.group(1))
    yield f"https://www.{domain}/favicon.ico"


def collect(brand):
    for domain in brand.get("official_domains", [])[:2]:
        for url in candidates(domain):
            data = fetch(url)
            res = to_png(data) if data else None
            if res:
                png, dh = res
                bits = bin(int(dh, 16)).count("1")
                if 10 <= bits <= 54:  # near-blank / solid icons would match everything
                    return brand["brand_id"], {"source": url, "dhash": dh, "sha256": hashlib.sha256(png).hexdigest()}, png
    return brand["brand_id"], None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()
    brands = json.load(open(os.path.join(BRANDS, "brand_registry.json"), encoding="utf-8"))[: args.limit]
    os.makedirs(os.path.join(BRANDS, "icons"), exist_ok=True)
    out = {}
    with ThreadPoolExecutor(8) as pool:
        for brand_id, meta, png in pool.map(collect, brands):
            if meta:
                with open(os.path.join(BRANDS, "icons", f"{brand_id}.png"), "wb") as f:
                    f.write(png)
                out[brand_id] = meta
    with open(os.path.join(BRANDS, "brand_icons.json"), "w", encoding="utf-8") as f:
        json.dump({"version": 1, "max_hamming": 4, "icons": out}, f, ensure_ascii=False, indent=1, sort_keys=True)
    print(f"icons collected for {len(out)} of {len(brands)} brands")


if __name__ == "__main__":
    main()
