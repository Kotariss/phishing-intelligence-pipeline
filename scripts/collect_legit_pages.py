"""Collects REAL legitimate pages of the target brands from their official domains — a legitimate set independent of the rules
(ТЗ 4.1.2.3: страницы входа и рассылки целевых брендов). Pages are third-party content: they are kept locally in file_for_case/legit_real/
(git-ignored) and never published.

    python scripts/collect_legit_pages.py [--out file_for_case/legit_real] [--limit N]
Then:  python phishctl.py legit-eval
"""
import argparse
import datetime
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import requests

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
UA = {"User-Agent": "Mozilla/5.0 (compatible; dw2-legit-set/1.0; research prototype)", "Accept-Language": "en,ru;q=0.8"}
PATHS = ["/", "/login", "/signin", "/account/login"]


def fetch(url):
    try:
        r = requests.get(url, headers=UA, timeout=10, allow_redirects=True)
        ctype = r.headers.get("content-type", "")
        if r.status_code == 200 and "html" in ctype and 500 < len(r.content) <= 600_000:
            return r.url, r.content
    except requests.RequestException:
        pass
    return None


def collect(job):
    brand, domain, out = job
    got = []
    for path in PATHS:
        res = fetch(f"https://{domain}{path}") or (fetch(f"https://www.{domain}{path}") if path == "/" else None)
        if res:
            final_url, data = res
            host = final_url.split("/")[2].lower()
            if not (host == domain or host.endswith("." + domain) or domain.endswith(host.replace("www.", ""))):
                continue  # redirected off the brand's own domain: not a page of the brand
            name = f"{brand['brand_id']}__{len(got)}.html"
            with open(os.path.join(out, name), "wb") as f:
                f.write(data)
            got.append({"file": name, "brand_id": brand["brand_id"], "brand": brand["display_name"], "url": final_url, "bytes": len(data)})
        if len(got) >= 2:
            break
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "file_for_case", "legit_real"))
    ap.add_argument("--limit", type=int)
    args = ap.parse_args()
    registry = json.load(open(os.path.join(ROOT, "services", "worker", "src", "brands", "brand_registry.json"), encoding="utf-8"))[: args.limit]
    os.makedirs(args.out, exist_ok=True)
    jobs = [(b, b["official_domains"][0], args.out) for b in registry if b.get("official_domains")]
    items = []
    with ThreadPoolExecutor(8) as pool:
        for got in pool.map(collect, jobs):
            items += got
    index = {"collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
             "note": "real pages of the official sites of the target brands; third-party content, local use only", "pages": items}
    with open(os.path.join(args.out, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=1)
    print(f"{len(items)} pages of {len({i['brand_id'] for i in items})} brands -> {args.out}")


if __name__ == "__main__":
    main()
