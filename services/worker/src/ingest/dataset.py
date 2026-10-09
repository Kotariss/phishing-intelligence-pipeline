"""
Offline loader for the Dr.Web DW-2 case dataset.

target_brands (keis2) layout:
    <Brand>/<sha1>/<sha1>                 raw EML (no extension)
    <Brand>/<sha1>/Link_N/url.txt         link found in the e-mail
    <Brand>/<sha1>/Link_N/chain_info.json redirect chain with HTTP status codes, or {"detail": "<why not collected>"}
    <Brand>/<sha1>/Link_N/html.html       final landing page HTML
    <Brand>/<sha1>/Link_N/screenshot.png  final landing page screenshot

The pipeline consumes these artefacts instead of re-visiting live phishing infrastructure.
"""
import base64
import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

try:
    from ..orchestrator.state import PhishingState
except (ImportError, ValueError):
    from orchestrator.state import PhishingState

MAX_HTML_BYTES = 3 * 1024 * 1024


def _fix_url(url: str) -> str:
    """Same repair as the sandbox parser: 'https:/host', 'https://https://host'."""
    u = (url or "").strip()
    u = re.sub(r'^(https?)(?::/*|//)(?=[^/])', r'\1://', u, flags=re.IGNORECASE)
    u = re.sub(r'^(https?://)+(https?)(?::/*|//)', r'\2://', u, flags=re.IGNORECASE)
    return u


def _read_text(path: str, limit: Optional[int] = None) -> str:
    with open(path, "rb") as f:
        data = f.read(limit) if limit else f.read()
    return data.decode("utf-8", errors="ignore")


def load_link_dir(link_dir: str) -> Dict[str, Any]:
    link: Dict[str, Any] = {"name": os.path.basename(link_dir)}
    url_file = os.path.join(link_dir, "url.txt")
    if os.path.exists(url_file):
        link["url"] = _fix_url(_read_text(url_file))

    chain_file = os.path.join(link_dir, "chain_info.json")
    if os.path.exists(chain_file):
        try:
            chain_info = json.loads(_read_text(chain_file))
        except ValueError:
            chain_info = {"detail": "chain_info.json is not valid JSON"}
        if "detail" in chain_info and "redirect_chain" not in chain_info:
            link["collection_error"] = str(chain_info["detail"]).splitlines()[0][:300]
        hops = chain_info.get("redirect_chain") or []
        link["redirect_chain"] = [
            {"from": h.get("from", ""), "to": h.get("to", ""), "status_code": h.get("status_code") or 0,
             "is_js_meta": bool(h.get("is_js_meta"))}
            for h in hops if isinstance(h, dict)
        ]
        link["download_triggered"] = bool(chain_info.get("download_triggered"))
        link["download_url"] = chain_info.get("download_url")
        if not link.get("url"):
            link["url"] = (chain_info.get("initial_url") or {}).get("value", "")

    html_file = os.path.join(link_dir, "html.html")
    if os.path.exists(html_file):
        link["html"] = _read_text(html_file, MAX_HTML_BYTES)

    shot_file = os.path.join(link_dir, "screenshot.png")
    if os.path.exists(shot_file):
        with open(shot_file, "rb") as f:
            link["screenshot_base64"] = base64.b64encode(f.read()).decode("ascii")

    chain = link.get("redirect_chain") or []
    link["final_url"] = _fix_url(chain[-1]["to"]) if chain and chain[-1].get("to") else link.get("url", "")
    return link


def _link_sort_key(name: str) -> int:
    m = re.search(r'(\d+)$', name)
    return int(m.group(1)) if m else 0


def load_sample_dir(sample_dir: str) -> Dict[str, Any]:
    """Returns {"eml_path", "eml_bytes", "links": [...]} for one keis2 sample directory."""
    sample_dir = os.path.abspath(sample_dir)
    sample_id = os.path.basename(sample_dir.rstrip(os.sep))
    eml_path = os.path.join(sample_dir, sample_id)
    if not os.path.isfile(eml_path):
        candidates = [os.path.join(sample_dir, f) for f in os.listdir(sample_dir)
                      if os.path.isfile(os.path.join(sample_dir, f))]
        eml_path = candidates[0] if candidates else ""
    eml_bytes = b""
    if eml_path:
        with open(eml_path, "rb") as f:
            eml_bytes = f.read()

    link_dirs = sorted((d for d in os.listdir(sample_dir)
                        if d.startswith("Link_") and os.path.isdir(os.path.join(sample_dir, d))),
                       key=_link_sort_key)
    links = [load_link_dir(os.path.join(sample_dir, d)) for d in link_dirs]
    return {"sample_id": sample_id, "eml_path": eml_path, "eml_bytes": eml_bytes, "links": links}


def is_sample_dir(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    sample_id = os.path.basename(os.path.abspath(path))
    return os.path.isfile(os.path.join(path, sample_id)) or any(
        d.startswith("Link_") for d in os.listdir(path))


def build_state_from_sample_dir(sample_dir: str, incident_id: Optional[str] = None) -> PhishingState:
    sample = load_sample_dir(sample_dir)
    return PhishingState(
        incident_id=incident_id or f"inc_{uuid.uuid4().hex[:10]}",
        source_type="eml",
        raw_target=sample["eml_path"] or sample_dir,
        raw_bytes=sample["eml_bytes"] or None,
        offline_mode=True,
        precollected_links=sample["links"],
    )


def iter_brand_samples(keis2_root: str):
    """Yields (brand_folder_name, sample_dir) for the whole target_brands dataset."""
    for brand in sorted(os.listdir(keis2_root)):
        brand_dir = os.path.join(keis2_root, brand)
        if not os.path.isdir(brand_dir):
            continue
        for sample in sorted(os.listdir(brand_dir)):
            sample_dir = os.path.join(brand_dir, sample)
            if is_sample_dir(sample_dir):
                yield brand, sample_dir
