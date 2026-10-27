"""
Extraction completeness (ТЗ табл. 3: «полнота извлечения ссылок, форм, QR-кодов и встроенных ресурсов» ≥ 0,85;
ПМИ К-2, формула (2): P_изв = E_и / E).

Ground truth: `docs/labelling/extraction_labels_v1.json` — elements found by reading the source of each object, not
produced by the extractors. The extractors under test are the sandbox parsers (HTML with script execution, e-mail, image
QR scan); no model is involved. The matching rule is stored in the labels file and must be approved before the run.

    python phishctl.py extraction-eval [--labels docs/labelling/extraction_labels_v1.json] [--out reports/extraction_eval.json]
"""
import collections
import datetime
import json
import os
import re
import sys
from typing import Any, Dict, List, Set
from urllib.parse import urlsplit

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SRC_DIR, "..", "..", ".."))
for _p in (SRC_DIR, os.path.join(REPO_ROOT, "services", "sandbox", "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_SKIP_KEYS = {"embedded_image_base64", "visible_text", "dom_skeleton", "evidence_snippets", "brand_context_text",
              "body_html", "body_text_preview", "screenshot_base64", "text_preview"}
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)


def norm(url: str) -> str:
    """Scheme-insensitive URL key: lower-case host, no fragment, no trailing slash."""
    try:
        u = urlsplit(url.strip())
    except ValueError:
        return url.strip().lower()
    host = (u.hostname or "").lower()
    path = u.path.rstrip("/")
    return f"{host}{path}" + (f"?{u.query}" if u.query else "")


def host_of(url: str) -> str:
    try:
        return (urlsplit(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _collect_urls(value: Any, out: Set[str]) -> None:
    if isinstance(value, str):
        out.update(m.rstrip(".,;)") for m in _URL.findall(value))
    elif isinstance(value, dict):
        for k, v in value.items():
            if k not in _SKIP_KEYS:
                _collect_urls(v, out)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            _collect_urls(v, out)


def _hosts(parsed: Dict[str, Any], urls: Set[str]) -> Set[str]:
    hosts = {host_of(u) for u in urls}
    for key in ("external_resource_hosts", "logo_image_hosts"):
        hosts.update(h.lower() for h in parsed.get(key) or [])
    return {h for h in hosts if h}


def _matches_domain(spec: str, hosts: Set[str]) -> bool:
    domain = spec.split(":", 1)[1].lower()
    return any(h == domain or h.endswith("." + domain) for h in hosts)


def _extract(obj: Dict[str, Any], dataset_root: str) -> Dict[str, Any]:
    from attachment_parser import AttachmentParser
    from browser import BrowserController
    from dispatch import parse_file_bytes
    path = os.path.join(dataset_root, obj["object"])
    if obj["type"] == "eml":
        eml = path if os.path.isfile(path) else os.path.join(path, os.path.basename(path))
        with open(eml, "rb") as f:
            return AttachmentParser.parse_eml(f.read())
    with open(path, "rb") as f:
        return parse_file_bytes(f.read(), os.path.basename(path), BrowserController())


def evaluate(labels_path: str, dataset_root: str) -> Dict[str, Any]:
    with open(labels_path, encoding="utf-8") as f:
        labels = json.load(f)
    by_kind = collections.defaultdict(lambda: [0, 0])
    by_type = collections.defaultdict(lambda: [0, 0])
    misses: List[Dict[str, Any]] = []
    errors: List[str] = []
    for obj in labels["objects"]:
        try:
            parsed = _extract(obj, dataset_root)
        except Exception as e:  # an object that cannot be parsed extracts nothing
            parsed, _ = {}, errors.append(f"{obj['object']}: {type(e).__name__}: {str(e)[:120]}")
        urls: Set[str] = set()
        _collect_urls({k: v for k, v in parsed.items()}, urls)
        norms = {norm(u) for u in urls}
        hosts = _hosts(parsed, urls)

        def record(kind: str, ok: bool, what: str):
            by_kind[kind][0] += 1
            by_type[obj["type"]][0] += 1
            if ok:
                by_kind[kind][1] += 1
                by_type[obj["type"]][1] += 1
            else:
                misses.append({"object": obj["object"], "kind": kind, "expected": what[:160]})

        for url in obj["links"]:
            record("links", _matches_domain(url, hosts) if url.startswith("domain:") else norm(url) in norms, url)
        for url in obj["resources"]:
            record("resources", _matches_domain(url, hosts) if url.startswith("domain:") else host_of(url) in hosts, url)
        for url in obj["endpoints"]:
            ok = norm(url) in norms or host_of(url) in hosts or \
                ("telegram" in url and bool(parsed.get("has_telegram_exfil"))) or \
                ("discord" in url and bool(parsed.get("has_discord_exfil")))
            record("endpoints", ok, url)
        if obj["forms"]:
            got = len(parsed.get("forms") or [])
            for i, form in enumerate(obj["forms"]):
                record("forms", got > i, json.dumps(form, ensure_ascii=False))
        if obj["qr"]:
            got = len(parsed.get("qr_codes") or [])
            for i in range(obj["qr"]):
                record("qr", got > i, f"QR #{i + 1}")
        if obj.get("attachments"):
            got = parsed.get("attachments_count") or 0
            for i in range(obj["attachments"]):
                record("attachments", got > i, f"attachment #{i + 1}")
    total = sum(v[0] for v in by_kind.values())
    found = sum(v[1] for v in by_kind.values())
    ratio = lambda a: round(a[1] / a[0], 4) if a[0] else None
    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "labels": os.path.basename(labels_path), "labels_version": labels.get("version"),
        "objects": len(labels["objects"]), "elements": total, "extracted": found,
        "completeness": round(found / total, 4) if total else None, "target": ">= 0.85",
        "by_kind": {k: {"elements": v[0], "extracted": v[1], "completeness": ratio(v)} for k, v in by_kind.items()},
        "by_object_type": {k: {"elements": v[0], "extracted": v[1], "completeness": ratio(v)} for k, v in by_type.items()},
        "matching_rule": labels.get("matching_rule"), "parse_errors": errors, "misses": misses,
    }
