"""
Light rule module (ТЗ п. 4.1.7, «лёгкий модуль применения правил»): applies an artefact package to an
object using only cheap parsing (no rendering, no ML/LLM). It is the reference for porting the package
into the customer's anti-spam engine and is used to measure portability.
"""
import hashlib
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from .engine import build_record, rule_matches
    from ..features.url_features import registrable_domain
    from ..features.fingerprints import dhash64, hamming
    from ..sandbox_bridge import load_parsers
except (ImportError, ValueError):
    from rules.engine import build_record, rule_matches
    from features.url_features import registrable_domain
    from features.fingerprints import dhash64, hamming
    from sandbox_bridge import load_parsers


def record_for_object(data: bytes, name: str = "", url: str = "") -> Dict[str, Any]:
    AttachmentParser, parse_file_bytes, _ = load_parsers()
    parsed = parse_file_bytes(data, name, base_url=url)
    kind = parsed.get("type")
    if kind == "eml":
        rec = build_record(attachment=parsed, forms=parsed.get("forms", []))
    elif kind == "html":
        if url:
            rec = build_record(url=url, page=parsed, forms=parsed.get("forms", []), dom_hash=parsed.get("dom_structural_hash"))
        else:  # an HTML attachment
            parsed["filename"] = os.path.basename(name)
            rec = build_record(page=parsed, attachment=parsed, forms=parsed.get("forms", []),
                               dom_hash=parsed.get("dom_structural_hash"), extra_names=[os.path.basename(name)])
    else:
        rec = build_record(attachment=dict(parsed, filename=os.path.basename(name)), extra_names=[os.path.basename(name)])
    if kind == "image" and parsed.get("screenshot_base64"):
        rec["screenshot_dhash"] = dhash64(parsed["screenshot_base64"])
    rec["sha256"] = hashlib.sha256(data).hexdigest()
    rec["attachment_hashes"] = [m.get("sha256") for m in parsed.get("attachments_meta") or [] if m.get("sha256")]
    return rec


def apply_package(package: Dict[str, Any], rec: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[Dict[str, Any]] = []
    known = package.get("known_phishing_signatures", {})

    hashes = {h["sha256"] for h in known.get("attachment_sha256", [])}
    for h in [rec.get("sha256")] + list(rec.get("attachment_hashes") or []):
        if h and h in hashes:
            reasons.append({"type": "known_signature", "indicator": "sha256", "value": h})
    domains = {d["domain"] for d in known.get("domains", [])}
    hosts = [rec.get("host")] + [urlparse(u).hostname or "" for u in rec.get("link_urls") or []]
    for host in hosts:
        if host and registrable_domain(host) in domains:
            reasons.append({"type": "known_signature", "indicator": "domain", "value": registrable_domain(host)})
    for item in known.get("screenshot_dhash", []):  # perceptual hash of the screenshot / image
        if rec.get("screenshot_dhash") and hamming(rec["screenshot_dhash"], item["dhash"]) <= item.get("max_hamming", 8):
            reasons.append({"type": "known_signature", "indicator": "screenshot_dhash", "value": item["dhash"]})
            break
    dom_hashes = {d["hash"] for d in known.get("dom_structural_hashes", [])}
    if rec.get("dom_hash") in dom_hashes:
        reasons.append({"type": "known_signature", "indicator": "dom_hash", "value": rec["dom_hash"]})

    best_risk = 0.0
    for rule in package.get("rules", []):
        if rule_matches(rule, rec):
            risk = float((rule.get("verdict") or {}).get("risk_score", 0.7))
            best_risk = max(best_risk, risk)
            reasons.append({"type": "rule", "rule_id": rule.get("rule_id"), "kind": rule.get("kind"),
                            "risk": risk, "reason_codes": rule.get("reason_codes", [])})

    thresholds = (package.get("evaluation") or {}).get("verdict_thresholds", {"phishing": 0.7, "suspicious": 0.3})
    if any(r["type"] == "known_signature" for r in reasons) or best_risk >= thresholds["phishing"]:
        verdict = "MALICIOUS"
    elif best_risk >= thresholds["suspicious"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
    return {"verdict": verdict, "matches": reasons}


def apply_to_file(package: Dict[str, Any], path: str, url: Optional[str] = None) -> Dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    result = apply_package(package, record_for_object(data, os.path.basename(path), url or ""))
    result["object"] = path
    return result
