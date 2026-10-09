"""
Versioned artefact package for the light anti-spam engine (ТЗ п. 4.1.7).

Sections are kept apart (п. 4.1.7.2):
  known_phishing_signatures — exact indicators of known phishing (attachment hashes, URLs, domains, DOM hashes);
  rules                     — generalised "set of conditions -> verdict" L-signatures (lar-rule-v1) with
                              weights (risk), reason codes and provenance;
  brand_features            — brand -> legitimate domains -> keywords -> reference fingerprints;
  reason_codes              — catalogue with weights so that the engine can explain its decisions;
  yara                      — attachment signatures (also written as a .yar bundle).
"""
import collections
import datetime
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from ..db.database import SessionLocal
    from ..db.models import IncidentModel, LSignatureModel
    from ..brands.matcher import get_brand_registry
    from ..features.url_features import registrable_domain, mask_url, is_shared_infrastructure
    from . import reason_codes as rc
except (ImportError, ValueError):
    from db.database import SessionLocal
    from db.models import IncidentModel, LSignatureModel
    from brands.matcher import get_brand_registry
    from features.url_features import registrable_domain, mask_url, is_shared_infrastructure
    from rules import reason_codes as rc

PACKAGE_FORMAT = "dw2-artifact-package/1.0"


def _next_version(out_dir: str) -> str:
    existing = []
    if os.path.isdir(out_dir):
        for name in os.listdir(out_dir):
            m = re.match(r'package_v(\d+)\.json$', name)
            if m:
                existing.append(int(m.group(1)))
    return str(max(existing, default=0) + 1)


def build_package(min_verdict: str = "MALICIOUS") -> Dict[str, Any]:
    registry = get_brand_registry()
    db = SessionLocal()
    try:
        signatures = db.query(LSignatureModel).filter(LSignatureModel.status == "ACTIVE_VERIFIED").all()
        incidents = db.query(IncidentModel).filter(IncidentModel.verdict == min_verdict).all()
    finally:
        db.close()

    # ---- generalised rules (deduplicated by predicate content) ----------------------------------
    rules: List[Dict[str, Any]] = []
    seen = {}
    for sig in signatures:
        rule = dict(sig.rule_json or {})
        key = hashlib.sha1(json.dumps(rule.get("predicates"), sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        if key in seen:
            seen[key]["provenance"]["incidents"].append(sig.incident_id)
            continue
        rule["provenance"] = {"incidents": [sig.incident_id], "reason_codes": rule.get("reason_codes", []),
                              "created_at": sig.created_at.isoformat() if sig.created_at else None}
        rule.pop("fingerprints", None)
        seen[key] = rule
        rules.append(rule)

    # ---- exact indicators of known phishing -------------------------------------------------------
    hashes, urls, domains, dom_hashes = {}, {}, collections.Counter(), collections.Counter()
    for inc in incidents:
        fp = inc.fingerprints or {}
        if fp.get("attachment_sha256"):
            hashes[fp["attachment_sha256"]] = inc.id
        if inc.final_url and inc.final_url.startswith("http"):
            host = (urlparse(inc.final_url).hostname or "").lower()
            if host and not registry.find_brand_for_domain(host):
                urls[mask_url(inc.final_url)] = inc.id
                if not is_shared_infrastructure(host):
                    domains[registrable_domain(host)] += 1
        if inc.dom_hash and (fp.get("dom_tags_count") or 0) >= 15:
            dom_hashes[inc.dom_hash] += 1

    known = {
        "attachment_sha256": [{"sha256": h, "source_incident": i} for h, i in sorted(hashes.items())],
        "urls_masked": [{"url": u, "source_incident": i} for u, i in sorted(urls.items())],
        "domains": [{"domain": d, "incidents": n} for d, n in domains.most_common()],
        "dom_structural_hashes": [{"hash": h, "incidents": n} for h, n in dom_hashes.most_common()],
    }

    # ---- brand features ------------------------------------------------------------------------------
    impersonated = collections.Counter(inc.target_brand for inc in incidents if inc.target_brand)
    brand_features = []
    for b in registry.brands:
        brand_features.append({
            "brand_id": b["brand_id"],
            "display_name": b["display_name"],
            "keywords": registry.brand_keywords(b["brand_id"]),
            "allowed_domain_patterns": b.get("allowed_domain_patterns", []),
            "observed_impersonations": impersonated.get(b["display_name"], 0),
        })

    yara_rules = [s.yara_rule for s in signatures if s.yara_rule]
    return {
        "format": PACKAGE_FORMAT,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "statistics": {"rules": len(rules), "known_signatures": sum(len(v) for v in known.values()),
                       "yara_rules": len(yara_rules), "source_incidents": len(incidents)},
        "evaluation": {"semantics": "rule matches when all_of holds and (any_of is empty or one any_of holds)",
                       "verdict_thresholds": {"phishing": 0.70, "suspicious": 0.30}},
        "known_phishing_signatures": known,
        "rules": rules,
        "brand_features": brand_features,
        "reason_codes": {code: {"weight": info.weight, "category": info.category, "severity": info.severity,
                                "description": info.description} for code, info in rc.REASON_CODES.items()},
        "yara": yara_rules,
    }


def save_package(package: Dict[str, Any], out_dir: str, version: Optional[str] = None) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    version = version or _next_version(out_dir)
    package = dict(package, version=version)
    json_path = os.path.join(out_dir, f"package_v{version}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(package, f, ensure_ascii=False, indent=2)
    yara_path = os.path.join(out_dir, f"package_v{version}.yar")
    with open(yara_path, "w", encoding="utf-8") as f:
        f.write("\n".join(package.get("yara", [])))
    digest = hashlib.sha256(open(json_path, "rb").read()).hexdigest()
    with open(os.path.join(out_dir, "LATEST"), "w", encoding="utf-8") as f:
        f.write(f"{version} {digest}\n")
    return {"version": version, "json": json_path, "yara": yara_path, "sha256": digest}


def load_package(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
