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
    from .engine import build_record, rule_matches
    from .zero_fpr_guard import ZeroFPRGuard
    from .yara_gen import hash_rule, hash_rules_file
    from ..brands.icons import load_icons
    from ..features.fingerprints import dhash64, hamming
except (ImportError, ValueError):
    from db.database import SessionLocal
    from db.models import IncidentModel, LSignatureModel
    from brands.matcher import get_brand_registry
    from features.url_features import registrable_domain, mask_url, is_shared_infrastructure
    from rules import reason_codes as rc
    from rules.engine import build_record, rule_matches
    from rules.zero_fpr_guard import ZeroFPRGuard
    from rules.yara_gen import hash_rule, hash_rules_file
    from brands.icons import load_icons
    from features.fingerprints import dhash64, hamming

PACKAGE_FORMAT = "dw2-artifact-package/1.0"
DHASH_MAX_DISTANCE = 8  # bits of 64: screenshots this close are "the same page" (ТЗ 4.1.2.5, 4.1.7.1)


def _benign_dhashes() -> List[str]:
    """Perceptual hashes of the known-legitimate images of the Developer's set (tests/fixtures)."""
    try:
        import base64
        import benign_samples  # tests/fixtures, on the path in the CLI and in tests
        return [h for h in (dhash64(base64.b64encode(img["png"]).decode())
                            for img in getattr(benign_samples, "IMAGES", [])) if h]
    except Exception:
        return []


def _next_version(out_dir: str) -> str:
    existing = []
    if os.path.isdir(out_dir):
        for name in os.listdir(out_dir):
            m = re.match(r'package_v(\d+)\.json$', name)
            if m:
                existing.append(int(m.group(1)))
    return str(max(existing, default=0) + 1)


def record_from_incident(inc) -> Dict[str, Any]:
    """Light-engine feature record rebuilt from a stored knowledge-base incident."""
    ev = inc.evidence_data or {}
    return build_record(url=inc.final_url or "", page=ev.get("page") or {}, attachment=ev.get("attachment") or {},
                        forms=ev.get("forms") or [], dom_hash=inc.dom_hash,
                        extra_names=[os.path.basename(str(inc.raw_target or ""))])


def rule_contribution(rules: List[Dict[str, Any]], incidents) -> Dict[str, Any]:
    """Contribution of each rule to the detected objects (ТЗ 4.1.5.2): hits, hits no other rule covers,
    hits on objects the pipeline itself considered clean (should stay 0 for a good rule)."""
    records = [(inc.id, inc.verdict, record_from_incident(inc)) for inc in incidents]
    hits = {r["rule_id"]: {iid for iid, _, rec in records if rule_matches(r, rec)} for r in rules}
    detected = {iid for iid, verdict, _ in records if verdict in ("MALICIOUS", "SUSPICIOUS")}
    out = []
    for r in rules:
        own = hits[r["rule_id"]]
        others = set().union(*(h for rid, h in hits.items() if rid != r["rule_id"])) if len(hits) > 1 else set()
        out.append({"rule_id": r["rule_id"], "kind": r.get("kind"), "target_brand": r.get("target_brand"),
                    "detected_objects": len(own & detected), "unique_objects": len((own & detected) - others),
                    "clean_objects_matched": len(own - detected)})
    covered = set().union(*hits.values()) & detected if hits else set()
    return {"detected_objects_total": len(detected), "covered_by_package": len(covered),
            "rules": sorted(out, key=lambda x: (-x["detected_objects"], -x["unique_objects"]))}


def build_package(min_verdict: str = "MALICIOUS") -> Dict[str, Any]:
    registry = get_brand_registry()
    db = SessionLocal()
    try:
        signatures = db.query(LSignatureModel).filter(LSignatureModel.status == "ACTIVE_VERIFIED").all()
        # "at least" min_verdict: SUSPICIOUS takes both suspicious and phishing incidents
        verdicts = ("MALICIOUS",) if min_verdict == "MALICIOUS" else ("MALICIOUS", "SUSPICIOUS")
        incidents = db.query(IncidentModel).filter(IncidentModel.verdict.in_(verdicts)).all()
        all_incidents = db.query(IncidentModel).all()
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
    dhashes: Dict[str, str] = {}
    for inc in incidents:
        fp = inc.fingerprints or {}
        att = fp.get("attachment_sha256") or []
        for h in ([att] if isinstance(att, str) else att) + ([fp["file_sha256"]] if fp.get("file_sha256") else []):
            hashes[h] = inc.id
        if inc.final_url and inc.final_url.startswith("http"):
            host = (urlparse(inc.final_url).hostname or "").lower()
            if host and not registry.find_brand_for_domain(host):
                urls[mask_url(inc.final_url)] = inc.id
                if not is_shared_infrastructure(host):
                    domains[registrable_domain(host)] += 1
        if fp.get("screenshot_dhash"):
            dhashes.setdefault(fp["screenshot_dhash"], inc.id)
        if inc.dom_hash and (fp.get("dom_tags_count") or 0) >= 15:
            dom_hashes[inc.dom_hash] += 1

    # Exact indicators are checked on the known-legitimate set before entering the package (ТЗ 4.1.7.3):
    # a domain or DOM template seen on a legitimate object is never a signature of phishing.
    benign = ZeroFPRGuard().corpus
    benign_domains = {registrable_domain(h) for r in benign for h in (r.get("host"), r.get("sender_domain")) if h}
    benign_doms = {r["dom_hash"] for r in benign if r.get("dom_hash")}
    dropped_domains = sorted(d for d in domains if d in benign_domains)
    dropped_doms = sorted(h for h in dom_hashes if h in benign_doms)
    # a perceptual hash close to the screenshot of a known-legitimate image is never a signature of phishing
    dropped_dhashes = sorted(h for h in dhashes if any(hamming(h, b) <= DHASH_MAX_DISTANCE for b in _benign_dhashes()))
    for h in dropped_dhashes:
        del dhashes[h]
    for d in dropped_domains:
        del domains[d]
    for h in dropped_doms:
        del dom_hashes[h]

    known = {
        "checked_on_benign": {"benign_objects": len(benign), "dropped_domains": dropped_domains,
                              "dropped_dom_hashes": dropped_doms, "dropped_screenshot_dhashes": dropped_dhashes},
        "attachment_sha256": [{"sha256": h, "source_incident": i} for h, i in sorted(hashes.items())],
        "urls_masked": [{"url": u, "source_incident": i} for u, i in sorted(urls.items())],
        "domains": [{"domain": d, "incidents": n} for d, n in domains.most_common()],
        "dom_structural_hashes": [{"hash": h, "incidents": n} for h, n in dom_hashes.most_common()],
        "screenshot_dhash": [{"dhash": h, "max_hamming": DHASH_MAX_DISTANCE, "source_incident": i} for h, i in sorted(dhashes.items())],
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
            "reference_icon": (load_icons()[0].get(b["brand_id"]) or {}).get("dhash"),
            "observed_impersonations": impersonated.get(b["display_name"], 0),
        })

    yara_rules = [s.yara_rule for s in signatures if s.yara_rule]
    contribution = rule_contribution(rules, all_incidents)
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
        "yara_hash_rules": [hash_rule(h, i) for h, i in sorted(hashes.items())],
        "rule_contribution": contribution,
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
    if package.get("yara_hash_rules"):  # hash signatures of known phishing files: a separate file, `import "hash"` once
        with open(os.path.join(out_dir, f"package_v{version}_hashes.yar"), "w", encoding="utf-8") as f:
            f.write(hash_rules_file(package["yara_hash_rules"]))
    digest = hashlib.sha256(open(json_path, "rb").read()).hexdigest()
    with open(os.path.join(out_dir, "LATEST"), "w", encoding="utf-8") as f:
        f.write(f"{version} {digest}\n")
    return {"version": version, "json": json_path, "yara": yara_path, "sha256": digest}


def load_package(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
