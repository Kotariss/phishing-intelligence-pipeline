"""
Quality evaluation (ТЗ п. 4.1.11, таблица 4): one command computes every metric and saves a JSON report.

* processing completeness — share of corpus objects analysed without an error;
* recall of "phishing + suspicious" verdicts on the phishing corpus (split by DOM template to
  avoid leakage: only one object per DOM skeleton hash counts in the template-split recall);
* false "phishing" verdicts on known-legitimate objects (must be 0);
* share of "suspicious" verdicts on known-legitimate objects (≤ 10 %);
* rule portability: agreement between the heavy pipeline and the light rule engine (package);
* reason-code coverage / frequency (global interpretation, п. 4.1.5.2).
"""
import collections
import datetime
import json
import os
import sys
import time
import traceback
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

try:
    from .orchestrator.state import PhishingState
    from .orchestrator.graph import run_pipeline
    from .ingest.dataset import build_state_from_sample_dir, iter_brand_samples
    from .rules.engine import record_from_state, rule_matches
except (ImportError, ValueError):
    from orchestrator.state import PhishingState
    from orchestrator.graph import run_pipeline
    from ingest.dataset import build_state_from_sample_dir, iter_brand_samples
    from rules.engine import record_from_state, rule_matches

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
FIXTURES_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")

SampleFactory = Callable[[], PhishingState]


# ------------------------------------------------------------------ sample sources
def phishing_sources(dataset_root: str, limit_per_source: Optional[int] = None,
                     sources=("keis2", "html", "png")) -> Iterator[Tuple[str, str, SampleFactory]]:
    """Yields (category, object_id, factory) for the customer's phishing corpus."""
    keis2 = os.path.join(dataset_root, "keis2")
    if "keis2" in sources and os.path.isdir(keis2):
        for i, (brand, sample_dir) in enumerate(iter_brand_samples(keis2)):
            if limit_per_source is not None and i >= limit_per_source:
                break
            yield "keis2_email", sample_dir, (lambda d=sample_dir: build_state_from_sample_dir(d))

    html_dir = os.path.join(dataset_root, "html_phishing2026")
    if "html" in sources and os.path.isdir(html_dir):
        names = sorted(f for f in os.listdir(html_dir) if f.lower().endswith((".html", ".htm")))
        for name in names[:limit_per_source] if limit_per_source else names:
            path = os.path.join(html_dir, name)
            yield "html_attachment", path, (lambda p=path: _file_state(p))

    png_dir = os.path.join(dataset_root, "grouped_png_phishing2026")
    if "png" in sources and os.path.isdir(png_dir):
        files = sorted(os.path.join(png_dir, c, f) for c in os.listdir(png_dir)
                       if os.path.isdir(os.path.join(png_dir, c)) for f in os.listdir(os.path.join(png_dir, c)))
        for path in files[:limit_per_source] if limit_per_source else files:
            yield "image_lure", path, (lambda p=path: _file_state(p))


def benign_sources() -> Iterator[Tuple[str, str, SampleFactory]]:
    if FIXTURES_DIR not in sys.path:
        sys.path.insert(0, FIXTURES_DIR)
    import benign_samples
    for s in benign_samples.HTML_PAGES:
        yield "benign_page", s["id"], (lambda s=s: PhishingState(
            incident_id=f"bn_{s['id']}", source_type="url", raw_target=s["url"], offline_mode=True,
            precollected_links=[{"url": s["url"], "final_url": s["url"], "html": s["html"], "redirect_chain": []}]))
    for s in benign_samples.EMAILS:
        yield "benign_email", s["id"], (lambda s=s: PhishingState(
            incident_id=f"bn_{s['id']}", source_type="eml", raw_target=f"{s['id']}.eml",
            raw_bytes=s["eml"], offline_mode=True))


def _file_state(path: str) -> PhishingState:
    with open(path, "rb") as f:  # OSError (e.g. AV quarantine) is reported as a processing failure
        data = f.read()
    return PhishingState(incident_id=f"ev_{abs(hash(path)) % 10**10}", source_type=path.rsplit(".", 1)[-1].lower(),
                         raw_target=path, raw_bytes=data, offline_mode=True)


# ---------------------------------------------------------------------- evaluation
def summarize(state: PhishingState, elapsed: float) -> Dict[str, Any]:
    return {
        "verdict": state.verdict,
        "risk": state.risk_score,
        "codes": state.reason_codes,
        "brand": state.brand_evidence.detected_brand_name,
        "dom_hash": state.dom_structural_hash,
        "campaign": state.campaign_id,
        "rule_kind": (state.generated_l_signature or {}).get("kind"),
        "rule_status": state.signature_status,
        "yara": bool(state.generated_yara_rule),
        "seconds": round(elapsed, 3),
        "record": record_from_state(state),
        "rule": state.generated_l_signature,
    }


def evaluate(dataset_root: str, limit_per_source: Optional[int] = None, sources=("keis2", "html", "png"),
             progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    started = time.time()
    rows: List[Dict[str, Any]] = []
    for group, iterator in (("phishing", phishing_sources(dataset_root, limit_per_source, sources)),
                            ("benign", benign_sources())):
        for category, object_id, factory in iterator:
            t0 = time.time()
            row = {"group": group, "category": category, "object": os.path.relpath(object_id, REPO_ROOT)
                   if os.path.isabs(object_id) else object_id}
            try:
                state = run_pipeline(factory())
                row.update(status="ok", **summarize(state, time.time() - t0))
            except Exception as e:
                row.update(status="error", error=f"{type(e).__name__}: {str(e)[:200]}",
                           trace=traceback.format_exc(limit=3)[-600:], seconds=round(time.time() - t0, 3))
            rows.append(row)
            if progress:
                progress(f"[{group}/{category}] {row['object'][:70]} -> {row.get('verdict', row['status'])}")
    return build_report(rows, time.time() - started, dataset_root, limit_per_source)


def _rate(n: int, d: int) -> Optional[float]:
    return round(n / d, 4) if d else None


def build_report(rows: List[Dict[str, Any]], elapsed: float, dataset_root: str, limit) -> Dict[str, Any]:
    phish = [r for r in rows if r["group"] == "phishing"]
    benign = [r for r in rows if r["group"] == "benign"]
    phish_ok = [r for r in phish if r["status"] == "ok"]
    benign_ok = [r for r in benign if r["status"] == "ok"]

    detected = [r for r in phish_ok if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
    # template split: one representative per DOM skeleton (objects without a DOM count individually)
    by_template: Dict[str, Dict[str, Any]] = {}
    for r in phish_ok:
        key = r.get("dom_hash") or f"obj:{r['object']}"
        by_template.setdefault(key, r)
    template_reps = list(by_template.values())

    per_category = {}
    for cat in sorted({r["category"] for r in rows}):
        items = [r for r in rows if r["category"] == cat]
        ok = [r for r in items if r["status"] == "ok"]
        verdicts = collections.Counter(r["verdict"] for r in ok)
        per_category[cat] = {"objects": len(items), "processed_ok": len(ok), "verdicts": dict(verdicts),
                             "mean_seconds": round(sum(r["seconds"] for r in items) / len(items), 3) if items else None}

    # Portability: active rules generated in this run, applied by the light engine to every record.
    rules = [r["rule"] for r in phish_ok if r.get("rule") and r.get("rule_status") == "ACTIVE_VERIFIED"]
    light_hits = [r for r in phish_ok if any(rule_matches(rule, r["record"]) for rule in rules)]
    benign_rule_hits = [{"object": r["object"], "rules": [rule["rule_id"] for rule in rules if rule_matches(rule, r["record"])]}
                        for r in benign_ok if any(rule_matches(rule, r["record"]) for rule in rules)]
    heavy_detected = {r["object"] for r in detected}
    light_agree = [r for r in light_hits if r["object"] in heavy_detected]

    code_freq = collections.Counter(c for r in phish_ok for c in r["codes"])
    benign_mal = [r["object"] for r in benign_ok if r["verdict"] == "MALICIOUS"]
    benign_susp = [r["object"] for r in benign_ok if r["verdict"] == "SUSPICIOUS"]

    metrics = {
        "processing_completeness": _rate(len(phish_ok), len(phish)),
        "recall_phishing_plus_suspicious": _rate(len(detected), len(phish_ok)),
        "recall_template_split": _rate(sum(1 for r in template_reps if r["verdict"] != "CLEAN"), len(template_reps)),
        "malicious_rate_on_phishing": _rate(sum(1 for r in phish_ok if r["verdict"] == "MALICIOUS"), len(phish_ok)),
        "benign_false_phishing": len(benign_mal),
        "benign_suspicious_share": _rate(len(benign_susp), len(benign_ok)),
        "reason_code_coverage": _rate(sum(1 for r in detected if r["codes"]), len(detected)),
        "light_engine_recall": _rate(len(light_hits), len(phish_ok)),
        "light_engine_agreement_with_heavy": _rate(len(light_agree), len(light_hits)),
        "light_engine_benign_hits": len(benign_rule_hits),
        "mean_seconds_per_object": round(sum(r["seconds"] for r in rows) / len(rows), 3) if rows else None,
    }
    targets = {
        "processing_completeness": (">=", 0.85),
        "recall_template_split": (">=", 0.90),
        "benign_false_phishing": ("==", 0),
        "benign_suspicious_share": ("<=", 0.10),
    }
    acceptance = {}
    for key, (op, value) in targets.items():
        actual = metrics[key]
        ok = actual is not None and ((op == ">=" and actual >= value) or (op == "<=" and actual <= value) or (op == "==" and actual == value))
        acceptance[key] = {"target": f"{op} {value}", "actual": actual, "passed": ok}

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "dataset_root": dataset_root,
        "limit_per_source": limit,
        "elapsed_seconds": round(elapsed, 1),
        "counts": {"phishing": len(phish), "benign": len(benign), "templates": len(template_reps),
                   "active_rules": len(rules), "yara_rules": sum(1 for r in phish_ok if r.get("yara"))},
        "metrics": metrics,
        "acceptance": acceptance,
        "per_category": per_category,
        "reason_code_frequency": dict(code_freq.most_common()),
        "benign_false_positives": {"malicious": benign_mal, "suspicious": benign_susp, "rule_hits": benign_rule_hits},
        "missed_phishing": [r["object"] for r in phish_ok if r["verdict"] == "CLEAN"][:200],
        "errors": [{"object": r["object"], "error": r["error"]} for r in rows if r["status"] == "error"][:200],
        "objects": [{k: r.get(k) for k in ("group", "category", "object", "status", "verdict", "risk", "codes", "brand",
                                           "campaign", "rule_kind", "rule_status", "seconds")} for r in rows],
    }


# --------------------------------------------------------------------- robustness (ТЗ табл. 11)
def _mutate_design(html: str, seed: int) -> str:
    """Changes the look without changing the technique: styles removed, class/id names randomised,
    padding text injected, colours changed."""
    import random
    import re
    rnd = random.Random(seed)
    out = re.sub(r'<style[^>]*>.*?</style>', '<style>body{background:#%06x}</style>' % rnd.randrange(0xFFFFFF), html, flags=re.S | re.I)
    out = re.sub(r'\sstyle="[^"]*"', "", out, flags=re.I)
    out = re.sub(r'\s(class|id)="[^"]*"', lambda m: f' {m.group(1)}="x{rnd.randrange(10**8)}"', out, flags=re.I)
    pad = "<div>" + " ".join(rnd.choice(["lorem", "ipsum", "dolor", "news", "update"]) for _ in range(40)) + "</div>"
    return re.sub(r'(<body[^>]*>)', r'\1' + pad, out, count=1, flags=re.I) if re.search(r'<body', out, re.I) else pad + out


def _mutate_delayed(html: str) -> str:
    """Content inserted by script after a delay (absent from the static HTML)."""
    import base64
    payload = base64.b64encode(html.encode("utf-8")).decode("ascii")
    return ('<html><head><title></title></head><body><div id="app"></div><script>'
            f'setTimeout(function(){{document.open();document.write(atob("{payload}"));document.close();}},800);'
            '</script></body></html>')


def _mutate_url(url: str, seed: int) -> str:
    import random
    from urllib.parse import urlparse
    rnd = random.Random(seed)
    host = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(9)) + rnd.choice([".top", ".xyz", ".online", ".site"])
    path = "/" + "/".join("".join(rnd.choice("abcdefghijk0123456789") for _ in range(6)) for _ in range(2))
    return f"{urlparse(url).scheme or 'https'}://{host}{path}"


def robustness(dataset_root: str, limit_per_source: int = 30, progress=None) -> Dict[str, Any]:
    """Re-analyses detected phishing objects after domain/URL replacement, design change and
    delayed loading; reports recall per scenario relative to the unmodified objects."""
    import copy
    from ingest.dataset import load_sample_dir
    scenarios = collections.defaultdict(lambda: {"objects": 0, "still_detected": 0, "missed": []})
    for category, object_id, factory in phishing_sources(dataset_root, limit_per_source, ("keis2", "html")):
        try:
            base = run_pipeline(factory())
        except Exception:
            continue
        if base.verdict == "CLEAN":
            continue
        variants = []
        if category == "html_attachment":
            with open(object_id, "rb") as f:
                html = f.read().decode("utf-8", errors="ignore")
            for name, mutated in (("design_change", _mutate_design(html, 1)), ("delayed_loading", _mutate_delayed(html))):
                variants.append((name, PhishingState(incident_id=f"rb_{uuid_hex()}", source_type="html", raw_target=object_id,
                                                     raw_bytes=mutated.encode("utf-8"), offline_mode=True)))
        else:
            sample = load_sample_dir(object_id)
            if not any(l.get("html") for l in sample["links"]):
                continue
            for name in ("domain_url_change", "design_change", "delayed_loading"):
                links = copy.deepcopy(sample["links"])
                for i, link in enumerate(links):
                    if name == "domain_url_change":
                        new = _mutate_url(link.get("final_url") or link.get("url") or "https://x", i)
                        link["url"], link["final_url"], link["redirect_chain"] = new, new, []
                    elif link.get("html"):
                        link["html"] = _mutate_design(link["html"], i) if name == "design_change" else _mutate_delayed(link["html"])
                variants.append((name, PhishingState(incident_id=f"rb_{uuid_hex()}", source_type="eml", raw_target=sample["eml_path"],
                                                     raw_bytes=sample["eml_bytes"] or None, offline_mode=True, precollected_links=links)))
        for name, state in variants:
            res = run_pipeline(state)
            sc = scenarios[name]
            sc["objects"] += 1
            if res.verdict != "CLEAN":
                sc["still_detected"] += 1
            else:
                sc["missed"].append(os.path.relpath(object_id, REPO_ROOT))
            if progress:
                progress(f"[{name}] {object_id[-60:]} -> {res.verdict}")
    for sc in scenarios.values():
        sc["recall"] = _rate(sc["still_detected"], sc["objects"])
        sc["recall_drop"] = round(1 - sc["recall"], 4) if sc["recall"] is not None else None
        sc["missed"] = sc["missed"][:50]
    return dict(scenarios)


def uuid_hex() -> str:
    import uuid
    return uuid.uuid4().hex[:10]


def save_report(report: Dict[str, Any], out_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return out_path
