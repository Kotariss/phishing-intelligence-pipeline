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
import hashlib
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
    from .ingest.split import in_part, sample_order
except (ImportError, ValueError):
    from orchestrator.state import PhishingState
    from orchestrator.graph import run_pipeline
    from ingest.dataset import build_state_from_sample_dir, iter_brand_samples
    from rules.engine import record_from_state, rule_matches
    from ingest.split import in_part, sample_order

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
FIXTURES_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")

SampleFactory = Callable[[], PhishingState]


# ------------------------------------------------------------------ sample sources
def phishing_sources(dataset_root: str, limit_per_source: Optional[int] = None,
                     sources=("keis2", "html", "png"), split: Optional[Dict[str, Any]] = None,
                     part: Optional[str] = None) -> Iterator[Tuple[str, str, SampleFactory]]:
    """Yields (category, object_id, factory) for the customer's phishing corpus.

    With a split manifest and part ("dev" / "test") only that part is used, in a deterministic spread-out
    order, so ``limit_per_source`` takes a sample across groups instead of the first folders."""
    def pick(paths: List[str]) -> List[str]:
        if split and part:
            paths = sample_order([p for p in paths if in_part(split, dataset_root, p, part)])
        return paths[:limit_per_source] if limit_per_source else paths

    keis2 = os.path.join(dataset_root, "keis2")
    if "keis2" in sources and os.path.isdir(keis2):
        for sample_dir in pick([d for _, d in iter_brand_samples(keis2)]):
            yield "keis2_email", sample_dir, (lambda d=sample_dir: build_state_from_sample_dir(d))

    html_dir = os.path.join(dataset_root, "html_phishing2026")
    if "html" in sources and os.path.isdir(html_dir):
        names = sorted(f for f in os.listdir(html_dir) if f.lower().endswith((".html", ".htm")))
        for path in pick([os.path.join(html_dir, n) for n in names]):
            yield "html_attachment", path, (lambda p=path: _file_state(p))

    png_dir = os.path.join(dataset_root, "grouped_png_phishing2026")
    if "png" in sources and os.path.isdir(png_dir):
        files = sorted(os.path.join(png_dir, c, f) for c in os.listdir(png_dir)
                       if os.path.isdir(os.path.join(png_dir, c)) for f in os.listdir(os.path.join(png_dir, c)))
        for path in pick(files):
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
    for s in getattr(benign_samples, "IMAGES", []):
        yield "benign_image", s["id"], (lambda s=s: PhishingState(
            incident_id=f"bn_{s['id']}", source_type="png", raw_target=f"{s['id']}.png",
            raw_bytes=s["png"], offline_mode=True))


def _file_state(path: str) -> PhishingState:
    with open(path, "rb") as f:  # OSError (e.g. AV quarantine) is reported as a processing failure
        data = f.read()
    return PhishingState(incident_id=f"ev_{hashlib.sha1(path.encode('utf-8')).hexdigest()[:10]}", source_type=path.rsplit(".", 1)[-1].lower(),
                         raw_target=path, raw_bytes=data, offline_mode=True)


# ---------------------------------------------------------------------- evaluation
def llm_degraded(state: PhishingState) -> bool:
    """The model was configured but skipped (back-off) or a call failed for this object."""
    failed = any(str((t.llm_audit or {}).get("call_type", "")).endswith("_FAILED") for t in state.agent_traces)
    return failed or bool(state.network_evidence.get("llm_unavailable"))


def diagnostics(state: PhishingState) -> Dict[str, Any]:
    """Why this verdict: every piece the decision was made of, small enough to keep for every object of a run."""
    try:
        from .rules import reason_codes as rc
    except ImportError:
        from rules import reason_codes as rc
    net = state.network_evidence or {}
    att = state.attachment_evidence or {}
    be = state.brand_evidence
    return {
        "codes": [{"code": c, "weight": rc.get(c).weight, "detail": (state.reason_details.get(c) or "")[:300]}
                  for c in sorted(state.reason_codes, key=lambda c: -rc.get(c).weight)],
        "brand": {"name": be.detected_brand_name, "source": be.detection_source, "confidence": be.vlm_confidence,
                  "impersonation": be.brand_impersonation_confirmed, "reason": be.impersonation_reason},
        "screenshot": state.screenshot_source if state.screenshot_base64 else None,
        "vlm": net.get("vlm_answer"),
        "vlm_unregistered_brand": net.get("vlm_unregistered_brand"),
        "llm_lure": net.get("llm_lure"),
        "llm_lure_input_chars": net.get("llm_lure_input_chars"),
        "llm_unavailable": bool(net.get("llm_unavailable")),
        "llm_calls": [{"agent": t.agent_id, "type": (t.llm_audit or {}).get("call_type"),
                       "seconds": (t.llm_audit or {}).get("elapsed_seconds"),
                       "prompt_version": (t.llm_audit or {}).get("prompt_version")}
                      for t in state.agent_traces if t.llm_audit],
        "agent_ms": {t.agent_id: t.duration_ms for t in state.agent_traces},
        "ocr_text": (att.get("ocr_text") or "")[:300] or None,
        "links": len(state.discovered_urls_from_attachments or []),
        "final_url": state.final_url,
        "zero_fpr_note": state.zero_fpr_note,
        "errors": [s for s in state.execution_steps if "error" in s.lower() or "failed" in s.lower()][:5],
    }


def summarize(state: PhishingState, elapsed: float) -> Dict[str, Any]:
    return {
        "incident_id": state.incident_id,
        "llm_degraded": llm_degraded(state),
        "diag": diagnostics(state),
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


def _run_object(group: str, category: str, object_id: str, factory: SampleFactory) -> Dict[str, Any]:
    t0 = time.time()
    row = {"group": group, "category": category, "object": os.path.relpath(object_id, REPO_ROOT)
           if os.path.isabs(object_id) else object_id}
    try:
        state = run_pipeline(factory())
        row.update(status="ok", **summarize(state, time.time() - t0))
    except Exception as e:
        row.update(status="error", error=f"{type(e).__name__}: {str(e)[:200]}",
                   trace=traceback.format_exc(limit=3)[-600:], seconds=round(time.time() - t0, 3))
    return row


def _phishing_factory(category: str, object_id: str) -> SampleFactory:
    if category == "keis2_email":
        return lambda: build_state_from_sample_dir(object_id)
    return lambda: _file_state(object_id)


def _run_phishing_task(task: Tuple[str, str]) -> Dict[str, Any]:
    """Worker-process entry point (picklable): rebuilds the sample from its category and path."""
    category, object_id = task
    return _run_object("phishing", category, object_id, _phishing_factory(category, object_id))


def evaluate(dataset_root: str, limit_per_source: Optional[int] = None, sources=("keis2", "html", "png"),
             progress: Optional[Callable[[str], None]] = None, split: Optional[Dict[str, Any]] = None,
             part: Optional[str] = None, workers: int = 1) -> Dict[str, Any]:
    """`workers` > 1 analyses the phishing objects in parallel processes (each with its own LLM client, browser
    and DB connection) — the run is bound by model latency, not CPU. Results keep the sequential order."""
    started = time.time()
    rows: List[Dict[str, Any]] = []

    def report_progress(row):
        rows.append(row)
        if progress:
            progress(f"[{row['group']}/{row['category']}] {row['object'][:70]} -> {row.get('verdict', row['status'])}")

    phishing = phishing_sources(dataset_root, limit_per_source, sources, split, part)
    if workers > 1:
        import multiprocessing
        from concurrent.futures import ProcessPoolExecutor
        tasks = [(category, object_id) for category, object_id, _ in phishing]
        with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("spawn")) as pool:
            for row in pool.map(_run_phishing_task, tasks):
                report_progress(row)
    else:
        for category, object_id, factory in phishing:
            report_progress(_run_object("phishing", category, object_id, factory))
    for category, object_id, factory in benign_sources():
        report_progress(_run_object("benign", category, object_id, factory))
    report = build_report(rows, time.time() - started, dataset_root, limit_per_source)
    report["split"] = {"part": part, "version": split.get("version"), "created_at": split.get("created_at")}         if split and part else None
    return report


def _rate(n: int, d: int) -> Optional[float]:
    return round(n / d, 4) if d else None


def run_diagnostics(rows: List[Dict[str, Any]], clean_t: float = 0.30, mal_t: float = 0.70) -> Dict[str, Any]:
    """Where to look after a run: misses by cause, objects at the thresholds, benign flags with their reasons,
    model behaviour (failures, answers vs. verdicts) and detections that hang on a single indicator."""
    import statistics
    ok = [r for r in rows if r.get("status") == "ok"]
    phish = [r for r in ok if r["group"] == "phishing"]
    benign = [r for r in ok if r["group"] == "benign"]
    ref = lambda r: {"object": r["object"], "verdict": r["verdict"], "risk": r["risk"], "codes": r["codes"]}

    missed = [r for r in phish if r["verdict"] == "CLEAN"]
    missed_by_cat: Dict[str, Dict[str, Any]] = {}
    for r in missed:
        m = missed_by_cat.setdefault(r["category"], {"missed": 0, "no_indicators": 0, "below_threshold": 0,
                                                      "codes_when_below": collections.Counter()})
        m["missed"] += 1
        if r["codes"]:
            m["below_threshold"] += 1
            m["codes_when_below"].update(r["codes"])
        else:
            m["no_indicators"] += 1
    for m in missed_by_cat.values():
        m["codes_when_below"] = dict(m["codes_when_below"].most_common(10))

    def near(lo, hi, items):
        return [ref(r) for r in items if lo <= (r.get("risk") or 0) < hi]

    calls = [c for r in ok for c in (r.get("diag") or {}).get("llm_calls", [])]
    secs = sorted(c["seconds"] for c in calls if c.get("seconds") is not None)
    vlm = [(r, r["diag"]["vlm"]) for r in ok if (r.get("diag") or {}).get("vlm")]
    lure = [(r, r["diag"]["llm_lure"]) for r in ok if (r.get("diag") or {}).get("llm_lure")]
    lure_yes = lambda a: a.get("is_phishing_lure") is True
    single = collections.Counter(r["codes"][0] for r in phish if r["verdict"] != "CLEAN" and len(set(r["codes"])) == 1)
    shots: Dict[str, Dict[str, int]] = {}
    for r in ok:
        s = shots.setdefault(r["category"], collections.Counter())
        s[(r.get("diag") or {}).get("screenshot") or "none"] += 1

    return {
        "missed_by_category": missed_by_cat,
        "near_threshold": {
            "phishing_just_below_suspicious": near(clean_t - 0.1, clean_t, phish)[:100],
            "phishing_just_below_phishing": len(near(mal_t - 0.1, mal_t, phish)),
            "benign_close_to_phishing": near(mal_t - 0.2, mal_t, benign),
        },
        "benign_flags": [{**ref(r), "brand": (r.get("diag") or {}).get("brand"), "vlm": (r.get("diag") or {}).get("vlm"),
                          "llm_lure": (r.get("diag") or {}).get("llm_lure")} for r in benign if r["verdict"] != "CLEAN"],
        "single_indicator_detections": dict(single.most_common()),
        "screenshots_by_category": {k: dict(v) for k, v in shots.items()},
        "llm": {
            "calls": len(calls),
            "calls_by_type": dict(collections.Counter(c.get("type") for c in calls)),
            "failed_calls": sum(1 for c in calls if str(c.get("type", "")).endswith("_FAILED")),
            "degraded_objects": [r["object"] for r in ok if r.get("llm_degraded")][:100],
            "seconds_median": round(statistics.median(secs), 2) if secs else None,
            "seconds_p95": secs[int(0.95 * (len(secs) - 1))] if secs else None,
            "prompt_versions": dict(collections.Counter(f"{c.get('agent')}:{c.get('prompt_version')}" for c in calls)),
            "vlm_actions": dict(collections.Counter(str(a.get("asks_user_action")) for _, a in vlm)),
            "vlm_lures": dict(collections.Counter(str(a.get("lure")) for _, a in vlm)),
            "vlm_brand_not_in_registry": dict(collections.Counter(
                r["diag"]["vlm_unregistered_brand"] for r in ok if (r.get("diag") or {}).get("vlm_unregistered_brand")).most_common(30)),
            "lure_yes_but_clean": [ref(r) for r, a in lure if lure_yes(a) and r["verdict"] == "CLEAN"][:100],
            "lure_no_but_phishing_verdict": [ref(r) for r, a in lure if not lure_yes(a) and r["verdict"] == "MALICIOUS"][:100],
            "lure_yes_on_benign": [ref(r) for r, a in lure if lure_yes(a) and r["group"] == "benign"],
            "lure_confidence_just_below": [ref(r) for r, a in lure if lure_yes(a)
                                           and 0.65 <= float(a.get("confidence") or 0) < 0.75][:100],
        },
    }


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
    # HTML templates only: objects without a DOM (images, e-mails without pages) are not templates
    html_templates: Dict[str, Dict[str, Any]] = {}
    for r in phish_ok:
        if r["category"] == "html_attachment" and r.get("dom_hash"):
            html_templates.setdefault(r["dom_hash"], r)

    per_category = {}
    for cat in sorted({r["category"] for r in rows}):
        items = [r for r in rows if r["category"] == cat]
        ok = [r for r in items if r["status"] == "ok"]
        verdicts = collections.Counter(r["verdict"] for r in ok)
        per_category[cat] = {"objects": len(items), "processed_ok": len(ok), "verdicts": dict(verdicts),
                             "mean_seconds": round(sum(r["seconds"] for r in items) / len(items), 3) if items else None}

    # Portability: active rules generated in this run, applied by the light engine to every record.
    rules = [r["rule"] for r in phish_ok if r.get("rule") and r.get("rule_status") == "ACTIVE_VERIFIED"]
    # Each rule is matched against each record exactly once; everything below is derived from these sets.
    phish_matches = [{i for i, rule in enumerate(rules) if rule_matches(rule, r["record"])} for r in phish_ok]
    benign_matches = [{i for i, rule in enumerate(rules) if rule_matches(rule, r["record"])} for r in benign_ok]
    light_hits = [r for r, m in zip(phish_ok, phish_matches) if m]
    benign_rule_hits = [{"object": r["object"], "rules": [rules[i]["rule_id"] for i in sorted(m)]}
                        for r, m in zip(benign_ok, benign_matches) if m]
    heavy_detected = {r["object"] for r in detected}
    light_agree = [r for r in light_hits if r["object"] in heavy_detected]

    contribution = []
    for i, rule in enumerate(rules):
        contribution.append({"rule_id": rule["rule_id"], "kind": rule.get("kind"), "target_brand": rule.get("target_brand"),
                             "phishing_hits": sum(1 for m in phish_matches if i in m),
                             "unique_hits": sum(1 for m in phish_matches if m == {i}),
                             "benign_hits": sum(1 for m in benign_matches if i in m)})
    contribution.sort(key=lambda x: (-x["phishing_hits"], -x["unique_hits"]))

    code_freq = collections.Counter(c for r in phish_ok for c in r["codes"])
    benign_mal = [r["object"] for r in benign_ok if r["verdict"] == "MALICIOUS"]
    benign_susp = [r["object"] for r in benign_ok if r["verdict"] == "SUSPICIOUS"]

    metrics = {
        "processing_completeness": _rate(len(phish_ok), len(phish)),
        "recall_phishing_plus_suspicious": _rate(len(detected), len(phish_ok)),
        "recall_template_split": _rate(sum(1 for r in template_reps if r["verdict"] != "CLEAN"), len(template_reps)),
        "recall_html_templates": _rate(sum(1 for r in html_templates.values() if r["verdict"] != "CLEAN"), len(html_templates)),
        "html_templates": len(html_templates),
        "malicious_rate_on_phishing": _rate(sum(1 for r in phish_ok if r["verdict"] == "MALICIOUS"), len(phish_ok)),
        "benign_false_phishing": len(benign_mal),
        "benign_suspicious_share": _rate(len(benign_susp), len(benign_ok)),
        "reason_code_coverage": _rate(sum(1 for r in detected if r["codes"]), len(detected)),
        "light_engine_recall": _rate(len(light_hits), len(phish_ok)),
        "light_engine_agreement_with_heavy": _rate(len(light_agree), len(light_hits)),
        "light_engine_benign_hits": len(benign_rule_hits),
        "mean_seconds_per_object": round(sum(r["seconds"] for r in rows) / len(rows), 3) if rows else None,
        # objects analysed without the configured model (back-off / failed call): a run with many is not valid
        "llm_degraded_objects": sum(1 for r in rows if r.get("llm_degraded")),
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
        # What these numbers can and cannot claim (honest metrics, docs/BACKLOG.md A2, A3, 23d)
        "caveats": [
            "benign set = the Zero FPR Guard corpus (tests/fixtures/benign_samples.py): benign false positives and "
            "light_engine_benign_hits are a consistency check, not an independent estimate",
            "benign set is synthetic and was written alongside the rules",
            "light_engine_recall applies rules distilled from the same objects (portability, not generalisation)",
            "recall_template_split counts every object without a DOM (images, e-mails) as its own template; "
            "see recall_html_templates for HTML templates only",
        ],
        "per_category": per_category,
        "diagnostics": run_diagnostics(rows),
        "reason_code_frequency": dict(code_freq.most_common()),
        "rule_contribution": contribution[:200],
        "benign_false_positives": {"malicious": benign_mal, "suspicious": benign_susp, "rule_hits": benign_rule_hits},
        "missed_phishing": [r["object"] for r in phish_ok if r["verdict"] == "CLEAN"][:200],
        "errors": [{"object": r["object"], "error": r["error"]} for r in rows if r["status"] == "error"][:200],
        "objects": [{k: r.get(k) for k in ("group", "category", "object", "status", "verdict", "risk", "codes", "brand",
                                           "campaign", "rule_kind", "rule_status", "seconds", "llm_degraded",
                                           "incident_id", "diag")} for r in rows],
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


def _mutate_delayed_chunks(html: str) -> str:
    """Content assembled by script from plain string pieces after a delay: no base64 / escape encoding that the
    static deobfuscator unpacks, so this scenario is not tailored to the extractor (the atob variant is)."""
    import json
    pieces = [html[i:i + 40] for i in range(0, len(html), 40)]
    return ('<html><head><title></title></head><body><div id="app"></div><script>'
            f'var p={json.dumps(pieces, ensure_ascii=False)};'
            'setTimeout(function(){document.open();document.write(p.join(""));document.close();},800);'
            '</script></body></html>')


def _mutate_url(url: str, seed: int) -> str:
    import random
    from urllib.parse import urlparse
    rnd = random.Random(seed)
    host = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(9)) + rnd.choice([".top", ".xyz", ".online", ".site"])
    path = "/" + "/".join("".join(rnd.choice("abcdefghijk0123456789") for _ in range(6)) for _ in range(2))
    return f"{urlparse(url).scheme or 'https'}://{host}{path}"


PAGE_SCENARIOS = (("design_change", lambda h, i: _mutate_design(h, i)),
                  ("delayed_loading_atob", lambda h, i: _mutate_delayed(h)),
                  ("delayed_loading_js_chunks", lambda h, i: _mutate_delayed_chunks(h)))


def robustness(dataset_root: str, limit_per_source: int = 30, progress=None, split: Optional[Dict[str, Any]] = None,
               part: Optional[str] = "test") -> Dict[str, Any]:
    """Re-analyses detected phishing objects after domain/URL replacement, design change and
    delayed loading; reports recall per scenario relative to the unmodified objects.

    Honest set-up: objects come from the held-out part only; an e-mail whose verdict does not need its pages
    (still detected with the links removed) is excluded — changing the page could not affect it anyway."""
    import copy
    from ingest.dataset import load_sample_dir
    scenarios = collections.defaultdict(lambda: {"objects": 0, "still_detected": 0, "missed": []})
    excluded = {"email_detected_without_pages": 0}
    for category, object_id, factory in phishing_sources(dataset_root, limit_per_source, ("keis2", "html"),
                                                         split=split, part=part):
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
            for name, mutate in PAGE_SCENARIOS:
                mutated = mutate(html, 1)
                variants.append((name, PhishingState(incident_id=f"rb_{uuid_hex()}", source_type="html", raw_target=object_id,
                                                     raw_bytes=mutated.encode("utf-8"), offline_mode=True)))
        else:
            sample = load_sample_dir(object_id)
            if not any(l.get("html") for l in sample["links"]):
                continue
            email_only = run_pipeline(PhishingState(incident_id=f"rb_{uuid_hex()}", source_type="eml", raw_target=sample["eml_path"],
                                                    raw_bytes=sample["eml_bytes"] or None, offline_mode=True, precollected_links=[]))
            if email_only.verdict != "CLEAN":
                excluded["email_detected_without_pages"] += 1
                continue
            mutators = dict(PAGE_SCENARIOS)
            for name in ("domain_url_change",) + tuple(mutators):
                links = copy.deepcopy(sample["links"])
                for i, link in enumerate(links):
                    if name == "domain_url_change":
                        new = _mutate_url(link.get("final_url") or link.get("url") or "https://x", i)
                        link["url"], link["final_url"], link["redirect_chain"] = new, new, []
                    elif link.get("html"):
                        link["html"] = mutators[name](link["html"], i)
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
    return {**dict(scenarios), "_excluded": excluded}


def evaluate_labeled_eml(root: str, out_dir: str, subset: str = "validation", limit: Optional[int] = None,
                         progress=None) -> Dict[str, Any]:
    """Labelled e-mail test set (manifest.csv: id, evaluation_path, evidence_dir, label, subset, ...).
    Writes per-object results and two prediction files for the set's own compare_labels.py:
      predictions_strict.csv  — phishing only for MALICIOUS (SUSPICIOUS counts as benign);
      predictions_lenient.csv — phishing for MALICIOUS or SUSPICIOUS."""
    import csv
    from ingest.dataset import load_link_dir, _link_sort_key
    with open(os.path.join(root, "manifest.csv"), encoding="utf-8-sig", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("subset") == subset]
    if limit:
        rows = rows[:limit]
    os.makedirs(out_dir, exist_ok=True)
    results = []
    started = time.time()
    for r in rows:
        t0 = time.time()
        item = {"id": r["id"], "label": r["label"], "language": r.get("language", ""), "group_id": r.get("group_id", "")}
        try:
            with open(os.path.join(root, r["evaluation_path"]), "rb") as f:
                eml = f.read()
            links = []
            ev = r.get("evidence_dir") or ""
            if ev and os.path.isdir(os.path.join(root, ev)):
                ev_dir = os.path.join(root, ev)
                links = [load_link_dir(os.path.join(ev_dir, d)) for d in sorted(
                    (d for d in os.listdir(ev_dir) if d.startswith("Link_")), key=_link_sort_key)]
            state = run_pipeline(PhishingState(incident_id=f"lbl_{r['id']}", source_type="eml", raw_target=r["evaluation_path"],
                                               raw_bytes=eml, offline_mode=True, precollected_links=links))
            item.update(status="ok", verdict=state.verdict, risk=state.risk_score, codes=state.reason_codes,
                        details=state.reason_details, brand=state.brand_evidence.detected_brand_name,
                        llm_degraded=llm_degraded(state), incident_id=state.incident_id, diag=diagnostics(state))
        except Exception as e:
            item.update(status="error", verdict="CLEAN", error=f"{type(e).__name__}: {str(e)[:200]}")
        item["seconds"] = round(time.time() - t0, 3)
        results.append(item)
        if progress:
            progress(f"{item['label']:8s} -> {item['verdict']:10s} {r['id']}")

    for name, positive in (("predictions_strict.csv", {"MALICIOUS"}), ("predictions_lenient.csv", {"MALICIOUS", "SUSPICIOUS"})):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["id", "predicted_label"])
            for it in results:
                w.writerow([it["id"], "phishing" if it["verdict"] in positive else "benign"])
    with open(os.path.join(out_dir, "results.jsonl"), "w", encoding="utf-8") as f:
        for it in results:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")

    phish = [i for i in results if i["label"] == "phishing"]
    benign = [i for i in results if i["label"] == "benign"]
    verdicts = lambda items: dict(collections.Counter(i["verdict"] for i in items))
    summary = {
        "objects": len(results), "errors": sum(i["status"] == "error" for i in results),
        "llm_degraded_objects": sum(1 for i in results if i.get("llm_degraded")),
        "elapsed_seconds": round(time.time() - started, 1),
        "phishing_verdicts": verdicts(phish), "benign_verdicts": verdicts(benign),
        "recall_strict": _rate(sum(i["verdict"] == "MALICIOUS" for i in phish), len(phish)),
        "recall_phishing_plus_suspicious": _rate(sum(i["verdict"] != "CLEAN" for i in phish), len(phish)),
        "benign_false_phishing": sum(i["verdict"] == "MALICIOUS" for i in benign),
        "benign_suspicious_share": _rate(sum(i["verdict"] == "SUSPICIOUS" for i in benign), len(benign)),
        "benign_false_phishing_ids": [i["id"] for i in benign if i["verdict"] == "MALICIOUS"],
        "benign_suspicious_ids": [i["id"] for i in benign if i["verdict"] == "SUSPICIOUS"],
        "missed_phishing_ids": [i["id"] for i in phish if i["verdict"] == "CLEAN"],
        "benign_code_frequency": dict(collections.Counter(c for i in benign for c in i.get("codes", [])).most_common()),
        "diagnostics": run_diagnostics([{**i, "group": "phishing" if i["label"] == "phishing" else "benign",
                                         "category": i.get("language") or "eml", "object": i["id"]} for i in results]),
    }
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    return summary


def _load_run(path: str) -> Dict[str, Dict[str, Any]]:
    """Objects of a run keyed by object id: a metrics report (.json) or a labelled-set output dir / results.jsonl."""
    if os.path.isdir(path):
        path = os.path.join(path, "results.jsonl")
    if path.endswith(".jsonl"):
        with open(path, encoding="utf-8") as f:
            items = [json.loads(l) for l in f if l.strip()]
        return {i["id"]: {**i, "category": i.get("label", ""), "object": i["id"]} for i in items}
    with open(path, encoding="utf-8") as f:
        report = json.load(f)
    return {o["object"]: o for o in report.get("objects", [])}


def diff_runs(path_a: str, path_b: str, limit: int = 200) -> Dict[str, Any]:
    """What changed between two runs on the same objects: verdict transitions per category and, per changed
    object, the indicators that appeared / disappeared (the cause of the change)."""
    a, b = _load_run(path_a), _load_run(path_b)
    common = [k for k in a if k in b]
    transitions = collections.Counter()
    changed = []
    code_gain, code_loss = collections.Counter(), collections.Counter()
    for k in common:
        x, y = a[k], b[k]
        added = sorted(set(y.get("codes") or []) - set(x.get("codes") or []))
        removed = sorted(set(x.get("codes") or []) - set(y.get("codes") or []))
        code_gain.update(added)
        code_loss.update(removed)
        if x.get("verdict") != y.get("verdict"):
            transitions[(x.get("category") or x.get("group"), x.get("verdict"), y.get("verdict"))] += 1
            changed.append({"object": k, "category": x.get("category"), "before": x.get("verdict"), "after": y.get("verdict"),
                            "risk": [x.get("risk"), y.get("risk")], "codes_added": added, "codes_removed": removed})
    return {
        "runs": [path_a, path_b], "objects_a": len(a), "objects_b": len(b), "common": len(common),
        "transitions": [{"category": c, "from": f, "to": t, "objects": n} for (c, f, t), n in transitions.most_common()],
        "codes_appeared": dict(code_gain.most_common()), "codes_disappeared": dict(code_loss.most_common()),
        "changed_objects": changed[:limit],
    }


def uuid_hex() -> str:
    import uuid
    return uuid.uuid4().hex[:10]


def save_report(report: Dict[str, Any], out_path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return out_path
