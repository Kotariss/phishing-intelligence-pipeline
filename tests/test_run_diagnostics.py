import json

from evaluation import diff_runs, run_diagnostics


def _row(obj, group, verdict, risk, codes, cat="html_attachment", **diag):
    return {"object": obj, "group": group, "category": cat, "status": "ok", "verdict": verdict, "risk": risk,
            "codes": codes, "diag": {"llm_calls": [], **diag}}


def test_diagnostics_point_at_the_causes():
    rows = [
        _row("a", "phishing", "CLEAN", 0.0, []),
        _row("b", "phishing", "CLEAN", 0.25, ["URL_FREE_HOSTING"]),
        _row("c", "phishing", "SUSPICIOUS", 0.30, ["RC_ATTACH_OBFUSCATED_JS"]),
        _row("d", "phishing", "CLEAN", 0.0, [], llm_lure={"is_phishing_lure": True, "confidence": 0.7}),
        {"object": "s", "group": "phishing", "category": "image_lure", "status": "skipped_llm", "error": "VISION_VLM failed"},
        _row("e", "benign", "MALICIOUS", 0.95, ["BRAND_IMPERSONATION_CONFIRMED"], cat="benign_page",
             vlm={"impersonated_brand": "Сбер", "asks_user_action": "enter_card"}),
    ]
    d = run_diagnostics(rows)
    m = d["missed_by_category"]["html_attachment"]
    assert (m["missed"], m["no_indicators"], m["below_threshold"]) == (3, 2, 1)
    assert d["near_threshold"]["phishing_just_below_suspicious"][0]["object"] == "b"
    assert d["single_indicator_detections"] == {"RC_ATTACH_OBFUSCATED_JS": 1}
    assert d["benign_flags"][0]["vlm"]["impersonated_brand"] == "Сбер"
    assert d["llm"]["skipped_objects"] == [{"object": "s", "error": "VISION_VLM failed"}]
    assert [r["object"] for r in d["llm"]["lure_yes_but_clean"]] == ["d"]
    assert [r["object"] for r in d["llm"]["lure_confidence_just_below"]] == ["d"]
    json.dumps(d)


def test_diff_runs_explains_changes(tmp_path):
    def report(objs):
        p = tmp_path / f"r{len(list(tmp_path.iterdir()))}.json"
        p.write_text(json.dumps({"objects": objs}), encoding="utf-8")
        return str(p)
    a = report([_row("x", "phishing", "SUSPICIOUS", 0.4, ["RC_CAMPAIGN_INVARIANT_MATCH"], cat="image_lure"),
                _row("y", "phishing", "CLEAN", 0.0, [])])
    b = report([_row("x", "phishing", "CLEAN", 0.0, [], cat="image_lure"),
                _row("y", "phishing", "CLEAN", 0.0, [])])
    diff = diff_runs(a, b)
    assert diff["transitions"] == [{"category": "image_lure", "from": "SUSPICIOUS", "to": "CLEAN", "objects": 1}]
    assert diff["changed_objects"][0]["codes_removed"] == ["RC_CAMPAIGN_INVARIANT_MATCH"]
