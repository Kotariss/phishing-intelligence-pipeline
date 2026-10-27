"""Matching rules of the extraction-completeness metric (ПМИ К-2)."""
import json
import os

from extraction_eval import _matches_domain, host_of, norm

LABELS = os.path.join(os.path.dirname(__file__), "..", "docs", "labelling", "extraction_labels_v1.json")


def test_url_normalisation_ignores_scheme_case_fragment_and_trailing_slash():
    assert norm("HTTP://Example.COM/a/#frag") == norm("https://example.com/a")
    assert norm("https://a.example/x?y=1") != norm("https://a.example/x?y=2")


def test_domain_spec_matches_subdomains_only_of_that_domain():
    hosts = {"ci3.googleusercontent.com", "evilgoogleusercontent.com"}
    assert _matches_domain("domain:googleusercontent.com", hosts)
    assert not _matches_domain("domain:googleusercontent.com", {"evilgoogleusercontent.com"})
    assert host_of("https://A.b.example:8443/x") == "a.b.example"


def test_labels_file_is_consistent():
    with open(LABELS, encoding="utf-8") as f:
        labels = json.load(f)
    assert labels["matching_rule"] and len(labels["objects"]) >= 30
    for obj in labels["objects"]:
        assert obj["type"] in ("html", "eml", "image")
        assert all(isinstance(obj[k], list) for k in ("links", "resources", "forms", "endpoints"))
