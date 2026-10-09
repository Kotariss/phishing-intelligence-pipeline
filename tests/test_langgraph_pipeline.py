"""End-to-end pipeline tests (offline): orchestration, persistence, serialisation, campaigns."""
import json
import os

import pytest

from orchestrator.state import PhishingState
from orchestrator.graph import run_pipeline
from ingest.dataset import build_state_from_sample_dir, load_link_dir
from db.repository import IncidentRepository
from helpers import run_page, run_file, TELEGRAM_KIT
from conftest import DATASET_DIR
from test_attachment_parser import _eml_with_html_attachment


def test_all_agents_run_and_state_is_json_safe():
    state = run_file("mail.eml", _eml_with_html_attachment())
    agent_ids = [t.agent_id for t in state.agent_traces]
    for agent in ("triage_dispatcher", "url_agent", "dom_agent", "vision_agent", "quishing_agent",
                  "content_agent", "aggregator", "synthesizer", "db_persist"):
        assert agent in agent_ids
    dumped = state.public_dump()
    json.dumps(dumped)
    assert "raw_bytes" not in dumped


def test_eml_with_html_attachment_is_phishing_and_persisted():
    state = run_file("mail.eml", _eml_with_html_attachment())
    assert state.verdict == "MALICIOUS"
    assert {"ATTACH_OFFLINE_FORM", "RC_BRAND_SPOOF_DISPLAYNAME", "RC_LURE_DOUBLE_EXTENSION"} <= set(state.reason_codes)
    inc = IncidentRepository().get_incident(state.incident_id)
    assert inc is not None and inc.verdict == "MALICIOUS" and inc.evidence_data["reason_details"]


def test_offline_mode_never_fetches(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access in offline mode")
    monkeypatch.setattr("requests.Session.get", boom)
    monkeypatch.setattr("requests.get", boom)
    state = run_pipeline(PhishingState(incident_id="t_off", source_type="url",
                                       raw_target="https://example.com/", offline_mode=True))
    assert state.verdict == "CLEAN"


def test_same_kit_on_two_domains_forms_one_campaign():
    a = run_page("https://kit-host-one.top/login", TELEGRAM_KIT)
    b = run_page("https://kit-host-two.xyz/secure/login", TELEGRAM_KIT)
    assert a.campaign_id and a.campaign_id == b.campaign_id
    campaigns = IncidentRepository().list_campaigns(min_size=2)
    assert any(c["campaign_id"] == a.campaign_id and c["incidents"] >= 2 for c in campaigns)


def test_dataset_link_dir_loader(tmp_path):
    link = tmp_path / "Link_0"
    link.mkdir()
    (link / "url.txt").write_text("https:/zcase7.info/add/x", encoding="utf-8")
    (link / "chain_info.json").write_text(json.dumps({"redirect_chain": [
        {"from": "https://zcase7.info/add/x", "to": "https://land.example.top/p", "status_code": 302, "is_js_meta": False}]}),
        encoding="utf-8")
    (link / "html.html").write_text("<html><title>x</title></html>", encoding="utf-8")
    loaded = load_link_dir(str(link))
    assert loaded["url"] == "https://zcase7.info/add/x"
    assert loaded["final_url"] == "https://land.example.top/p"


def test_real_dataset_sample_if_available():
    sample = os.path.join(DATASET_DIR, "keis2", "Adobe", "bfc7879dc6f69c94cc86b74f3158ee30033bd12f")
    if not os.path.isdir(sample):
        pytest.skip("Dataset not available")
    state = run_pipeline(build_state_from_sample_dir(sample))
    assert state.verdict == "MALICIOUS"
    assert "RC_DROP_SCREENCONNECT_RAT" in state.reason_codes
    assert state.generated_l_signature["kind"] == "payload_drop"
