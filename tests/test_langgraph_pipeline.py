import sys
import os
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "worker", "src"))
sys.path.insert(0, os.path.join(ROOT_DIR, "services", "sandbox", "src"))

from orchestrator.state import PhishingState
from orchestrator.graph import run_pipeline

def test_pipeline_sberbank_phishing_eml():
    eml_path = os.path.join(ROOT_DIR, "file_for_case/keis2/Сбер/0517e90f5805fff01c086cbc6ace8010e0a643e6/0517e90f5805fff01c086cbc6ace8010e0a643e6")
    if not os.path.exists(eml_path):
        pytest.skip("Dataset file not available")

    with open(eml_path, "rb") as f:
        content = f.read()

    state = PhishingState(
        incident_id="e2e-sber-01",
        source_type="eml",
        raw_target=eml_path,
        raw_bytes=content
    )
    result = run_pipeline(state)
    assert result.verdict in ("MALICIOUS", "SUSPICIOUS")
    assert result.risk_score >= 0.70
    assert result.brand_evidence.brand_impersonation_confirmed is True
    assert result.generated_l_signature is not None
    assert result.zero_fpr_passed is True

def test_pipeline_html_phishing_kit():
    html_dir = os.path.join(ROOT_DIR, "file_for_case/html_phishing2026")
    files = [f for f in os.listdir(html_dir) if f.endswith(".html")]
    if not files:
        pytest.skip("HTML dataset not available")

    sample_p = os.path.join(html_dir, files[0])
    with open(sample_p, "rb") as f:
        content = f.read()

    state = PhishingState(
        incident_id="e2e-html-01",
        source_type="html",
        raw_target=sample_p,
        raw_bytes=content
    )
    result = run_pipeline(state)
    assert result.verdict in ("MALICIOUS", "SUSPICIOUS")
    assert result.zero_fpr_passed is True

def test_pipeline_zero_fpr_clean_url():
    state = PhishingState(
        incident_id="e2e-clean-01",
        source_type="url",
        raw_target="https://online.sberbank.ru/CSAFront/index.do"
    )
    result = run_pipeline(state)
    assert result.verdict == "CLEAN"
    assert result.risk_score < 0.30
    assert result.zero_fpr_passed is True
    assert result.generated_l_signature is None
