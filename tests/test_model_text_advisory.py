"""The model's reading of the text never decides alone (ТЗ 4.1.4.6, А.1.3): advisory without independent evidence."""
import pytest

from agents.synthesizer_agent import SynthesizerAgent
from orchestrator.state import PhishingState


def _run(*codes):
    state = PhishingState(incident_id="t_adv", source_type="eml", raw_target="x.eml")
    for code in codes:
        state.add_reason(code, "test", None)
    return SynthesizerAgent().run(state)


def test_model_text_alone_is_advisory_and_keeps_evidence():
    state = _run("CONTENT_LLM_LURE", "CONTENT_ACCOUNT_THREAT")
    assert state.verdict == "CLEAN"
    assert set(state.network_evidence["model_text_advisory"]) == {"CONTENT_LLM_LURE", "CONTENT_ACCOUNT_THREAT"}
    assert "CONTENT_LLM_LURE" in state.reason_codes and "справочный" in state.explanation


def test_model_text_with_support_codes_only_stays_advisory():
    assert _run("CONTENT_LLM_LURE", "RC_EPHEMERAL_HOST_DEAD").verdict == "CLEAN"


@pytest.mark.parametrize("other", ["EMAIL_REPLY_TO_MISMATCH", "RC_BRAND_SPOOF_DISPLAYNAME", "URL_IP_HOST", "RC_ATTACH_PASSWORD_INPUT"])
def test_model_text_with_an_independent_signal_counts(other):
    state = _run("CONTENT_LLM_LURE", other)
    assert "model_text_advisory" not in state.network_evidence
    assert state.verdict in ("SUSPICIOUS", "MALICIOUS") and state.risk_score >= 0.45


def test_image_findings_are_not_advisory():
    state = _run("IMAGE_CREDENTIAL_PROMPT", "IMAGE_FAKE_DOCUMENT_VIEWER")
    assert state.verdict == "SUSPICIOUS" and "model_text_advisory" not in state.network_evidence


def test_fake_human_check_in_an_attachment_is_independent_evidence():
    state = _run("CONTENT_LLM_LURE", "ATTACH_FAKE_HUMAN_CHECK")
    assert "model_text_advisory" not in state.network_evidence and state.verdict in ("SUSPICIOUS", "MALICIOUS")
