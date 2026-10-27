"""LLM_MODE=off: the structural extractors work alone, every result says so (ТЗ 4.4.2, 7.11; curator's request 27.10)."""
import pytest

from config import Settings
from helpers import run_file, run_page, TELEGRAM_KIT
from llm import client as llm_client
from llm.client import DisabledLLMClient, LLMUnavailable, get_llm_client
from test_attachment_parser import _eml_with_html_attachment


@pytest.fixture
def llm_off(monkeypatch):
    monkeypatch.setattr(llm_client, "_default_client", DisabledLLMClient(Settings(_env_file=None, LLM_MODE="off")))


def test_off_mode_needs_no_model_configuration():
    s = Settings(_env_file=None, LLM_MODE="off", LLM_LOCAL_BASE_URL="", LLM_LOCAL_TEXT_MODEL="")
    assert s.llm_mode == "off" and not s.llm_enabled and s.llm_config_problem() == ""
    assert Settings(_env_file=None, LLM_MODE="local").llm_enabled


def test_client_factory_returns_the_disabled_client(monkeypatch):
    monkeypatch.setattr(llm_client, "_default_client", None)
    monkeypatch.setattr(llm_client, "get_settings", lambda: Settings(_env_file=None, LLM_MODE="off"))
    client = get_llm_client()
    assert isinstance(client, DisabledLLMClient) and not client.enabled
    with pytest.raises(LLMUnavailable):
        client.ask_llm("x")


def test_pipeline_judges_a_kit_without_a_model_and_marks_the_mode(llm_off):
    state = run_file("mail.eml", _eml_with_html_attachment())
    assert state.verdict == "MALICIOUS" and state.reason_codes and state.llm_mode == "off"
    assert "CONTENT_LLM_LURE" not in state.reason_codes
    content = next(t for t in state.agent_traces if t.agent_id == "content_agent")
    assert "LLM_MODE=off" in content.decision and not content.tools_called
    assert state.explanation  # evidence list and verdict stay; only the model's summary is absent


def test_page_analysis_works_without_a_model(llm_off):
    state = run_page("https://kit-off-mode.top/login", TELEGRAM_KIT)
    assert state.llm_mode == "off" and state.verdict in ("SUSPICIOUS", "MALICIOUS")


def test_model_mode_is_marked_too():
    assert run_file("page.html", b"<html><body>hello</body></html>").llm_mode == "local"
