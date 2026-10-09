import requests

from config import Settings
from llm.client import LLMClient
from llm import prompts


def _settings(**kw):
    base = dict(LLM_MODE="cloud", LLM_CLOUD_BASE_URL="https://llm.example/api", LLM_CLOUD_API_KEY="k",
                LLM_LOCAL_BASE_URL="http://localhost:11434/v1", LOGS_DIR="./logs_test_tmp")
    base.update(kw)
    return Settings(_env_file=None, **base)


def test_modes():
    assert _settings(LLM_MODE="off").llm_configured is False
    assert _settings(LLM_MODE="cloud", LLM_CLOUD_API_KEY="").llm_configured is False
    local = _settings(LLM_MODE="local")
    assert local.llm_configured and local.llm_base_url.startswith("http://localhost") and local.llm_api_key == ""
    cloud = _settings()
    assert cloud.llm_base_url == "https://llm.example/api" and cloud.llm_api_key == "k"


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code, self._payload, self.text = status, payload, text

    def json(self):
        return self._payload


def test_client_errors_are_not_retried(monkeypatch):
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        return _Resp(400, text='{"detail":"Model not found"}')
    monkeypatch.setattr(requests, "post", fake_post)
    client = LLMClient(_settings())
    answer = client.ask_llm("hi")
    assert client.is_fallback(answer) and len(calls) == 1
    assert "Model not found" in answer


def test_unreachable_local_server_is_skipped_afterwards(monkeypatch):
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        raise requests.ConnectionError("refused")
    monkeypatch.setattr(requests, "post", fake_post)
    client = LLMClient(_settings(LLM_MODE="local"))
    assert client.is_fallback(client.ask_llm("a"))
    assert client.enabled is False
    client.ask_llm("b")
    assert len(calls) == 1


def test_reasoning_text_is_not_used_as_answer(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(200, {"choices": [{"message": {
        "content": None, "reasoning_content": "Brand: maybe Sber? or VTB..."}}]}))
    client = LLMClient(_settings())
    assert client.is_fallback(client.ask_vlm("q", "iVBORw0KGgo="))


def test_prompts_are_versioned_files():
    text = prompts.render("lure_classifier", content="Тест")
    assert "is_phishing_lure" in text and text.endswith("Тест")
    assert '"brand"' in prompts.render("vision_brand", lure_types="a, b")
