import requests

from config import Settings
from llm.client import LLMClient
from llm import prompts


def _settings(**kw):
    base = dict(LLM_MODE="cloud", LLM_CLOUD_BASE_URL="https://llm.example/api", LLM_CLOUD_API_KEY="k",
                LLM_CLOUD_TEXT_MODEL="cloud-model", LLM_LOCAL_BASE_URL="http://localhost:11434/v1",
                LLM_LOCAL_TEXT_MODEL="qwen-local", LLM_LOCAL_VISION_MODEL="", LOGS_DIR="./logs_test_tmp")
    base.update(kw)
    return Settings(_env_file=None, **base)


def test_modes():
    assert _settings(LLM_MODE="off").llm_configured is False
    assert _settings(LLM_MODE="cloud", LLM_CLOUD_API_KEY="").llm_configured is False
    local = _settings(LLM_MODE="local")
    assert local.llm_configured and local.llm_base_url.startswith("http://localhost") and local.llm_api_key == ""
    cloud = _settings()
    assert cloud.llm_base_url == "https://llm.example/api" and cloud.llm_api_key == "k"


def test_each_mode_uses_its_own_models():
    cloud, local = _settings(), _settings(LLM_MODE="local")
    assert (cloud.text_model, cloud.vision_model) == ("cloud-model", "cloud-model")  # multimodal text model
    assert (local.text_model, local.vision_model) == ("qwen-local", "qwen-local")
    assert _settings(LLM_CLOUD_TEXT_MODEL="").llm_configured is False


def test_reasoning_effort_is_sent(monkeypatch):
    sent = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        sent.update(json)
        return _Resp(200, {"choices": [{"message": {"content": "ok"}}]})
    monkeypatch.setattr(requests, "post", fake_post)
    LLMClient(_settings(LLM_REASONING_EFFORT="none")).ask_llm("hi")
    assert sent["reasoning_effort"] == "none" and sent["model"] == "cloud-model"
    sent.clear()
    LLMClient(_settings()).ask_llm("hi")
    assert "reasoning_effort" not in sent


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
    monkeypatch.setattr("llm.client.time.sleep", lambda s: None)
    client = LLMClient(_settings(LLM_MODE="local"))
    assert client.is_fallback(client.ask_llm("a"))
    assert client.enabled is False
    client.ask_llm("b")
    assert len(calls) == 3  # retried, then skipped during the back-off


def test_single_connection_glitch_does_not_disable_the_llm(monkeypatch):
    """One TLS / reset error mid-batch must not switch the LLM off for the following objects."""
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise requests.exceptions.SSLError("EOF occurred in violation of protocol")
        return _Resp(200, {"choices": [{"message": {"content": "ok"}}]})
    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr("llm.client.time.sleep", lambda s: None)
    client = LLMClient(_settings())
    assert client.ask_llm("a") == "ok"
    assert client.enabled is True


def test_reasoning_text_is_not_used_as_answer(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(200, {"choices": [{"message": {
        "content": None, "reasoning_content": "Brand: maybe Sber? or VTB..."}}]}))
    client = LLMClient(_settings())
    assert client.is_fallback(client.ask_vlm("q", "iVBORw0KGgo="))


def test_truncated_completion_is_retried_once_with_more_tokens(monkeypatch):
    sent = []

    def fake_post(url, headers=None, json=None, timeout=None):
        sent.append(json["max_tokens"])
        return _Resp(200, {"choices": [{"finish_reason": "length", "message": {"content": None}}]})
    monkeypatch.setattr(requests, "post", fake_post)
    client = LLMClient(_settings())
    assert client.is_fallback(client.ask_llm("hi", max_tokens=100))
    assert sent == [100, 200]


def test_prompts_are_versioned_files():
    text = prompts.render("lure_classifier", content="Тест")
    assert "is_phishing_lure" in text and text.endswith("Тест")
    assert '"impersonated_brand"' in prompts.render("vision_brand", lure_types="a, b")


def test_audit_jsonl_names_the_object_prompt_version_and_retries(monkeypatch, tmp_path):
    import json
    from llm.client import set_current_object
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            return _Resp(503)
        return _Resp(200, {"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}], "usage": {"total_tokens": 7}})
    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr("llm.client.time.sleep", lambda s: None)
    client = LLMClient(_settings(LOGS_DIR=str(tmp_path)))
    set_current_object("inc_42")
    try:
        assert client.ask_llm("Текст письма", prompt_name="lure_classifier") == "ok"
    finally:
        set_current_object(None)
    rec = json.loads((tmp_path / "llm_audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert rec["object"] == "inc_42" and rec["prompt_name"] == "lure_classifier" and len(rec["prompt_version"]) == 8
    assert rec["attempts"] == 2 and rec["retried_errors"] == ["HTTP 503"] and rec["usage"] == {"total_tokens": 7}
    assert rec["prompt"] == "Текст письма" and rec["finish_reason"] == "stop"
