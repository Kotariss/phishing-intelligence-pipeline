import json
import os

import pytest
import requests

from config import Settings
from llm.client import LLMClient, LLMUnavailable, set_current_object
from llm import prompts


def _settings(**kw):
    base = dict(LLM_MODE="cloud", LLM_CLOUD_BASE_URL="https://llm.example/api", LLM_CLOUD_API_KEY="k",
                LLM_CLOUD_TEXT_MODEL="cloud-model", LLM_LOCAL_BASE_URL="http://localhost:11434/v1",
                LLM_LOCAL_TEXT_MODEL="qwen-local", LLM_LOCAL_VISION_MODEL="", LOGS_DIR=os.environ["LOGS_DIR"])
    base.update(kw)
    return Settings(_env_file=None, **base)


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code, self._payload, self.text = status, payload, text

    def json(self):
        return self._payload


def _ok(content="ok", **choice):
    return _Resp(200, {"choices": [{"message": {"content": content}, **choice}]})


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr("llm.client.time.sleep", lambda s: None)


def test_modes_and_configuration():
    local, cloud = _settings(LLM_MODE="local"), _settings()
    assert local.llm_base_url.startswith("http://localhost") and local.llm_api_key == ""
    assert cloud.llm_base_url == "https://llm.example/api" and cloud.llm_api_key == "k"
    assert (cloud.text_model, cloud.vision_model) == ("cloud-model", "cloud-model")  # multimodal text model
    assert (local.text_model, local.vision_model) == ("qwen-local", "qwen-local")
    assert "LLM_CLOUD_API_KEY" in _settings(LLM_CLOUD_API_KEY="").llm_config_problem()
    with pytest.raises(LLMUnavailable):  # the model is required: an unconfigured client cannot be created
        LLMClient(_settings(LLM_CLOUD_TEXT_MODEL=""))


def test_reasoning_effort_is_sent(monkeypatch):
    sent = {}
    monkeypatch.setattr(requests, "post", lambda url, headers=None, json=None, timeout=None: sent.update(json) or _ok())
    LLMClient(_settings(LLM_REASONING_EFFORT="none")).ask_llm("hi")
    assert sent["reasoning_effort"] == "none" and sent["model"] == "cloud-model"
    sent.clear()
    LLMClient(_settings()).ask_llm("hi")
    assert "reasoning_effort" not in sent


def test_client_errors_are_not_retried(monkeypatch):
    calls = []
    monkeypatch.setattr(requests, "post", lambda *a, **k: calls.append(1) or _Resp(400, text='{"detail":"Model not found"}'))
    with pytest.raises(LLMUnavailable, match="Model not found"):
        LLMClient(_settings()).ask_llm("hi")
    assert len(calls) == 1


def test_transient_errors_are_retried_then_the_call_fails(monkeypatch):
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        raise requests.exceptions.SSLError("EOF occurred in violation of protocol")
    monkeypatch.setattr(requests, "post", fake_post)
    with pytest.raises(LLMUnavailable, match="4 attempt"):
        LLMClient(_settings(LLM_ATTEMPTS=4)).ask_llm("a")
    assert len(calls) == 4


def test_a_glitch_is_recovered_by_the_retry(monkeypatch):
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise requests.exceptions.SSLError("EOF occurred in violation of protocol")
        return _ok()
    monkeypatch.setattr(requests, "post", fake_post)
    assert LLMClient(_settings()).ask_llm("a") == "ok"


def test_reasoning_text_is_never_the_answer(monkeypatch):
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(200, {"choices": [{"message": {
        "content": None, "reasoning_content": "Brand: maybe Sber? or VTB..."}}]}))
    with pytest.raises(LLMUnavailable, match="Empty completion"):
        LLMClient(_settings(LLM_ATTEMPTS=2)).ask_vlm("q", "iVBORw0KGgo=")


def test_truncated_completion_gets_more_tokens_on_retry(monkeypatch):
    sent = []

    def fake_post(url, headers=None, json=None, timeout=None):
        sent.append(json["max_tokens"])
        return _ok(None, finish_reason="length") if len(sent) == 1 else _ok("done")
    monkeypatch.setattr(requests, "post", fake_post)
    assert LLMClient(_settings()).ask_llm("hi", max_tokens=100) == "done"
    assert sent == [100, 200]


def test_audit_jsonl_names_the_object_prompt_version_and_retries(monkeypatch):
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            return _Resp(503)
        return _Resp(200, {"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}], "usage": {"total_tokens": 7}})
    monkeypatch.setattr(requests, "post", fake_post)
    client = LLMClient(_settings())
    set_current_object("inc_42")
    try:
        assert client.ask_llm("Текст письма", prompt_name="lure_classifier") == "ok"
    finally:
        set_current_object(None)
    with open(os.path.join(os.environ["LOGS_DIR"], "llm_audit.jsonl"), encoding="utf-8") as f:
        rec = json.loads(f.read().splitlines()[-1])
    assert rec["object"] == "inc_42" and rec["prompt_name"] == "lure_classifier" and len(rec["prompt_version"]) == 8
    assert rec["attempts"] == 2 and rec["retried_errors"] == ["HTTP 503"] and rec["usage"] == {"total_tokens": 7}
    assert rec["prompt"] == "Текст письма" and rec["finish_reason"] == "stop"


def test_prompts_are_versioned_files():
    text = prompts.render("lure_classifier", content="Тест")
    assert "is_phishing_lure" in text and "techniques" in text and text.endswith("Тест")
    assert '"impersonated_brand"' in prompts.render("vision_brand", lure_types="a, b")
    assert prompts.version("vision_brand") != prompts.version("lure_classifier")
