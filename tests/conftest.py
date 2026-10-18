import json
import os
import sys
import tempfile

import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TMP = tempfile.mkdtemp(prefix="phish_tests_")

# Deterministic, offline, isolated test environment (must be set before the worker modules load).
# The model is required by the pipeline; tests never reach a server: the `fake_llm` fixture answers instead.
os.environ["LLM_MODE"] = "local"
os.environ["LLM_LOCAL_BASE_URL"] = "http://127.0.0.1:1/v1"  # nothing listens there
os.environ["SANDBOX_INPROCESS_FALLBACK"] = "true"
os.environ["SANDBOX_HOST"] = "127.0.0.1"
os.environ["SANDBOX_PORT"] = "1"  # nothing listens there -> in-process extractors
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_TMP, 'test.db')}"
os.environ["EXPORTS_DIR"] = os.path.join(_TMP, "exports")
os.environ["LOGS_DIR"] = os.path.join(_TMP, "logs")

for path in (os.path.join(ROOT_DIR, "services", "worker", "src"),
             os.path.join(ROOT_DIR, "services", "sandbox", "src"),
             os.path.join(ROOT_DIR, "tests", "fixtures")):
    if path not in sys.path:
        sys.path.insert(0, path)

DATASET_DIR = os.path.join(ROOT_DIR, "file_for_case")

# Neutral answers: "not a lure", "no impersonated brand, asks nothing". Tests set their own per call type.
DEFAULT_LURE = {"is_phishing_lure": False, "lure_type": "none", "confidence": 0.9, "indicators": [],
                "techniques": {"account_threat": None, "victim_addressed": None, "fake_human_check": None}}
DEFAULT_VLM = {"impersonated_brand": None, "other_brands": [], "asks_user_action": "none", "lure": "other",
               "login_form_visible": False, "logo_box": None, "confidence": 0.9, "reason": "test"}


@pytest.fixture(autouse=True)
def fake_llm(monkeypatch):
    """The model of every pipeline run in the tests. `fake_llm.lure` / `fake_llm.vlm` set the answers,
    `fake_llm.fail = True` makes every call fail as an unreachable server would (after its retries)."""
    from llm import client as llm_client
    from llm.client import LLMClient, LLMUnavailable

    class FakeModel(LLMClient):
        def __init__(self):
            super().__init__()
            self.lure, self.vlm, self.fail, self.calls = dict(DEFAULT_LURE), dict(DEFAULT_VLM), False, []

        def _answer(self, prompt_name: str, prompt: str) -> str:
            self.calls.append((prompt_name, prompt))
            if self.fail:
                raise LLMUnavailable(f"{prompt_name}: test server unavailable")
            self.last_call = {"call_type": "TEST", "prompt_name": prompt_name, "elapsed_seconds": 0.0}
            if prompt_name == "lure_classifier":
                return json.dumps(self.lure, ensure_ascii=False)
            if prompt_name == "vision_brand":
                return json.dumps(self.vlm, ensure_ascii=False)
            return "Тестовое заключение аналитика."

        def ask_llm(self, prompt, *args, prompt_name="", **kwargs):
            return self._answer(prompt_name, prompt)

        def ask_vlm(self, prompt, image_base64, *args, prompt_name="", **kwargs):
            return self._answer(prompt_name, prompt)

        def prompts_of(self, prompt_name: str):
            return [p for n, p in self.calls if n == prompt_name]

    model = FakeModel()
    monkeypatch.setattr(llm_client, "_default_client", model)
    monkeypatch.setattr("agents.content_agent._CACHE", {})
    monkeypatch.setattr("agents.vision_agent._VLM_CACHE", {})
    return model
