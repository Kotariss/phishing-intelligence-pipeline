import contextvars
import datetime
import hashlib
import json
import os
import time
from typing import Optional, Dict, Any, List

import requests

try:
    from ..config import get_settings
    from . import prompts
except (ImportError, ValueError):
    from config import get_settings
    from llm import prompts


RETRYABLE_STATUS = (429, 500, 502, 503, 504)
RETRY_PAUSES = (2.0, 5.0, 10.0, 20.0)  # seconds before attempt 2, 3, 4, ...
try:  # LLM_RETRY_PAUSES="10,30,90": a loaded CPU server may need longer pauses than the defaults
    RETRY_PAUSES = tuple(float(x) for x in os.environ["LLM_RETRY_PAUSES"].split(",") if x.strip()) or RETRY_PAUSES
except (KeyError, ValueError):
    pass
AUDIT_TEXT_LIMIT = 20000

# The object being analysed (set by the pipeline): every model call in the audit log names its object.
CURRENT_OBJECT: contextvars.ContextVar = contextvars.ContextVar("llm_current_object", default=None)
_current_object_fallback: List[Optional[str]] = [None]  # graph nodes may run in executor threads without the context


def set_current_object(object_id: Optional[str]) -> None:
    CURRENT_OBJECT.set(object_id)
    _current_object_fallback[0] = object_id


def current_object() -> Optional[str]:
    return CURRENT_OBJECT.get() or _current_object_fallback[0]


class LLMUnavailable(RuntimeError):
    """The model did not answer after all attempts: the object is skipped, never analysed without it."""


class LLMClient:
    """Thin client for any OpenAI-compatible chat-completions endpoint: a local server (Ollama, LM Studio,
    vLLM, llama.cpp) or a cloud endpoint with an API key. Every call is audited; a call that still fails
    after LLM_ATTEMPTS raises LLMUnavailable."""

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.last_call: Optional[Dict[str, Any]] = None
        problem = self.settings.llm_config_problem()
        if problem:
            raise LLMUnavailable(f"model is not configured — {problem}")

    def get_last_call(self) -> Optional[Dict[str, Any]]:
        return self.last_call

    def _endpoint(self) -> str:
        api_url = self.settings.llm_base_url.rstrip("/")
        if not api_url.endswith("/chat/completions"):
            api_url = f"{api_url}/chat/completions"
        return api_url

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.settings.llm_api_key:
            headers["Authorization"] = f"Bearer {self.settings.llm_api_key}"
        return headers

    # ------------------------------------------------------------------ audit
    def _log_call(self, call_type: str, model: str, prompt: str, response: str, elapsed: float,
                  details: Dict[str, Any]) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = {
            "call_type": call_type,
            "model": model,
            "prompt": prompt,
            "response": response,
            "elapsed_seconds": round(elapsed, 2),
            "timestamp": ts,
            "success": not call_type.endswith("_FAILED"),
            "object": current_object(),
            "prompt_name": details.get("prompt_name"),
            "prompt_version": details.get("prompt_version"),
        }
        self.last_call = entry
        log_line = (
            f"[{ts}] [{call_type}] Model: {model} | Elapsed: {elapsed:.2f}s | object {entry['object']}\n"
            f"  PROMPT: {prompt.strip()[:200]}...\n"
            f"  RESPONSE: {response.strip()[:300]}...\n"
            + "-" * 70 + "\n"
        )
        # Machine-readable audit: the full prompt and answer (no image bytes), object, prompt version,
        # attempts, finish_reason, token usage and errors — one JSON line per call, for per-object diagnosis.
        record = {**entry, **details, "prompt": prompt[:AUDIT_TEXT_LIMIT], "response": response[:AUDIT_TEXT_LIMIT]}
        try:
            log_dir = self.settings.LOGS_DIR
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "llm_audit.log"), "a", encoding="utf-8") as f:
                f.write(log_line)
            with open(os.path.join(log_dir, "llm_audit.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError:
            pass

    # ------------------------------------------------------------------- call
    def _chat(self, call_type: str, model: str, messages: List[Dict[str, Any]], prompt_for_log: str,
              temperature: Optional[float], max_tokens: int, details: Dict[str, Any]) -> str:
        if details.get("prompt_name"):
            details["prompt_version"] = prompts.version(details["prompt_name"])
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.settings.LLM_TEMPERATURE,
            "max_tokens": max_tokens,
        }
        if self.settings.LLM_REASONING_EFFORT:
            payload["reasoning_effort"] = self.settings.LLM_REASONING_EFFORT

        t_start = time.time()
        errors: List[str] = []  # every failed attempt, in order: the audit shows what was retried and why
        attempts = max(1, self.settings.LLM_ATTEMPTS)
        for attempt in range(attempts):
            if attempt:
                time.sleep(RETRY_PAUSES[min(attempt - 1, len(RETRY_PAUSES) - 1)])
            details["attempts"] = attempt + 1
            try:
                resp = requests.post(self._endpoint(), headers=self._headers(), json=payload,
                                     timeout=self.settings.LLM_TIMEOUT_SECONDS)
            except requests.RequestException as e:  # connection reset, TLS error, timeout: transient
                errors.append(f"{type(e).__name__}: {str(e)[:150]}")
                continue
            if resp.status_code in RETRYABLE_STATUS:
                errors.append(f"HTTP {resp.status_code}: {resp.text[:200].strip()}".rstrip(": "))
                if "repeat limit" in resp.text:
                    # a small model stuck in a token loop (greedy decoding): the next attempt samples differently
                    payload["temperature"] = max(payload["temperature"], 0.6)
                    payload["presence_penalty"] = 0.6
                    payload["seed"] = attempt + 1
                continue
            if resp.status_code >= 400:
                # Client errors (bad model name, bad key, ...) do not get better on retry.
                errors.append(f"HTTP {resp.status_code}: {resp.text[:200]}")
                break
            try:
                body = resp.json()
                choice = body["choices"][0]
                message = choice["message"]
            except (ValueError, KeyError, IndexError, TypeError) as e:
                errors.append(f"Malformed response: {e}")
                continue
            details.update(finish_reason=choice.get("finish_reason"), usage=body.get("usage"), max_tokens=payload["max_tokens"])
            # The model's chain-of-thought is never used as an answer (it lists hypotheses).
            content = (message.get("content") or "").strip()
            if not content:
                errors.append(f"Empty completion (finish_reason={choice.get('finish_reason')})")
                if choice.get("finish_reason") == "length":
                    # the reasoning of a thinking model used up max_tokens: more room on the next attempt
                    payload["max_tokens"] = payload["max_tokens"] * 2
                continue
            if errors:
                details["retried_errors"] = errors
            self._log_call(call_type, model, prompt_for_log, content, time.time() - t_start, details)
            return content

        details.update(error=errors[-1] if errors else "unknown", retried_errors=errors)
        self._log_call(f"{call_type}_FAILED", model, prompt_for_log, "", time.time() - t_start, details)
        raise LLMUnavailable(f"{call_type} failed after {details['attempts']} attempt(s): {details['error']}")

    def ask_llm(self, prompt: str, system_prompt: str = "", model: Optional[str] = None,
                temperature: Optional[float] = None, max_tokens: Optional[int] = None, prompt_name: str = "") -> str:
        model = model or self.settings.text_model
        messages = [{"role": "system", "content": system_prompt}] if system_prompt else []
        messages.append({"role": "user", "content": prompt})
        return self._chat("TEXT_LLM", model, messages, prompt, temperature, max_tokens or self.settings.LLM_MAX_TOKENS,
                          {"prompt_name": prompt_name})

    def ask_vlm(self, prompt: str, image_base64: str, system_prompt: str = "", model: Optional[str] = None,
                temperature: Optional[float] = None, max_tokens: Optional[int] = None, prompt_name: str = "") -> str:
        model = model or self.settings.vision_model
        if image_base64.startswith("data:image"):
            image_data_url = image_base64
        else:
            mime = "image/jpeg" if image_base64.startswith("/9j/") else "image/png"
            image_data_url = f"data:{mime};base64,{image_base64}"
        messages = [{"role": "system", "content": system_prompt}] if system_prompt else []
        messages.append({"role": "user", "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": image_data_url}},
        ]})
        details = {"prompt_name": prompt_name, "image_b64_chars": len(image_base64),
                   "image_sha1": hashlib.sha1(image_base64.encode("ascii", errors="ignore")).hexdigest()[:12]}
        return self._chat("VISION_VLM", model, messages, prompt, temperature, max_tokens or self.settings.LLM_MAX_TOKENS, details)


_default_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client
