import contextvars
import hashlib
import json
import os
import time
import datetime
import requests
from typing import Optional, Dict, Any, List
try:
    from ..config import get_settings
    from . import prompts
except (ImportError, ValueError):
    from config import get_settings
    from llm import prompts

# The object being analysed (set by the pipeline): every model call in the audit log names its object.
CURRENT_OBJECT: contextvars.ContextVar = contextvars.ContextVar("llm_current_object", default=None)
_current_object_fallback: List[Optional[str]] = [None]  # graph nodes may run in executor threads without the context


def set_current_object(object_id: Optional[str]) -> None:
    CURRENT_OBJECT.set(object_id)
    _current_object_fallback[0] = object_id


def current_object() -> Optional[str]:
    return CURRENT_OBJECT.get() or _current_object_fallback[0]
AUDIT_TEXT_LIMIT = 20000


FALLBACK_PREFIX = "[Fallback"
RETRYABLE_STATUS = (429, 500, 502, 503, 504)


UNAVAILABLE_BACKOFF_SECONDS = 60


class LLMClient:
    """Thin client for any OpenAI-compatible chat-completions endpoint: a local server
    (Ollama, LM Studio, vLLM, llama.cpp) or a cloud endpoint with an API key. Every call is audited."""

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.last_call: Optional[Dict[str, Any]] = None
        self._unavailable_until = 0.0

    @property
    def enabled(self) -> bool:
        return self.settings.llm_configured and time.time() >= self._unavailable_until

    def available_for(self, evidence: Dict[str, Any]) -> bool:
        """`enabled`, and marks the object when a configured model was skipped (server in back-off), so a run
        can report how many objects were analysed without the model instead of passing silently."""
        if self.enabled:
            return True
        if self.settings.llm_configured:
            evidence["llm_unavailable"] = True
        return False

    @staticmethod
    def is_fallback(text: Optional[str]) -> bool:
        return not text or text.startswith(FALLBACK_PREFIX)

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

    def _log_call(self, call_type: str, model: str, prompt_snippet: str, response_snippet: str, elapsed: float,
                  details: Optional[Dict[str, Any]] = None):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        details = details or {}
        entry = {
            "call_type": call_type,
            "model": model,
            "prompt": prompt_snippet,
            "response": response_snippet,
            "elapsed_seconds": round(elapsed, 2),
            "timestamp": ts,
            "success": not call_type.endswith(("_FAILED", "_DISABLED")),
            "object": current_object(),
            "prompt_name": details.get("prompt_name"),
            "prompt_version": details.get("prompt_version"),
        }
        self.last_call = entry
        if call_type.endswith("_DISABLED"):
            return
        self._write_audit_jsonl({**entry, **details, "prompt": (prompt_snippet or "")[:AUDIT_TEXT_LIMIT],
                                 "response": (response_snippet or "")[:AUDIT_TEXT_LIMIT]})

        log_line = (
            f"[{ts}] [{call_type}] Model: {model} | Elapsed: {elapsed:.2f}s\n"
            f"  PROMPT: {prompt_snippet.strip()[:200]}...\n"
            f"  RESPONSE: {response_snippet.strip()[:300]}...\n"
            + "-" * 70 + "\n"
        )
        try:
            log_dir = self.settings.LOGS_DIR
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "llm_audit.log"), "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception:
            pass

    def _write_audit_jsonl(self, record: Dict[str, Any]) -> None:
        """Machine-readable audit: one JSON line per call with the full prompt and answer (no image bytes), the
        object, the prompt version, attempts, finish_reason, token usage and the error — for per-object diagnosis."""
        try:
            log_dir = self.settings.LOGS_DIR
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "llm_audit.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except Exception:
            pass

    def _chat(
        self,
        call_type: str,
        model: str,
        messages: List[Dict[str, Any]],
        prompt_for_log: str,
        temperature: Optional[float],
        max_tokens: int,
        allow_reasoning_fallback: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        details = dict(details or {})
        if details.get("prompt_name"):
            try:
                details["prompt_version"] = prompts.version(details["prompt_name"])
            except OSError:
                pass
        if not self.enabled:
            msg = f"{FALLBACK_PREFIX}] LLM disabled, not configured or temporarily unavailable (LLM_MODE={self.settings.llm_mode})."
            self._log_call(f"{call_type}_DISABLED", model, prompt_for_log, msg, 0.0, details)
            return msg

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.settings.LLM_TEMPERATURE,
            "max_tokens": max_tokens
        }
        if self.settings.LLM_REASONING_EFFORT:
            payload["reasoning_effort"] = self.settings.LLM_REASONING_EFFORT

        t_start = time.time()
        last_err: Optional[str] = None
        errors: List[str] = []  # every failed attempt, in order (the audit shows what was retried and why)
        for attempt in range(3):
            details["attempts"] = attempt + 1
            if last_err and (not errors or errors[-1] != last_err):
                errors.append(last_err)
            try:
                resp = requests.post(
                    self._endpoint(),
                    headers=self._headers(),
                    json=payload,
                    timeout=self.settings.LLM_TIMEOUT_SECONDS
                )
            except requests.ConnectionError as e:
                # A single reset / TLS error is transient and is retried; only a server that stays unreachable
                # is skipped for a while (batch runs stay fast) — otherwise one glitch silently turns the LLM off
                # for every object processed during the back-off.
                last_err = f"{type(e).__name__}: server unreachable"
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                self._unavailable_until = time.time() + UNAVAILABLE_BACKOFF_SECONDS
                break
            except requests.RequestException as e:
                last_err = f"{type(e).__name__}: {e}"
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                break

            if resp.status_code in RETRYABLE_STATUS and attempt < 2:
                last_err = f"HTTP {resp.status_code}"
                time.sleep(2 * (attempt + 1))
                continue
            if resp.status_code >= 400:
                # Client errors (bad model name, bad key, ...) are not retried.
                last_err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                break

            try:
                body = resp.json()
                choice = body["choices"][0]
                message = choice["message"]
            except (ValueError, KeyError, IndexError, TypeError) as e:
                last_err = f"Malformed response: {e}"
                break
            details["finish_reason"] = choice.get("finish_reason")
            details["usage"] = body.get("usage")
            details["max_tokens"] = payload["max_tokens"]

            content = (message.get("content") or "").strip()
            if not content and allow_reasoning_fallback:
                content = (message.get("reasoning_content") or "").strip()
            if not content:
                last_err = f"Empty completion (finish_reason={choice.get('finish_reason')})"
                # finish_reason "length": the reasoning of a thinking model used up max_tokens — retry once with more room
                if choice.get("finish_reason") == "length" and payload["max_tokens"] == max_tokens and attempt < 2:
                    payload["max_tokens"] = max_tokens * 2
                    continue
                break
            if errors:
                details["retried_errors"] = errors
            self._log_call(call_type, model, prompt_for_log, content, time.time() - t_start, details)
            return content

        details["error"] = last_err
        details["retried_errors"] = errors
        fallback_msg = f"{FALLBACK_PREFIX}] {call_type} unavailable: {last_err}"
        self._log_call(f"{call_type}_FAILED", model, prompt_for_log, fallback_msg, time.time() - t_start, details)
        return fallback_msg

    def ask_llm(
        self,
        prompt: str,
        system_prompt: str = "",
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        prompt_name: str = ""
    ) -> str:
        model = model or self.settings.text_model
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return self._chat("TEXT_LLM", model, messages, prompt, temperature, max_tokens or self.settings.LLM_MAX_TOKENS,
                          allow_reasoning_fallback=False, details={"prompt_name": prompt_name})

    def ask_vlm(
        self,
        prompt: str,
        image_base64: str,
        system_prompt: str = "",
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        prompt_name: str = ""
    ) -> str:
        model = model or self.settings.vision_model
        if image_base64.startswith("data:image"):
            image_data_url = image_base64
        else:
            mime = "image/jpeg" if image_base64.startswith("/9j/") else "image/png"
            image_data_url = f"data:{mime};base64,{image_base64}"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": image_data_url}}
        ]})
        # The model's chain-of-thought is never parsed as an answer: it lists hypotheses.
        image_sha1 = hashlib.sha1(image_base64.encode("ascii", errors="ignore")).hexdigest()[:12]
        return self._chat("VISION_VLM", model, messages, prompt, temperature, max_tokens or self.settings.LLM_MAX_TOKENS,
                          allow_reasoning_fallback=False,
                          details={"prompt_name": prompt_name, "image_sha1": image_sha1, "image_b64_chars": len(image_base64)})


_default_client: Optional[LLMClient] = None

def get_llm_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client


def reset_llm_client() -> None:
    global _default_client
    _default_client = None
