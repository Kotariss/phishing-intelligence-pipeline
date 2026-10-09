import os
import time
import datetime
import requests
from typing import Optional, Dict, Any, List
try:
    from ..config import get_settings
except (ImportError, ValueError):
    from config import get_settings


FALLBACK_PREFIX = "[Fallback"
RETRYABLE_STATUS = (429, 500, 502, 503, 504)


UNAVAILABLE_BACKOFF_SECONDS = 60


class LLMClient:
    """Thin client for any OpenAI-compatible chat-completions endpoint: a local server
    (Ollama, LM Studio, vLLM, llama.cpp) or a cloud endpoint with an API key. Every call is audited."""

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.last_call: Optional[Dict[str, Any]] = None
        self.call_history: List[Dict[str, Any]] = []
        self._unavailable_until = 0.0

    @property
    def enabled(self) -> bool:
        return self.settings.llm_configured and time.time() >= self._unavailable_until

    @staticmethod
    def is_fallback(text: Optional[str]) -> bool:
        return not text or text.startswith(FALLBACK_PREFIX)

    def get_last_call(self) -> Optional[Dict[str, Any]]:
        return self.last_call

    def get_call_history(self) -> List[Dict[str, Any]]:
        return self.call_history

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

    def _log_call(self, call_type: str, model: str, prompt_snippet: str, response_snippet: str, elapsed: float):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = {
            "call_type": call_type,
            "model": model,
            "prompt": prompt_snippet,
            "response": response_snippet,
            "elapsed_seconds": round(elapsed, 2),
            "timestamp": ts,
            "success": not call_type.endswith(("_FAILED", "_DISABLED"))
        }
        self.last_call = entry
        self.call_history.append(entry)
        if call_type.endswith("_DISABLED"):
            return

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

    def _chat(
        self,
        call_type: str,
        model: str,
        messages: List[Dict[str, Any]],
        prompt_for_log: str,
        temperature: Optional[float],
        max_tokens: int,
        allow_reasoning_fallback: bool,
    ) -> str:
        if not self.enabled:
            msg = f"{FALLBACK_PREFIX}] LLM disabled, not configured or temporarily unavailable (LLM_MODE={self.settings.llm_mode})."
            self._log_call(f"{call_type}_DISABLED", model, prompt_for_log, msg, 0.0)
            return msg

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.settings.LLM_TEMPERATURE,
            "max_tokens": max_tokens
        }

        t_start = time.time()
        last_err: Optional[str] = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    self._endpoint(),
                    headers=self._headers(),
                    json=payload,
                    timeout=self.settings.LLM_TIMEOUT_SECONDS
                )
            except requests.ConnectionError as e:
                # Server not running: stop hammering it for a while (batch runs stay fast).
                last_err = f"{type(e).__name__}: server unreachable"
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
                message = resp.json()["choices"][0]["message"]
            except (ValueError, KeyError, IndexError, TypeError) as e:
                last_err = f"Malformed response: {e}"
                break

            content = (message.get("content") or "").strip()
            if not content and allow_reasoning_fallback:
                content = (message.get("reasoning_content") or "").strip()
            if not content:
                last_err = "Empty completion"
                break
            self._log_call(call_type, model, prompt_for_log, content, time.time() - t_start)
            return content

        fallback_msg = f"{FALLBACK_PREFIX}] {call_type} unavailable: {last_err}"
        self._log_call(f"{call_type}_FAILED", model, prompt_for_log, fallback_msg, time.time() - t_start)
        return fallback_msg

    def ask_llm(
        self,
        prompt: str,
        system_prompt: str = "",
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: int = 1500
    ) -> str:
        model = model or self.settings.LLM_TEXT_MODEL
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return self._chat("TEXT_LLM", model, messages, prompt, temperature, max_tokens,
                          allow_reasoning_fallback=False)

    def ask_vlm(
        self,
        prompt: str,
        image_base64: str,
        system_prompt: str = "",
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: int = 1500
    ) -> str:
        model = model or self.settings.LLM_VISION_MODEL
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
        return self._chat("VISION_VLM", model, messages, prompt, temperature, max_tokens,
                          allow_reasoning_fallback=False)


_default_client: Optional[LLMClient] = None

def get_llm_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client


def reset_llm_client() -> None:
    global _default_client
    _default_client = None
