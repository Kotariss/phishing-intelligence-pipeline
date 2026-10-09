import os
import time
import datetime
import base64
import requests
from typing import Optional, Dict, Any, List
try:
    from ..config import get_settings
except (ImportError, ValueError):
    from config import get_settings


class LLMClient:
    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self.last_call: Optional[Dict[str, Any]] = None
        self.call_history: List[Dict[str, Any]] = []

    def get_last_call(self) -> Optional[Dict[str, Any]]:
        return self.last_call

    def get_call_history(self) -> List[Dict[str, Any]]:
        return self.call_history

    def _log_call(self, call_type: str, model: str, prompt_snippet: str, response_snippet: str, elapsed: float):
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = {
            "call_type": call_type,
            "model": model,
            "prompt": prompt_snippet,
            "response": response_snippet,
            "elapsed_seconds": round(elapsed, 2),
            "timestamp": ts,
            "success": not call_type.endswith("_FAILED")
        }
        self.last_call = entry
        self.call_history.append(entry)

        log_line = (
            f"[{ts}] [{call_type}] Model: {model} | Elapsed: {elapsed:.2f}s\n"
            f"  PROMPT: {prompt_snippet.strip()[:200]}...\n"
            f"  RESPONSE: {response_snippet.strip()[:300]}...\n"
            + "-" * 70 + "\n"
        )
        print(f"[LLM Cloud NSU] {call_type} [{model}] finished in {elapsed:.2f}s: {response_snippet.strip()[:80]}...")
        try:
            log_dir = os.path.join(os.getcwd(), "logs")
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "llm_audit.log"), "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception:
            pass

    def ask_llm(
        self,
        prompt: str,
        system_prompt: str = "",
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: int = 1500
    ) -> str:
        model = model or self.settings.LLM_TEXT_MODEL
        temperature = temperature if temperature is not None else self.settings.LLM_TEMPERATURE
        
        api_url = self.settings.LLM_BASE_URL.rstrip("/")
        if not api_url.endswith("/chat/completions"):
            api_url = f"{api_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.settings.LLM_API_KEY}",
            "Content-Type": "application/json"
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        t_start = time.time()
        last_err = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=self.settings.LLM_TIMEOUT_SECONDS
                )
                if resp.status_code in (502, 503, 504, 429) and attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                resp.raise_for_status()
                data = resp.json()
                
                choice = data["choices"][0]["message"]
                content = choice.get("content", "").strip()
                if not content and choice.get("reasoning_content"):
                    content = choice["reasoning_content"].strip()
                self._log_call("TEXT_LLM", model, prompt, content, time.time() - t_start)
                return content
            except Exception as e:
                last_err = e
                if attempt < 2:
                    time.sleep(1.5 * (attempt + 1))
                    continue

        # If LLM API fails, return deterministic heuristic text
        fallback_msg = f"[Fallback Heuristic] Analysis based on static indicators: {last_err}"
        self._log_call("TEXT_LLM_FAILED", model, prompt, fallback_msg, time.time() - t_start)
        return fallback_msg

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
        temperature = temperature if temperature is not None else self.settings.LLM_TEMPERATURE

        api_url = self.settings.LLM_BASE_URL.rstrip("/")
        if not api_url.endswith("/chat/completions"):
            api_url = f"{api_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.settings.LLM_API_KEY}",
            "Content-Type": "application/json"
        }

        # Ensure image data url prefix
        if not image_base64.startswith("data:image"):
            image_data_url = f"data:image/png;base64,{image_base64}"
        else:
            image_data_url = image_base64

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        user_content = [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": image_data_url}}
        ]
        messages.append({"role": "user", "content": user_content})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        t_start = time.time()
        last_err = None
        for attempt in range(3):
            try:
                resp = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=self.settings.LLM_TIMEOUT_SECONDS
                )
                if resp.status_code in (502, 503, 504, 429) and attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue
                resp.raise_for_status()
                data = resp.json()

                choice = data["choices"][0]["message"]
                content = choice.get("content", "").strip()
                if not content and choice.get("reasoning_content"):
                    content = choice["reasoning_content"].strip()
                self._log_call("VISION_VLM", model, prompt, content, time.time() - t_start)
                return content
            except Exception as e:
                last_err = e
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
                    continue

        fallback_msg = f"[VLM Fallback] Vision analysis unavailable: {last_err}"
        self._log_call("VISION_VLM_FAILED", model, prompt, fallback_msg, time.time() - t_start)
        return fallback_msg

_default_client: Optional[LLMClient] = None

def get_llm_client() -> LLMClient:
    global _default_client
    if _default_client is None:
        _default_client = LLMClient()
    return _default_client
