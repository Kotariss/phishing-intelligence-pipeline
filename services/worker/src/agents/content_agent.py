import hashlib
import json
import re
import time
from typing import Any, Dict, Optional

try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..llm.client import get_llm_client
    from ..llm import prompts
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from llm.client import get_llm_client
    from llm import prompts


_CACHE: Dict[str, Dict[str, Any]] = {}


def _parse(text: str) -> Optional[Dict[str, Any]]:
    m = re.search(r'\{.*\}', text or "", re.DOTALL)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


class ContentAgent:
    """LLM analysis of the lure text (e-mail body / landing page): covers social-engineering
    e-mails that carry no link or attachment at all (e.g. "reply to this message" scams)."""

    MIN_CONFIDENCE = 0.75

    def __init__(self, llm_client=None):
        self.llm = llm_client or get_llm_client()

    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        state.execution_steps.append("content_agent: LLM lure-text classification")
        att = state.attachment_evidence or {}
        parts = []
        if att.get("subject"):
            parts.append(f"Тема: {att['subject']}")
        if att.get("from_name") or att.get("from_address"):
            parts.append(f"Отправитель: {att.get('from_name', '')} <{att.get('from_address', '')}>")
        body = att.get("body_text_preview") or ""
        if not body and state.dom_html and att.get("type") == "eml":
            body = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', state.dom_html))[:1500]
        if body:
            parts.append(f"Текст письма: {body[:1500]}")
        page_text = (state.page_features or {}).get("visible_text")
        if page_text:
            parts.append(f"Текст страницы ({state.final_url or 'вложение'}): {page_text[:1200]}")
        text = "\n".join(parts)

        status, decision, call_info, result = "SKIPPED", "Нет текста для анализа или LLM отключена.", None, None
        if text and len(text) > 80 and self.llm.enabled and not state.has_rescanned_url:
            key = hashlib.sha1(text.encode("utf-8")).hexdigest()
            result = _CACHE.get(key)
            if result is None:
                answer = self.llm.ask_llm(prompts.render("lure_classifier", content=text), max_tokens=1500, temperature=0.0)
                call_info = self.llm.get_last_call()
                result = None if self.llm.is_fallback(answer) else _parse(answer)
                if result is not None:
                    _CACHE[key] = result
            if result:
                try:
                    conf = float(result.get("confidence", 0))
                except (TypeError, ValueError):
                    conf = 0.0
                state.network_evidence["llm_lure"] = {k: result.get(k) for k in ("is_phishing_lure", "lure_type", "confidence", "indicators")}
                if result.get("is_phishing_lure") is True and conf >= self.MIN_CONFIDENCE:
                    indicators = "; ".join(str(i) for i in (result.get("indicators") or [])[:3])
                    state.add_reason("CONTENT_LLM_LURE", f"{result.get('lure_type')} (уверенность {conf:.2f}): {indicators}"[:300],
                                     {"type": "text", "value": "\n".join(f"- {i}" for i in (result.get("indicators") or [])[:6]), "label": "Признаки приманки в тексте (LLM)"})
                    status = "TRIGGERED"
                else:
                    status = "COMPLETED"
                decision = f"Вердикт LLM: {'приманка' if result.get('is_phishing_lure') else 'не приманка'}, тип {result.get('lure_type')}, уверенность {conf:.2f}."
            else:
                status, decision = "WARNING", "LLM недоступна, анализ текста пропущен."

        state.agent_traces.append(AgentStepTrace(
            agent_id="content_agent",
            agent_name=f"Lure Content Agent ({self.llm.settings.LLM_TEXT_MODEL})",
            icon="✉️",
            phase="Phase 5b: Social-Engineering Text Analysis",
            status=status,
            duration_ms=round((time.time() - t0) * 1000, 1),
            reasoning="Классификация текста письма и страницы большой языковой моделью: срочность, угрозы, обещания выплат, просьбы сообщить данные. "
                      f"Признак учитывается только при уверенности ≥ {self.MIN_CONFIDENCE} и сам по себе не даёт вердикт BLOCK.",
            decision=decision,
            tools_called=[f"LLM({self.llm.settings.LLM_TEXT_MODEL})"] if call_info else [],
            findings=[{"label": "Тип приманки", "value": str((result or {}).get("lure_type") or "—")},
                      {"label": "Индикаторы", "value": "; ".join(str(i) for i in ((result or {}).get("indicators") or [])[:4]) or "—"}],
            llm_audit=call_info,
            state_delta={"triggered_codes": ["CONTENT_LLM_LURE"] if status == "TRIGGERED" else []}
        ))
        return state
