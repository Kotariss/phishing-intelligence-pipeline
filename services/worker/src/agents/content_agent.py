import hashlib
import json
import re
import time
from typing import Any, Dict, Optional

try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..llm.client import get_llm_client, LLMUnavailable
    from ..llm import prompts
    from ..features.url_features import hostname, registrable_domain
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from llm.client import get_llm_client, LLMUnavailable
    from llm import prompts
    from features.url_features import hostname, registrable_domain


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


_EMAIL_IN_TEXT = re.compile(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+')


def _norm(text: str) -> str:
    return " ".join((text or "").lower().split())


def _quoted(quote: Any, source_text: str) -> Optional[str]:
    """The model's quote if it really occurs in the text the attacker sent (a claim without a verbatim quote
    is not evidence — guards against invented findings)."""
    if not isinstance(quote, str):
        return None
    q = _norm(quote).strip(" «»\"'.…")
    if len(q) < 6 or q in ("null", "none"):
        return None
    return quote.strip() if q in _norm(source_text) else None


def _techniques_from_llm(result: Dict[str, Any], sent_text: str) -> Dict[str, Any]:
    """Technique evidence from the model's answer; each claim must quote the sent text verbatim."""
    tech = result.get("techniques") if isinstance(result.get("techniques"), dict) else {}
    threat = _quoted(tech.get("account_threat"), sent_text)
    victim_quote = _quoted(tech.get("victim_addressed"), sent_text)
    victim = _EMAIL_IN_TEXT.search(victim_quote) if victim_quote else None
    human = _quoted(tech.get("fake_human_check"), sent_text)
    return {"account_threat": [threat] if threat else [], "victim_address": victim.group(0) if victim else None,
            "victim_snippet": victim_quote if victim else None, "human_check": human}


class ContentAgent:
    """LLM analysis of the lure text (e-mail body / landing page): covers social-engineering
    e-mails that carry no link or attachment at all (e.g. "reply to this message" scams)."""

    MIN_CONFIDENCE = 0.75

    def __init__(self, llm_client=None):
        self.llm = llm_client or get_llm_client()

    def _classify(self, text: str):
        """Model answer as a dict; an unparseable answer is asked once more, then the object is skipped."""
        key = hashlib.sha1(text.encode("utf-8")).hexdigest()
        if key in _CACHE:
            return _CACHE[key], None
        for _ in range(2):
            answer = self.llm.ask_llm(prompts.render("lure_classifier", content=text), temperature=0.0, prompt_name="lure_classifier")
            result = _parse(answer)
            if result is not None:
                _CACHE[key] = result
                return result, self.llm.get_last_call()
        raise LLMUnavailable("lure classifier answer is not JSON after 2 requests")

    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        state.execution_steps.append("content_agent: LLM lure-text classification")
        att = state.attachment_evidence or {}
        parts = []
        if att.get("subject"):
            parts.append(f"Тема: {att['subject']}")
        if att.get("from_name") or att.get("from_address"):
            parts.append(f"Отправитель: {att.get('from_name', '')} <{att.get('from_address', '')}>")
        if att.get("type") == "eml" and att.get("links"):
            link_domains = list(dict.fromkeys(registrable_domain(hostname(u)) for u in att["links"] if hostname(u)))
            if link_domains:
                parts.append("Домены ссылок: " + ", ".join(link_domains[:10]))
        body = att.get("body_text_preview") or ""
        if not body and state.dom_html and att.get("type") == "eml":
            html = re.sub(r'(?is)<(style|script|head)\b.*?</\1\s*>', ' ', state.dom_html)
            body = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html))[:1500]
        if body:
            parts.append(f"Текст письма: {body[:1500]}")
        page_text = (state.page_features or {}).get("visible_text")
        if page_text:
            parts.append(f"Текст страницы ({state.final_url or 'вложение'}): {page_text[:1200]}")
        if att.get("ocr_text"):
            parts.append(f"Текст на изображении: {att['ocr_text'][:1200]}")
        # Text of the e-mail's own attachments: PDF / HTML text and OCR of attached pictures (ТЗ 4.1.1.2)
        attachment_texts = []
        for item in att.get("attachments_analysis") or []:
            for key, label in (("text_preview", "Текст вложения"), ("ocr_text", "Текст на изображении во вложении")):
                if (item.get(key) or "").strip() and len(attachment_texts) < 3:
                    attachment_texts.append(item[key][:800])
                    parts.append(f"{label} {item.get('filename') or ''}: {item[key][:800]}")
        text = "\n".join(parts)

        # Only the text the attacker sent — the e-mail and attached files — carries technique evidence, never a
        # landing page, which may be a genuine site ("session expired" on a real login page).
        sent_text = " ".join(filter(None, [att.get("subject"), body,
                                           page_text if att.get("type") == "html" else None] + attachment_texts))

        status, decision, call_info, result = "SKIPPED", "Текста для анализа нет.", None, None
        if not self.llm.enabled:
            decision = "Модель отключена (LLM_MODE=off): анализ текста приманки пропущен."
        elif text.strip() and not state.has_rescanned_url:
            state.network_evidence["llm_lure_input_chars"] = len(text)
            result, call_info = self._classify(text)
            try:
                conf = float(result.get("confidence", 0))
            except (TypeError, ValueError):
                conf = 0.0
            state.network_evidence["llm_lure"] = {k: result.get(k) for k in
                                                  ("is_phishing_lure", "lure_type", "confidence", "indicators", "techniques")}
            if result.get("is_phishing_lure") is True and conf >= self.MIN_CONFIDENCE:
                indicators = "; ".join(str(i) for i in (result.get("indicators") or [])[:3])
                state.add_reason("CONTENT_LLM_LURE", f"{result.get('lure_type')} (уверенность {conf:.2f}): {indicators}"[:300],
                                 {"type": "text", "value": "\n".join(f"- {i}" for i in (result.get("indicators") or [])[:6]), "label": "Признаки приманки в тексте (LLM)"})
                status = "TRIGGERED"
            else:
                status = "COMPLETED"
            decision = f"Вердикт LLM: {'приманка' if result.get('is_phishing_lure') else 'не приманка'}, тип {result.get('lure_type')}, уверенность {conf:.2f}."

            lure = _techniques_from_llm(result, sent_text)
            if lure["account_threat"]:
                state.add_reason("CONTENT_ACCOUNT_THREAT", f"Угроза доступу к почте / учётной записи: «{lure['account_threat'][0][:150]}»",
                                 {"type": "text", "value": "\n".join(f"… {t} …" for t in lure["account_threat"]),
                                  "label": "Фраза-предлог в тексте (LLM, цитата проверена)"})
            if lure["victim_address"] and (lure["account_threat"] or state.discovered_urls_from_attachments):
                state.add_reason("CONTENT_VICTIM_ADDRESSED", f"Обращение к получателю по адресу ящика {lure['victim_address']}",
                                 {"type": "text", "value": f"… {lure['victim_snippet']} …", "label": "Обращение по адресу почты (LLM, цитата проверена)"})
            if lure["human_check"] and att.get("type") == "html" and not state.final_url:
                state.add_reason("ATTACH_FAKE_HUMAN_CHECK", "HTML-вложение изображает проверку «вы не робот»",
                                 {"type": "text", "value": f"… {lure['human_check']} …", "label": "Текст вложения (LLM, цитата проверена)"})

        state.agent_traces.append(AgentStepTrace(
            agent_id="content_agent",
            agent_name=f"Lure Content Agent ({self.llm.settings.text_model})",
            icon="✉️",
            phase="Phase 5b: Social-Engineering Text Analysis",
            status=status,
            duration_ms=round((time.time() - t0) * 1000, 1),
            reasoning="Классификация текста письма, вложений и страницы большой языковой моделью: срочность, угрозы, обещания выплат, "
                      "просьбы сообщить данные; приёмы засчитываются только с дословной цитатой из присланного текста. "
                      f"Признак приманки учитывается при уверенности ≥ {self.MIN_CONFIDENCE} и сам по себе не даёт вердикт BLOCK.",
            decision=decision,
            tools_called=[f"LLM({self.llm.settings.text_model})"] if call_info else [],
            findings=[{"label": "Тип приманки", "value": str((result or {}).get("lure_type") or "—")},
                      {"label": "Индикаторы", "value": "; ".join(str(i) for i in ((result or {}).get("indicators") or [])[:4]) or "—"}],
            llm_audit=call_info,
            state_delta={"triggered_codes": ["CONTENT_LLM_LURE"] if status == "TRIGGERED" else []}
        ))
        return state
