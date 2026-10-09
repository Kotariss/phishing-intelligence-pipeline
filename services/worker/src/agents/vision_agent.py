import hashlib
import json
import re
import time
from typing import Any, Dict, Optional, Tuple

try:
    from ..orchestrator.state import PhishingState, BrandEvidence, AgentStepTrace
    from ..brands.matcher import get_brand_registry, extract_hostname, normalize_display_text
    from ..features.image_text import image_lure_signals
    from ..llm.client import get_llm_client
    from ..llm import prompts
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, BrandEvidence, AgentStepTrace
    from brands.matcher import get_brand_registry, extract_hostname, normalize_display_text
    from features.image_text import image_lure_signals
    from llm.client import get_llm_client
    from llm import prompts


STRONG_PAGE_SOURCES = ("title", "vlm", "lookalike_domain")
LURE_TYPES = ("banking_login", "b2b_invoice", "delivery_awb", "security_alert", "penalty_notice",
              "account_login", "payment", "prize", "document_share", "other")

VISUAL_DOCUMENT_LURES = {"b2b_invoice", "delivery_awb", "payment", "document_share", "penalty_notice", "security_alert", "account_login", "banking_login"}

_VLM_CACHE: Dict[str, Dict[str, Any]] = {}


def _parse_vlm_json(text: str) -> Dict[str, Any]:
    m = re.search(r'\{.*\}', text or "", re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(0))
            if isinstance(data, dict):
                return data
        except ValueError:
            pass
    # tolerant fallback for "Brand: X / Lure: Y" answers
    brand = re.search(r'brand"?\s*[:=]\s*"?([^"\n,}]+)', text or "", re.IGNORECASE)
    lure = re.search(r'lure"?\s*[:=]\s*"?([^"\n,}]+)', text or "", re.IGNORECASE)
    return {"brand": brand.group(1).strip() if brand else None,
            "lure": lure.group(1).strip() if lure else None, "confidence": 0.6}


def _logo_box(vlm_result) -> Optional[list]:
    """VLM logo box normalised to fractions [x1, y1, x2, y2]; None if absent or implausible."""
    box = (vlm_result or {}).get("logo_box")
    if not isinstance(box, (list, tuple)) or len(box) != 4:
        return None
    try:
        x1, y1, x2, y2 = (float(v) for v in box)
    except (TypeError, ValueError):
        return None
    if max(x1, y1, x2, y2) > 1.0:  # pixel coordinates (Qwen-VL convention: 0..1000 grid)
        scale = 1000.0 if max(x1, y1, x2, y2) <= 1000 else max(x2, y2)
        x1, y1, x2, y2 = (v / scale for v in (x1, y1, x2, y2))
    if not (0 <= x1 < x2 <= 1 and 0 <= y1 < y2 <= 1):
        return None
    return [round(v, 4) for v in (x1, y1, x2, y2)]


class VisionAgent:
    """Brand identification (display name, page title, VLM screenshot analysis, look-alike domains)
    + allowlist verification: the Phishpedia 'intended target vs. hosting domain' check."""

    def __init__(self, brand_registry=None, llm_client=None):
        self.registry = brand_registry or get_brand_registry()
        self.llm = llm_client or get_llm_client()

    def _ask_vlm(self, image_b64: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        key = hashlib.sha1(image_b64[:200000].encode("ascii", errors="ignore")).hexdigest()
        if key in _VLM_CACHE:
            return _VLM_CACHE[key], {"call_type": "VISION_VLM_CACHED", "model": self.llm.settings.LLM_VISION_MODEL}
        answer = self.llm.ask_vlm(prompts.render("vision_brand", lure_types=", ".join(LURE_TYPES)), image_b64, max_tokens=1500)
        call = self.llm.get_last_call()
        if self.llm.is_fallback(answer):
            return None, call
        parsed = _parse_vlm_json(answer)
        _VLM_CACHE[key] = parsed
        return parsed, call

    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        state.execution_steps.append("vision_agent: Performing multimodal brand & lure analysis")
        vlm_invoked = False
        vlm_call_info = None
        vlm_result: Optional[Dict[str, Any]] = None

        att = state.attachment_evidence or {}
        page = state.page_features or {}
        page_url = state.final_url or state.scan_url or (state.raw_target if state.raw_target.startswith("http") else "")
        page_host = extract_hostname(page_url) if page_url else ""
        from_domain = att.get("from_domain") or ""

        # 1. E-mail display name (sender spoofing)
        email_brand = None
        if att.get("from_name"):
            display, obfuscated = normalize_display_text(att["from_name"])
            hit = self.registry.find_brand_in_text(display)
            if hit:
                email_brand = hit[0]
            if obfuscated:
                state.add_reason("EMAIL_DISPLAYNAME_OBFUSCATED",
                                 f"Имя отправителя замаскировано (невидимые символы / разрядка): «{display}»",
                                 {"type": "header", "value": f"From: {att['from_name']!r} <{att.get('from_address', '')}>", "label": "Исходное имя отправителя"})
        if email_brand and from_domain and not self.registry.is_domain_allowed(email_brand["brand_id"], from_domain):
            state.add_reason("RC_BRAND_SPOOF_DISPLAYNAME",
                             f"Отправитель «{att['from_name']}» имитирует {email_brand['display_name']}, но домен {from_domain} не принадлежит бренду",
                             {"type": "header", "value": f"From: {att['from_name']} <{att.get('from_address', '')}>", "label": "Заголовок From"})
        elif att.get("subject") and from_domain and not email_brand:
            hit = self.registry.find_brand_in_text(att["subject"])
            if hit and not self.registry.is_domain_allowed(hit[0]["brand_id"], from_domain):
                state.add_reason("EMAIL_SUBJECT_BRAND_OFF_DOMAIN",
                                 f"Тема письма упоминает {hit[0]['display_name']}, отправитель {from_domain} не принадлежит бренду",
                                 {"type": "header", "value": f"Subject: {att['subject']}\nFrom: {att.get('from_address', '')}", "label": "Тема и отправитель"})

        # 2. Image lure: text recognised on an image attachment (fake document viewer / sign-in screenshot)
        ocr_text = (att.get("ocr_text") or "") if state.screenshot_source == "image_file" else ""
        image_signals = image_lure_signals(ocr_text)
        if image_signals["credential_prompt"]:
            ocr_evidence = {"type": "text", "value": "\n".join(f"… {s} …" for s in image_signals["snippets"]),
                            "label": "Текст на изображении (OCR)"}
            state.add_reason("IMAGE_CREDENTIAL_PROMPT", "На изображении — запрос пароля / входа в учётную запись", ocr_evidence)
            if image_signals["document_gate"]:
                state.add_reason("IMAGE_FAKE_DOCUMENT_VIEWER",
                                 "Изображение: «защищённый документ», для просмотра требуется пароль", ocr_evidence)

        # 3. Brand presented by the page / attachment
        page_brand, source, confidence = None, None, 0.0
        # The page presents itself as a brand in its title / top headings (not in footers or payment logos).
        title_text = " ".join(filter(None, [page.get("brand_context_text") or page.get("title"),
                                            (att.get("brand_context_text") or att.get("title")) if att.get("type") == "html" else None]))
        if title_text:
            hit = self.registry.find_brand_in_text(title_text)
            if hit:
                page_brand, source, confidence = hit[0], "title", 0.85

        lure_type = None
        if not page_brand and state.screenshot_base64 and len(state.screenshot_base64) > 1000 and self.llm.enabled:
            vlm_invoked = True
            vlm_result, vlm_call_info = self._ask_vlm(state.screenshot_base64)
            if vlm_result:
                lure_type = str(vlm_result.get("lure") or "").strip().lower() or None
                # An image attachment that renders a document / payment / delivery lure ("click to view invoice").
                # The same fact seen by OCR is not counted twice.
                if state.screenshot_source == "image_file" and lure_type in VISUAL_DOCUMENT_LURES \
                        and "IMAGE_FAKE_DOCUMENT_VIEWER" not in state.reason_codes:
                    state.add_reason("VISUAL_DOCUMENT_LURE", f"VLM: изображение-вложение изображает приманку типа «{lure_type}»",
                                     {"type": "image_region", "box": _logo_box(vlm_result), "label": f"Изображение: {lure_type}"})
                if state.screenshot_source == "image_file" and vlm_result.get("login_form_visible") is True \
                        and "IMAGE_CREDENTIAL_PROMPT" not in state.reason_codes:
                    state.add_reason("IMAGE_CREDENTIAL_PROMPT", "VLM: на изображении форма входа / ввода пароля",
                                     {"type": "image_region", "box": None, "label": "Форма входа на изображении (VLM)"})
                name = str(vlm_result.get("brand") or "").strip().strip('"\'')
                try:
                    conf = float(vlm_result.get("confidence", 0.7))
                except (TypeError, ValueError):
                    conf = 0.7
                if name and name.lower() not in ("none", "null", "unknown", "n/a", "generic") and conf >= 0.5:
                    found = self.registry.find_brand(name)
                    if found:
                        page_brand, source, confidence = found, "vlm", round(min(conf, 0.95), 2)
                    else:
                        state.network_evidence["vlm_unregistered_brand"] = name[:80]

        # Brand named in the text of an image attachment (no VLM, or VLM did not recognise a brand).
        if not page_brand and ocr_text:
            ocr_hit = self.registry.find_brand_in_text(ocr_text)
            if ocr_hit:
                page_brand, source, confidence = ocr_hit[0], "ocr", 0.6

        # The look-alike brand describes the page only if the page is actually hosted on that domain.
        lookalike_name = state.network_evidence.get("lookalike_brand")
        if lookalike_name and extract_hostname(state.network_evidence.get("lookalike_host") or "") != page_host:
            lookalike_name = None
        if not page_brand and lookalike_name:
            found = self.registry.find_brand(lookalike_name)
            if found:
                page_brand, source, confidence = found, "lookalike_domain", 0.8

        if not page_brand:
            text = page.get("visible_text") or att.get("body_text_preview") or ""
            hit = self.registry.find_brand_in_text(text)
            if hit:
                page_brand, source, confidence = hit[0], "body_text", 0.5

        legit_owner = self.registry.find_brand_for_domain(page_host) if page_host else None
        if not page_brand and legit_owner:
            page_brand, source, confidence = legit_owner, "official_domain", 0.9

        # 3. Allowlist verification of the page brand against where the page is actually hosted
        brand = page_brand or email_brand
        brand_ev = BrandEvidence(
            detected_brand_name=brand["display_name"] if brand else None,
            brand_id=brand["brand_id"] if brand else None,
            detection_source=source or ("display_name" if email_brand else None),
            vlm_confidence=confidence if page_brand else (0.85 if email_brand else 0.0),
            visual_lure_type=lure_type,
            logo_box=_logo_box(vlm_result) if source == "vlm" else None,
        )

        if page_brand and source != "official_domain":
            # Offline attachment pages have no hosting domain: they are never "official".
            on_official = bool(page_host) and self.registry.is_domain_allowed(page_brand["brand_id"], page_host)
            brand_ev.is_domain_in_allowlist = on_official
            if not on_official:
                where = page_host or "локальный файл вложения"
                brand_ev.impersonation_reason = f"{page_brand['display_name']} представлен на {where}, вне allowlist бренда"
                # A brand in a title/heading is only an impersonation when the page also asks for data
                # (news / reviews / aggregators legitimately name brands in headings).
                asks_for_data = any(f.has_password or f.has_card or f.has_email for f in state.dom_forms) or \
                    bool(page.get("has_password_field") or att.get("has_password_field"))
                # An offline HTML attachment branded in its title that forwards the victim elsewhere.
                if not page_host and (att.get("meta_refresh") or att.get("js_redirects")):
                    asks_for_data = True
                if source in ("vlm", "lookalike_domain") or (source == "title" and asks_for_data) or \
                        (source == "ocr" and image_signals["document_gate"]):
                    brand_ev.brand_impersonation_confirmed = True
                    if source == "vlm":
                        evidence = {"type": "image_region", "box": brand_ev.logo_box, "label": f"Логотип {page_brand['display_name']} (VLM)"}
                    elif source == "ocr":  # brand name + credential prompt in the image text
                        evidence = {"type": "text", "value": ocr_hit[1],
                                    "label": "Название бренда в тексте изображения (OCR)"}
                    elif source == "title":
                        title_snip = (page.get("evidence_snippets") or att.get("evidence_snippets") or {}).get("title") or title_text
                        evidence = {"type": "dom", "value": title_snip, "label": "Заголовок страницы"}
                    else:
                        evidence = {"type": "url", "value": page_host, "label": "Домен-двойник"}
                    state.add_reason("BRAND_IMPERSONATION_CONFIRMED",
                                     f"{page_brand['display_name']} (источник: {source}) на {where}", evidence)
                    if lure_type and lure_type != "other":
                        state.add_reason("BRAND_VISUAL_LURE_MATCH", f"Тип приманки: {lure_type}")
                else:
                    state.add_reason("BRAND_MENTION_OFF_DOMAIN", f"Упоминание {page_brand['display_name']} в тексте на {where}")
            else:
                brand_ev.impersonation_reason = f"Хост {page_host} входит в allowlist {page_brand['display_name']}"
        elif email_brand and not page_brand:
            brand_ev.is_domain_in_allowlist = "RC_BRAND_SPOOF_DISPLAYNAME" not in state.reason_codes
            brand_ev.brand_impersonation_confirmed = not brand_ev.is_domain_in_allowlist
            brand_ev.impersonation_reason = state.reason_details.get("RC_BRAND_SPOOF_DISPLAYNAME")

        state.brand_evidence = brand_ev

        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        model = self.llm.settings.LLM_VISION_MODEL
        if vlm_invoked:
            reasoning_text = (f"Заголовок страницы не содержал бренда. Скриншот ({state.screenshot_source}) передан мультимодальной модели {model} "
                              f"для распознавания логотипа/айдентики; результат сверен с реестром брендов и allowlist доменов.")
        elif brand:
            reasoning_text = f"Бренд «{brand['display_name']}» определён по источнику «{brand_ev.detection_source}» и сверен с allowlist доменов."
        else:
            reasoning_text = "Ни заголовок, ни отправитель, ни скриншот, ни домен не указывают на охраняемый бренд."
        if brand_ev.brand_impersonation_confirmed:
            decision_text = f"ПОДМЕНА БРЕНДА: {brand_ev.impersonation_reason}."
        elif brand:
            decision_text = f"Бренд «{brand['display_name']}»: {brand_ev.impersonation_reason or 'подмена не подтверждена'}."
        else:
            decision_text = "Признаков целевого спуфинга бренда не зафиксировано."

        state.agent_traces.append(AgentStepTrace(
            agent_id="vision_agent",
            agent_name=f"Multimodal Vision & Brand Agent ({model if vlm_invoked else 'Brand Registry'})",
            icon="👁️",
            phase="Phase 4: Multimodal Vision & Brand Protection",
            status="TRIGGERED" if brand_ev.brand_impersonation_confirmed else ("COMPLETED" if brand else "SKIPPED"),
            duration_ms=elapsed_ms,
            reasoning=reasoning_text,
            decision=decision_text,
            tools_called=([f"VLM({model})"] if vlm_invoked else []) + ["BrandRegistry.find_brand_in_text", "BrandRegistry.is_domain_allowed"],
            findings=[
                {"label": "Обнаруженный бренд", "value": brand_ev.detected_brand_name or "Не обнаружен"},
                {"label": "Источник определения", "value": brand_ev.detection_source or "—"},
                {"label": "Категория приманки", "value": lure_type or "—"},
                {"label": "Уверенность", "value": f"{brand_ev.vlm_confidence:.0%}"},
                {"label": "VLM анализ скриншота", "value": "Да" if vlm_invoked else "Нет"},
                {"label": "Подтверждена подмена бренда", "value": "ДА" if brand_ev.brand_impersonation_confirmed else "НЕТ"},
            ],
            llm_audit=vlm_call_info,
            state_delta={
                "brand": brand_ev.detected_brand_name,
                "impersonated": brand_ev.brand_impersonation_confirmed,
                "triggered_codes": added_codes
            }
        ))
        return state
