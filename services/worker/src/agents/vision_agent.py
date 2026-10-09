import re
import time
from typing import Dict, Any, Optional
try:
    from ..orchestrator.state import PhishingState, BrandEvidence, AgentStepTrace
    from ..brands.matcher import get_brand_registry
    from ..llm.client import get_llm_client
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, BrandEvidence, AgentStepTrace
    from brands.matcher import get_brand_registry
    from llm.client import get_llm_client


class VisionAgent:
    """Multimodal Vision Agent combining VLM logo recognition with 175-Brand Allowlist."""

    def __init__(self, brand_registry=None, llm_client=None):
        self.registry = brand_registry or get_brand_registry()
        self.llm = llm_client or get_llm_client()

    def run(self, state: PhishingState) -> Dict[str, Any]:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        vlm_invoked = False
        vlm_call_info = None

        state.execution_steps.append("vision_agent: Performing multimodal brand & lure analysis")
        reasons = list(state.reason_codes)

        candidate_brand_name: Optional[str] = state.brand_evidence.detected_brand_name
        lure_type: Optional[str] = state.brand_evidence.visual_lure_type
        vlm_confidence = state.brand_evidence.vlm_confidence

        # 1. Check sender display name from EML metadata
        eml_meta = state.attachment_evidence
        if not candidate_brand_name and eml_meta and eml_meta.get("from_name"):
            found_b = self.registry.find_brand(eml_meta["from_name"])
            if found_b:
                candidate_brand_name = found_b["display_name"]
                vlm_confidence = 0.85

        # 2. Check VLM on screenshot
        if not candidate_brand_name and state.screenshot_base64 and len(state.screenshot_base64) > 100:
            prompt = (
                "Examine this webpage/document screenshot carefully.\n"
                "1. What organization, company, or brand logo/identity is depicted? (e.g. Sber, Tinkoff, VTB, Gosuslugi, Microsoft, DocuSign, DHL, FedEx, PayPal, etc.). If none or generic, write 'None'.\n"
                "2. What is the lure category? (banking_login, b2b_invoice, delivery_awb, security_alert, penalty_notice, other).\n"
                "Respond in format:\n"
                "Brand: <brand_name>\n"
                "Lure: <lure_type>"
            )
            vlm_response = self.llm.ask_vlm(prompt, state.screenshot_base64, max_tokens=1200)
            vlm_invoked = True
            vlm_call_info = self.llm.get_last_call()
            
            # Parse response
            brand_match = re.search(r'Brand:\s*([^\n\r]+)', vlm_response, re.IGNORECASE)
            lure_match = re.search(r'Lure:\s*([^\n\r]+)', vlm_response, re.IGNORECASE)
            
            if brand_match:
                extracted_brand = brand_match.group(1).strip().strip('"').strip("'")
                if extracted_brand.lower() not in ("none", "unknown", "n/a", "etc", "etc.", ""):
                    # Validate against registry
                    found_b = self.registry.find_brand(extracted_brand)
                    if found_b:
                        candidate_brand_name = found_b["display_name"]
                        vlm_confidence = 0.95

            if lure_match:
                lure_type = lure_match.group(1).strip().lower()

        # 3. Check if target domain is an official domain for any known brand
        target_check = state.final_url
        if not target_check and eml_meta and eml_meta.get("from_domain"):
            target_check = eml_meta["from_domain"]
        if not target_check:
            target_check = state.raw_target

        if not candidate_brand_name and target_check:
            legit_brand = self.registry.find_brand_for_domain(target_check)
            if legit_brand:
                candidate_brand_name = legit_brand["display_name"]
                vlm_confidence = 0.90

        # 4. Fallback: inspect page title first, then cleaned body text
        if not candidate_brand_name and state.dom_html:
            # Check <title> tag
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', state.dom_html, re.IGNORECASE)
            title_text = title_match.group(1).strip() if title_match else ""
            if title_text:
                for b in self.registry.brands:
                    for alias in b.get("aliases", []):
                        if len(alias) >= 3 and re.search(rf'\b{re.escape(alias)}\b', title_text, re.IGNORECASE):
                            candidate_brand_name = b["display_name"]
                            vlm_confidence = 0.85
                            break
                    if candidate_brand_name:
                        break

            # If still not found, check body text (stripping head, scripts, styles)
            if not candidate_brand_name:
                clean_dom = re.sub(r'<(head|script|style)[^>]*>.*?</\1>', '', state.dom_html, flags=re.IGNORECASE | re.DOTALL)
                clean_text = re.sub(r'<[^>]+>', ' ', clean_dom)
                for b in self.registry.brands:
                    for alias in b.get("aliases", []):
                        if len(alias) >= 4 and alias.lower() not in ("apple", "cloud", "sign", "auth", "post", "mail") and re.search(rf'\b{re.escape(alias)}\b', clean_text, re.IGNORECASE):
                            candidate_brand_name = b["display_name"]
                            vlm_confidence = 0.70
                            break
                    if candidate_brand_name:
                        break

        # 4. Allowlist & Impersonation Verification
        brand_ev = BrandEvidence(
            detected_brand_name=candidate_brand_name,
            vlm_confidence=vlm_confidence,
            visual_lure_type=lure_type or "standard_lure"
        )

        target_check = state.final_url
        if not target_check and eml_meta and eml_meta.get("from_domain"):
            target_check = eml_meta["from_domain"]
        if not target_check:
            target_check = state.raw_target

        if candidate_brand_name and target_check:
            impersonated, b_entry, reason = self.registry.check_brand_impersonation(candidate_brand_name, target_check)

            brand_ev.brand_impersonation_confirmed = impersonated
            brand_ev.is_domain_in_allowlist = not impersonated
            brand_ev.impersonation_reason = reason

            if impersonated:
                reasons.append("BRAND_IMPERSONATION_CONFIRMED")
                reasons.append("RC_BRAND_SPOOF_DISPLAYNAME")
                if lure_type:
                    reasons.append("BRAND_VISUAL_LURE_MATCH")
            else:
                brand_ev.is_domain_in_allowlist = True
                # Clean brand on legitimate domain -> remove false brand impersonation flags
                reasons = [r for r in reasons if r not in ("BRAND_IMPERSONATION_CONFIRMED", "RC_BRAND_SPOOF_DISPLAYNAME")]

        state.brand_evidence = brand_ev
        state.reason_codes = sorted(list(set(reasons)))

        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)

        if vlm_invoked:
            reasoning_text = (
                f"Текстовые анализаторы и DOM не содержали явных ключевых слов. Активирована мультимодальная нейросеть VLM ({self.llm.settings.LLM_VISION_MODEL}) "
                f"для распознавания логотипа и интерфейса со снимка экрана. Проведена верификация распознанного бренда '{candidate_brand_name}' по реестру Allowlist (175 брендов)."
            )
        elif candidate_brand_name:
            reasoning_text = (
                f"Кандидат бренда '{candidate_brand_name}' определен из метаданных письма/DOM. Проведена строгая верификация по реестру Allowlist (175 брендов) "
                f"против целевого ресурса '{target_check}'."
            )
        else:
            reasoning_text = (
                "Анализ графических и текстовых артефактов не выявил охраняемых брендов или корпоративной айдентики."
            )

        tools = ["BrandRegistry.find_brand", "BrandRegistry.check_brand_impersonation"]
        if vlm_invoked:
            tools.insert(0, f"VLM_VisionModel({self.llm.settings.LLM_VISION_MODEL})")

        if brand_ev.brand_impersonation_confirmed:
            decision_text = f"КРИТИЧЕСКАЯ УГРОЗА: Обнаружена подмена бренда '{candidate_brand_name}'! Целевой ресурс '{target_check}' не входит в официальный белый список доменов бренда ({brand_ev.impersonation_reason})."
        elif candidate_brand_name:
            decision_text = f"Бренд '{candidate_brand_name}' подтвержден как ЛЕГИТИМНЫЙ: хост '{target_check}' входит в официальный реестр доверенных доменов бренда."
        else:
            decision_text = "Признаков целевого спуфинга бренда не зафиксировано."

        state.agent_traces.append(AgentStepTrace(
            agent_id="vision_agent",
            agent_name=f"Multimodal Vision Agent ({'VLM Qwen3.8-27B' if vlm_invoked else 'Brand Registry'})",
            icon="👁️",
            phase="Phase 4: Multimodal Vision & Brand Protection",
            status="TRIGGERED" if brand_ev.brand_impersonation_confirmed else ("COMPLETED" if candidate_brand_name else "SKIPPED"),
            duration_ms=elapsed_ms,
            reasoning=reasoning_text,
            decision=decision_text,
            tools_called=tools,
            findings=[
                {"label": "Обнаруженный бренд", "value": candidate_brand_name or "Не обнаружен"},
                {"label": "Категория приманки (Lure)", "value": lure_type or "standard"},
                {"label": "Уверенность распознавания", "value": f"{vlm_confidence:.0%}"},
                {"label": "Использован VLM анализ пикселей", "value": "Да (Qwen3.8-27B)" if vlm_invoked else "Нет (извлечено из метаданных)"},
                {"label": "Подтверждена подмена бренда", "value": "ДА (ФИШИНГ)" if brand_ev.brand_impersonation_confirmed else "НЕТ"},
                {"label": "Домен в белом списке (Allowlist)", "value": "ДА" if brand_ev.is_domain_in_allowlist else "НЕТ"}
            ],
            llm_audit=vlm_call_info,
            state_delta={
                "brand": candidate_brand_name,
                "impersonated": brand_ev.brand_impersonation_confirmed,
                "triggered_codes": added_codes
            }
        ))

        return state.model_dump()
