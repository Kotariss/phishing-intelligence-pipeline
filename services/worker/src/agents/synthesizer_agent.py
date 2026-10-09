import time
from typing import Dict, Any, List, Optional
try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..rules.compiler import LSignatureCompiler
    from ..rules.yara_gen import YARAGenerator
    from ..rules.zero_fpr_guard import ZeroFPRGuard
    from ..brands.matcher import get_brand_registry
    from ..llm.client import get_llm_client
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from rules.compiler import LSignatureCompiler
    from rules.yara_gen import YARAGenerator
    from rules.zero_fpr_guard import ZeroFPRGuard
    from brands.matcher import get_brand_registry
    from llm.client import get_llm_client


REASON_CODE_WEIGHTS = {
    "RC_ATTACH_TELEGRAM_EXFIL": 1.00,
    "RC_ATTACH_DISCORD_EXFIL": 1.00,
    "RC_DROP_SCREENCONNECT_RAT": 1.00,
    "RC_ATTACH_PASSWORD_INPUT": 0.85,
    "FORM_PASSWORD_HARVESTING": 0.85,
    "RC_ATTACH_OBFUSCATED_JS": 0.75,
    "RC_BRAND_SPOOF_DISPLAYNAME": 0.65,
    "BRAND_IMPERSONATION_CONFIRMED": 0.65,
    "RC_LURE_DOUBLE_EXTENSION": 0.60,
    "RC_SANDBOX_EVASION_CODE": 0.50,
    "FORM_TELEGRAM_EXFILTRATION": 1.00,
    "RC_REDIRECT_MULTI_HOP": 0.45,
    "FORM_EXTERNAL_ACTION": 0.40,
    "RC_REDIRECT_ABUSE_TRUSTED": 0.40,
    "FORM_SUBMIT_BUTTON_LINK": 0.35,
    "BRAND_HOMOGRAPH_DOMAIN": 0.35,
    "ATTACH_QR_CODE_FOUND": 0.35,
    "ATTACH_ACTIVE_MACRO_MARKER": 0.40,
    "ATTACH_OFFLINE_FORM": 0.45,
    "RC_EPHEMERAL_HOST_DEAD": 0.15,
    "BRAND_VISUAL_LURE_MATCH": 0.25,
    "RC_CAMPAIGN_INVARIANT_MATCH": 0.50
}

class SynthesizerAgent:
    """Aggregates all specialist findings, computes Risk Score, runs Zero FPR Guard, and generates rules."""

    def __init__(self, compiler=None, yara_gen=None, zero_guard=None, llm_client=None):
        self.compiler = compiler or LSignatureCompiler()
        self.yara_gen = yara_gen or YARAGenerator()
        self.zero_guard = zero_guard or ZeroFPRGuard()
        self.registry = get_brand_registry()
        self.llm = llm_client or get_llm_client()

    def run(self, state: PhishingState) -> Dict[str, Any]:
        t0 = time.time()
        state.execution_steps.append("synthesizer_agent: Calculating risk score & synthesizing rules")
        codes = state.reason_codes

        # 1. Calculate base score
        raw_score = 0.0
        for code in codes:
            raw_score += REASON_CODE_WEIGHTS.get(code, 0.20)

        # Critical single indicators guarantee 1.0
        if any(c in codes for c in ("RC_ATTACH_TELEGRAM_EXFIL", "RC_ATTACH_DISCORD_EXFIL", "RC_DROP_SCREENCONNECT_RAT")):
            raw_score = max(raw_score, 1.0)

        risk_score = min(round(raw_score, 2), 1.0)
        target_brand = state.brand_evidence.detected_brand_name or "Generic"
        target_url = state.final_url or state.raw_target

        # 2. Synthesize preliminary L-signature & YARA
        has_password = any(form.has_password for form in state.dom_forms) or "RC_ATTACH_PASSWORD_INPUT" in codes
        has_ext = any(form.is_external_target for form in state.dom_forms) or "FORM_EXTERNAL_ACTION" in codes

        brand_entry = self.registry.find_brand(target_brand) if target_brand != "Generic" else None
        allowed_domains = brand_entry.get("official_domains", []) if brand_entry else []

        sig_rule = None
        if risk_score >= 0.50 or state.brand_evidence.brand_impersonation_confirmed:
            sig_rule = self.compiler.compile(
                target_brand=target_brand,
                risk_score=risk_score,
                reason_codes=codes,
                final_url=target_url,
                has_password=has_password,
                has_external_action=has_ext,
                allowed_domains=allowed_domains,
                zero_fpr_verified=True,
                dom_structural_hash=state.dom_structural_hash
            )
            state.generated_l_signature = sig_rule

        # YARA rule
        yara_code = self.yara_gen.generate(
            reason_codes=codes,
            brand_name=target_brand,
            risk_score=risk_score
        )
        state.generated_yara_rule = yara_code

        # 3. Zero FPR Guard Verification
        is_approved, fpr_note, adjusted_score = self.zero_guard.verify(
            risk_score=risk_score,
            target_brand=target_brand,
            target_url=target_url,
            rule_json=sig_rule
        )

        state.risk_score = adjusted_score
        state.zero_fpr_passed = is_approved

        # 4. Final Verdict determination
        if state.risk_score >= 0.70:
            state.verdict = "MALICIOUS"
            state.confidence = "HIGH"
        elif state.risk_score >= 0.30:
            state.verdict = "SUSPICIOUS"
            state.confidence = "MEDIUM"
        else:
            state.verdict = "CLEAN"
            state.confidence = "HIGH"

        # 5. Formulate Explanation via NSU DeepSeek LLM
        reasons_str = ", ".join(codes) if codes else "Подозрительных признаков не обнаружено"
        deterministic_summary = (
            f"Вердикт: {state.verdict} (Risk Score: {state.risk_score:.2f}). "
            f"Целевой бренд: {target_brand}. "
            f"Триггеры: [{reasons_str}]. "
            f"Zero FPR Guard: {fpr_note}"
        )

        llm_call_info = None
        try:
            llm_prompt = (
                f"Сформируй экспертное аналитическое заключение SOC-аналитика антиспама (2-3 предложения) на русском языке:\n"
                f"- Объект: {target_url}\n"
                f"- Бренд: {target_brand}\n"
                f"- Индикаторы: {reasons_str}\n"
                f"- Итоговый вердикт: {state.verdict} (Risk: {state.risk_score:.2f})\n"
                f"- Zero FPR статус: {fpr_note}\n"
                f"Опиши суть угрозы и рекомендацию."
            )
            ai_text = self.llm.ask_llm(
                prompt=llm_prompt,
                system_prompt="Ты — SOC-аналитик Лаборатории антиспама Doctor Web. Отвечай строго по существу, профессионально, кратко, на русском языке.",
                max_tokens=300
            )
            llm_call_info = self.llm.get_last_call()
            if ai_text and not ai_text.startswith("[Fallback"):
                state.explanation = f"{ai_text.strip()}\n\n[Технические индикаторы: {deterministic_summary}]"
            else:
                state.explanation = deterministic_summary
        except Exception:
            state.explanation = deterministic_summary

        elapsed_ms = round((time.time() - t0) * 1000, 1)
        state.agent_traces.append(AgentStepTrace(
            agent_id="synthesizer",
            agent_name=f"Synthesizer & Zero FPR Guard Agent ({self.llm.settings.LLM_TEXT_MODEL.split('/')[-1]})",
            icon="🧠",
            phase="Phase 7: Verdict Synthesis & L-Signature Distillation",
            status="TRIGGERED" if state.verdict == "MALICIOUS" else ("WARNING" if state.verdict == "SUSPICIOUS" else "CLEAN"),
            duration_ms=elapsed_ms,
            reasoning=f"Взвешенная агрегация собранных улик (Risk Score = {state.risk_score:.2f}). Компиляция компактной L-сигнатуры и YARA-правила. Верификация Zero FPR Guard (проверка по белому списку легитимных доменов). Генерация экспертного заключения через нейросеть {self.llm.settings.LLM_TEXT_MODEL}.",
            decision=f"ИТОГОВЫЙ ВЕРДИКТ: {state.verdict} (Risk: {state.risk_score:.2f}, Уверенность: {state.confidence}). Zero FPR Guard: {fpr_note}.",
            tools_called=[f"LLM_NSU_Cloud({self.llm.settings.LLM_TEXT_MODEL})", "RiskScoreCalculator", "LSignatureCompiler", "YARAGenerator", "ZeroFPRGuard"],
            findings=[
                {"label": "Итоговый вердикт", "value": state.verdict},
                {"label": "Оценка риска (Risk Score)", "value": f"{state.risk_score:.2f} / 1.00"},
                {"label": "Степень достоверности", "value": state.confidence},
                {"label": "Сгенерирована L-сигнатура", "value": "Да" if state.generated_l_signature else "Нет"},
                {"label": "Сгенерировано YARA правило", "value": "Да" if state.generated_yara_rule else "Нет"},
                {"label": "Проверка Zero FPR Guard", "value": "ПРОЙДЕНА (PASSED)" if state.zero_fpr_passed else "ОТКЛОНЕНА (FAILED)"}
            ],
            llm_audit=llm_call_info,
            state_delta={
                "verdict": state.verdict,
                "risk_score": state.risk_score,
                "zero_fpr_passed": state.zero_fpr_passed,
                "signature_generated": bool(state.generated_l_signature)
            }
        ))

        return state.model_dump()
