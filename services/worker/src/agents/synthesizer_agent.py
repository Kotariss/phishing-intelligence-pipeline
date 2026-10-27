import hashlib
import os
import time

try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..rules.compiler import LSignatureCompiler
    from ..rules.yara_gen import YARAGenerator
    from ..rules.zero_fpr_guard import ZeroFPRGuard
    from ..rules.engine import record_from_state
    from ..rules import reason_codes as rc
    from ..rules.verdict import decide
    from ..brands.matcher import get_brand_registry, extract_hostname
    from ..features.fingerprints import dhash64, campaign_key
    from ..features.url_features import registrable_domain
    from ..llm.client import get_llm_client
    from ..llm import prompts
    from ..config import get_settings
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from rules.compiler import LSignatureCompiler
    from rules.yara_gen import YARAGenerator
    from rules.zero_fpr_guard import ZeroFPRGuard
    from rules.engine import record_from_state
    from rules import reason_codes as rc
    from rules.verdict import decide
    from brands.matcher import get_brand_registry, extract_hostname
    from features.fingerprints import dhash64, campaign_key
    from features.url_features import registrable_domain
    from llm.client import get_llm_client
    from llm import prompts
    from config import get_settings


# Evidence extracted from the landing page itself (neutralised when the page is on an official domain).
PAGE_CODES = {
    "RC_ATTACH_PASSWORD_INPUT", "FORM_EXTERNAL_ACTION", "FORM_PASSWORD_HARVESTING", "FORM_CARD_HARVESTING",
    "FORM_SUBMIT_BUTTON_LINK", "DOM_PREFILLED_VICTIM_EMAIL", "RC_ATTACH_OBFUSCATED_JS", "RC_SANDBOX_EVASION_CODE",
    "BRAND_IMPERSONATION_CONFIRMED", "BRAND_MENTION_OFF_DOMAIN", "BRAND_VISUAL_LURE_MATCH",
    "COMBO_BRAND_CREDENTIAL_FORM", "RC_EPHEMERAL_HOST_DEAD",
}

# Analyst-facing explanation is in Russian (ТЗ 4.5.1); internal verdict values stay as stored.
VERDICT_RU = {"MALICIOUS": "фишинг", "SUSPICIOUS": "подозрительно", "CLEAN": "чисто"}
SEVERITY_RU = {"critical": "критично", "high": "высокая", "medium": "средняя", "low": "низкая", "info": "справочно"}


class SynthesizerAgent:
    """Aggregates all specialist findings, computes the risk score, applies the Zero FPR guard,
    distils L-signature / YARA artefacts and fingerprints, and writes the analyst explanation."""

    def __init__(self, compiler=None, yara_gen=None, zero_guard=None, llm_client=None, settings=None):
        self.settings = settings or get_settings()
        self.registry = get_brand_registry()
        self.compiler = compiler or LSignatureCompiler(self.registry)
        self.yara_gen = yara_gen or YARAGenerator()
        self.zero_guard = zero_guard or ZeroFPRGuard(self.registry)
        self.llm = llm_client or get_llm_client()

    # ---------------------------------------------------------------- scoring
    @staticmethod
    def _match_known_iocs(state: PhishingState) -> None:
        """Exact match of the object (or of an attachment) with a confirmed indicator of compromise of the knowledge base.
        Switched off in metric runs (DW2_DISABLE_IOC): recall is measured without exact indicators (ТЗ, табл. 3)."""
        if os.environ.get("DW2_DISABLE_IOC"):
            return
        hashes = []
        if state.raw_bytes:
            hashes.append(hashlib.sha256(state.raw_bytes).hexdigest())
        att = state.attachment_evidence or {}
        hashes += [m["sha256"] for m in att.get("attachments_meta") or [] if m.get("sha256") and not m.get("inline")]
        try:
            from ..db.repository import IncidentRepository
        except (ImportError, ValueError):
            from db.repository import IncidentRepository
        hits = IncidentRepository().find_iocs(hashes, exclude_incident=state.incident_id)
        if hits:
            state.add_reason("RC_KNOWN_IOC_MATCH", f"SHA-256 {hits[0].sha256[:16]}… подтверждён инцидентом {hits[0].incident_id}",
                             {"type": "text", "value": "\n".join(f"{h.kind}: {h.sha256} ← {h.incident_id}" for h in hits[:5]),
                              "label": "Совпадение с известным индикатором компрометации"})

    @staticmethod
    def _add_composites(state: PhishingState) -> None:
        codes = set(state.reason_codes)
        credential_input = any(f.has_password or f.has_card for f in state.dom_forms) or \
            bool(state.page_features.get("has_password_field"))
        if "BRAND_IMPERSONATION_CONFIRMED" in codes and credential_input:
            state.add_reason("COMBO_BRAND_CREDENTIAL_FORM",
                             f"{state.brand_evidence.detected_brand_name} вне официального домена + форма ввода учётных данных",
                             state.reason_evidence.get("RC_ATTACH_PASSWORD_INPUT") or state.reason_evidence.get("FORM_CARD_HARVESTING"))
        if "BRAND_LOOKALIKE_DOMAIN" in codes and credential_input:
            state.add_reason("COMBO_LOOKALIKE_CREDENTIAL_FORM",
                             f"Домен-двойник {state.network_evidence.get('lookalike_host')} + форма ввода учётных данных",
                             state.reason_evidence.get("RC_ATTACH_PASSWORD_INPUT") or state.reason_evidence.get("FORM_CARD_HARVESTING"))

    def _allowlist_clamp(self, state: PhishingState) -> str:
        """Level 1: a landing page hosted on an official brand domain is legitimate content, so the
        evidence extracted *from that page* is neutralised. E-mail, link and attachment evidence is kept:
        attackers redirect scanners to the genuine site (cloaking), which is itself recorded."""
        url = state.final_url or ""
        host = extract_hostname(url) if url.startswith("http") else ""
        if not host:
            return ""
        brand_id = state.brand_evidence.brand_id
        owner = self.registry.find_brand_for_domain(host)
        if brand_id and self.registry.is_domain_allowed(brand_id, host):
            owner = self.registry.by_id.get(brand_id)
        if not owner:
            return ""

        neutralised = [c for c in state.reason_codes if c in PAGE_CODES and c not in rc.NON_CLAMPABLE]
        for code in neutralised:
            state.drop_reason(code)
        state.network_evidence["neutralised_by_allowlist"] = neutralised

        start_host = extract_hostname(state.scan_url or "") if (state.scan_url or "").startswith("http") else ""
        sender = (state.attachment_evidence or {}).get("from_domain") or ""
        foreign_start = start_host and not self.registry.find_brand_for_domain(start_host) and \
            registrable_domain(start_host) != registrable_domain(host)
        sender_official = sender and self.registry.is_domain_allowed(owner["brand_id"], sender)
        if foreign_start and state.redirect_chain and not sender_official:
            state.add_reason("RC_CLOAKING_TO_OFFICIAL", f"{start_host} → {host} ({owner['display_name']})",
                             {"type": "chain", "value": [state.scan_url or ""] + [h.url for h in state.redirect_chain] + [url], "label": "Перенаправление на официальный сайт"})
        return f"Уровень 1: {host} — официальный домен {owner['display_name']}; признаки страницы нейтрализованы ({len(neutralised)})"

    def _fingerprints(self, state: PhishingState) -> None:
        rec = record_from_state(state)
        att = state.attachment_evidence or {}
        fp = {
            "dom_structural_hash": state.dom_structural_hash,
            "dom_tags_count": state.page_features.get("tags_count"),
            "screenshot_dhash": dhash64(state.screenshot_base64),
            "final_domain": registrable_domain(extract_hostname(state.final_url or "")) if state.final_url else None,
            "favicon": state.page_features.get("favicon") or None,
            "telegram_bot_ids": rec["telegram_bot_ids"],
            "discord_webhooks": rec["discord_webhook_ids"],
            "credential_post_domain": next((registrable_domain(f.action_host) for f in state.dom_forms
                                            if f.is_external_target and f.action_host), None),
            "attachment_sha256": list(dict.fromkeys(m["sha256"] for m in att.get("attachments_meta") or []
                                                    if m.get("sha256") and not m.get("inline"))),
            "sender_domain": att.get("from_domain") or None,
            # the analysed file itself (standalone HTML / image / document): a signature of known phishing
            "file_sha256": hashlib.sha256(state.raw_bytes).hexdigest() if state.raw_bytes else None,
        }
        state.fingerprints = {k: v for k, v in fp.items() if v not in (None, [], "")}
        state.campaign_id = campaign_key(state.fingerprints)

    # -------------------------------------------------------------------- run
    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        state.execution_steps.append("synthesizer_agent: Calculating risk score & synthesizing rules")

        state.llm_mode = self.settings.llm_mode if self.llm.enabled else "off"  # results of the modes are never mixed up
        self._add_composites(state)
        self._match_known_iocs(state)
        clamp_note = self._allowlist_clamp(state)
        decision = decide(state.reason_codes, self.settings.SCORE_CLEAN_THRESHOLD, self.settings.SCORE_MALICIOUS_THRESHOLD)
        state.risk_score, state.verdict = decision["risk"], decision["verdict"]
        if decision["advisory"]:  # the model's reading of the text is advisory without independent evidence (ТЗ А.1.3)
            state.network_evidence["model_text_advisory"] = decision["advisory"]
        if decision["capped"]:  # ТЗ 4.1.4.6: единичные признаки не дают «фишинг» — нужны признаки из двух независимых групп
            state.network_evidence["verdict_capped"] = decision["capped"]
        mal_t = self.settings.SCORE_MALICIOUS_THRESHOLD
        if state.verdict == "MALICIOUS":
            state.confidence = "HIGH" if state.risk_score >= 0.85 else "MEDIUM"
        elif state.verdict == "SUSPICIOUS":
            state.confidence = "MEDIUM"
        else:
            state.confidence = "MEDIUM" if (state.reason_codes and not clamp_note) or decision["advisory"] else "HIGH"

        self._fingerprints(state)

        # Artefact distillation (only for incidents worth a rule) + Zero FPR audit
        state.generated_l_signature, state.generated_yara_rule = None, None
        state.signature_status = "NOT_GENERATED"
        validation = None
        if state.verdict != "CLEAN":
            rule = self.compiler.compile(state)
            if rule:
                validation = self.zero_guard.verify_rule(rule, record_from_state(state), state.risk_score, mal_t)
                rule["validation_metrics"] = {k: v for k, v in validation.items() if k != "approved"}
                rule["validation_metrics"]["zero_fpr_verified"] = validation["approved"]
                state.signature_status = "ACTIVE_VERIFIED" if validation["approved"] else "DRAFT_REQUIRES_TUNING"
                state.generated_l_signature = rule
                state.generated_yara_rule = self.yara_gen.generate(state, rule_id=rule["rule_id"])
        state.zero_fpr_passed = validation["approved"] if validation else True
        if validation:
            no_rule_note = validation["note"]
        elif state.verdict == "CLEAN":
            no_rule_note = "Уровень 2: вердикт «чисто» — правило не требуется."
        else:
            no_rule_note = "Правило не построено: нет обобщаемого набора признаков."
        state.zero_fpr_note = clamp_note or no_rule_note

        # Explanation: indicators with weights and details
        lines = [f"- {code} ({SEVERITY_RU.get(rc.get(code).severity, rc.get(code).severity)}, вес {rc.get(code).weight:.2f}): "
                 f"{state.reason_details.get(code) or rc.get(code).description}"
                 for code in sorted(state.reason_codes, key=lambda c: -rc.get(c).weight)]
        # The evidence list always follows the analyst summary: every claim is traceable to an indicator.
        evidence_text = (f"Вердикт: {VERDICT_RU.get(state.verdict, state.verdict)} (риск {state.risk_score:.2f}, "
                         f"{'признаки одной группы — «фишинг» требует двух независимых' if state.network_evidence.get('verdict_capped') else 'объединение ' + str(len(state.reason_codes)) + ' независимых признаков'}). "
                         + (f"Вывод модели по тексту ({', '.join(state.network_evidence['model_text_advisory'])}) учтён как справочный: без независимой улики он не меняет вердикт. " if state.network_evidence.get("model_text_advisory") else "")
                         + f"Бренд: {state.brand_evidence.detected_brand_name or '—'}. Проверка на легитимных данных: {state.zero_fpr_note}"
                         + ("\nОбоснование:\n" + "\n".join(lines) if lines else ""))
        llm_call_info = None
        state.explanation = evidence_text
        if state.verdict != "CLEAN" and self.llm.enabled:
            prompt = prompts.render("analyst_summary", target=state.raw_target, final_url=state.final_url or "—",
                                    brand=state.brand_evidence.detected_brand_name or "—", verdict=state.verdict,
                                    risk=f"{state.risk_score:.2f}", indicators="\n".join(lines[:12]))
            text = self.llm.ask_llm(prompt, system_prompt=prompts.render("analyst_summary_system"), prompt_name="analyst_summary")
            llm_call_info = self.llm.get_last_call()
            state.explanation = f"{text.strip()}\n\n{evidence_text}"

        elapsed_ms = round((time.time() - t0) * 1000, 1)
        state.agent_traces.append(AgentStepTrace(
            agent_id="synthesizer",
            agent_name=f"Synthesizer & Zero FPR Guard Agent ({self.settings.text_model})",
            icon="🧠",
            phase="Phase 7: Verdict Synthesis & L-Signature Distillation",
            status="TRIGGERED" if state.verdict == "MALICIOUS" else ("WARNING" if state.verdict == "SUSPICIOUS" else "CLEAN"),
            duration_ms=elapsed_ms,
            reasoning=f"Комбинирование {len(state.reason_codes)} независимых индикаторов (noisy-OR: 1-Π(1-wᵢ)) → {decision["risk"]:.2f}. "
                      f"Составные признаки, Level-1 allowlist, дистилляция L-сигнатуры/YARA, регрессия правила на эталонной выборке ({len(self.zero_guard.corpus)} легитимных образцов).",
            decision=f"ИТОГОВЫЙ ВЕРДИКТ: {state.verdict} (Risk: {state.risk_score:.2f}, уверенность: {state.confidence}). {state.zero_fpr_note}",
            tools_called=(["LLM(" + self.settings.text_model + ")"] if llm_call_info else []) + ["NoisyOrScorer", "LSignatureCompiler", "YARAGenerator", "ZeroFPRGuard"],
            findings=[
                {"label": "Итоговый вердикт", "value": state.verdict},
                {"label": "Risk Score", "value": f"{state.risk_score:.2f} / 1.00"},
                {"label": "L-сигнатура", "value": f"{state.generated_l_signature['kind']} ({state.signature_status})" if state.generated_l_signature else "Нет"},
                {"label": "YARA правило", "value": "Да" if state.generated_yara_rule else "Нет"},
                {"label": "Кампания", "value": state.campaign_id or "—"},
                {"label": "Zero FPR Guard", "value": "ПРОЙДЕНА" if state.zero_fpr_passed else "ОТКЛОНЕНА (черновик)"}
            ],
            llm_audit=llm_call_info,
            state_delta={
                "verdict": state.verdict,
                "risk_score": state.risk_score,
                "zero_fpr_passed": state.zero_fpr_passed,
                "signature_status": state.signature_status
            }
        ))
        return state
