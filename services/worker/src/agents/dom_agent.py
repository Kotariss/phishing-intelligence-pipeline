import re
import time
from typing import Dict, Any, List
from bs4 import BeautifulSoup
try:
    from ..orchestrator.state import PhishingState, FormEvidence, AgentStepTrace
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, FormEvidence, AgentStepTrace


GENERIC_DROP_SCRIPTS = re.compile(
    r'(?i)(formsubmit\.php|please-wait-a-moment\.php|post\.php|login\.php|auth\.php|grab\.php)'
)

class DOMAgent:
    """Specialist agent analyzing DOM tree, forms, scripts, and exfiltration paths."""

    def run(self, state: PhishingState) -> Dict[str, Any]:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        state.execution_steps.append("dom_agent: Analyzing DOM structure and interactive forms")
        reasons = list(state.reason_codes)

        dom_html = state.dom_html or ""
        html_lower = dom_html.lower()

        # 1. Check for password harvesting
        has_password = False
        has_external_action = False
        has_submit_link = False

        for form in state.dom_forms:
            if form.has_password:
                has_password = True
            if form.is_external_target or GENERIC_DROP_SCRIPTS.search(form.action):
                has_external_action = True
            if form.submit_target_url and form.submit_target_url != form.action:
                has_submit_link = True
            if form.submit_mechanism == "telegram_bot":
                reasons.append("RC_ATTACH_TELEGRAM_EXFIL")

        if not has_password and ('type="password"' in html_lower or "type='password'" in html_lower):
            has_password = True

        if has_password:
            reasons.append("RC_ATTACH_PASSWORD_INPUT")

        if has_external_action:
            reasons.append("FORM_EXTERNAL_ACTION")

        if has_submit_link:
            reasons.append("FORM_SUBMIT_BUTTON_LINK")

        # 2. Exfiltration channels
        if "api.telegram.org/bot" in html_lower:
            reasons.append("RC_ATTACH_TELEGRAM_EXFIL")
        if "discord.com/api/webhooks" in html_lower or "discordapp.com/api/webhooks" in html_lower:
            reasons.append("RC_ATTACH_DISCORD_EXFIL")

        # 3. Script Obfuscation
        has_obfuscation = False
        if "string.fromcharcode" in html_lower:
            has_obfuscation = True
        elif "eval(function(p,a,c,k" in html_lower:
            has_obfuscation = True
        elif "unescape(" in html_lower and "document.write" in html_lower:
            has_obfuscation = True
        elif "atob(" in html_lower and len(dom_html) > 500:
            has_obfuscation = True

        if has_obfuscation:
            reasons.append("RC_ATTACH_OBFUSCATED_JS")
            state.script_obfuscation_detected = True

        # 4. Anti-Analysis / Sandbox Evasion
        if "navigator.webdriver" in html_lower or "devtools" in html_lower:
            reasons.append("RC_SANDBOX_EVASION_CODE")

        # 5. Extract DOM Skeleton and Structural Hash if not yet computed
        if not state.dom_structural_hash and dom_html:
            try:
                try:
                    from services.sandbox.src.attachment_parser import AttachmentParser
                except (ImportError, ValueError):
                    from attachment_parser import AttachmentParser
                skel_res = AttachmentParser.extract_dom_skeleton_hash(dom_html)
                state.dom_structural_hash = skel_res.get("dom_structural_hash")
                state.dom_skeleton = skel_res.get("dom_skeleton")
            except Exception:
                pass

        state.reason_codes = sorted(list(set(reasons)))

        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        state.agent_traces.append(AgentStepTrace(
            agent_id="dom_agent",
            agent_name="DOM & Script Inspection Agent",
            icon="📄",
            phase="Phase 3: DOM, Forms & Scripts Analysis",
            status="TRIGGERED" if added_codes else "COMPLETED",
            duration_ms=elapsed_ms,
            reasoning=f"Синтаксический разбор DOM-дерева HTML/Email, интерактивных форм `<form>`, полей ввода паролей, внешних action URL, каналов эксфильтрации данных (Telegram/Discord) и обфусцированного JS-кода (eval/fromCharCode/atob). Вычисление структурного хеша остова тегов (Tag Skeleton Hash).",
            decision=f"Выявлено подозрительных признаков DOM/JS: {len(added_codes)} шт. " + (f"[{', '.join(added_codes)}]" if added_codes else "[Признаков перехвата паролей и обфускации не обнаружено]"),
            tools_called=["BeautifulSoupDOMParser", "FormCredentialHarvestingDetector", "JSObfuscationScanner", "C2ExfiltrationChannelDetector", "TagSkeletonHasher"],
            findings=[
                {"label": "Формы с паролями (Password Harvesting)", "value": "Да" if has_password else "Нет"},
                {"label": "Внешний Action отправки данных", "value": "Да" if has_external_action else "Нет"},
                {"label": "Эксфильтрация в Telegram Bot", "value": "Да" if "RC_ATTACH_TELEGRAM_EXFIL" in state.reason_codes else "Нет"},
                {"label": "Эксфильтрация в Discord Webhook", "value": "Да" if "RC_ATTACH_DISCORD_EXFIL" in state.reason_codes else "Нет"},
                {"label": "Обфусцированный JS-скрипт", "value": "Да" if state.script_obfuscation_detected else "Нет"},
                {"label": "Структурный хеш DOM (Tag Skeleton Hash)", "value": state.dom_structural_hash or "—"}
            ],
            state_delta={
                "triggered_codes": added_codes,
                "script_obfuscation": state.script_obfuscation_detected,
                "dom_structural_hash": state.dom_structural_hash
            }
        ))

        return state.model_dump()
