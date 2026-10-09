import re
import time

try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..sandbox_bridge import dom_skeleton_hash
    from ..brands.matcher import get_brand_registry
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from sandbox_bridge import dom_skeleton_hash
    from brands.matcher import get_brand_registry


PASSWORD_INPUT = re.compile(r'<input\b[^>]*\btype\s*=\s*["\']?password\b', re.IGNORECASE)


class DOMAgent:
    """Specialist agent analyzing DOM tree, forms, scripts, and exfiltration paths."""

    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        state.execution_steps.append("dom_agent: Analyzing DOM structure and interactive forms")

        page = state.page_features or {}
        att = state.attachment_evidence or {}
        dom_html = state.dom_html or ""

        # 1. Credential collection surface
        has_password = any(f.has_password for f in state.dom_forms) or bool(page.get("has_password_field")) \
            or bool(att.get("has_password_field")) or bool(PASSWORD_INPUT.search(dom_html))
        # Posting to an official domain of a known brand (payment gateway, corporate IdP of a target
        # brand) is not exfiltration.
        registry = get_brand_registry()
        external_forms = [f for f in state.dom_forms if f.is_external_target
                          and not (f.action_host and registry.find_brand_for_domain(f.action_host))]
        js_external = [u for u in (page.get("js_external_endpoints") or []) if not registry.find_brand_for_domain(u)]
        card_forms = [f for f in state.dom_forms if f.has_card]

        # Evidence fragments: page snippets, otherwise those of the HTML attachments of an e-mail
        snippets = dict(page.get("evidence_snippets") or {})
        for item in att.get("attachments_analysis", []) or []:
            for key, value in (item.get("evidence_snippets") or {}).items():
                snippets.setdefault(key, f"[{item.get('filename', 'вложение')}] {value}")
        for key, value in (att.get("evidence_snippets") or {}).items():
            snippets.setdefault(key, value)
        origin = "страница" if page else "вложение"

        def dom(fragment: str, label: str) -> dict:
            return {"type": "dom", "value": fragment, "label": label}

        if has_password:
            pw_form = next((f for f in state.dom_forms if f.has_password and f.snippet), None)
            state.add_reason("RC_ATTACH_PASSWORD_INPUT", "Обнаружено поле ввода пароля",
                             dom(pw_form.snippet if pw_form else snippets.get("password_input", ""), f"Форма с паролем ({origin})"))
        if external_forms:
            hosts = sorted({f.action_host or f.action for f in external_forms})
            state.add_reason("FORM_EXTERNAL_ACTION", f"Форма отправляет данные на: {', '.join(hosts)[:200]}",
                             dom(external_forms[0].snippet, f"action → {external_forms[0].action_host}"))
        if has_password and (any(f.has_password for f in external_forms) or js_external):
            ext_pw = next((f for f in external_forms if f.has_password), None)
            target = ext_pw.action_host if ext_pw else js_external[0]
            state.add_reason("FORM_PASSWORD_HARVESTING", f"Пароль уходит на сторонний ресурс: {target}",
                             dom(ext_pw.snippet if ext_pw else snippets.get("js_endpoint", ""), "Отправка учётных данных"))
        if card_forms:
            state.add_reason("FORM_CARD_HARVESTING", "Форма с полями банковской карты", dom(card_forms[0].snippet, "Форма с полями карты"))
        mismatch = next((f for f in state.dom_forms if f.submit_target_url and f.action and f.submit_target_url not in (f.action, "")
                         and not f.submit_target_url.endswith(f.action)), None)
        if mismatch:
            state.add_reason("FORM_SUBMIT_BUTTON_LINK", "Кнопка отправки указывает на другой адрес, чем action формы",
                             dom(mismatch.snippet, "Форма"))
        prefilled = next((f for f in state.dom_forms if f.prefilled_victim_email), None)
        if prefilled:
            state.add_reason("DOM_PREFILLED_VICTIM_EMAIL", "Поле логина предзаполнено e-mail адресом получателя",
                             dom(prefilled.snippet, "Предзаполненная форма"))

        # 2. Exfiltration channels (page or attachments)
        if page.get("has_telegram_exfil") or att.get("has_telegram_exfil") or                 any(f.submit_mechanism == "telegram_bot" for f in state.dom_forms) or "api.telegram.org/bot" in dom_html.lower():
            tokens = page.get("telegram_bot_tokens") or []
            state.add_reason("RC_ATTACH_TELEGRAM_EXFIL", "Отправка данных в Telegram Bot API" + (f" (бот {tokens[0].split(':')[0]})" if tokens else ""),
                             dom(snippets.get("telegram", ""), "Вызов Telegram Bot API"))
        if page.get("has_discord_exfil") or att.get("has_discord_exfil") or "discord.com/api/webhooks" in dom_html.lower():
            state.add_reason("RC_ATTACH_DISCORD_EXFIL", "Отправка данных в Discord Webhook",
                             dom(snippets.get("discord", ""), "Вызов Discord Webhook"))

        # 3. Script obfuscation / anti-analysis (feature extractor counts independent techniques)
        markers = list(page.get("obfuscation_markers") or [])
        for item in att.get("attachments_analysis", []) or []:
            markers += item.get("obfuscation_markers") or []
        if markers or att.get("has_script_obfuscation"):
            state.script_obfuscation_detected = True
            state.add_reason("RC_ATTACH_OBFUSCATED_JS", f"Техники обфускации: {', '.join(sorted(set(markers))) or 'в вложении'}",
                             dom(snippets.get("obfuscation", ""), "Обфусцированный фрагмент"))
        if page.get("has_sandbox_evasion"):
            state.add_reason("RC_SANDBOX_EVASION_CODE", f"Антианализ: {', '.join(page.get('evasion_markers') or [])}",
                             dom(snippets.get("evasion", ""), "Проверка окружения"))

        # 4. DOM skeleton hash (phishing-kit reuse fingerprint)
        if not state.dom_structural_hash and dom_html:
            skel = dom_skeleton_hash(dom_html)
            state.dom_structural_hash = skel.get("dom_structural_hash")
            state.dom_skeleton = skel.get("dom_skeleton")
            if skel.get("tags_count") is not None:
                state.page_features.setdefault("tags_count", skel["tags_count"])

        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        state.agent_traces.append(AgentStepTrace(
            agent_id="dom_agent",
            agent_name="DOM & Script Inspection Agent",
            icon="📄",
            phase="Phase 3: DOM, Forms & Scripts Analysis",
            status="TRIGGERED" if added_codes else "COMPLETED",
            duration_ms=elapsed_ms,
            reasoning="Разбор DOM-дерева страницы/вложения: формы `<form>` (action относительно домена страницы), поля пароля и карт, JS-эндпоинты отправки данных, каналы эксфильтрации (Telegram/Discord), обфускация (packer/fromCharCode/base64), антианализ. Вычисление структурного хеша остова тегов (Tag Skeleton Hash).",
            decision=f"Выявлено подозрительных признаков DOM/JS: {len(added_codes)} шт. " + (f"[{', '.join(added_codes)}]" if added_codes else "[Признаков перехвата учётных данных и обфускации не обнаружено]"),
            tools_called=["BeautifulSoupDOMParser", "FormCredentialHarvestingDetector", "JSObfuscationScanner", "C2ExfiltrationChannelDetector", "TagSkeletonHasher"],
            findings=[
                {"label": "Поле пароля", "value": "Да" if has_password else "Нет"},
                {"label": "Внешний action / JS-эндпоинт", "value": ", ".join(sorted({f.action_host for f in external_forms if f.action_host} | set(js_external[:3]))) or "Нет"},
                {"label": "Эксфильтрация в Telegram", "value": "Да" if "RC_ATTACH_TELEGRAM_EXFIL" in state.reason_codes else "Нет"},
                {"label": "Эксфильтрация в Discord", "value": "Да" if "RC_ATTACH_DISCORD_EXFIL" in state.reason_codes else "Нет"},
                {"label": "Обфускация JS", "value": "Да" if state.script_obfuscation_detected else "Нет"},
                {"label": "iframe / favicon", "value": f"{len(page.get('iframes') or [])} / {page.get('favicon') or '—'}"},
                {"label": "Структурный хеш DOM", "value": state.dom_structural_hash or "—"}
            ],
            state_delta={
                "triggered_codes": added_codes,
                "script_obfuscation": state.script_obfuscation_detected,
                "dom_structural_hash": state.dom_structural_hash
            }
        ))
        return state
