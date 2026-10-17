import os
import re
import time
from typing import Any, Dict, List

try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
    from ..features.url_features import hostname, qr_payload_url
    from ..features.file_names import DOUBLE_EXT_PATTERN
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from features.url_features import hostname, qr_payload_url
    from features.file_names import DOUBLE_EXT_PATTERN


# Indicators of specific known campaigns (file names, hashes) are not detection logic: they come from the
# knowledge base as signatures of known phishing and are excluded from recall (ТЗ табл. 3, BACKLOG п. 1, A1).


class QuishingAgent:
    """Specialist agent for attachments: QR-phishing, double extensions, HTML attachments,
    macros, remote templates, executables inside archives, PDF active content."""

    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        state.execution_steps.append("quishing_agent: Inspecting attachments and QR codes")

        att = state.attachment_evidence or {}
        # Items to inspect: nested e-mail attachments, or the uploaded file itself.
        items: List[Dict[str, Any]] = list(att.get("attachments_analysis") or [])
        if att and att.get("type") in ("html", "pdf", "office", "image", "archive"):
            own = dict(att)
            own.setdefault("filename", os.path.basename(str(state.raw_target)))
            own["kind"] = att.get("type")
            items.append(own)

        names = [os.path.basename(str(state.raw_target))] + [i.get("filename") or "" for i in items]
        names += [m.get("filename") or "" for m in att.get("attachments_meta") or []]
        for name in dict.fromkeys(n for n in names if n):
            if DOUBLE_EXT_PATTERN.search(name):
                state.add_reason("RC_LURE_DOUBLE_EXTENSION", f"Файл «{name}» маскирует тип двойным расширением", {"type": "file", "value": name, "label": "Имя файла"})

        qr_urls = sorted({q for i in items for q in (i.get("qr_codes") or [])} | set(att.get("qr_codes") or []))
        qr_http = list(dict.fromkeys(u for u in map(qr_payload_url, qr_urls) if u))
        if qr_http:
            state.add_reason("ATTACH_QR_CODE_FOUND", f"QR-код ведёт на {qr_http[0][:150]}", {"type": "url", "value": qr_http[0], "label": "URL из QR-кода"})
            for q in qr_http:
                if q not in state.discovered_urls_from_attachments:
                    state.discovered_urls_from_attachments.append(q)

        for item in items:
            name = item.get("filename") or "вложение"
            kind = item.get("kind")
            if item.get("has_vba_macros"):
                state.add_reason("ATTACH_ACTIVE_MACRO_MARKER", f"{name}: VBA-макросы", {"type": "file", "value": name, "label": "Документ с макросами"})
            if item.get("has_remote_template"):
                state.add_reason("ATTACH_REMOTE_TEMPLATE", f"{name}: удалённый шаблон/OLE", {"type": "file", "value": name, "label": "Документ"})
            if kind == "pdf" and (item.get("has_javascript") or item.get("has_launch_action") or item.get("has_embedded_payload")):
                active = [what for what, on in (("JavaScript", item.get("has_javascript")), ("Launch", item.get("has_launch_action")),
                                                ("встроенный файл " + ", ".join(item.get("embedded_files") or [])[:120],
                                                 item.get("has_embedded_payload"))) if on]
                state.add_reason("ATTACH_PDF_ACTIVE_CONTENT", f"{name}: {'; '.join(active)} в PDF", {"type": "file", "value": name, "label": "PDF"})
            if item.get("is_executable"):
                state.add_reason("ATTACH_EXECUTABLE", f"{name}: исполняемый файл" + (" в архиве" if kind == "archive" else ""),
                                 {"type": "file", "value": ", ".join([name] + [n for n in item.get("archive_entries") or [] if n.lower().endswith((".exe", ".scr", ".js", ".vbs", ".lnk", ".iso", ".msi", ".bat", ".hta"))][:5]), "label": "Исполняемое содержимое"})
            if kind == "html":
                card_form = any(f.get("has_card") for f in item.get("forms") or [])
                if item.get("has_password_field") or card_form:
                    what = "поле пароля" if item.get("has_password_field") else "поля банковской карты"
                    state.add_reason("ATTACH_OFFLINE_FORM", f"{name}: HTML-вложение запрашивает {what}",
                                     {"type": "dom", "value": next((f.get("snippet", "") for f in item.get("forms") or [] if f.get("has_password") or f.get("has_card")), (item.get("evidence_snippets") or {}).get("password_input", "")), "label": f"Форма во вложении {name}"})
                redirect = item.get("meta_refresh") or next(iter(item.get("js_redirects") or []), "")
                if redirect and redirect.lower().startswith("http"):
                    state.add_reason("ATTACH_HTML_REDIRECTOR", f"{name}: перенаправляет на {hostname(redirect)}",
                                     {"type": "dom", "value": (item.get("evidence_snippets") or {}).get("meta_refresh") or (item.get("evidence_snippets") or {}).get("js_redirect") or redirect, "label": "Перенаправление во вложении"})
                    if redirect not in state.discovered_urls_from_attachments:
                        state.discovered_urls_from_attachments.append(redirect)
                if item.get("has_telegram_exfil"):
                    state.add_reason("RC_ATTACH_TELEGRAM_EXFIL", f"{name}: отправка в Telegram Bot API", {"type": "dom", "value": (item.get("evidence_snippets") or {}).get("telegram", ""), "label": "Вызов Telegram Bot API"})
                if item.get("has_discord_exfil"):
                    state.add_reason("RC_ATTACH_DISCORD_EXFIL", f"{name}: отправка в Discord Webhook", {"type": "dom", "value": (item.get("evidence_snippets") or {}).get("discord", ""), "label": "Вызов Discord Webhook"})

        # E-mail level signals
        if att.get("type") == "eml":
            if att.get("reply_to_mismatch"):
                state.add_reason("EMAIL_REPLY_TO_MISMATCH", f"From: {att.get('from_domain')} → Reply-To: {att.get('reply_to_domain')}", {"type": "header", "value": f"From: {att.get('from_address')}\nReply-To: {att.get('reply_to')}", "label": "Заголовки письма"})
            if att.get("spf_fail") or att.get("dmarc_fail"):
                state.add_reason("EMAIL_AUTH_FAIL", "SPF/DMARC fail в Authentication-Results", {"type": "header", "value": att.get("auth_results_raw", ""), "label": "Authentication-Results"})
            mismatches = att.get("link_text_mismatch") or []
            if mismatches:
                m = mismatches[0]
                state.add_reason("EMAIL_LINK_TEXT_MISMATCH", f"Текст «{m['shown'][:60]}» → {hostname(m['href'])}",
                             {"type": "url", "value": f"показано: {m['shown'][:100]}\nведёт на: {m['href']}", "label": "Подмена текста ссылки"})

        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        state.agent_traces.append(AgentStepTrace(
            agent_id="quishing_agent",
            agent_name="Quishing & Attachment Specialist Agent",
            icon="📦",
            phase="Phase 5: Attachment, QR & E-mail Header Analysis",
            status="TRIGGERED" if added_codes else ("COMPLETED" if items or att else "SKIPPED"),
            duration_ms=elapsed_ms,
            reasoning=f"Инспекция {len(items)} вложений (рекурсивно из письма) и заголовков: QR-коды (quishing), двойные расширения, HTML-вложения с формами/редиректами, VBA-макросы, удалённые шаблоны, активный контент PDF, исполняемые файлы в архивах, Reply-To/SPF/DMARC, подмена текста ссылок.",
            decision=f"Выявлено признаков: {len(added_codes)} шт. " + (f"[{', '.join(added_codes)}]" if added_codes else "[Признаков вредоносных вложений не обнаружено]"),
            tools_called=["QRCodeDecoder", "DoubleExtensionDetector", "OfficeMacroInspector", "PDFActiveContentInspector", "EmailHeaderAnalyzer"],
            findings=[
                {"label": "Вложений проанализировано", "value": str(len(items))},
                {"label": "QR-кодов со ссылками", "value": str(len(qr_http))},
                {"label": "Двойное расширение", "value": "Да" if "RC_LURE_DOUBLE_EXTENSION" in state.reason_codes else "Нет"},
                {"label": "HTML-вложение с формой", "value": "Да" if "ATTACH_OFFLINE_FORM" in state.reason_codes else "Нет"},
                {"label": "Макросы / удалённый шаблон", "value": "Да" if {"ATTACH_ACTIVE_MACRO_MARKER", "ATTACH_REMOTE_TEMPLATE"} & set(state.reason_codes) else "Нет"},
            ],
            state_delta={
                "triggered_codes": added_codes,
                "discovered_urls_count": len(state.discovered_urls_from_attachments)
            }
        ))
        return state
