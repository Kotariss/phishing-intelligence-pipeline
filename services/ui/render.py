"""Rendering of an analysis result: what the pipeline found, why, and the supporting evidence."""
import base64
import io
import json
from typing import Any, Dict, List, Optional

import streamlit as st

VERDICT = {
    "MALICIOUS": ("Фишинг", "red", "🔴"),
    "SUSPICIOUS": ("Подозрительно", "orange", "🟠"),
    "CLEAN": ("Признаков фишинга не обнаружено", "green", "🟢"),
}
SEVERITY = {"critical": ("критично", "red"), "high": ("высокая", "orange"), "medium": ("средняя", "blue"),
            "low": ("низкая", "gray"), "info": ("инфо", "gray")}
CATEGORY = {
    "combo": "Сочетание улик", "brand": "Имитация бренда", "dom": "Страница: формы и сценарии",
    "attachment": "Вложения", "email": "Письмо", "network": "Ссылки и перенаправления",
    "content": "Текст и изображение (LLM / VLM)", "campaign": "Известные кампании", "info": "Справочно",
}
CATEGORY_ORDER = ["combo", "brand", "dom", "attachment", "email", "network", "content", "campaign", "info"]
SOURCE_RU = {"display_name": "имя отправителя", "title": "заголовок страницы", "vlm": "распознавание скриншота (VLM)",
             "lookalike_domain": "домен-двойник", "body_text": "текст", "official_domain": "официальный домен"}


# ------------------------------------------------------------------------------ helpers
def _image_bytes(b64: Optional[str]) -> Optional[bytes]:
    if not b64:
        return None
    try:
        return base64.b64decode(b64.split("base64,")[-1])
    except (ValueError, TypeError):
        return None


def screenshot_with_box(b64: Optional[str], box: Optional[List[float]]) -> Optional[bytes]:
    """Draws the VLM logo region on the screenshot."""
    raw = _image_bytes(b64)
    if not raw:
        return None
    if not box:
        return raw
    try:
        from PIL import Image, ImageDraw
        img = Image.open(io.BytesIO(raw)).convert("RGB")
        w, h = img.size
        x1, y1, x2, y2 = box[0] * w, box[1] * h, box[2] * w, box[3] * h
        draw = ImageDraw.Draw(img)
        for i in range(4):
            draw.rectangle([x1 - i, y1 - i, x2 + i, y2 + i], outline=(230, 30, 30))
        out = io.BytesIO()
        img.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return raw


def _explanation_parts(text: Optional[str]):
    """Splits the stored explanation into the LLM analyst summary (if any) and the deterministic part."""
    if not text:
        return None, None
    if text.startswith("Вердикт:"):
        return None, text
    head, _, rest = text.partition("\n\nВердикт:")
    return head.strip(), ("Вердикт:" + rest) if rest else None


# ------------------------------------------------------------------------------ rules in plain language
def humanize_condition(c: Dict[str, Any]) -> str:
    t = c.get("type")
    if t == "brand_mismatch":
        doms = ", ".join(p.replace("^([a-z0-9-]+\\.)*", "").replace("\\.", ".").rstrip("$") for p in c.get("allowed_domain_patterns", [])[:4])
        where = "имени отправителя" if c.get("scope") == "sender" else "заголовке страницы"
        alt = [k for k in c.get("keywords", []) if k.lower() != str(c.get("brand", "")).lower()][:3]
        alt_text = f" (или {', '.join(alt)})" if alt else ""
        return f"в {where} есть «{c.get('brand')}»{alt_text}, а домен не из официальных ({doms})"
    if t == "host_brand_token":
        return f"домен содержит «{c.get('token')}», но не принадлежит бренду"
    if t == "dom_form_structure":
        parts = []
        if c.get("has_password_input"):
            parts.append("полем пароля")
        if c.get("has_card_input"):
            parts.append("полями банковской карты")
        text = "на странице есть форма с " + " и ".join(parts or ["полями ввода"])
        return text + (", отправляющая данные на сторонний домен" if c.get("action_is_external") else "")
    if t == "url_path_pattern":
        return f"путь URL соответствует шаблону `{c.get('regex')}`"
    if t == "dom_structural_hash":
        return f"структура страницы (остов DOM) совпадает с `{c.get('hash')}`"
    if t == "exfil_endpoint":
        kind, value = c.get("kind"), c.get("value")
        return {"telegram": f"данные отправляются Telegram-боту `{value}`",
                "discord": f"данные отправляются в Discord-вебхук `{value}`"}.get(kind, f"данные уходят на домен `{value}`")
    if t == "attachment_name_pattern":
        return f"имя вложения соответствует шаблону `{c.get('regex')}`"
    if t == "attachment_html_feature":
        return {"password_input": "HTML-вложение содержит форму ввода пароля или карты",
                "external_redirect": "HTML-вложение перенаправляет на внешний сайт"}.get(c.get("feature"), str(c))
    if t == "title_keyword":
        return f"заголовок содержит {', '.join(c.get('keywords', [])[:3])}"
    if t == "reply_to_mismatch":
        return "адрес для ответа (Reply-To) на другом домене, чем отправитель"
    return json.dumps(c, ensure_ascii=False)


def render_rule(rule: Dict[str, Any], status: Optional[str] = None):
    preds = rule.get("predicates") or {}
    all_of, any_of = preds.get("all_of") or [], preds.get("any_of") or []
    st.markdown(f"**{rule.get('rule_id')}** · вид: `{rule.get('kind')}` · бренд: {rule.get('target_brand')}")
    lines = []
    if all_of:
        lines.append("Правило срабатывает, если **одновременно**:")
        lines += [f"- {humanize_condition(c)}" for c in all_of]
    if any_of:
        lines.append(("и **хотя бы одно** из:" if all_of else "Правило срабатывает, если **хотя бы одно** из:"))
        lines += [f"- {humanize_condition(c)}" for c in any_of]
    st.markdown("\n".join(lines))
    vm = rule.get("validation_metrics") or {}
    verdict = (rule.get("verdict") or {}).get("action")
    if status == "ACTIVE_VERIFIED" or vm.get("zero_fpr_verified"):
        st.success(f"Проверено на {vm.get('benign_samples_tested', '?')} легитимных объектах: 0 срабатываний. "
                   f"Срабатывает на исходном образце. Действие: {verdict}.", icon="✅")
    elif vm:
        st.warning(f"Черновик, в пакет не включено: {vm.get('note', '')}", icon="📝")


# ------------------------------------------------------------------------------ evidence
def render_evidence(ev: Optional[Dict[str, Any]], result: Dict[str, Any]):
    if not ev:
        return
    t, label = ev.get("type"), ev.get("label") or "Улика"
    if t == "dom":
        st.caption(f"Улика — {label}")
        st.code(ev.get("value", ""), language="html", wrap_lines=True)
    elif t in ("url", "file", "header"):
        st.caption(f"Улика — {label}")
        st.code(ev.get("value", ""), language="text", wrap_lines=True)
    elif t == "chain":
        st.caption(f"Улика — {label}")
        steps = [u for u in ev.get("value") or [] if u]
        st.code("\n".join(f"{i}. {u}" for i, u in enumerate(steps, 1)), language="text", wrap_lines=True)
    elif t == "text":
        st.caption(f"Улика — {label}")
        st.markdown(ev.get("value", ""))
    elif t == "image_region":
        img = screenshot_with_box(result.get("screenshot_base64"), ev.get("box"))
        st.caption(f"Улика — {label}" + ("" if ev.get("box") else " (модель не указала область логотипа)"))
        if img:
            st.image(img, width=520)
        elif result.get("from_knowledge_base"):
            st.caption("Снимок экрана не хранится в базе знаний; повторите анализ, чтобы увидеть изображение.")


def render_findings(result: Dict[str, Any], catalogue: Dict[str, Any]):
    codes = result.get("reason_codes") or []
    if not codes:
        st.info("Программа не нашла признаков фишинговых техник.")
        return
    details = result.get("reason_details") or {}
    evidence = result.get("reason_evidence") or {}
    by_cat: Dict[str, List[str]] = {}
    for code in codes:
        by_cat.setdefault((catalogue.get(code) or {}).get("category", "info"), []).append(code)
    for cat in CATEGORY_ORDER + [c for c in by_cat if c not in CATEGORY_ORDER]:
        if cat not in by_cat:
            continue
        st.markdown(f"##### {CATEGORY.get(cat, cat)}")
        for code in sorted(by_cat[cat], key=lambda c: -(catalogue.get(c) or {}).get("weight", 0)):
            info = catalogue.get(code) or {}
            sev_ru, sev_color = SEVERITY.get(info.get("severity", "info"), ("—", "gray"))
            with st.container(border=True):
                head, badges = st.columns([4, 2])
                head.markdown(f"**{info.get('description', code)}**")
                badges.markdown(f":{sev_color}-badge[{sev_ru}] :gray-badge[вес {info.get('weight', 0):.2f}] :gray-badge[{code}]")
                if details.get(code):
                    st.markdown(f"Найдено: {details[code]}")
                render_evidence(evidence.get(code), result)


# ------------------------------------------------------------------------------ object overview
def render_object(result: Dict[str, Any]):
    att = result.get("attachment_evidence") or {}
    page = result.get("page_features") or {}
    left, right = st.columns([3, 2])
    with left:
        if att.get("type") == "eml":
            st.markdown("**Письмо**")
            st.code("\n".join(filter(None, [
                f"From: {att.get('from_name', '')} <{att.get('from_address', '')}>",
                f"Reply-To: {att.get('reply_to')}" if att.get("reply_to") else "",
                f"Subject: {att.get('subject', '')}",
                f"SPF: {'pass' if att.get('spf_pass') else ('fail' if att.get('spf_fail') else 'нет данных')}"
                f" · DKIM: {'pass' if att.get('dkim_pass') else 'нет данных'}"
                f" · DMARC: {'fail' if att.get('dmarc_fail') else 'нет fail'}",
            ])), language="text", wrap_lines=True)
            links = att.get("links") or []
            if links:
                with st.expander(f"Ссылки в письме: {len(links)}"):
                    for u in links[:60]:
                        st.text(u)
            items = att.get("attachments_analysis") or []
            if items:
                st.markdown("**Вложения**")
                st.dataframe([{"Файл": i.get("filename"), "Тип": i.get("kind"), "Размер": i.get("size"),
                               "Ссылок": len(i.get("links") or []), "QR": len(i.get("qr_codes") or []),
                               "Пароль/карта": "да" if i.get("has_password_field") or any(f.get("has_card") for f in i.get("forms") or []) else ""}
                              for i in items], hide_index=True, use_container_width=True)
        elif att.get("type") in ("html", "pdf", "office", "image", "archive"):
            st.markdown(f"**Файл:** `{result.get('raw_target')}` (тип: {att.get('type')})")
        chain = [h.get("url") for h in result.get("redirect_chain") or [] if h.get("url")]
        if result.get("final_url"):
            st.markdown("**Ссылка → итоговая страница**")
            st.code("\n".join(f"{i}. {u}" for i, u in enumerate(chain + [result["final_url"]], 1)), language="text", wrap_lines=True)
        if page.get("title") or page.get("forms_count"):
            st.markdown(f"**Страница:** «{page.get('title', '')}» · форм: {page.get('forms_count', 0)}"
                        f" · iframe: {len(page.get('iframes') or [])} · внешних скриптов: {len(page.get('external_scripts') or [])}")
        forms = result.get("dom_forms") or []
        if forms:
            st.dataframe([{"Источник": "вложение" if f.get("origin") == "attachment" else "страница",
                           "Отправка на": f.get("action_host") or f.get("action") or "(та же страница)",
                           "Пароль": "да" if f.get("has_password") else "", "Карта": "да" if f.get("has_card") else "",
                           "Сторонний домен": "да" if f.get("is_external_target") else ""} for f in forms],
                         hide_index=True, use_container_width=True)
    with right:
        box = (result.get("brand_evidence") or {}).get("logo_box")
        img = screenshot_with_box(result.get("screenshot_base64"), box)
        if img:
            src = {"browser": "снимок песочницы", "dataset": "снимок из датасета", "attachment_render": "рендер вложения",
                   "image_file": "изображение-вложение", "embedded_image": "изображение из HTML"}.get(result.get("screenshot_source"), "")
            st.image(img, caption=src + (" · красная рамка — логотип по VLM" if box else ""), use_container_width=True)


def render_brand(result: Dict[str, Any]):
    b = result.get("brand_evidence") or {}
    if not b.get("detected_brand_name"):
        st.caption("Бренд не определён.")
        return
    status = "имитация подтверждена" if b.get("brand_impersonation_confirmed") else (
        "официальный домен бренда" if b.get("is_domain_in_allowlist") else "подмена не подтверждена")
    st.markdown(f"**{b['detected_brand_name']}** — определён по: {SOURCE_RU.get(b.get('detection_source'), b.get('detection_source'))}; {status}.")
    if b.get("impersonation_reason"):
        st.caption(b["impersonation_reason"])


def render_artifacts(result: Dict[str, Any]):
    rule, yara = result.get("generated_l_signature"), result.get("generated_yara_rule")
    fp = result.get("fingerprints") or {}
    if rule:
        render_rule(rule, result.get("signature_status"))
        c1, c2 = st.columns(2)
        c1.download_button("Скачать правило (.json)", json.dumps(rule, ensure_ascii=False, indent=2),
                           file_name=f"{rule.get('rule_id', 'rule')}.json", mime="application/json")
        if yara:
            c2.download_button("Скачать YARA (.yar)", yara, file_name=f"{rule.get('rule_id', 'rule')}.yar")
        with st.expander("Правило в формате JSON (lar-rule-v1)"):
            st.json(rule)
        if yara:
            with st.expander("YARA-правило"):
                st.code(yara, language="c")
    else:
        st.caption("Правило не сформировано: признаков фишинга нет или улики не обобщаются в правило без ложных срабатываний.")
    if fp:
        names = {"dom_structural_hash": "Остов DOM", "screenshot_dhash": "Перцептивный хеш скриншота",
                 "telegram_bot_ids": "Telegram-бот", "discord_webhooks": "Discord-вебхук", "credential_post_domain": "Домен приёма данных",
                 "attachment_sha256": "SHA-256 вложения", "final_domain": "Домен страницы", "favicon": "Favicon",
                 "sender_domain": "Домен отправителя", "dom_tags_count": "Тегов в DOM"}
        st.markdown("**Отпечатки**" + (f" · кампания `{result['campaign_id']}`" if result.get("campaign_id") else ""))
        st.dataframe([{"Отпечаток": names.get(k, k), "Значение": ", ".join(map(str, v)) if isinstance(v, list) else str(v)}
                      for k, v in fp.items()], hide_index=True, use_container_width=True)


def render_traces(result: Dict[str, Any]):
    traces = result.get("agent_traces") or []
    if not traces:
        return
    st.dataframe([{"Агент": t.get("agent_name"), "Итог": {"TRIGGERED": "нашёл признаки", "WARNING": "внимание",
                                                            "SKIPPED": "пропущен", "CLEAN": "чисто"}.get(t.get("status"), "выполнен"),
                   "Решение": t.get("decision"), "мс": round(t.get("duration_ms") or 0)} for t in traces],
                 hide_index=True, use_container_width=True)
    llm = [t for t in traces if t.get("llm_audit")]
    for t in llm:
        a = t["llm_audit"]
        with st.expander(f"Обращение к модели: {t.get('agent_name')} · {a.get('model')} · {a.get('elapsed_seconds', 0):.1f} с"):
            st.markdown("**Промпт**")
            st.code(a.get("prompt", ""), language="text", wrap_lines=True)
            st.markdown("**Ответ**")
            st.code(a.get("response", ""), language="text", wrap_lines=True)


# ------------------------------------------------------------------------------ full result
def render_result(result: Dict[str, Any], catalogue: Dict[str, Any]):
    if result.get("error") and not result.get("verdict"):
        st.error(result["error"])
        return
    verdict = result.get("verdict", "CLEAN")
    title, color, icon = VERDICT.get(verdict, (verdict, "gray", "⚪"))
    risk = float(result.get("risk_score") or 0)
    codes = result.get("reason_codes") or []
    top = sorted(codes, key=lambda c: -(catalogue.get(c) or {}).get("weight", 0))[:3]

    with st.container(border=True):
        c1, c2, c3 = st.columns([3, 1, 1])
        c1.markdown(f"## {icon} :{color}[{title}]")
        c1.caption(f"Объект: {result.get('raw_target')}")
        c2.metric("Риск", f"{risk:.2f}")
        c3.metric("Находок", len(codes))
        st.progress(min(risk, 1.0))
        if top:
            st.markdown("**Главное:** " + "; ".join((catalogue.get(c) or {}).get("description", c) for c in top) + ".")

    summary, _ = _explanation_parts(result.get("explanation"))
    if summary:
        with st.container(border=True):
            st.markdown("**Заключение аналитика (LLM)**")
            st.markdown(summary)

    tab_found, tab_object, tab_rules, tab_agents = st.tabs(
        [f"Что найдено ({len(codes)})", "Объект", "Правила и отпечатки", "Работа агентов"])
    with tab_found:
        render_findings(result, catalogue)
    with tab_object:
        render_brand(result)
        render_object(result)
    with tab_rules:
        render_artifacts(result)
    with tab_agents:
        render_traces(result)
