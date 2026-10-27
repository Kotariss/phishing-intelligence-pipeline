import collections
import io
import json
import os
import sys
import zipfile

import requests
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backend  # noqa: E402
import render  # noqa: E402

st.set_page_config(page_title="Phishing Intelligence Pipeline", page_icon="🛡️", layout="wide")
MODE_NAMES = {"api": "Worker API", "local": "локальный", "none": "Worker API недоступен"}


@st.cache_data(ttl=60, show_spinner=False)
def catalogue():
    return backend.reason_catalogue()


def show_result(result):
    st.session_state["last_result"] = result
    render.render_result(result, catalogue())


# ==============================================================================================
def page_analyze():
    st.title("Проверка объекта")
    st.caption("Образец анализируется в изолированной песочнице агентами LangGraph; ниже — что именно нашла программа.")

    src_dataset, src_file, src_page, src_url = st.tabs(
        ["Образец из датасета", "Файл (EML, HTML, PDF, Office, изображение)", "Сохранённая страница", "URL"])
    result = None

    with src_dataset:
        kind = st.segmented_control("Источник", ["Письма брендов (keis2)", "HTML-вложения", "Изображения-приманки",
                                                 "Тестовый набор EML (540)"], default="Письма брендов (keis2)")
        if kind == "Письма брендов (keis2)":
            brands = backend.dataset_brands()
            if not brands:
                st.warning("Каталог file_for_case/keis2 не найден.")
            else:
                c1, c2 = st.columns(2)
                brand = c1.selectbox("Бренд", brands, index=brands.index("Сбер") if "Сбер" in brands else 0)
                sample = c2.selectbox("Письмо", backend.dataset_samples(brand))
                st.caption("Письмо анализируется вместе с собранными для него артефактами ссылок "
                           "(цепочки перенаправлений, HTML и скриншоты страниц) — без обращения к живым фишинговым сайтам.")
                if st.button("Проверить письмо", type="primary"):
                    with st.spinner("Анализ..."):
                        result = backend.analyze_dataset_sample(f"keis2/{brand}/{sample}")
        elif kind:
            folder = {"HTML-вложения": "html_phishing2026", "Изображения-приманки": "grouped_png_phishing2026",
                      "Тестовый набор EML (540)": "antiphishing_eml_540_combined/eml"}[kind]
            files = backend.dataset_files(folder)
            if not files:
                st.warning(f"Каталог file_for_case/{folder} не найден.")
            else:
                name = st.selectbox("Файл", files)
                if st.button("Проверить файл", type="primary"):
                    with st.spinner("Анализ..."):
                        result = backend.analyze_file(os.path.basename(name), backend.read_dataset_file(folder, name))

    with src_file:
        up = st.file_uploader("Файл для анализа", accept_multiple_files=False)
        if st.button("Проверить файл", type="primary", key="btn_file", disabled=up is None):
            with st.spinner("Анализ..."):
                result = backend.analyze_file(up.name, up.getvalue())

    with src_page:
        st.caption("HTML-страница, сохранённая с адреса URL, и (по желанию) её снимок экрана — анализ без выхода в сеть.")
        url = st.text_input("Адрес, с которого сохранена страница", placeholder="https://example.com/login")
        c1, c2 = st.columns(2)
        html = c1.file_uploader("HTML страницы", type=["html", "htm"], key="snap_html")
        shot = c2.file_uploader("Снимок экрана (необязательно)", type=["png", "jpg", "jpeg"], key="snap_png")
        if st.button("Проверить страницу", type="primary", disabled=not (url and html)):
            with st.spinner("Анализ..."):
                result = backend.analyze_snapshot(url.strip(), html.getvalue(), shot.getvalue() if shot else None)

    with src_url:
        st.caption("Активное раскрытие ссылки выполняет только песочница с выходом в сеть (профиль `live-fetch` Docker Compose).")
        live = st.text_input("URL", placeholder="https://")
        if st.button("Проверить URL", type="primary", disabled=not live):
            with st.spinner("Анализ..."):
                result = backend.analyze_url(live.strip())

    if result is None:
        result = st.session_state.get("last_result")
        if result:
            st.divider()
            st.caption("Последний результат")
    else:
        st.divider()
    if result:
        show_result(result)


# ==============================================================================================
def page_knowledge_base():
    st.title("База знаний")
    stats = backend.kb_stats()
    cols = st.columns(5)
    for col, (label, key) in zip(cols, [("Объектов", "total_incidents"), ("Фишинг", "malicious_count"),
                                        ("Подозрительно", "suspicious_count"), ("Чисто", "clean_count"),
                                        ("Активных правил", "active_signatures")]):
        col.metric(label, stats.get(key, 0))

    incidents = backend.kb_incidents(limit=500)
    if not incidents:
        st.info("База знаний пуста. Проверьте объекты или выполните `python phishctl.py analyze-dir <каталог>`.")
        return
    cat = catalogue()

    st.subheader("Частота техник")
    freq = collections.Counter(c for i in incidents for c in (i.get("reason_codes") or []))
    if freq:
        st.bar_chart({(cat.get(c) or {}).get("description", c)[:60]: n for c, n in freq.most_common(15)}, horizontal=True)

    st.subheader("Объекты")
    c1, c2 = st.columns([1, 2])
    verdict = c1.selectbox("Вердикт", ["все", "MALICIOUS", "SUSPICIOUS", "CLEAN"])
    query = c2.text_input("Поиск по объекту / бренду", "")
    rows = [i for i in incidents if (verdict == "все" or i["verdict"] == verdict)
            and (not query or query.lower() in f"{i.get('raw_target')} {i.get('target_brand')}".lower())]
    table = [{"ID": i["id"], "Время": (i.get("created_at") or "")[:16].replace("T", " "),
              "Вердикт": render.VERDICT.get(i["verdict"], (i["verdict"],))[0], "Риск": round(i.get("risk_score") or 0, 2),
              "Бренд": i.get("target_brand") or "", "Находок": len(i.get("reason_codes") or []),
              "Кампания": i.get("campaign_id") or "", "Объект": str(i.get("raw_target", ""))[-80:]} for i in rows]
    event = st.dataframe(table, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row")
    selected = event.selection.rows if event and event.selection else []
    if selected:
        inc = backend.kb_incident(table[selected[0]]["ID"])
        if inc:
            st.divider()
            render.render_result(inc, cat)
    else:
        st.caption("Выберите строку, чтобы увидеть, что программа нашла в объекте.")


# ==============================================================================================
def page_campaigns():
    st.title("Кампании")
    st.caption("Объекты одного злоумышленника: общий phishing kit (остов DOM), Telegram-бот, домен приёма данных или вложение.")
    campaigns = backend.kb_campaigns()
    if not campaigns:
        st.info("Кампании появляются, когда хотя бы два объекта имеют общий отпечаток.")
        return
    cat = catalogue()
    for c in campaigns:
        with st.container(border=True):
            h, m = st.columns([4, 1])
            h.markdown(f"**{c['campaign_id']}** · бренды: {', '.join(c['brands']) or '—'}")
            m.metric("Объектов", c["incidents"])
            st.markdown("Техники: " + ", ".join((cat.get(x) or {}).get("description", x) for x in c["reason_codes"][:6]))
            if c.get("final_urls"):
                with st.expander(f"Страницы ({len(c['final_urls'])})"):
                    for u in c["final_urls"]:
                        st.text(u)
            st.caption(f"Первый: {(c.get('first_seen') or '')[:16]} · последний: {(c.get('last_seen') or '')[:16]} · "
                       f"объекты: {', '.join(c['incident_ids'][:8])}")


# ==============================================================================================
def page_package():
    st.title("Пакет правил для антиспам-движка")
    st.caption("Версионированный JSON: сигнатуры известного фишинга, обобщённые правила (проверены на легитимных объектах), "
               "признаки брендов, коды причин, YARA. Применяется лёгким модулем без тяжёлых экстракторов.")
    if st.button("Сформировать новую версию пакета", type="primary"):
        with st.spinner("Сборка пакета..."):
            st.session_state["package"] = backend.build_package()
    data = st.session_state.get("package")
    if not data:
        sigs = backend.kb_signatures()
        active = [s for s in sigs if s.get("status") == "ACTIVE_VERIFIED"]
        st.info(f"В базе {len(active)} проверенных правил из {len(sigs)}. Сформируйте пакет, чтобы увидеть вклад каждого правила.")
        return
    if data.get("error"):
        st.error(data["error"])
        return
    pkg = data["package"]
    s = pkg.get("statistics", {})
    c = st.columns(4)
    c[0].metric("Версия", data["version"])
    c[1].metric("Обобщённых правил", s.get("rules", 0))
    c[2].metric("Сигнатур известного фишинга", s.get("known_signatures", 0))
    c[3].metric("YARA", s.get("yara_rules", 0))
    pkg_json = json.dumps(pkg, ensure_ascii=False, indent=2)
    pkg_yara = "\n".join(pkg.get("yara") or [])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"package_v{data['version']}.json", pkg_json)
        zf.writestr(f"package_v{data['version']}.yar", pkg_yara)
    d = st.columns(3)
    d[0].download_button("Скачать пакет (JSON)", pkg_json, file_name=f"package_v{data['version']}.json", mime="application/json")
    d[1].download_button("Скачать YARA (.yar)", pkg_yara, file_name=f"package_v{data['version']}.yar", disabled=not pkg_yara)
    d[2].download_button("Скачать пакет (ZIP: JSON + YARA)", buf.getvalue(), file_name=f"package_v{data['version']}.zip",
                         mime="application/zip")

    contrib = pkg.get("rule_contribution") or {}
    st.subheader("Вклад правил в выявленные объекты")
    if contrib.get("rules"):
        st.caption(f"Пакет покрывает {contrib.get('covered_by_package', 0)} из {contrib.get('detected_objects_total', 0)} "
                   "объектов базы знаний с вердиктом «фишинг»/«подозрительно».")
        st.dataframe([{"Правило": r["rule_id"], "Вид": r["kind"], "Бренд": r["target_brand"],
                       "Выявляет объектов": r["detected_objects"], "Только этим правилом": r["unique_objects"],
                       "Срабатываний на чистых": r["clean_objects_matched"]} for r in contrib["rules"]],
                     hide_index=True, width="stretch")
    st.subheader("Правила")
    for rule in pkg.get("rules", []):
        with st.container(border=True):
            render.render_rule(rule, "ACTIVE_VERIFIED")
            st.caption("Получено из: " + ", ".join(rule.get("provenance", {}).get("incidents", [])[:6]))
    known = pkg.get("known_phishing_signatures", {})
    with st.expander("Сигнатуры известного фишинга"):
        for key, title in (("domains", "Домены"), ("urls_masked", "URL (токены скрыты)"),
                           ("attachment_sha256", "SHA-256 вложений"), ("dom_structural_hashes", "Остовы DOM")):
            if known.get(key):
                st.markdown(f"**{title}**")
                st.dataframe(known[key], hide_index=True, width="stretch")


# ==============================================================================================
def _acceptance_table(rows):
    st.dataframe([{"Критерий": r[0], "Цель": r[1], "Результат": r[2], "": "✅" if r[3] else "❌"} for r in rows],
                 hide_index=True, width="stretch")


# Which saved reports the page shows is data, not code: reports/index.json names them with a label and a note
# (model, code version), see docs/METRICS.md. Without the index the default file names of the CLI are used.
DEFAULT_REPORTS = {
    "labeled": [{"path": "labeled_eval_off/summary.json", "label": "Без LLM"},
                {"path": "labeled_eval_llm/summary.json", "label": "С LLM"}],
    "corpus": [{"path": "metrics.json", "label": "Корпус Заказчика"}],
    "robustness": [{"path": "robustness.json", "label": "Устойчивость к обходу"}],
}
ACCEPTANCE_NAMES = {
    "processing_completeness": "Полнота обработки",
    "recall_template_split": "Recall «фишинг + подозрительно» (по DOM-шаблонам)",
    "benign_false_phishing": "«Фишинг» на легитимных",
    "benign_suspicious_share": "«Подозрительно» на легитимных",
}


def _reports(kind):
    index = backend.load_report("index.json") or DEFAULT_REPORTS
    out = []
    for entry in index.get(kind, []):
        report = backend.load_report(entry["path"])
        if report:
            out.append((entry, report))
    return out


def _report_heading(entry, extra=""):
    st.markdown(f"**{entry['label']}**" + (f" — {extra}" if extra else ""))
    if entry.get("note"):
        st.caption(entry["note"])


def page_metrics():
    st.title("Метрики качества")
    st.caption("Отчёты формируются командами `phishctl.py metrics`, `eval-labeled`, `robustness` (см. docs/METRICS.md).")

    corpus = _reports("corpus")
    if corpus:
        st.subheader("Корпус Заказчика")
        for entry, r in corpus:
            part = {"test": "отложенная часть", "dev": "часть для настройки"}.get((r.get("split") or {}).get("part"), "")
            _report_heading(entry, f"{r['counts']['phishing']} фишинговых и {r['counts']['benign']} легитимных объектов"
                                   + (f", {part}" if part else "") + f" · {r['generated_at'][:10]}")
            _acceptance_table([(ACCEPTANCE_NAMES.get(k, k), v["target"], v["actual"], v["passed"])
                               for k, v in r["acceptance"].items()])
        entry, r = corpus[0]
        with st.expander(f"Разрез по источникам ({entry['label']})"):
            st.dataframe([{"Источник": k, "Объектов": v["objects"], **v["verdicts"], "с/объект": v["mean_seconds"]}
                          for k, v in r["per_category"].items()], hide_index=True, width="stretch")
        if r.get("rule_contribution"):
            with st.expander(f"Вклад правил ({entry['label']})"):
                st.dataframe(r["rule_contribution"][:50], hide_index=True, width="stretch")

    labeled = _reports("labeled")
    if labeled:
        st.subheader("Размеченный тестовый набор EML")
        for entry, r in labeled:
            _report_heading(entry, f"{r['objects']} писем")
            _acceptance_table([
                ("Recall «фишинг + подозрительно»", "≥ 0.90", r["recall_phishing_plus_suspicious"],
                 (r["recall_phishing_plus_suspicious"] or 0) >= 0.9),
                ("«Фишинг» на легитимных", "0", r["benign_false_phishing"], r["benign_false_phishing"] == 0),
                ("«Подозрительно» на легитимных", "≤ 10 %", f"{(r['benign_suspicious_share'] or 0):.1%}",
                 (r["benign_suspicious_share"] or 0) <= 0.1),
                ("Ошибки обработки", "0", r["errors"], r["errors"] == 0),
            ])

    robust = _reports("robustness")
    if robust:
        st.subheader("Устойчивость к обходу")
        names = {"domain_url_change": "Замена домена и URL", "design_change": "Изменение оформления",
                 "delayed_loading": "Отложенная загрузка"}
        for entry, r in robust:
            _report_heading(entry, (r.get("generated_at") or "")[:10])
            st.dataframe([{"Сценарий": names.get(k, k), "Объектов": v["objects"], "Recall": v["recall"],
                           "Падение recall": v["recall_drop"]} for k, v in r["scenarios"].items()],
                         hide_index=True, width="stretch")
    if not (labeled or corpus or robust):
        st.info("Отчёты ещё не сформированы.")


# ==============================================================================================
nav = st.navigation([
    st.Page(page_analyze, title="Проверка объекта", icon="🔍", default=True),
    st.Page(page_knowledge_base, title="База знаний", icon="🗂️"),
    st.Page(page_campaigns, title="Кампании", icon="🕸️"),
    st.Page(page_package, title="Пакет правил", icon="📦"),
    st.Page(page_metrics, title="Метрики", icon="📈"),
])
mode = backend.mode()
with st.sidebar:
    h = backend.health()
    st.caption(f"Режим: {MODE_NAMES[mode]} · модель: {h.get('llm_mode', '—')} ({h.get('llm_model') or '—'})")
    if h and not h.get("llm_ready", True):
        st.warning(f"Модель не настроена: {h.get('llm_problem')}")
try:
    nav.run()
except (ImportError, requests.RequestException) as e:
    # The UI container has no pipeline code of its own: without the worker it can only show saved reports.
    st.error(f"Нет связи с Worker API ({backend.WORKER_API}): {type(e).__name__}. "
             "Проверьте, что запущен сервис worker (`docker compose ps`).")
