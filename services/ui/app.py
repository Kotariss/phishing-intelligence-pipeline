import base64
import collections
import io
import json
import os
import sys
import uuid
import zipfile

import requests
import streamlit as st

st.set_page_config(
    page_title="Phishing Intelligence Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ------------------------------------------------------------------------------ paths
_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(_HERE, "file_for_case")):
    ROOT_DIR = _HERE
else:
    ROOT_DIR = os.environ.get("ROOT_DIR", os.path.abspath(os.path.join(_HERE, "..", "..")))

WORKER_SRC = os.path.join(ROOT_DIR, "services", "worker", "src")
SANDBOX_SRC = os.path.join(ROOT_DIR, "services", "sandbox", "src")
FIXTURES = os.path.join(ROOT_DIR, "tests", "fixtures")
for _p in (WORKER_SRC, SANDBOX_SRC, FIXTURES):
    if os.path.exists(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

WORKER_API = f"http://{os.getenv('WORKER_HOST', 'localhost')}:{os.getenv('WORKER_PORT', '8000')}"
DATASET = os.path.join(ROOT_DIR, "file_for_case")
REPORTS = os.path.join(ROOT_DIR, "reports")
EXPORTS = os.path.join(ROOT_DIR, "exports")

VERDICT_RU = {"MALICIOUS": "ФИШИНГ", "SUSPICIOUS": "ПОДОЗРИТЕЛЬНО", "CLEAN": "ПРИЗНАКОВ ФИШИНГА НЕ ОБНАРУЖЕНО"}


# --------------------------------------------------------------------------- backend
def _worker_alive() -> bool:
    try:
        return requests.get(f"{WORKER_API}/health", timeout=1.5).status_code == 200
    except requests.RequestException:
        return False


def _local_available() -> bool:
    return os.path.isdir(WORKER_SRC)


def run_local(state) -> dict:
    from orchestrator.graph import run_pipeline
    return run_pipeline(state).public_dump()


def analyze_url(url: str) -> dict:
    if _worker_alive():
        resp = requests.post(f"{WORKER_API}/api/v1/scan", data={"url": url}, timeout=180)
        if resp.status_code == 200:
            return resp.json()
        return {"error": resp.text[:500]}
    from orchestrator.state import PhishingState
    return run_local(PhishingState(incident_id=f"ui_{uuid.uuid4().hex[:8]}", source_type="url", raw_target=url))


def analyze_file(name: str, data: bytes) -> dict:
    if _worker_alive():
        resp = requests.post(f"{WORKER_API}/api/v1/scan", files={"file": (name, data)}, timeout=180)
        if resp.status_code == 200:
            return resp.json()
        return {"error": resp.text[:500]}
    from orchestrator.state import PhishingState
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else "bin"
    return run_local(PhishingState(incident_id=f"ui_{uuid.uuid4().hex[:8]}", source_type=ext, raw_target=name, raw_bytes=data))


def reason_catalogue() -> dict:
    try:
        from rules.reason_codes import REASON_CODES
        return REASON_CODES
    except ImportError:
        return {}


# ------------------------------------------------------------------------- demo cases
def demo_spec(choice: str):
    """Demo cases run OFFLINE on pre-collected artefacts (no visits to live phishing infrastructure)."""
    if choice.startswith("1"):
        return {"type": "sample", "path": "keis2/Adobe/bfc7879dc6f69c94cc86b74f3158ee30033bd12f"}
    if choice.startswith("2"):
        return {"type": "sample", "path": "keis2/Сбер/2a5b3ccfd50b3a4c7223fd5eec48e7a00a116c86"}
    if choice.startswith("3"):
        from helpers_demo import TELEGRAM_KIT
        return {"type": "file", "name": "Счет_на_оплату.pdf.html", "data": TELEGRAM_KIT.encode("utf-8")}
    if choice.startswith("4"):
        p = os.path.join(DATASET, "grouped_png_phishing2026", "cluster_10",
                         "570516f8ef2a63f2eb3e5e3c172cf5479ae1300d_PO.2025072100002.PDF.png")
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return {"type": "file", "name": os.path.basename(p), "data": f.read()}
    if choice.startswith("5"):
        import benign_samples
        s = next(x for x in benign_samples.HTML_PAGES if x["id"] == "benign-sber-login")
        return {"type": "snapshot", "url": s["url"], "html": s["html"]}
    if choice.startswith("6"):
        p = os.path.join(DATASET, "hardcore_demo", "hardcore_visual_sber_phish.html")
        if not os.path.exists(p):
            return None
        with open(p, "rb") as f:
            return {"type": "file", "name": os.path.basename(p), "data": f.read()}
    return None


def run_demo(spec: dict) -> dict:
    """Through the worker API when it is running (Docker), otherwise in-process."""
    if _worker_alive():
        if spec["type"] == "sample":
            r = requests.post(f"{WORKER_API}/api/v1/scan/sample", data={"path": spec["path"]}, timeout=300)
        elif spec["type"] == "snapshot":
            r = requests.post(f"{WORKER_API}/api/v1/scan/snapshot", data={"url": spec["url"]},
                              files={"html": ("page.html", spec["html"].encode("utf-8"))}, timeout=300)
        else:
            r = requests.post(f"{WORKER_API}/api/v1/scan", files={"file": (spec["name"], spec["data"])}, timeout=300)
        return r.json() if r.status_code == 200 else {"error": r.text[:500]}
    from orchestrator.state import PhishingState
    from ingest.dataset import build_state_from_sample_dir
    iid = f"demo_{uuid.uuid4().hex[:8]}"
    if spec["type"] == "sample":
        path = os.path.join(DATASET, spec["path"])
        if not os.path.isdir(path):
            return {"error": f"нет каталога {path}"}
        return run_local(build_state_from_sample_dir(path, iid))
    if spec["type"] == "snapshot":
        return run_local(PhishingState(incident_id=iid, source_type="url", raw_target=spec["url"], offline_mode=True,
                                       precollected_links=[{"url": spec["url"], "final_url": spec["url"], "html": spec["html"],
                                                            "redirect_chain": []}]))
    ext = spec["name"].lower().rsplit(".", 1)[-1]
    return run_local(PhishingState(incident_id=iid, source_type=ext, raw_target=spec["name"], raw_bytes=spec["data"], offline_mode=True))


DEMO_CASES = [
    "1. Письмо «Adobe»: OAuth-редирект Microsoft → загрузка ScreenConnect (RAT)",
    "2. Письмо «Сбербанк»: подмена отправителя и редирект через сокращатель",
    "3. HTML-вложение «счёт.pdf.html»: форма входа Сбера + эксфильтрация в Telegram",
    "4. Изображение-приманка с двойным расширением (.PDF.png), кампания PO",
    "5. Легитимная страница входа СберБанк Онлайн (проверка отсутствия ложного срабатывания)",
    "6. Визуальный фишинг без текста бренда (нужен VLM)",
]


# --------------------------------------------------------------------------- rendering
def render_agent_traces(traces: list):
    st.subheader("🤖 Трассировка мультиагентного конвейера LangGraph")
    if not traces:
        st.info("Данные трассировки недоступны.")
        return
    total_ms = sum(t.get("duration_ms", 0) for t in traces)
    llm_calls = [t for t in traces if t.get("llm_audit")]
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Шагов агентов", len(traces))
    m2.metric("Время конвейера", f"{total_ms / 1000:.2f} c")
    m3.metric("Обращений к LLM / VLM", len(llm_calls))
    m4.metric("Агентов с находками", sum(1 for t in traces if t.get("status") == "TRIGGERED"))

    badges = {"TRIGGERED": "🔴 НАХОДКИ", "WARNING": "🟡 ВНИМАНИЕ", "SKIPPED": "⚪ ПРОПУЩЕН", "CLEAN": "🟢 ЧИСТО"}
    for idx, trace in enumerate(traces, 1):
        llm_info = trace.get("llm_audit")
        status = trace.get("status", "COMPLETED")
        ai_tag = f" 🧠 [{llm_info.get('model', 'LLM')}]" if llm_info else ""
        header = f"{trace.get('icon', '🤖')} Шаг {idx}: {trace.get('agent_name', 'Agent')} — {badges.get(status, '🟢 ВЫПОЛНЕН')} ({trace.get('duration_ms', 0):.0f} мс){ai_tag}"
        with st.expander(header, expanded=status == "TRIGGERED"):
            st.caption(f"Фаза: `{trace.get('phase', '')}` · агент: `{trace.get('agent_id', '')}`")
            left, right = st.columns([3, 2])
            with left:
                st.markdown("**Рассуждение агента:**")
                st.write(trace.get("reasoning", "—"))
                st.markdown("**Решение:**")
                (st.error if status == "TRIGGERED" else st.warning if status == "WARNING" else st.info)(trace.get("decision", "—"))
                if trace.get("tools_called"):
                    st.markdown("**Инструменты:** " + " ".join(f"`{t}`" for t in trace["tools_called"]))
            with right:
                if trace.get("findings"):
                    st.dataframe([{"Параметр": f.get("label", ""), "Значение": str(f.get("value", ""))}
                                  for f in trace["findings"]], hide_index=True, use_container_width=True)
            if llm_info:
                ok = llm_info.get("success", True)
                st.markdown(f"**Обращение к модели `{llm_info.get('model', '?')}`** ({llm_info.get('call_type', '')}, "
                            f"{llm_info.get('elapsed_seconds', 0):.2f} c) — {'успешно' if ok else 'недоступна, использован детерминированный результат'}")
                with st.expander("Промпт и ответ модели", expanded=False):
                    st.code(llm_info.get("prompt", ""), language="text")
                    st.code(llm_info.get("response", ""), language="text")


def render_result(result: dict):
    if result.get("error") and not result.get("verdict"):
        st.error(f"Ошибка анализа: {result['error']}")
        return
    verdict = result.get("verdict", "UNKNOWN")
    risk = float(result.get("risk_score", 0.0))
    brand_ev = result.get("brand_evidence", {}) or {}
    brand = brand_ev.get("detected_brand_name") or "—"

    c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
    with c1:
        text = f"### Вердикт: {VERDICT_RU.get(verdict, verdict)}"
        (st.error if verdict == "MALICIOUS" else st.warning if verdict == "SUSPICIOUS" else st.success)(text)
    with c2:
        st.metric("Risk score", f"{risk:.2f}")
        st.progress(min(risk, 1.0))
    with c3:
        st.metric("Бренд", brand)
        st.caption(f"источник: {brand_ev.get('detection_source') or '—'}")
    with c4:
        st.metric("Кампания", result.get("campaign_id") or "—")
        st.caption(result.get("signature_status") or "")

    if result.get("zero_fpr_note"):
        st.caption(f"Zero FPR Guard: {result['zero_fpr_note']}")
    if result.get("explanation"):
        st.markdown("### 🧾 Пояснение решения")
        st.chat_message("assistant", avatar="🛡️").markdown(result["explanation"].replace("\n", "  \n"))

    st.subheader("📋 Коды причин и подтверждающие признаки")
    codes = result.get("reason_codes", [])
    if codes:
        catalogue = reason_catalogue()
        rows = []
        for code in sorted(codes, key=lambda c: -getattr(catalogue.get(c), "weight", 0)):
            info = catalogue.get(code)
            rows.append({
                "Код": code,
                "Важность": info.severity if info else "",
                "Вес": f"{info.weight:.2f}" if info else "",
                "Подтверждающий признак": (result.get("reason_details") or {}).get(code, ""),
                "Описание": info.description if info else "",
            })
        st.dataframe(rows, hide_index=True, use_container_width=True)
    else:
        st.info("Признаков фишинговых техник не обнаружено.")

    shot = result.get("screenshot_base64")
    left, right = st.columns([1, 1])
    with left:
        if shot:
            st.subheader("🖼️ Снимок страницы / изображение")
            try:
                st.image(base64.b64decode(shot.split("base64,")[-1]), caption=result.get("screenshot_source") or "", use_container_width=True)
            except Exception:
                st.caption("Изображение не удалось отобразить.")
    with right:
        st.subheader("🔎 Отпечатки и сеть")
        st.json({"final_url": result.get("final_url"), "redirect_chain": [h.get("url") for h in result.get("redirect_chain", [])],
                 "fingerprints": result.get("fingerprints", {}),
                 "dom_structural_hash": result.get("dom_structural_hash")}, expanded=False)

    st.subheader("📦 Компактные артефакты")
    sig, yara = result.get("generated_l_signature"), result.get("generated_yara_rule")
    s1, s2 = st.columns(2)
    with s1:
        st.markdown("**L-сигнатура (lar-rule-v1)**")
        if sig:
            st.json(sig, expanded=False)
            st.download_button("💾 Скачать .json", json.dumps(sig, ensure_ascii=False, indent=2),
                               file_name=f"{sig.get('rule_id', 'rule')}.json", mime="application/json")
        else:
            st.info("Правило не формировалось (вердикт CLEAN или улики не обобщаются).")
    with s2:
        st.markdown("**YARA**")
        if yara:
            st.code(yara, language="c")
            st.download_button("💾 Скачать .yar", yara, file_name=f"{(sig or {}).get('rule_id', 'rule')}.yar")
        else:
            st.info("Для образца нет специфичных строк для YARA.")

    st.markdown("---")
    render_agent_traces(result.get("agent_traces", []))


# ----------------------------------------------------------------------------- sidebar
st.sidebar.title("🛡️ Phishing Intelligence Pipeline")
st.sidebar.caption("Глубокий анализ фишинга → база знаний → компактные артефакты")
page = st.sidebar.radio("Разделы", ["🔍 Анализ объекта", "📚 База знаний и кампании", "📈 Метрики качества", "🧠 Журнал LLM / VLM"])
st.sidebar.markdown("---")
st.sidebar.markdown(
    "**Вердикт (noisy-OR по кодам причин):**\n"
    "- `< 0.30` — признаков нет\n- `0.30–0.70` — подозрительно\n- `≥ 0.70` — фишинг\n\n"
    "Одиночный признак не даёт вердикт «фишинг»; каждое правило проверяется на эталонной выборке легитимных объектов.")
st.sidebar.caption(f"Worker API: {'🟢 доступен' if _worker_alive() else '⚪ не запущен — локальный режим'}")


# ------------------------------------------------------------------------------ pages
if page == "🔍 Анализ объекта":
    st.title("🔍 Анализ объекта")
    tab_demo, tab_file, tab_url = st.tabs(["🧪 Кейсы из датасета", "📁 Файл (EML, HTML, PDF, Office, изображение)", "🔗 URL"])
    result = None
    with tab_demo:
        choice = st.selectbox("Кейс:", DEMO_CASES)
        st.caption("Кейсы анализируются офлайн по собранным артефактам (цепочки редиректов, HTML, скриншоты) — без обращения к живой фишинговой инфраструктуре.")
        if st.button("⚡ Запустить", type="primary", key="demo"):
            spec = demo_spec(choice)
            if spec is None:
                st.warning("Файлы кейса отсутствуют (каталог file_for_case не подключён).")
            elif not _worker_alive() and not _local_available():
                st.error("Нет ни Worker API, ни локальных исходников воркера.")
            else:
                with st.spinner("Работает мультиагентный конвейер..."):
                    result = run_demo(spec)
    with tab_file:
        uploaded = st.file_uploader("Файл для разбора в песочнице", type=None)
        if st.button("🔍 Проанализировать", type="primary", key="file") and uploaded:
            with st.spinner("Работает мультиагентный конвейер..."):
                result = analyze_file(uploaded.name, uploaded.read())
    with tab_url:
        url = st.text_input("URL", placeholder="https://example.com/login")
        st.caption("Активное раскрытие ссылки выполняется только песочницей с выходом в сеть (профиль live-fetch).")
        if st.button("🚀 Проанализировать URL", type="primary", key="url") and url:
            with st.spinner("Работает мультиагентный конвейер..."):
                result = analyze_url(url.strip())
    if result is not None:
        st.divider()
        render_result(result)

elif page == "📚 База знаний и кампании":
    st.title("📚 База знаний, кампании и пакет артефактов")
    stats, incidents, signatures, campaigns = {}, [], [], []
    if _worker_alive():
        try:
            stats = requests.get(f"{WORKER_API}/api/v1/stats", timeout=5).json()
            incidents = requests.get(f"{WORKER_API}/api/v1/incidents?limit=200", timeout=5).json()
            signatures = requests.get(f"{WORKER_API}/api/v1/signatures?limit=200", timeout=5).json()
            campaigns = requests.get(f"{WORKER_API}/api/v1/campaigns", timeout=5).json()
        except (requests.RequestException, ValueError):
            pass
    elif _local_available():
        from db.repository import IncidentRepository
        repo = IncidentRepository()
        stats = repo.count_stats()
        incidents = [{"id": i.id, "created_at": i.created_at.isoformat() if i.created_at else "", "source_type": i.source_type,
                      "raw_target": i.raw_target, "verdict": i.verdict, "target_brand": i.target_brand,
                      "risk_score": i.risk_score, "reason_codes": i.reason_codes, "campaign_id": i.campaign_id}
                     for i in repo.list_incidents(limit=200)]
        signatures = [{"id": s.id, "name": s.name, "target_brand": s.target_brand, "status": s.status,
                       "created_at": s.created_at.isoformat() if s.created_at else "", "incident_id": s.incident_id}
                      for s in repo.list_signatures(limit=200)]
        campaigns = repo.list_campaigns()

    m = st.columns(6)
    m[0].metric("Инцидентов", stats.get("total_incidents", 0))
    m[1].metric("Фишинг", stats.get("malicious_count", 0))
    m[2].metric("Подозрительно", stats.get("suspicious_count", 0))
    m[3].metric("Чисто", stats.get("clean_count", 0))
    m[4].metric("Правил (активных)", stats.get("active_signatures", 0))
    m[5].metric("Кампаний", len(campaigns))

    st.subheader("📊 Частота фишинговых техник по базе знаний")
    freq = collections.Counter(c for i in incidents for c in (i.get("reason_codes") or []))
    if freq:
        st.bar_chart({code: n for code, n in freq.most_common(20)}, horizontal=True)
    else:
        st.info("База знаний пуста — проанализируйте объекты или запустите `python phishctl.py analyze-dir`.")

    st.subheader("🕸️ Кампании (общий kit, канал эксфильтрации или инфраструктура)")
    if campaigns:
        st.dataframe([{"Кампания": c["campaign_id"], "Инцидентов": c["incidents"], "Бренды": ", ".join(c["brands"]),
                       "Техники": ", ".join(c["reason_codes"][:6]), "Последний": c["last_seen"]} for c in campaigns],
                     hide_index=True, use_container_width=True)
    else:
        st.caption("Кампании появляются, когда ≥ 2 инцидента имеют общий отпечаток.")

    st.subheader("📦 Пакет артефактов для антиспам-движка")
    st.caption("Версионированный JSON: сигнатуры известного фишинга отдельно от обобщённых правил, признаки брендов, коды причин и YARA.")
    if _local_available() and st.button("Сформировать новую версию пакета", type="primary"):
        from rules.package import build_package, save_package
        info = save_package(build_package(), os.path.join(EXPORTS, "package"))
        st.success(f"Пакет v{info['version']} сохранён: {info['json']}")
        with open(info["json"], "rb") as f:
            st.download_button("📥 Скачать package.json", f.read(), file_name=os.path.basename(info["json"]), mime="application/json")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(info["json"], os.path.basename(info["json"]))
            zf.write(info["yara"], os.path.basename(info["yara"]))
        st.download_button("📥 Скачать пакет (ZIP: JSON + YARA)", buf.getvalue(), file_name=f"package_v{info['version']}.zip",
                           mime="application/zip")

    st.subheader("🗂️ Журнал инцидентов")
    if incidents:
        st.dataframe([{"ID": i.get("id"), "Время": (i.get("created_at") or "").replace("T", " ")[:16], "Тип": i.get("source_type"),
                       "Объект": str(i.get("raw_target", ""))[-70:], "Вердикт": i.get("verdict"), "Бренд": i.get("target_brand") or "",
                       "Risk": f"{float(i.get('risk_score') or 0):.2f}", "Кампания": i.get("campaign_id") or ""} for i in incidents],
                     hide_index=True, use_container_width=True)
    st.subheader("📜 Реестр правил")
    if signatures:
        st.dataframe([{"Rule ID": s.get("id"), "Название": s.get("name"), "Бренд": s.get("target_brand"),
                       "Статус": s.get("status"), "Инцидент": s.get("incident_id"),
                       "Дата": (s.get("created_at") or "").replace("T", " ")[:16]} for s in signatures],
                     hide_index=True, use_container_width=True)

elif page == "📈 Метрики качества":
    st.title("📈 Метрики качества (ТЗ п. 4.1.11)")
    st.caption("Отчёт формируется командой `python phishctl.py metrics` (или кнопкой ниже на ограниченной выборке).")
    report_path = os.path.join(REPORTS, "metrics.json")
    if _local_available():
        limit = st.slider("Объектов на источник для быстрого прогона", 5, 200, 20, step=5)
        if st.button("Пересчитать метрики (офлайн)"):
            from evaluation import evaluate, save_report
            with st.spinner("Прогон корпуса и легитимного набора..."):
                save_report(evaluate(DATASET, limit), report_path)
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        st.caption(f"Отчёт от {report.get('generated_at')} · объектов: {report.get('counts')}")
        st.subheader("Критерии приёмки")
        st.dataframe([{"Метрика": k, "Цель": v["target"], "Факт": v["actual"], "Выполнено": "✅" if v["passed"] else "❌"}
                      for k, v in report["acceptance"].items()], hide_index=True, use_container_width=True)
        st.subheader("Все метрики")
        st.json(report["metrics"])
        st.subheader("Разрез по источникам")
        st.dataframe([{"Источник": k, **{kk: (json.dumps(vv, ensure_ascii=False) if isinstance(vv, dict) else vv) for kk, vv in v.items()}}
                      for k, v in report["per_category"].items()], hide_index=True, use_container_width=True)
        st.subheader("Глобальная интерпретация: частота техник")
        st.bar_chart(dict(list(report.get("reason_code_frequency", {}).items())[:20]), horizontal=True)
        if report.get("benign_false_positives", {}).get("suspicious"):
            st.warning("«Подозрительно» на легитимных: " + ", ".join(report["benign_false_positives"]["suspicious"]))
    else:
        st.info("Отчёт ещё не сформирован.")

    robust_path = os.path.join(REPORTS, "robustness.json")
    st.subheader("Устойчивость к обходу (`phishctl.py robustness`)")
    if os.path.exists(robust_path):
        with open(robust_path, "r", encoding="utf-8") as f:
            robust = json.load(f)
        names = {"domain_url_change": "Замена домена и URL", "design_change": "Изменение оформления",
                 "delayed_loading": "Отложенная загрузка содержимого"}
        st.dataframe([{"Сценарий": names.get(k, k), "Объектов": v["objects"], "Обнаружено": v["still_detected"],
                       "Recall": v["recall"], "Падение recall": v["recall_drop"]} for k, v in robust["scenarios"].items()],
                     hide_index=True, use_container_width=True)
    else:
        st.caption("Отчёт об устойчивости ещё не сформирован.")

elif page == "🧠 Журнал LLM / VLM":
    st.title("🧠 Журнал обращений к LLM / VLM")
    try:
        from config import get_settings
        s = get_settings()
        st.caption(f"Режим: **{s.llm_mode}** · текстовая модель: `{s.LLM_TEXT_MODEL}` · VLM: `{s.LLM_VISION_MODEL}` · "
                   f"{'настроено' if s.llm_configured else 'не настроено'}")
    except Exception:
        pass
    log_path = os.path.join(ROOT_DIR, "logs", "llm_audit.log")
    if st.button("🔄 Обновить"):
        st.rerun()
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            entries = [e.strip() for e in f.read().split("-" * 70) if e.strip()]
        c1, c2, c3 = st.columns(3)
        c1.metric("Всего обращений", len(entries))
        c2.metric("VLM (скриншоты)", sum(1 for e in entries if "VISION_VLM" in e))
        c3.metric("LLM (текст)", sum(1 for e in entries if "TEXT_LLM" in e))
        for idx, entry in enumerate(reversed(entries[-100:]), 1):
            header = entry.splitlines()[0] if entry else "call"
            with st.expander(("👁️ " if "VISION" in header else "🧠 ") + header, expanded=idx <= 2):
                st.code(entry, language="text")
    else:
        st.info("Обращений к моделям ещё не было (или LLM_MODE=off).")
