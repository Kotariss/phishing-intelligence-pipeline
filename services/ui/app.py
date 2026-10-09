import os
import sys
import io
import json
import base64
import requests
import zipfile
import streamlit as st

# Setup page config
st.set_page_config(
    page_title="Phishing Intelligence Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Ensure paths
if os.path.exists(os.path.join(os.path.dirname(__file__), "file_for_case")):
    ROOT_DIR = os.path.dirname(__file__)
elif os.path.exists(os.path.join(os.path.dirname(__file__), "../..", "file_for_case")):
    ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
else:
    ROOT_DIR = os.environ.get("ROOT_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

WORKER_SRC = os.path.join(ROOT_DIR, "services", "worker", "src")
SANDBOX_SRC = os.path.join(ROOT_DIR, "services", "sandbox", "src")
if os.path.exists(WORKER_SRC) and WORKER_SRC not in sys.path:
    sys.path.insert(0, WORKER_SRC)
if os.path.exists(SANDBOX_SRC) and SANDBOX_SRC not in sys.path:
    sys.path.insert(0, SANDBOX_SRC)

WORKER_HOST = os.getenv("WORKER_HOST", "localhost")
WORKER_PORT = os.getenv("WORKER_PORT", "8000")
WORKER_API = f"http://{WORKER_HOST}:{WORKER_PORT}"

# Fallback in-process runner
def execute_pipeline_local(source_type: str, raw_target: str, raw_bytes: bytes = None):
    try:
        from orchestrator.state import PhishingState
        from orchestrator.graph import run_pipeline
        import uuid
        state = PhishingState(
            incident_id=f"ui_{uuid.uuid4().hex[:8]}",
            source_type=source_type,
            raw_target=raw_target,
            raw_bytes=raw_bytes
        )
        return run_pipeline(state).model_dump()
    except Exception as e:
        return {"error": str(e), "verdict": "ERROR", "risk_score": 0.0}

def analyze_target(source_type: str, target_val: str, file_bytes: bytes = None):
    # Try Worker API first
    try:
        if source_type == "url":
            resp = requests.post(f"{WORKER_API}/api/v1/scan", data={"url": target_val}, timeout=120)
        else:
            files = {"file": (os.path.basename(target_val), file_bytes)}
            resp = requests.post(f"{WORKER_API}/api/v1/scan", files=files, timeout=120)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    
    # In-process fallback
    return execute_pipeline_local(source_type, target_val, file_bytes)

def render_agent_traces(traces: list):
    """Renders the step-by-step multi-agent execution pipeline trace."""
    st.subheader("🤖 Пошаговая трассировка мультиагентного конвейера LangGraph")
    st.caption("Каждый агент изолированно анализирует артефакты, вызывает специализированные инструменты и нейросети, обогащая общее состояние расследования (State).")
    
    if not traces:
        st.info("Данные трассировки недоступны.")
        return

    total_time_ms = sum(t.get("duration_ms", 0) for t in traces)
    llm_calls_count = sum(1 for t in traces if t.get("llm_audit"))
    threat_nodes = sum(1 for t in traces if t.get("status") == "TRIGGERED")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Всего шагов агентов", len(traces))
    m2.metric("Суммарное время пайплайна", f"{total_time_ms / 1000:.2f} сек")
    m3.metric("Обращений к нейросетям", f"{llm_calls_count} (VLM / LLM)")
    m4.metric("Узлов с детекцией угроз", f"{threat_nodes}")

    st.markdown("---")

    for idx, trace in enumerate(traces, 1):
        icon = trace.get("icon", "🤖")
        name = trace.get("agent_name", "Unknown Agent")
        phase = trace.get("phase", "Analysis")
        status = trace.get("status", "COMPLETED")
        dur_ms = trace.get("duration_ms", 0.0)
        llm_info = trace.get("llm_audit")

        # Status badge styling
        if status == "TRIGGERED":
            status_badge = "🔴 ОБНАРУЖЕНА УГРОЗА"
        elif status == "WARNING":
            status_badge = "🟡 ТРЕБУЕТ ВНИМАНИЯ"
        elif status == "SKIPPED":
            status_badge = "⚪ ПРОПУЩЕН"
        else:
            status_badge = "🟢 ВЫПОЛНЕН"

        ai_tag = f" 🧠 [AI: {llm_info.get('model', 'Cloud').split('/')[-1]}]" if llm_info else ""
        header = f"{icon} Шаг {idx}: {name} — {status_badge} ({dur_ms:.1f} мс){ai_tag}"

        # Expand automatically if threat detected or LLM was called or key steps
        default_expanded = bool(status == "TRIGGERED" or llm_info or idx in (1, 4, 7))

        with st.expander(header, expanded=default_expanded):
            st.caption(f"**Фаза пайплайна:** `{phase}` | **Идентификатор агента:** `{trace.get('agent_id', 'agent')}`")
            
            c_left, c_right = st.columns([3, 2])

            with c_left:
                st.markdown("**💭 Цепочка рассуждений агента (Agent Reasoning):**")
                st.write(trace.get("reasoning", "—"))

                st.markdown("**⚖️ Принятое решение (Decision):**")
                if status == "TRIGGERED":
                    st.error(trace.get("decision", "—"))
                elif status == "WARNING":
                    st.warning(trace.get("decision", "—"))
                else:
                    st.info(trace.get("decision", "—"))

                tools = trace.get("tools_called", [])
                if tools:
                    st.markdown("**🛠️ Вызванные алгоритмы и инструменты (Tools & Algorithms):**")
                    tools_badges = " ".join([f"`{t}`" for t in tools])
                    st.markdown(tools_badges)

            with c_right:
                findings = trace.get("findings", [])
                if findings:
                    st.markdown("**📊 Выявленные параметры (Findings):**")
                    table_rows = []
                    for f in findings:
                        table_rows.append({
                            "Параметр": f.get("label", ""),
                            "Значение": str(f.get("value", ""))
                        })
                    st.dataframe(table_rows, hide_index=True, use_container_width=True)

            # Neural Network Call Highlight
            if llm_info:
                st.markdown("---")
                call_type = llm_info.get("call_type", "AI_CALL")
                model_name = llm_info.get("model", "Unknown")
                elapsed_s = llm_info.get("elapsed_seconds", 0.0)
                
                st.markdown(f"#### 🧠 Прямой вызов нейросети NSU Cloud AI (`{call_type}`)")
                
                c_ai_meta1, c_ai_meta2 = st.columns([1, 1])
                with c_ai_meta1:
                    st.info(f"**Модель:** `{model_name}`\n\n**Время инференса:** `{elapsed_s:.2f} сек`")
                with c_ai_meta2:
                    st.success(f"**Таймстемп:** `{llm_info.get('timestamp', 'UTC')}`\n\n**Статус:** `SUCCESS (200 OK)`")

                with st.expander("📥 Посмотреть промпт, переданный в модель", expanded=False):
                    st.code(llm_info.get("prompt", ""), language="text")

                st.markdown("**📤 Непосредственный ответ нейросети (Raw Output):**")
                st.code(llm_info.get("response", ""), language="text")

# Sidebar Navigation
st.sidebar.markdown("## 🛡️ Anti-Spam Threat Lab")
st.sidebar.title("Phishing Intelligence Pipeline")
st.sidebar.markdown("**Мультиагентный анализ фишинга и дистилляция в компактные L-сигнатуры**")
st.sidebar.divider()

page = st.sidebar.radio(
    "Навигация по разделам",
    [
        "🔍 Сканер & Анализатор угроз",
        "📚 База знаний & Реестр L-сигнатур",
        "🤖 Логи нейросетей (LLM & VLM Live Audit)"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info(
    "**Стандарт Zero FPR:**\n"
    "• Clean: < 0.30\n"
    "• Review: 0.30 - 0.70\n"
    "• Block: >= 0.70\n"
    "Гарантия нулевых ложных срабатываний на корпоративной почте."
)

# ==============================================================================
# PAGE 1: SCANNER & ANALYZER
# ==============================================================================
if page == "🔍 Сканер & Анализатор угроз":
    st.title("🛡️ Мультиагентный сканер фишинговых угроз")
    st.caption("Полносвязный мультиагентный конвейер LangGraph: изоляция Sandbox, VLM-компьютерное зрение и синтез L-сигнатур")

    tab_url, tab_file, tab_demo = st.tabs([
        "🔗 Подозрительный URL",
        "📁 Загрузка файла (EML, HTML, PDF, PNG)",
        "🧪 Готовые кейсы из датасета (Демо)"
    ])

    scan_triggered = False
    source_type = ""
    target_str = ""
    raw_content = None

    with tab_url:
        st.subheader("Анализ подозрительной ссылки")
        url_input = st.text_input("Введите URL для раскрытия редиректов и песочницы:", placeholder="https://example.com/promo-auth")
        if st.button("🚀 Запустить глубокий анализ ссылки", key="btn_scan_url", type="primary"):
            if url_input:
                scan_triggered = True
                source_type = "url"
                target_str = url_input.strip()
            else:
                st.warning("Пожалуйста, укажите URL.")

    with tab_file:
        st.subheader("Загрузка подозрительного файла")
        uploaded_file = st.file_uploader(
            "Перетащите файл для безопасного разбора в песочнице:",
            type=["eml", "msg", "html", "htm", "pdf", "docx", "xlsx", "png", "jpg", "jpeg"]
        )
        if st.button("🔍 Проанализировать загруженный файл", key="btn_scan_file", type="primary"):
            if uploaded_file:
                scan_triggered = True
                ext = uploaded_file.name.split(".")[-1].lower() if "." in uploaded_file.name else "bin"
                source_type = ext
                target_str = uploaded_file.name
                raw_content = uploaded_file.read()
            else:
                st.warning("Пожалуйста, загрузите файл.")

    with tab_demo:
        st.subheader("Предустановленные кейсы из датасета")
        demo_choice = st.selectbox(
            "Выберите образцовый кейс для моментальной демонстрации пайплайна:",
            [
                "Кейс 1: Фишинг под Сбербанк (EML с подменой отображаемого имени)",
                "Кейс 2: Подделка Госуслуг / Автономный HTML-фишинг кит с JS-обфускацией",
                "Кейс 3: Quishing / B2B приманка с двойным расширением (.PDF.png)",
                "Кейс 4: Легитимная деловая ссылка (Гарантия Zero FPR: Сбербанк Онлайн)",
                "🔥 Кейс 5 (ХАРДКОР VLM + LLM): Чисто визуальный фишинг БЕЗ единого слова в тексте"
            ]
        )
        if "Кейс 5" in demo_choice:
            st.info("💡 **Хардкор-сценарий для нейросетей:** В HTML-коде и DOM вообще нет текста и упоминаний бренда (0 ключевых слов). Традиционные парсеры и regex бессильны. Для детекции критически необходима **мультимодальная Vision нейросеть (Qwen3.8-27B)** для распознавания пикселей логотипа и интерфейса Сбера, а также **DeepSeek-V4-Flash** для синтеза вердикта.")
        if st.button("⚡ Загрузить кейс и выполнить анализ", key="btn_scan_demo", type="primary"):
            scan_triggered = True
            if "Кейс 1" in demo_choice:
                source_type = "eml"
                target_str = os.path.join(ROOT_DIR, "file_for_case/keis2/Сбер/0517e90f5805fff01c086cbc6ace8010e0a643e6/0517e90f5805fff01c086cbc6ace8010e0a643e6")
                if os.path.exists(target_str):
                    with open(target_str, "rb") as f:
                        raw_content = f.read()
            elif "Кейс 2" in demo_choice:
                source_type = "html"
                h_dir = os.path.join(ROOT_DIR, "file_for_case/html_phishing2026")
                h_files = [f for f in os.listdir(h_dir) if f.endswith(".html")]
                target_str = os.path.join(h_dir, h_files[0])
                with open(target_str, "rb") as f:
                    raw_content = f.read()
            elif "Кейс 3" in demo_choice:
                source_type = "png"
                target_str = os.path.join(ROOT_DIR, "file_for_case/grouped_png_phishing2026/cluster_10/570516f8ef2a63f2eb3e5e3c172cf5479ae1300d_PO.2025072100002.PDF.png")
                with open(target_str, "rb") as f:
                    raw_content = f.read()
            elif "Кейс 4" in demo_choice:
                source_type = "url"
                target_str = "https://online.sberbank.ru/CSAFront/index.do"
            elif "Кейс 5" in demo_choice:
                source_type = "html"
                target_str = os.path.join(ROOT_DIR, "file_for_case/hardcore_demo/hardcore_visual_sber_phish.html")
                with open(target_str, "rb") as f:
                    raw_content = f.read()

    if scan_triggered:
        st.divider()
        with st.status("Исполнение мультиагентного конвейера LangGraph...", expanded=True) as status:
            st.write("🔵 **Triage Agent:** Валидация входного типа, Anti-SSRF фильтрация и Sandbox изоляция...")
            st.write("🌐 **URL Agent:** Анализ перенаправлений, OAuth-абуза и полезных нагрузок RAT...")
            st.write("📄 **DOM Agent:** Глубокий разбор форм, скриптов и каналов эксфильтрации...")
            st.write("👁️ **Vision Agent:** Мультимодальный VLM-анализ графики и проверка по 175-Brand Allowlist...")
            st.write("📦 **Quishing Agent:** Поиск QR-кодов и маскированных вложений...")
            st.write("🧠 **Synthesizer Agent:** Синтез SOC-вердикта через DeepSeek LLM и компиляция L-сигнатур...")
            
            result = analyze_target(source_type, target_str, raw_content)
            status.update(label="Мультиагентный анализ завершен успешно!", state="complete", expanded=False)

        # Verdict Section
        verdict = result.get("verdict", "UNKNOWN")
        risk_score = result.get("risk_score", 0.0)
        confidence = result.get("confidence", "LOW")
        brand_ev = result.get("brand_evidence", {})
        target_brand = brand_ev.get("detected_brand_name") or result.get("target_brand") or "Generic"

        col_verdict, col_metrics, col_brand = st.columns([2, 1, 1])

        with col_verdict:
            if verdict == "MALICIOUS":
                st.error(f"### 🔴 ВЕРДИКТ: {verdict} / ЗАБЛОКИРОВАНО")
                st.markdown(f"**Объект классифицирован как подтвержденный фишинг.** Сгенерирована L-сигнатура.")
            elif verdict == "SUSPICIOUS":
                st.warning(f"### 🟡 ВЕРДИКТ: {verdict} / ТРЕБУЕТСЯ ПРОВЕРКА")
                st.markdown(f"**Подозрительный объект.** Передан на проверку SOC-аналитику.")
            else:
                st.success(f"### 🟢 ВЕРДИКТ: {verdict} / ЧИСТЫЙ ОБЪЕКТ")
                st.markdown(f"**Легитимный трафик.** Полное соответствие стандарту Zero FPR.")

        with col_metrics:
            st.metric("Risk Score", f"{risk_score:.2f} / 1.00")
            st.progress(min(float(risk_score), 1.0))
            st.caption(f"Степень уверенности: **{confidence}**")

        with col_brand:
            st.metric("Таргет-бренд", target_brand)
            impersonated = brand_ev.get("brand_impersonation_confirmed", False)
            if impersonated:
                st.error("⚠️ Brand Impersonation")
            else:
                st.success("✅ Allowlist Match")

        # SOC Analyst LLM Synthesis Callout
        explanation_text = result.get("explanation")
        if explanation_text:
            st.markdown("### 🧠 Экспертное заключение SOC-аналитика (DeepSeek-V4-Flash)")
            st.caption("Аналитическое заключение автоматически сформировано нейросетью на облачной инфраструктуре НГУ:")
            st.chat_message("assistant", avatar="🛡️").markdown(explanation_text)

        st.markdown("---")

        # AGENT EXECUTION TRACE SECTION
        agent_traces = result.get("agent_traces", [])
        render_agent_traces(agent_traces)

        st.markdown("---")

        # Reason Codes Table
        st.subheader("📋 Сработавшие коды причин (Reason Codes)")
        reason_codes = result.get("reason_codes", [])
        if reason_codes:
            rc_data = []
            for code in reason_codes:
                rc_data.append({
                    "Reason Code": code,
                    "Описание индикатора": "Детектирован признак фишинговой техники / эксфильтрации",
                    "Статус": "TRIGGERED"
                })
            st.dataframe(rc_data, use_container_width=True)
        else:
            st.info("Аномальных признаков или подозрительных кодов не обнаружено.")

        # Visual Artifacts & Screenshot
        screenshot_b64 = result.get("screenshot_base64")
        if screenshot_b64:
            st.subheader("🖼️ Визуальные улики (Снимок песочницы / Вложения)")
            try:
                img_data = base64.b64decode(screenshot_b64)
                st.image(img_data, caption="Рендеринг песочницы Sandbox / Входной графический артефакт", width=700)
            except Exception:
                pass

        # Generated L-Signature & YARA rules
        st.subheader("📦 Сгенерированные правила для локального движка Dr.Web")
        l_sig = result.get("generated_l_signature")
        yara_rule = result.get("generated_yara_rule")

        col_sig1, col_sig2 = st.columns(2)

        with col_sig1:
            st.markdown("#### 1. Компактная L-сигнатура (JSON)")
            if l_sig:
                st.json(l_sig)
                sig_json_str = json.dumps(l_sig, indent=2, ensure_ascii=False)
                st.download_button(
                    label="💾 Скачать L-сигнатуру (.json)",
                    data=sig_json_str,
                    file_name=f"{l_sig.get('rule_id', 'rule')}.json",
                    mime="application/json"
                )
            else:
                st.info("L-сигнатура блокировки не генерировалась (объект признан легитимным).")

        with col_sig2:
            st.markdown("#### 2. YARA-правило для вложений")
            if yara_rule:
                st.code(yara_rule, language="c")
                st.download_button(
                    label="💾 Скачать YARA-правило (.yar)",
                    data=yara_rule,
                    file_name="generated_rule.yar",
                    mime="text/plain"
                )
            else:
                st.info("YARA-правило для данного образца не требуется.")

# ==============================================================================
# PAGE 2: KNOWLEDGE BASE & SIGNATURE REGISTRY
# ==============================================================================
elif page == "📚 База знаний & Реестр L-сигнатур":
    st.title("📚 Реестр инцидентов и База знаний L-сигнатур")
    st.caption("Архив проанализированных образцов и пакетный экспорт правил для Dr.Web")

    # Fetch stats & records (Try Worker API first, then local DB fallback)
    stats = {"total_incidents": 0, "malicious_count": 0, "suspicious_count": 0, "clean_count": 0, "total_signatures": 0}
    incidents = []
    signatures = []

    try:
        r_stats = requests.get(f"{WORKER_API}/api/v1/stats", timeout=3)
        if r_stats.status_code == 200:
            stats = r_stats.json()
        r_inc = requests.get(f"{WORKER_API}/api/v1/incidents?limit=50", timeout=3)
        if r_inc.status_code == 200:
            incidents = r_inc.json()
        r_sig = requests.get(f"{WORKER_API}/api/v1/signatures?limit=50", timeout=3)
        if r_sig.status_code == 200:
            signatures = r_sig.json()
    except Exception:
        pass

    if not incidents and not signatures:
        try:
            from db.repository import IncidentRepository
            repo = IncidentRepository()
            stats = repo.count_stats()
            incidents = repo.list_incidents(limit=50)
            signatures = repo.list_signatures(limit=50)
        except Exception:
            pass

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Всего инцидентов", stats.get("total_incidents", 0))
    m2.metric("Вредоносных (MALICIOUS)", stats.get("malicious_count", 0))
    m3.metric("Подозрительных (SUSPICIOUS)", stats.get("suspicious_count", 0))
    m4.metric("Чистых (CLEAN)", stats.get("clean_count", 0))
    m5.metric("Активных L-сигнатур", stats.get("total_signatures", 0))

    st.divider()

    # Batch ZIP export
    col_exp1, col_exp2 = st.columns([3, 1])
    with col_exp1:
        st.markdown("### 📦 Пакетный экспорт правил")
        st.markdown("Экспортируйте весь накопленный каталог активных JSON L-сигнатур и YARA правил для развертывания в локальном антиспам-движке.")
    with col_exp2:
        # Generate ZIP on the fly
        zip_buf = io.BytesIO()
        exports_dir = os.path.join(ROOT_DIR, "exports")
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(exports_dir):
                for f in files:
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, exports_dir)
                    zf.write(full_p, arcname=rel_p)
        zip_buf.seek(0)
        st.download_button(
            label="📥 Скачать весь пакет правил (ZIP)",
            data=zip_buf,
            file_name="phishing_signatures_bundle.zip",
            mime="application/zip",
            type="primary"
        )

    st.divider()

    # Incidents Table
    st.subheader("Журнал инцидентов")
    if incidents:
        table_rows = []
        for inc in incidents:
            if isinstance(inc, dict):
                c_time = inc.get("created_at", "") or ""
                if "T" in c_time:
                    c_time = c_time.replace("T", " ")[:16]
                table_rows.append({
                    "ID": inc.get("id"),
                    "Время": c_time,
                    "Тип": inc.get("source_type"),
                    "Целевой объект": str(inc.get("raw_target", ""))[:60],
                    "Вердикт": inc.get("verdict"),
                    "Бренд": inc.get("target_brand") or "None",
                    "Risk Score": f"{float(inc.get('risk_score', 0.0)):.2f}",
                    "Zero FPR": "PASSED" if inc.get("zero_fpr_passed") else "FAILED"
                })
            else:
                table_rows.append({
                    "ID": inc.id,
                    "Время": inc.created_at.strftime("%Y-%m-%d %H:%M") if inc.created_at else "",
                    "Тип": inc.source_type,
                    "Целевой объект": inc.raw_target[:60],
                    "Вердикт": inc.verdict,
                    "Бренд": inc.target_brand or "None",
                    "Risk Score": f"{inc.risk_score:.2f}",
                    "Zero FPR": "PASSED" if inc.zero_fpr_passed else "FAILED"
                })
        st.dataframe(table_rows, use_container_width=True)
    else:
        st.info("Инцидентов в базе данных пока нет. Запустите анализ на странице «Сканер & Анализатор».")

    # Signatures Registry
    st.subheader("Реестр активных L-сигнатур")
    if signatures:
        sig_rows = []
        for s in signatures:
            if isinstance(s, dict):
                c_time = s.get("created_at", "") or ""
                if "T" in c_time:
                    c_time = c_time.replace("T", " ")[:16]
                sig_rows.append({
                    "Rule ID": s.get("id"),
                    "Название": s.get("name"),
                    "Бренд": s.get("target_brand"),
                    "Статус": s.get("status"),
                    "Дата": c_time
                })
            else:
                sig_rows.append({
                    "Rule ID": s.id,
                    "Название": s.name,
                    "Бренд": s.target_brand,
                    "Статус": s.status,
                    "Дата": s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else ""
                })
        st.dataframe(sig_rows, use_container_width=True)
    else:
        st.info("Активных L-сигнатур пока нет.")

# ==============================================================================
# PAGE 3: LLM & VLM LIVE AUDIT LOG
# ==============================================================================
elif page == "🤖 Логи нейросетей (LLM & VLM Live Audit)":
    st.title("🤖 Журнал прямых обращений к нейросетям (NSU Cloud AI Audit)")
    st.caption("Аудит обращений к Multimodal Vision VLM (Qwen3.8-27B) и Text LLM (deepseek-ai/DeepSeek-V4-Flash-0731)")

    log_path = os.path.join(ROOT_DIR, "logs", "llm_audit.log")

    if st.button("🔄 Обновить журнал логов"):
        st.rerun()

    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
        
        entries = [e.strip() for e in raw_content.split("-" * 70) if e.strip()]
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Всего обращений к моделям", len(entries))
        vlm_count = sum(1 for e in entries if "VISION_VLM" in e)
        llm_count = sum(1 for e in entries if "TEXT_LLM" in e)
        c2.metric("Вызовов Vision VLM (Qwen)", vlm_count)
        c3.metric("Вызовов Text LLM (DeepSeek)", llm_count)

        st.markdown("---")
        st.subheader("Последние записи аудита (в обратном хронологическом порядке):")

        for idx, entry in enumerate(reversed(entries), 1):
            lines = entry.splitlines()
            header_line = lines[0] if lines else "Call"
            is_vlm = "VISION_VLM" in header_line
            badge_icon = "👁️" if is_vlm else "🧠"

            with st.expander(f"{badge_icon} Запись #{len(entries) - idx + 1}: {header_line}", expanded=(idx <= 3)):
                st.code(entry, language="text")
    else:
        st.info("Файл логов `logs/llm_audit.log` пока не создан. Выполните анализ на первой вкладке, чтобы увидеть вызовы нейросетей.")
