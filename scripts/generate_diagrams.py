import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

# Create output dir
OUT_DIR = os.path.join(os.getcwd(), "docs", "diagrams")
os.makedirs(OUT_DIR, exist_ok=True)

# Set common font family
plt.rcParams['font.sans-serif'] = ['Segoe UI', 'Arial', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# Colors
NAVY = "#1B365D"
SLATE = "#2E5B88"
LIGHT_BLUE = "#EBF3FB"
GREEN = "#2E7D32"
LIGHT_GREEN = "#E8F5E9"
RED = "#C62828"
LIGHT_RED = "#FFEBEE"
ORANGE = "#EF6C00"
LIGHT_ORANGE = "#FFF3E0"
GREY = "#546E7A"
LIGHT_GREY = "#ECEFF1"
BORDER_COLOR = "#90A4AE"


def create_fig1_architecture():
    fig, ax = plt.subplots(figsize=(12, 7), dpi=300)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7.5)
    ax.axis('off')

    # Background title
    ax.text(6, 7.1, "Архитектура Phishing Intelligence Pipeline и Зонирование Безопасности",
            ha='center', va='center', fontsize=14, fontweight='bold', color=NAVY)

    # 1. Untrusted Zone (Left)
    untrusted_box = patches.FancyBboxPatch((0.5, 0.8), 4.8, 5.8,
                                          boxstyle="round,pad=0.2",
                                          edgecolor=RED, facecolor=LIGHT_RED,
                                          linewidth=2, linestyle='--')
    ax.add_patch(untrusted_box)
    ax.text(2.9, 6.3, "ИЗОЛИРОВАННАЯ ЗОНА (Untrusted Sandbox)",
            ha='center', va='center', fontsize=11, fontweight='bold', color=RED)
    ax.text(2.9, 5.95, "Защита хоста: read_only, tmpfs, cap_drop ALL, non-root",
            ha='center', va='center', fontsize=8.5, fontstyle='italic', color=GREY)

    # Sandbox Box
    sb_box = patches.FancyBboxPatch((0.9, 2.2), 4.0, 3.4,
                                   boxstyle="round,pad=0.15",
                                   edgecolor=RED, facecolor='white',
                                   linewidth=1.5)
    ax.add_patch(sb_box)
    ax.text(2.9, 5.25, "Сервис: sandbox (:8001)", ha='center', va='center',
            fontsize=11, fontweight='bold', color=NAVY)

    # Inside sandbox modules
    sub_modules = [
        ("Anti-SSRF фильтр адресов (RFC1918, loopback, link-local)", LIGHT_ORANGE, ORANGE),
        ("Headless Chromium (Playwright) — рендер, редиректы, DOM", LIGHT_BLUE, SLATE),
        ("Оффлайн-парсеры: EML, HTML, PDF (PyMuPDF), DOCX", LIGHT_BLUE, SLATE),
        ("Декодер QR-кодов (Quishing Detection via pyzbar)", LIGHT_BLUE, SLATE)
    ]
    for i, (text, fcol, ecol) in enumerate(sub_modules):
        y_pos = 4.6 - i * 0.7
        sub_p = patches.FancyBboxPatch((1.1, y_pos - 0.22), 3.6, 0.45,
                                      boxstyle="round,pad=0.08",
                                      edgecolor=ecol, facecolor=fcol, linewidth=1)
        ax.add_patch(sub_p)
        ax.text(2.9, y_pos, text, ha='center', va='center', fontsize=8, color=NAVY)

    # Egress arrow
    ext_box = patches.FancyBboxPatch((0.9, 1.0), 4.0, 0.8,
                                    boxstyle="round,pad=0.1",
                                    edgecolor=GREY, facecolor=LIGHT_GREY, linewidth=1.2)
    ax.add_patch(ext_box)
    ax.text(2.9, 1.4, "Внешняя сеть / Подозрительный URL (Только HTTP/S)",
            ha='center', va='center', fontsize=8.5, fontweight='bold', color=GREY)
    ax.annotate('', xy=(2.9, 1.8), xytext=(2.9, 2.2),
                arrowprops=dict(arrowstyle="<->", color=RED, lw=1.5, ls=':'))

    # 2. Trusted Zone (Right)
    trusted_box = patches.FancyBboxPatch((5.8, 0.8), 5.7, 5.8,
                                        boxstyle="round,pad=0.2",
                                        edgecolor=GREEN, facecolor=LIGHT_GREEN,
                                        linewidth=2)
    ax.add_patch(trusted_box)
    ax.text(8.65, 6.3, "ДОВЕРЕННАЯ ЗОНА (Trusted Core & Orchestrator)",
            ha='center', va='center', fontsize=11, fontweight='bold', color=GREEN)
    ax.text(8.65, 5.95, "Оркестрация, генерация правил, ML/VLM, база знаний",
            ha='center', va='center', fontsize=8.5, fontstyle='italic', color=GREY)

    # Worker Container
    w_box = patches.FancyBboxPatch((6.1, 2.7), 5.1, 2.9,
                                  boxstyle="round,pad=0.15",
                                  edgecolor=SLATE, facecolor='white', linewidth=1.5)
    ax.add_patch(w_box)
    ax.text(8.65, 5.25, "Сервис: worker (:8000) — LangGraph Orchestrator",
            ha='center', va='center', fontsize=10.5, fontweight='bold', color=NAVY)

    w_modules = [
        ("6 Агентов: Triage, URL, DOM, Vision, Quishing, Synthesizer", LIGHT_BLUE),
        ("Реестр 175 брендов (Allowlist & Cyrillic Matcher)", LIGHT_BLUE),
        ("Генератор L-сигнатур (lar-rule-v1) и YARA правил", LIGHT_BLUE),
        ("Zero FPR Guard (3-уровневый верификатор)", LIGHT_GREEN)
    ]
    for i, (text, fcol) in enumerate(w_modules):
        y_pos = 4.65 - i * 0.55
        p = patches.FancyBboxPatch((6.3, y_pos - 0.18), 4.7, 0.38,
                                  boxstyle="round,pad=0.08",
                                  edgecolor=SLATE, facecolor=fcol, linewidth=1)
        ax.add_patch(p)
        ax.text(8.65, y_pos, text, ha='center', va='center', fontsize=8, color=NAVY)

    # Persistence & External AI
    db_box = patches.FancyBboxPatch((6.1, 1.0), 2.4, 1.3,
                                   boxstyle="round,pad=0.1",
                                   edgecolor=NAVY, facecolor='white', linewidth=1.2)
    ax.add_patch(db_box)
    ax.text(7.3, 1.8, "База Данных (:5432)", ha='center', va='center',
            fontsize=9, fontweight='bold', color=NAVY)
    ax.text(7.3, 1.4, "PostgreSQL 16 / SQLite\nИнциденты, правила, аудит",
            ha='center', va='center', fontsize=7.5, color=GREY)

    llm_box = patches.FancyBboxPatch((8.8, 1.0), 2.4, 1.3,
                                    boxstyle="round,pad=0.1",
                                    edgecolor=NAVY, facecolor='white', linewidth=1.2)
    ax.add_patch(llm_box)
    ax.text(10.0, 1.8, "VLM & LLM Бэкенд", ha='center', va='center',
            fontsize=9, fontweight='bold', color=NAVY)
    ax.text(10.0, 1.4, "Qwen-2.5-VL / DeepSeek\n(НГУ Cloud / Ollama)",
            ha='center', va='center', fontsize=7.5, color=GREY)

    # User & UI at top/side
    ui_box = patches.FancyBboxPatch((6.1, 6.7), 5.1, 0.65,
                                   boxstyle="round,pad=0.1",
                                   edgecolor=NAVY, facecolor=LIGHT_BLUE, linewidth=1.5)
    ax.add_patch(ui_box)
    ax.text(8.65, 7.02, "Сервис: ui (:8501) — Streamlit Аналитический Дашборд",
            ha='center', va='center', fontsize=9.5, fontweight='bold', color=NAVY)

    # Arrows between zones
    # UI <-> Worker
    ax.annotate('', xy=(8.65, 5.6), xytext=(8.65, 6.7),
                arrowprops=dict(arrowstyle="<->", color=NAVY, lw=1.5))
    ax.text(8.75, 6.15, "REST API / JSON", fontsize=7.5, color=NAVY)

    # Worker <-> Sandbox
    ax.annotate('', xy=(4.9, 3.9), xytext=(6.1, 3.9),
                arrowprops=dict(arrowstyle="<->", color=RED, lw=2))
    ax.text(5.5, 4.15, "POST /extract\nClean JSON", ha='center', fontsize=7.5, fontweight='bold', color=RED)

    # Worker <-> DB
    ax.annotate('', xy=(7.3, 2.7), xytext=(7.3, 2.3),
                arrowprops=dict(arrowstyle="<->", color=NAVY, lw=1.2))

    # Worker <-> LLM
    ax.annotate('', xy=(10.0, 2.7), xytext=(10.0, 2.3),
                arrowprops=dict(arrowstyle="<->", color=NAVY, lw=1.2))

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "fig1_system_architecture.png"), bbox_inches='tight')
    plt.close(fig)
    print("Fig 1 generated successfully.")


def create_fig2_langgraph_flow():
    fig, ax = plt.subplots(figsize=(12, 6.8), dpi=300)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7.2)
    ax.axis('off')

    ax.text(6, 6.8, "Граф Состояний Мультиагентного Конвейера (LangGraph StateGraph)",
            ha='center', va='center', fontsize=13, fontweight='bold', color=NAVY)

    # Nodes
    # 1. START
    start_p = patches.FancyBboxPatch((0.5, 4.8), 1.2, 0.8, boxstyle="round,pad=0.1",
                                    edgecolor=GREY, facecolor=LIGHT_GREY, lw=1.5)
    ax.add_patch(start_p)
    ax.text(1.1, 5.2, "START\n(Входной URL / файл)", ha='center', va='center', fontsize=8, fontweight='bold', color=NAVY)

    # 2. Triage Dispatcher
    triage_p = patches.FancyBboxPatch((2.2, 4.6), 1.7, 1.2, boxstyle="round,pad=0.1",
                                     edgecolor=SLATE, facecolor=LIGHT_BLUE, lw=1.5)
    ax.add_patch(triage_p)
    ax.text(3.05, 5.2, "1. Triage Agent\n& Sandbox Call\n(Рендеринг/Парсинг)",
            ha='center', va='center', fontsize=8, fontweight='bold', color=NAVY)

    # Connect START -> Triage
    ax.annotate('', xy=(2.2, 5.2), xytext=(1.7, 5.2),
                arrowprops=dict(arrowstyle="->", color=NAVY, lw=1.5))

    # Parallel Specialist Agents (Stacked in Column)
    spec_agents = [
        ("2. URL Agent\n(Редиректы, TLD, Punycode)", 4.5, 5.8),
        ("3. DOM Agent\n(Формы паролей, Submit buttons)", 4.5, 4.6),
        ("4. Vision Agent\n(VLM Детект бренда + Allowlist)", 4.5, 3.4),
        ("5. Quishing Agent\n(QR-коды, Office макросы)", 4.5, 2.2)
    ]

    for label, x, y in spec_agents:
        p = patches.FancyBboxPatch((x, y - 0.4), 2.1, 0.8, boxstyle="round,pad=0.1",
                                  edgecolor=SLATE, facecolor='white', lw=1.2)
        ax.add_patch(p)
        ax.text(x + 1.05, y, label, ha='center', va='center', fontsize=7.5, color=NAVY)
        # Arrow from triage to each agent
        ax.annotate('', xy=(x, y), xytext=(3.9, 5.2),
                    arrowprops=dict(arrowstyle="->", color=SLATE, lw=1.2, connectionstyle="arc3,rad=-0.1"))

    # Dynamic Rescan Edge from Quishing
    ax.annotate('QR нашел URL?\n(Conditional Loop)', xy=(3.05, 4.6), xytext=(5.55, 1.8),
                arrowprops=dict(arrowstyle="->", color=RED, lw=1.5, ls="--", connectionstyle="arc3,rad=0.35"),
                fontsize=7.5, fontweight='bold', color=RED)

    # Aggregator Node
    agg_p = patches.FancyBboxPatch((7.2, 3.6), 1.6, 1.4, boxstyle="round,pad=0.1",
                                  edgecolor=ORANGE, facecolor=LIGHT_ORANGE, lw=1.5)
    ax.add_patch(agg_p)
    ax.text(8.0, 4.3, "Aggregator Node\n(Сведение улик,\nпроверка условий\nрескана)",
            ha='center', va='center', fontsize=8, fontweight='bold', color=NAVY)

    # Arrows from specialists to Aggregator
    for _, x, y in spec_agents:
        ax.annotate('', xy=(7.2, 4.3), xytext=(x + 2.1, y),
                    arrowprops=dict(arrowstyle="->", color=SLATE, lw=1.2, connectionstyle="arc3,rad=0.05"))

    # Synthesizer Node
    synth_p = patches.FancyBboxPatch((9.3, 3.6), 1.7, 1.4, boxstyle="round,pad=0.1",
                                    edgecolor=GREEN, facecolor=LIGHT_GREEN, lw=1.5)
    ax.add_patch(synth_p)
    ax.text(10.15, 4.3, "6. Synthesizer &\nRule Generator\n(Risk Score,\nReason Codes,\nL-сигнатуры)",
            ha='center', va='center', fontsize=7.8, fontweight='bold', color=NAVY)

    ax.annotate('', xy=(9.3, 4.3), xytext=(8.8, 4.3),
                arrowprops=dict(arrowstyle="->", color=NAVY, lw=1.5))

    # Zero FPR Guard & DB Persist
    persist_p = patches.FancyBboxPatch((8.3, 1.2), 2.2, 1.1, boxstyle="round,pad=0.1",
                                      edgecolor=NAVY, facecolor=LIGHT_BLUE, lw=1.5)
    ax.add_patch(persist_p)
    ax.text(9.4, 1.75, "Zero FPR Guard &\nDatabase Persistence\n(PostgreSQL / SQLite)",
            ha='center', va='center', fontsize=8, fontweight='bold', color=NAVY)

    ax.annotate('', xy=(10.15, 2.3), xytext=(10.15, 3.6),
                arrowprops=dict(arrowstyle="->", color=GREEN, lw=1.5))
    ax.annotate('', xy=(8.3, 1.75), xytext=(7.5, 1.75),
                arrowprops=dict(arrowstyle="<-", color=NAVY, lw=1.5))

    # END
    end_p = patches.FancyBboxPatch((6.0, 1.3), 1.3, 0.8, boxstyle="round,pad=0.1",
                                  edgecolor=GREY, facecolor=LIGHT_GREY, lw=1.5)
    ax.add_patch(end_p)
    ax.text(6.65, 1.7, "END\n(Готовый вердикт\nи правила)", ha='center', va='center',
            fontsize=8, fontweight='bold', color=NAVY)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "fig2_langgraph_flow.png"), bbox_inches='tight')
    plt.close(fig)
    print("Fig 2 generated successfully.")


def create_fig3_zero_fpr_funnel():
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6)
    ax.axis('off')

    ax.text(5, 5.6, "Трехуровневая Архитектура Zero FPR Guard (Гарантия 0.00% FP)",
            ha='center', va='center', fontsize=13, fontweight='bold', color=NAVY)

    # 3 Layers Funnel
    levels = [
        ("УРОВЕНЬ 1: БЕЗУСЛОВНЫЙ ALLOWLIST БРЕНДОВ",
         "Сверка финального домена с реестром 175 брендов. Домены *.sberbank.ru, *.gosuslugi.ru и др. блокируются 0 раз.",
         LIGHT_GREEN, GREEN, 4.4, 8.4),
        ("УРОВЕНЬ 2: ГРАДУИРОВАННАЯ ШКАЛА РИСКА (ТРИ ЗОНЫ)",
         "Risk Score < 0.30: Чистый трафик (CLEAN) | 0.30 - 0.70: Подозрение (REVIEW в SOC) | >= 0.70: Блокировка (BLOCK)",
         LIGHT_BLUE, SLATE, 2.8, 6.8),
        ("УРОВЕНЬ 3: РЕГРЕССИОННЫЙ ТЕСТ НА ЧИСТОМ ДАТАСЕТЕ",
         "Автоматическая прогонка сгенерированной L-сигнатуры по 120+ легитимным письмам. Допуск в ACTIVE только при 0 FP.",
         LIGHT_ORANGE, ORANGE, 1.2, 5.2)
    ]

    for title, desc, fcol, ecol, y_pos, width in levels:
        x_left = 5.0 - width / 2.0
        p = patches.FancyBboxPatch((x_left, y_pos - 0.5), width, 1.0,
                                  boxstyle="round,pad=0.15",
                                  edgecolor=ecol, facecolor=fcol, lw=2)
        ax.add_patch(p)
        ax.text(5.0, y_pos + 0.15, title, ha='center', va='center',
                fontsize=9.5, fontweight='bold', color=NAVY)
        ax.text(5.0, y_pos - 0.2, desc, ha='center', va='center',
                fontsize=7.5, color=GREY)

    # Output badge at bottom
    out_p = patches.FancyBboxPatch((2.5, 0.05), 5.0, 0.6,
                                  boxstyle="round,pad=0.1",
                                  edgecolor=GREEN, facecolor=GREEN, lw=1.5)
    ax.add_patch(out_p)
    ax.text(5.0, 0.35, "РЕЗУЛЬТАТ: Статус ACTIVE_VERIFIED (0.00% FP на чистой деловой почте)",
            ha='center', va='center', fontsize=8.5, fontweight='bold', color='white')

    # Arrows between levels
    ax.annotate('', xy=(5, 3.4), xytext=(5, 3.8),
                arrowprops=dict(arrowstyle="->", color=NAVY, lw=2))
    ax.annotate('', xy=(5, 1.8), xytext=(5, 2.2),
                arrowprops=dict(arrowstyle="->", color=NAVY, lw=2))
    ax.annotate('', xy=(5, 0.65), xytext=(5, 0.7),
                arrowprops=dict(arrowstyle="->", color=GREEN, lw=2))

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "fig3_zero_fpr_funnel.png"), bbox_inches='tight')
    plt.close(fig)
    print("Fig 3 generated successfully.")


def create_fig4_dataset_threat_breakdown():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5), dpi=300)

    # Subplot 1: HTML Phishing Kits Techniques (7,642 samples)
    techniques = [
        "JS Execution\n(Встроенный скрипт)",
        "Формы ввода\nлогин / пароль",
        "SVG / Data URI\n(Smuggling)",
        "String.fromCharCode\n(Обфускация)",
        "Base64 / atob\n(Кодирование)",
        "Telegram / Discord\n(Эксфильтрация)"
    ]
    counts = [6931, 2896, 1399, 1110, 184, 109]
    colors = [SLATE, NAVY, ORANGE, RED, GREY, "#8E24AA"]

    bars = ax1.barh(techniques, counts, color=colors, edgecolor='none', height=0.6)
    ax1.set_xlabel("Количество обнаруженных образцов (из 7 642 файлов)", fontsize=9, color=NAVY)
    ax1.set_title("Структурные аномалии в HTML-вложениях\n(Датасет html_phishing2026)", fontsize=11, fontweight='bold', color=NAVY)
    ax1.grid(axis='x', linestyle='--', alpha=0.5)

    for bar in bars:
        w = bar.get_width()
        pct = (w / 7642.0) * 100
        ax1.text(w + 100, bar.get_y() + bar.get_height() / 2,
                 f"{w} ({pct:.1f}%)", ha='left', va='center', fontsize=8, color=NAVY, fontweight='bold')
    ax1.set_xlim(0, 8200)
    ax1.invert_yaxis()

    # Subplot 2: Visual Lures Categories (2,854 images)
    categories = [
        "SWIFT / MT103\nПлатежные документы",
        "Транспортные AWB\nDHL / FedEx / Почта",
        "Заказы и спецификации\nPO / RFQ Orders",
        "Счета фактуры\ne-Tax / Fapiao",
        "Прочие B2B\nуведомления"
    ]
    pcts = [56.3, 19.6, 16.9, 5.0, 2.2]
    colors_pie = [NAVY, SLATE, ORANGE, GREEN, GREY]

    wedges, texts, autotexts = ax2.pie(pcts, labels=categories, autopct='%1.1f%%',
                                      startangle=140, colors=colors_pie,
                                      wedgeprops=dict(width=0.45, edgecolor='white', linewidth=2),
                                      textprops=dict(fontsize=8, color=NAVY))
    for at in autotexts:
        at.set_color('white')
        at.set_weight('bold')
        at.set_fontsize(8)

    ax2.set_title("Кластеризация визуальных приманок\n(Датасет grouped_png_phishing2026, 2 854 файла)",
                  fontsize=11, fontweight='bold', color=NAVY)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "fig4_dataset_threat_breakdown.png"), bbox_inches='tight')
    plt.close(fig)
    print("Fig 4 generated successfully.")


def create_fig5_latency_performance():
    fig, ax = plt.subplots(figsize=(11, 5.5), dpi=300)

    operations = [
        "Тяжелый рендеринг Playwright (Sandbox)",
        "Мультимодальный анализ VLM (Qwen-2.5-VL)",
        "Полный цикл конвейера LangGraph (Worker)",
        "Проверка вложения YARA правилом",
        "Исполнение L-сигнатуры на клиенте Dr.Web"
    ]
    # Milliseconds
    latencies = [4200.0, 3500.0, 8400.0, 3.4, 1.2]
    colors = [RED, RED, ORANGE, GREEN, GREEN]

    y_pos = np.arange(len(operations))
    bars = ax.barh(y_pos, latencies, color=colors, height=0.55)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(operations, fontsize=9.5, fontweight='bold', color=NAVY)
    ax.set_xscale('log')
    ax.set_xlabel("Задержка выполнения (миллисекунды, логарифмическая шкала)", fontsize=10, color=NAVY)
    ax.set_title("Сравнение времени работы: Тяжелый анализ (SOC) vs. Локальный клиент (Dr.Web Engine)\nУскорение в 1 700 - 7 000 раз!",
                 fontsize=11, fontweight='bold', color=NAVY)
    ax.grid(axis='x', linestyle='--', alpha=0.5)

    for i, bar in enumerate(bars):
        w = bar.get_width()
        if w >= 1000:
            label = f"{w/1000:.1f} сек ({int(w)} мс)"
        else:
            label = f"{w:.1f} мс (Сверхбыстро)"
        ax.text(w * 1.2, bar.get_y() + bar.get_height()/2, label,
                ha='left', va='center', fontsize=9, fontweight='bold',
                color=GREEN if w < 10 else RED)

    ax.set_xlim(0.5, 30000)
    ax.invert_yaxis()

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "fig5_latency_performance.png"), bbox_inches='tight')
    plt.close(fig)
    print("Fig 5 generated successfully.")


def create_fig6_roadmap_2weeks():
    fig, ax = plt.subplots(figsize=(12, 6.2), dpi=300)
    ax.set_xlim(0, 15)
    ax.set_ylim(0, 7.5)
    ax.axis('off')

    ax.text(7.5, 7.0, "Детальная Дорожная Карта Развития ПО на 2 Недели (Дни 1 – 14)",
            ha='center', va='center', fontsize=13, fontweight='bold', color=NAVY)

    # Week 1 Box
    w1_box = patches.FancyBboxPatch((0.5, 1.0), 6.7, 5.5, boxstyle="round,pad=0.15",
                                   edgecolor=SLATE, facecolor=LIGHT_BLUE, lw=1.5)
    ax.add_patch(w1_box)
    ax.text(3.85, 6.2, "НЕДЕЛЯ 1 (Дни 1 – 7): Масштабирование и Углубленный Анализ",
            ha='center', va='center', fontsize=10, fontweight='bold', color=NAVY)

    w1_items = [
        ("День 1-2: Кластеризация кампаний (Graph & DBSCAN)",
         "Автоматическая группировка тысяч EML/HTML в единые кампании по DOM и URL инвариантам."),
        ("День 3-4: Расширенные парсеры макросов (VBA/OLE)",
         "Глубокий анализ DOCX/XLSX/PDF с извлечением шеллкодов и авто-генерацией YARA правил."),
        ("День 5-6: Интеграция онлайн-фидов угроз",
         "Автоматический коннектор к PhishTank, OpenPhish и VirusTotal для постоянного обогащения."),
        ("День 7: Верификационный контрольный прогон недели 1",
         "Сквозное тестирование на расширенной выборке 5 000 образцов с нулевым FPR.")
    ]

    for i, (title, desc) in enumerate(w1_items):
        y = 5.3 - i * 1.15
        p = patches.FancyBboxPatch((0.8, y - 0.4), 6.1, 0.85, boxstyle="round,pad=0.08",
                                  edgecolor=SLATE, facecolor='white', lw=1.0)
        ax.add_patch(p)
        ax.text(0.95, y + 0.12, title, fontsize=8.5, fontweight='bold', color=NAVY)
        ax.text(0.95, y - 0.18, desc, fontsize=7.2, color=GREY)

    # Week 2 Box
    w2_box = patches.FancyBboxPatch((7.8, 1.0), 6.7, 5.5, boxstyle="round,pad=0.15",
                                   edgecolor=GREEN, facecolor=LIGHT_GREEN, lw=1.5)
    ax.add_patch(w2_box)
    ax.text(11.15, 6.2, "НЕДЕЛЯ 2 (Дни 8 – 14): Высокая Нагрузка и Интеграция с Движком",
            ha='center', va='center', fontsize=10, fontweight='bold', color=GREEN)

    w2_items = [
        ("День 8-9: Высоконагруженная шина очередей (Redis/Celery)",
         "Асинхронная обработка до 100 000 объектов в сутки с пулом воркеров песочницы."),
        ("День 10-11: Native C++ / gRPC коннектор к ядру Dr.Web",
         "Сверхбыстрый модуль прямой загрузки L-сигнатур в локальный антиспам-демон."),
        ("День 12-13: Active Learning Loop & автокалибровка весов",
         "Автоматическая подстройка весов Reason Codes по обратной связи SOC-аналитиков."),
        ("День 14: Финальное стресс-тестирование и релиз DW-2.1",
         "Нагрузочные испытания, валидация Zero FPR, передача дистрибутива заказчику.")
    ]

    for i, (title, desc) in enumerate(w2_items):
        y = 5.3 - i * 1.15
        p = patches.FancyBboxPatch((8.1, y - 0.4), 6.1, 0.85, boxstyle="round,pad=0.08",
                                  edgecolor=GREEN, facecolor='white', lw=1.0)
        ax.add_patch(p)
        ax.text(8.25, y + 0.12, title, fontsize=8.5, fontweight='bold', color=NAVY)
        ax.text(8.25, y - 0.18, desc, fontsize=7.2, color=GREY)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "fig6_roadmap_2weeks.png"), bbox_inches='tight')
    plt.close(fig)
    print("Fig 6 generated successfully.")


if __name__ == "__main__":
    create_fig1_architecture()
    create_fig2_langgraph_flow()
    create_fig3_zero_fpr_funnel()
    create_fig4_dataset_threat_breakdown()
    create_fig5_latency_performance()
    create_fig6_roadmap_2weeks()
    print("All diagrams generated successfully in docs/diagrams/!")
