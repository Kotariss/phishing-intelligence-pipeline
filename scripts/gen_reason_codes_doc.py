"""Generates docs/REASON_CODES.md from the reason-code catalogue (single source of truth).

    python scripts/gen_reason_codes_doc.py
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "services", "worker", "src"))

from rules.reason_codes import REASON_CODES, NON_CLAMPABLE  # noqa: E402

CATEGORY_RU = {
    "network": "URL, домены и перенаправления", "dom": "HTML/DOM, формы и сценарии", "brand": "Имитация бренда",
    "email": "Признаки письма", "attachment": "Вложения и QR-коды", "campaign": "Индикаторы кампаний",
    "content": "Анализ текста приманки (LLM)", "combo": "Составные признаки", "info": "Информационные",
}


def main():
    lines = [
        "# Таксономия фишинговых техник и коды причин",
        "",
        "> Файл сгенерирован `python scripts/gen_reason_codes_doc.py` из `services/worker/src/rules/reason_codes.py`.",
        "",
        "Каждый вердикт сопровождается перечнем кодов причин и подтверждающими признаками (`reason_details`).",
        "Риск объекта — комбинация независимых улик по схеме noisy-OR: `risk = 1 − Π(1 − wᵢ)`.",
        "Пороги: `< 0.30` — признаков фишинга не обнаружено, `0.30–0.70` — подозрительно, `≥ 0.70` — фишинг.",
        "Ни один одиночный некритичный признак не даёт `≥ 0.70` (проверяется тестом `test_no_single_non_critical_indicator_reaches_block`).",
        "",
        "Коды, помеченные «не нейтрализуется», сохраняются даже если финальная страница находится на официальном домене бренда.",
        "",
    ]
    by_cat = {}
    for code, info in REASON_CODES.items():
        by_cat.setdefault(info.category, []).append((code, info))
    for cat in ("network", "dom", "brand", "email", "attachment", "campaign", "content", "combo", "info"):
        if cat not in by_cat:
            continue
        lines += [f"## {CATEGORY_RU.get(cat, cat)}", "", "| Код | Вес | Важность | Описание |", "|---|---|---|---|"]
        for code, info in sorted(by_cat[cat], key=lambda t: -t[1].weight):
            mark = " (не нейтрализуется)" if code in NON_CLAMPABLE else ""
            lines.append(f"| `{code}` | {info.weight:.2f} | {info.severity}{mark} | {info.description} |")
        lines.append("")
    out = os.path.join(ROOT, "docs", "REASON_CODES.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Wrote {out} ({len(REASON_CODES)} codes)")


if __name__ == "__main__":
    main()
