#!/usr/bin/env bash
# Builds a clean copy of the repository for a public GitHub push: the full commit history with everything that belongs to the
# Customer (ТЗ 4.5.2.2) or is internal working material removed from EVERY commit. The working repository is not modified.
#
#   scripts/publish_public.sh <output-dir>        # build + scan, no push
#   cd <output-dir> && git remote add origin <url> && git push --force origin main
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: publish_public.sh <output-dir>}"
rm -rf "$OUT"
git clone -q --no-local "$SRC" "$OUT"
cd "$OUT"
git checkout -q -B main

# Customer documents, data-derived analyses and internal notes (never published)
EXCLUDE=(
  "docs/ТЗ_DW_2_v3_правки.docx" "docs/Task_2.pdf" "docs/Что хотят DW2.pdf" "docs/Task.md" "docs/ИНФА ПРЕЗА И ТАБЛИЦА.md"
  "docs/Техническая_документация_Phishing_Intelligence_Pipeline.docx" "docs/Phishing_Intelligence_Pipeline_Technical_Documentation.docx"
  "docs/archive" "docs/diagrams" "docs/extracted_slides" "docs/threat_research" "docs/presentation" "docs/report" "docs/labelling"
  "docs/BACKLOG.md" "docs/TZ_GAPS.md" "docs/PMI_DATA_FOR_CURATOR.md" "docs/TECHNICAL_DOCS.md" "docs/DW-2_Project_Summary.md"
  "docs/ai_client.py" "docs/font.ttf" "docs/explanation_page.png" "docs/dw2_slide_1.png" "docs/dw2_slide_2.png" "docs/dw2_slide_3.png"
  "docs/dw2_slide_4.png" "docs/dw2_slide_5.png" "docs/dw2_slide_6.png" "docs/dw2_slide_7.png" "docs/dw2_slide_8.png"
  "docs/00_INDEX.md" "docs/01_SYSTEM_ARCHITECTURE.md" "docs/02_SANDBOX_AND_SECURITY.md" "docs/03_MULTIAGENT_ORCHESTRATION.md"
  "docs/04_L_SIGNATURES_AND_ZERO_FPR.md" "docs/05_STREAMLIT_UI_SPEC.md" "docs/06_IMPLEMENTATION_ROADMAP.md"
  "exports" "reports" "logs" "file_for_case" "pipeline.db" "services/worker/src/exports" "services/worker/src/logs"
)
FILTER="git rm -r -q --cached --ignore-unmatch --"
for p in "${EXCLUDE[@]}"; do FILTER+=" '$p'"; done
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --prune-empty --index-filter "$FILTER" -- main >/dev/null 2>&1
git for-each-ref --format='%(refname)' refs/original | xargs -r -n1 git update-ref -d
git remote remove origin
git reflog expire --expire=now --all
git gc -q --prune=now
git tag -l | xargs -r git tag -d >/dev/null
echo "history: $(git rev-list --count HEAD) commits, $(git ls-files | wc -l) files, $(du -sh .git | cut -f1)"
