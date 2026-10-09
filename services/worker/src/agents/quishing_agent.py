import re
import time
from typing import Dict, Any, List
try:
    from ..orchestrator.state import PhishingState, AgentStepTrace
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace


DOUBLE_EXT_PATTERN = re.compile(
    r'(?i)\.(?:pdf|pfd|xlsx?|xlxs|docx?)\.png$'
)

CAMPAIGN_INVARIANTS = re.compile(
    r'(?i)(?:AWB[_-]1461983596|PO[_-]230270|PO[_-]0094321|MT103[_-]paymentform|电子发票[_-]22632020518862400758)'
)

class QuishingAgent:
    """Specialist agent detecting Quishing (QR-phishing), double extensions, and malicious attachments."""

    def run(self, state: PhishingState) -> Dict[str, Any]:
        t0 = time.time()
        initial_codes = set(state.reason_codes)
        state.execution_steps.append("quishing_agent: Inspecting attachments and QR codes")
        reasons = list(state.reason_codes)

        att_meta = state.attachment_evidence or {}
        filename = att_meta.get("filename", "") or state.raw_target

        # 1. Double extension check
        if DOUBLE_EXT_PATTERN.search(filename):
            reasons.append("RC_LURE_DOUBLE_EXTENSION")

        # 2. Campaign invariant pattern
        if CAMPAIGN_INVARIANTS.search(filename):
            reasons.append("RC_CAMPAIGN_INVARIANT_MATCH")

        # 3. QR code detection
        qr_codes = att_meta.get("qr_codes", [])
        if qr_codes:
            reasons.append("ATTACH_QR_CODE_FOUND")
            # Update discovered URLs
            discovered = list(state.discovered_urls_from_attachments)
            for q in qr_codes:
                if q.startswith(("http://", "https://")) and q not in discovered:
                    discovered.append(q)
            state.discovered_urls_from_attachments = discovered

        # 4. Office Macro markers
        if att_meta.get("has_vba_macros"):
            reasons.append("ATTACH_ACTIVE_MACRO_MARKER")

        # 5. Offline HTML form in attachment
        if att_meta.get("type") == "html" and att_meta.get("has_password_field"):
            reasons.append("ATTACH_OFFLINE_FORM")

        state.reason_codes = sorted(list(set(reasons)))

        added_codes = [c for c in state.reason_codes if c not in initial_codes]
        elapsed_ms = round((time.time() - t0) * 1000, 1)

        state.agent_traces.append(AgentStepTrace(
            agent_id="quishing_agent",
            agent_name="Quishing & Attachment Specialist Agent",
            icon="📦",
            phase="Phase 5: Attachment, QR & Stego Analysis",
            status="TRIGGERED" if added_codes else ("COMPLETED" if state.attachment_evidence else "SKIPPED"),
            duration_ms=elapsed_ms,
            reasoning=f"Инспекция бинарных вложений и графических файлов ({filename}). Поиск вредоносных QR-кодов (Quishing), маскировки расширений (.pdf.png), сигнатур целевых спам-кампаний и офисных VBA-макросов.",
            decision=f"Выявлено признаков вредоносных вложений: {len(added_codes)} шт. " + (f"[{', '.join(added_codes)}]" if added_codes else "[Признаков Quishing и скрытых вложений не обнаружено]"),
            tools_called=["ZXingQRCodeScanner", "DoubleExtensionDetector", "OfficeMacroInspector", "CampaignPatternClassifier"],
            findings=[
                {"label": "Имя файла вложения", "value": str(filename)},
                {"label": "Двойное расширение (.pdf.png)", "value": "Да" if "RC_LURE_DOUBLE_EXTENSION" in state.reason_codes else "Нет"},
                {"label": "Обнаружено QR-кодов", "value": str(len(qr_codes))},
                {"label": "Активные макросы VBA", "value": "Да" if "ATTACH_ACTIVE_MACRO_MARKER" in state.reason_codes else "Нет"},
                {"label": "Офлайн HTML-форма с паролем", "value": "Да" if "ATTACH_OFFLINE_FORM" in state.reason_codes else "Нет"}
            ],
            state_delta={
                "triggered_codes": added_codes,
                "discovered_urls_count": len(state.discovered_urls_from_attachments)
            }
        ))

        return state.model_dump()
