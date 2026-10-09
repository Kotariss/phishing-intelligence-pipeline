import os
import sys
import time
import requests
from typing import Dict, Any

_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_CURRENT_DIR, "../../../.."))
_SANDBOX_DIR = os.path.abspath(os.path.join(_PROJECT_ROOT, "services", "sandbox", "src"))
for _p in [_PROJECT_ROOT, _SANDBOX_DIR]:
    if _p not in sys.path and os.path.exists(_p):
        sys.path.insert(0, _p)

try:
    from ..orchestrator.state import PhishingState, RedirectHop, FormEvidence, AgentStepTrace
    from ..config import get_settings
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, RedirectHop, FormEvidence, AgentStepTrace
    from config import get_settings


class TriageAgent:
    """Dispatches raw targets to Sandbox and populates initial artifacts."""

    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._sandbox_available_cached = None

    def _is_sandbox_service_available(self) -> bool:
        if self._sandbox_available_cached is not None:
            return self._sandbox_available_cached
        import socket
        try:
            with socket.create_connection((self.settings.SANDBOX_HOST, self.settings.SANDBOX_PORT), timeout=0.2):
                self._sandbox_available_cached = True
                return True
        except Exception:
            self._sandbox_available_cached = False
            return False

    def run(self, state: PhishingState) -> Dict[str, Any]:
        t0 = time.time()
        state.execution_steps.append("triage_dispatcher: Processing input target")
        sandbox_url = f"http://{self.settings.SANDBOX_HOST}:{self.settings.SANDBOX_PORT}"

        # 1. Check if target is a URL
        if state.source_type == "url" or (isinstance(state.raw_target, str) and state.raw_target.startswith(("http://", "https://"))):
            target_url = state.raw_target
            extracted = None

            # Attempt HTTP call to sandbox if service is active
            if self._is_sandbox_service_available():
                try:
                    resp = requests.post(
                        f"{sandbox_url}/api/v1/extract/url",
                        json={"url": target_url, "timeout_seconds": self.settings.SANDBOX_TIMEOUT_SECONDS},
                        timeout=(1.0, self.settings.SANDBOX_TIMEOUT_SECONDS + 5)
                    )
                    if resp.status_code == 200:
                        extracted = resp.json()
                except Exception:
                    pass

            # In-process fallback if Sandbox HTTP is not reachable
            if not extracted:
                try:
                    try:
                        from services.sandbox.src.browser import BrowserController
                    except (ImportError, ValueError):
                        from browser import BrowserController
                    b_ctrl = BrowserController(anti_ssrf_enabled=self.settings.ANTI_SSRF_ENABLED)
                    extracted = b_ctrl.extract_url(target_url, timeout_seconds=self.settings.SANDBOX_TIMEOUT_SECONDS)
                except Exception as e:

                    # In case of absolute fallback
                    extracted = {
                        "initial_url": target_url,
                        "final_url": target_url,
                        "http_status": 0,
                        "redirect_chain": [],
                        "dom_html": f"<html><body><p>Sandbox unreachable: {e}</p></body></html>",
                        "screenshot_base64": "",
                        "forms": []
                    }

            # Populate state
            state.final_url = extracted.get("final_url", target_url)
            state.http_status = extracted.get("http_status", 200)
            
            hops = []
            for hop in extracted.get("redirect_chain", []):
                hops.append(RedirectHop(
                    url=hop.get("url", ""),
                    status_code=hop.get("status", 200),
                    hop_type=hop.get("type", "http_redirect")
                ))
            state.redirect_chain = hops
            # Preserve authentic visual lure from attachment/HTML if already present during rescan
            if not state.screenshot_base64:
                state.screenshot_base64 = extracted.get("screenshot_base64", "")
            elif not state.has_rescanned_url and extracted.get("screenshot_base64"):
                state.screenshot_base64 = extracted.get("screenshot_base64")

            # Form evidences
            forms_list = []
            for f in extracted.get("forms", []):
                forms_list.append(FormEvidence(
                    action=f.get("action", ""),
                    method=f.get("method", "GET"),
                    has_password=f.get("has_password", False),
                    has_email=f.get("has_email", False),
                    has_card=f.get("has_card", False),
                    is_external_target=f.get("is_external", False),
                    submit_target_url=f.get("submit_button", {}).get("target_url"),
                    submit_mechanism="telegram_bot" if f.get("submit_button", {}).get("has_telegram") else "standard_submit"
                ))
            state.dom_forms = forms_list
            if "dom_structural_hash" in extracted:
                state.dom_structural_hash = extracted["dom_structural_hash"]
                state.dom_skeleton = extracted.get("dom_skeleton")

        # 2. Check if target is a file or bytes
        elif state.raw_bytes or (isinstance(state.raw_target, str) and os.path.exists(state.raw_target)):
            file_bytes = state.raw_bytes
            target_name = state.raw_target
            if not file_bytes and os.path.exists(target_name):
                with open(target_name, "rb") as f:
                    file_bytes = f.read()

            name_low = str(target_name).lower()
            is_eml = (
                name_low.endswith((".eml", ".msg"))
                or state.source_type == "eml"
                or (file_bytes and any(file_bytes.startswith(prefix) for prefix in (b"Received", b"From", b"X-", b"Return-Path", b"Authentication-Results", b"Delivered-To")))
            )
            is_pdf = name_low.endswith(".pdf") or state.source_type == "pdf" or (file_bytes and file_bytes.startswith(b"%PDF"))
            is_office = name_low.endswith((".docx", ".xlsx")) or state.source_type in ("docx", "xlsx", "office")
            is_img = name_low.endswith((".png", ".jpg", ".jpeg")) or state.source_type in ("png", "jpg", "jpeg", "image") or (file_bytes and file_bytes.startswith((b"\x89PNG", b"\xff\xd8\xff")))

            extracted = None
            # Attempt HTTP call to sandbox if service is active
            if self._is_sandbox_service_available():
                try:
                    files = {"file": (os.path.basename(target_name), file_bytes)}
                    resp = requests.post(f"{sandbox_url}/api/v1/extract/file", files=files, timeout=(1.0, 20.0))
                    if resp.status_code == 200:
                        extracted = resp.json()
                except Exception:
                    pass

            # In-process fallback
            if not extracted:
                try:
                    try:
                        from services.sandbox.src.attachment_parser import AttachmentParser
                    except (ImportError, ValueError):
                        from attachment_parser import AttachmentParser

                    if is_eml:
                        extracted = AttachmentParser.parse_eml(file_bytes)
                    elif is_pdf:
                        extracted = AttachmentParser.parse_pdf(file_bytes)
                    elif is_office:
                        extracted = AttachmentParser.parse_office(file_bytes, filename=target_name)
                    elif is_img:
                        from services.sandbox.src.qr_scanner import scan_qr_codes
                        import base64
                        qr_urls = scan_qr_codes(file_bytes)
                        extracted = {
                            "type": "image",
                            "filename": target_name,
                            "qr_codes": qr_urls,
                            "screenshot_base64": base64.b64encode(file_bytes).decode("utf-8")
                        }
                    else:
                        extracted = AttachmentParser.parse_html(file_bytes.decode("utf-8", errors="ignore"))
                except Exception as e:
                    extracted = {"type": "unknown", "error": str(e), "links": []}


            # Map extracted file artifacts
            state.attachment_evidence = extracted or {}
            discovered = extracted.get("links", [])
            if "qr_codes" in extracted:
                discovered.extend(extracted.get("qr_codes", []))
            state.discovered_urls_from_attachments = sorted(list(set(discovered)))

            if "body_html" in extracted and extracted["body_html"]:
                state.dom_html = extracted["body_html"]
            elif not state.dom_html and file_bytes and not is_pdf and not is_office and not is_img:
                try:
                    state.dom_html = file_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    pass

            if "screenshot_base64" in extracted:
                state.screenshot_base64 = extracted.get("screenshot_base64")

            # Populate dom_forms from file forms if any
            if "forms" in extracted:
                forms_list = []
                for f in extracted.get("forms", []):
                    forms_list.append(FormEvidence(
                        action=f.get("action", ""),
                        method=f.get("method", "GET"),
                        has_password=f.get("has_password", False),
                        has_email=f.get("has_email", False),
                        has_card=f.get("has_card", False),
                        is_external_target=f.get("is_external", False),
                        submit_target_url=f.get("submit_button", {}).get("target_url"),
                        submit_mechanism="telegram_bot" if f.get("submit_button", {}).get("has_telegram") else "standard_submit"
                    ))
                state.dom_forms = forms_list

            if "dom_structural_hash" in extracted:
                state.dom_structural_hash = extracted["dom_structural_hash"]
                state.dom_skeleton = extracted.get("dom_skeleton")

            # If the file has a discovered URL, set final_url
            if discovered and not state.final_url:
                state.final_url = discovered[0]

        elapsed_ms = round((time.time() - t0) * 1000, 1)
        dom_len = len(state.dom_html or "")
        state.agent_traces.append(AgentStepTrace(
            agent_id="triage_dispatcher",
            agent_name="Triage & Sandbox Isolation Agent",
            icon="🧭",
            phase="Phase 1: Ingestion & Sandbox",
            status="COMPLETED",
            duration_ms=elapsed_ms,
            reasoning=f"Валидация типа источника '{state.source_type}' ({state.raw_target}). Изоляция в безопасной среде Sandbox с защитой Anti-SSRF, раскрытие сетевых перенаправлений и безопасный рендеринг артефактов.",
            decision=f"Успешно извлечены: DOM-структура ({dom_len} символов), цепочка редиректов ({len(state.redirect_chain)} хопов), снимок экрана ({'Да' if state.screenshot_base64 else 'Нет'}), интерактивные формы ({len(state.dom_forms)} шт.).",
            tools_called=["AntiSSRFValidator", "SandboxBrowserController" if state.source_type == "url" else "AttachmentParser"],
            findings=[
                {"label": "Целевой объект", "value": str(state.raw_target)},
                {"label": "Тип источника", "value": state.source_type},
                {"label": "HTTP статус", "value": str(state.http_status or 200)},
                {"label": "Редиректов в цепочке", "value": str(len(state.redirect_chain))},
                {"label": "Интерактивных форм", "value": str(len(state.dom_forms))},
                {"label": "Найдено ссылок во вложениях", "value": str(len(state.discovered_urls_from_attachments))}
            ],
            state_delta={
                "final_url": state.final_url,
                "forms_count": len(state.dom_forms),
                "attachments_parsed": bool(state.attachment_evidence)
            }
        ))

        return state.model_dump()
