import os
import re
import time
from typing import Dict, Any, List, Optional

try:
    from ..orchestrator.state import PhishingState, RedirectHop, FormEvidence, AgentStepTrace
    from ..config import get_settings
    from ..sandbox_bridge import SandboxClient
    from ..features.url_features import hostname, registrable_domain
    from ..brands.matcher import get_brand_registry
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, RedirectHop, FormEvidence, AgentStepTrace
    from config import get_settings
    from sandbox_bridge import SandboxClient
    from features.url_features import hostname, registrable_domain
    from brands.matcher import get_brand_registry


# Links that are infrastructure noise, not the lure destination.
NOISE_LINK = re.compile(
    r'(?i)(unsubscribe|optout|opt-out|list-manage|/preferences|privacy|w3\.org|schemas\.|'
    r'\.(?:png|jpe?g|gif|svg|ico|css|woff2?)(?:\?|$)|fonts\.googleapis|facebook\.com/sharer|twitter\.com/intent)'
)
BULKY_FEATURE_KEYS = ("embedded_image_base64", "dom_html", "screenshot_base64", "body_html")


def _forms_from(raw_forms: List[Dict[str, Any]], origin: str) -> List[FormEvidence]:
    forms = []
    for f in raw_forms or []:
        submit = f.get("submit_button") or {}
        forms.append(FormEvidence(
            action=f.get("action", "") or "",
            action_host=f.get("action_host", "") or "",
            method=f.get("method", "GET") or "GET",
            has_password=bool(f.get("has_password")),
            has_email=bool(f.get("has_email")),
            has_card=bool(f.get("has_card")),
            prefilled_victim_email=bool(f.get("prefilled_victim_email")),
            is_external_target=bool(f.get("is_external")),
            submit_target_url=submit.get("target_url"),
            submit_mechanism="telegram_bot" if submit.get("has_telegram") else "standard_submit",
            origin=origin,
        ))
    return forms


def _compact(features: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in (features or {}).items() if k not in BULKY_FEATURE_KEYS}


def choose_primary_url(links: List[str], qr_codes: List[str], sender_domain: str = "") -> Optional[str]:
    """Picks the most probable lure destination among the links of an e-mail / document."""
    for q in qr_codes or []:
        if q.lower().startswith(("http://", "https://")):
            return q
    sender_site = registrable_domain(sender_domain) if sender_domain else ""
    registry = get_brand_registry()
    candidates = [u for u in links or [] if not NOISE_LINK.search(u)]
    # Links pointing away from the sender's own site and not to genuine brand sites are the lure.
    foreign = [u for u in candidates if registrable_domain(hostname(u)) != sender_site]
    unbranded = [u for u in foreign if not registry.find_brand_for_domain(u)]
    pool = unbranded or foreign or candidates or list(links or [])
    return pool[0] if pool else None


class TriageAgent:
    """Dispatches raw targets to the Sandbox and populates initial artifacts."""

    def __init__(self, settings=None, sandbox: Optional[SandboxClient] = None):
        self.settings = settings or get_settings()
        self.sandbox = sandbox or SandboxClient(self.settings)

    # ------------------------------------------------------------------ helpers
    def _apply_page(self, state: PhishingState, extracted: Dict[str, Any], origin: str) -> None:
        state.final_url = extracted.get("final_url") or state.final_url
        state.http_status = extracted.get("http_status", state.http_status)
        hops = [RedirectHop(url=h.get("url", ""), status_code=int(h.get("status") or h.get("status_code") or 0),
                            hop_type=h.get("type", "http_redirect"))
                for h in extracted.get("redirect_chain", []) or []]
        if hops:
            state.redirect_chain = hops
        if extracted.get("dom_html"):
            state.dom_html = extracted["dom_html"]
        if extracted.get("screenshot_base64"):
            state.screenshot_base64 = extracted["screenshot_base64"]
            state.screenshot_source = "browser"
        state.dom_forms = _forms_from(extracted.get("forms", []), origin)
        if extracted.get("dom_structural_hash"):
            state.dom_structural_hash = extracted["dom_structural_hash"]
            state.dom_skeleton = extracted.get("dom_skeleton")
        state.page_features = _compact(extracted)

    def _process_precollected(self, state: PhishingState) -> Dict[str, Any]:
        """Uses dataset artefacts (redirect chain, landing HTML, screenshot) instead of live crawling."""
        summaries = []
        for link in state.precollected_links:
            summaries.append({
                "url": link.get("url", ""),
                "final_url": link.get("final_url", ""),
                "hops": len(link.get("redirect_chain") or []),
                "status_codes": [h.get("status_code") for h in link.get("redirect_chain") or []],
                "js_meta_hops": sum(1 for h in link.get("redirect_chain") or [] if h.get("is_js_meta")),
                "has_html": bool(link.get("html")),
                "has_screenshot": bool(link.get("screenshot_base64")),
                "download_url": link.get("download_url"),
                "collection_error": link.get("collection_error"),
            })

        # Primary link: lures embed genuine brand links to borrow trust, so links ending on an
        # official brand domain come last; then collected landing pages with content first.
        registry = get_brand_registry()
        ranked = sorted(
            state.precollected_links,
            key=lambda l: (not NOISE_LINK.search(l.get("url") or ""),
                           not registry.find_brand_for_domain(l.get("final_url") or l.get("url") or ""),
                           bool(l.get("html")) and len(l.get("html", "")) > 200,
                           bool(l.get("screenshot_base64")),
                           not l.get("collection_error"),
                           len(l.get("redirect_chain") or [])),
            reverse=True)
        primary = ranked[0] if ranked else None
        if primary:
            state.scan_url = primary.get("url") or state.scan_url
            state.final_url = primary.get("final_url") or primary.get("url")
            chain = primary.get("redirect_chain") or []
            state.redirect_chain = [
                RedirectHop(url=h.get("from") or "", status_code=int(h.get("status_code") or 0),
                            hop_type="js_or_meta_redirect" if h.get("is_js_meta") else "http_redirect")
                for h in chain]
            state.http_status = 0 if primary.get("collection_error") else 200
            if primary.get("screenshot_base64"):
                state.screenshot_base64 = primary["screenshot_base64"]
                state.screenshot_source = "dataset"
            html = primary.get("html") or ""
            if html:
                state.dom_html = html
                parsed = self.sandbox.extract_file(html.encode("utf-8"), "landing.html", base_url=state.final_url or "")
                if parsed.get("error") and not parsed.get("forms") and parsed.get("type") == "unknown":
                    state.execution_steps.append(f"triage: landing page not parsed: {parsed['error']}")
                state.dom_forms = _forms_from(parsed.get("forms", []), "page")
                if parsed.get("dom_structural_hash"):
                    state.dom_structural_hash = parsed["dom_structural_hash"]
                    state.dom_skeleton = parsed.get("dom_skeleton")
                state.page_features = _compact(parsed)
                if not state.screenshot_base64 and parsed.get("screenshot_base64"):
                    state.screenshot_base64 = parsed["screenshot_base64"]
                    state.screenshot_source = "attachment_render"
        state.network_evidence["links"] = summaries
        return {"links": len(summaries), "primary": primary.get("url") if primary else None}

    # --------------------------------------------------------------------- run
    def run(self, state: PhishingState) -> PhishingState:
        t0 = time.time()
        state.execution_steps.append("triage_dispatcher: Processing input target")
        tools = []
        notes = []
        target = state.current_url
        is_url_target = state.has_rescanned_url or state.source_type == "url" or (
            isinstance(target, str) and target.startswith(("http://", "https://")) and not state.raw_bytes)

        if is_url_target:
            if state.offline_mode or state.precollected_links:
                notes.append("offline mode / pre-collected artefacts: live URL fetching skipped")
            else:
                extracted = self.sandbox.extract_url(target)
                tools.append("SandboxBrowserController")
                if extracted.get("error"):
                    notes.append(extracted["error"])
                    state.network_evidence["fetch_error"] = extracted["error"]
                if extracted.get("ssrf_blocked"):
                    state.network_evidence["ssrf_blocked"] = True
                if extracted.get("blocked_requests"):
                    state.network_evidence["blocked_subrequests"] = len(extracted["blocked_requests"])
                # During a rescan keep the attachment forms and only add page forms.
                attachment_forms = [f for f in state.dom_forms if f.origin == "attachment"]
                self._apply_page(state, extracted, "page")
                state.dom_forms = attachment_forms + state.dom_forms
        else:
            file_bytes = state.raw_bytes
            if not file_bytes and isinstance(state.raw_target, str) and os.path.isfile(state.raw_target):
                with open(state.raw_target, "rb") as f:
                    file_bytes = f.read()
            if file_bytes:
                extracted = self.sandbox.extract_file(file_bytes, os.path.basename(str(state.raw_target)) or "sample")
                tools.append("AttachmentParser")
                if extracted.get("error"):
                    notes.append(extracted["error"])
                kind = extracted.get("type", "unknown")
                if kind in ("eml", "html", "pdf", "office", "image", "archive"):
                    state.source_type = kind
                state.attachment_evidence = _compact(extracted)

                discovered = list(extracted.get("links", []) or [])
                for q in extracted.get("qr_codes", []) or []:
                    if q not in discovered:
                        discovered.append(q)
                state.discovered_urls_from_attachments = discovered

                if kind == "eml":
                    if extracted.get("body_html"):
                        state.dom_html = extracted["body_html"]
                    state.dom_forms = _forms_from(extracted.get("forms", []), "attachment")
                    primary = choose_primary_url(discovered, extracted.get("qr_codes", []), extracted.get("from_domain", ""))
                    if primary:
                        state.scan_url = primary
                elif kind == "html":
                    # The attachment itself is the phishing page.
                    state.dom_html = file_bytes.decode("utf-8", errors="ignore")
                    state.dom_forms = _forms_from(extracted.get("forms", []), "attachment")
                    if extracted.get("dom_structural_hash"):
                        state.dom_structural_hash = extracted["dom_structural_hash"]
                        state.dom_skeleton = extracted.get("dom_skeleton")
                    state.page_features = _compact(extracted)
                    if extracted.get("screenshot_base64"):
                        state.screenshot_base64 = extracted["screenshot_base64"]
                        state.screenshot_source = "attachment_render"
                    elif extracted.get("embedded_image_base64"):
                        state.screenshot_base64 = extracted["embedded_image_base64"]
                        state.screenshot_source = "embedded_image"
                elif kind == "image":
                    state.screenshot_base64 = extracted.get("screenshot_base64")
                    state.screenshot_source = "image_file"
                    if discovered:
                        state.scan_url = discovered[0]
                elif discovered:
                    state.scan_url = choose_primary_url(discovered, extracted.get("qr_codes", []))


        if state.precollected_links and not state.has_rescanned_url:
            info = self._process_precollected(state)
            tools.append("DatasetArtifactLoader")
            notes.append(f"pre-collected links: {info['links']}, primary: {info['primary']}")

        state.network_evidence["offline_mode"] = state.offline_mode
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        dom_len = len(state.dom_html or "")
        state.agent_traces.append(AgentStepTrace(
            agent_id="triage_dispatcher",
            agent_name="Triage & Sandbox Isolation Agent",
            icon="🧭",
            phase="Phase 1: Ingestion & Sandbox",
            status="WARNING" if notes and any("unreachable" in n or "failed" in n for n in notes) else "COMPLETED",
            duration_ms=elapsed_ms,
            reasoning=f"Валидация типа источника '{state.source_type}' ({state.raw_target}). Изоляция в Sandbox с защитой Anti-SSRF, раскрытие перенаправлений, офлайн-разбор вложений и собранных артефактов датасета.",
            decision=f"Извлечены: DOM ({dom_len} символов), цепочка редиректов ({len(state.redirect_chain)} хопов), снимок экрана ({state.screenshot_source or 'нет'}), формы ({len(state.dom_forms)} шт.)." + (f" Примечания: {'; '.join(notes)[:300]}" if notes else ""),
            tools_called=tools or ["none"],
            findings=[
                {"label": "Целевой объект", "value": str(state.raw_target)},
                {"label": "Тип источника", "value": state.source_type},
                {"label": "Анализируемый URL", "value": state.scan_url or "—"},
                {"label": "Финальный URL", "value": state.final_url or "—"},
                {"label": "HTTP статус", "value": str(state.http_status if state.http_status is not None else "—")},
                {"label": "Редиректов в цепочке", "value": str(len(state.redirect_chain))},
                {"label": "Интерактивных форм", "value": str(len(state.dom_forms))},
                {"label": "Ссылок во вложениях/письме", "value": str(len(state.discovered_urls_from_attachments))}
            ],
            state_delta={
                "final_url": state.final_url,
                "forms_count": len(state.dom_forms),
                "attachments_parsed": bool(state.attachment_evidence)
            }
        ))
        return state
