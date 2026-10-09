import time
from typing import Literal
from langgraph.graph import StateGraph, START, END

try:
    from .state import PhishingState, AgentStepTrace
    from ..agents.triage_agent import TriageAgent
    from ..agents.url_agent import URLAgent
    from ..agents.dom_agent import DOMAgent
    from ..agents.vision_agent import VisionAgent
    from ..agents.quishing_agent import QuishingAgent
    from ..agents.content_agent import ContentAgent
    from ..agents.synthesizer_agent import SynthesizerAgent
    from ..db.repository import IncidentRepository
    from ..db.database import init_db
    from ..rules.exporter import export_artifacts
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from agents.triage_agent import TriageAgent
    from agents.url_agent import URLAgent
    from agents.dom_agent import DOMAgent
    from agents.vision_agent import VisionAgent
    from agents.quishing_agent import QuishingAgent
    from agents.content_agent import ContentAgent
    from agents.synthesizer_agent import SynthesizerAgent
    from db.repository import IncidentRepository
    from db.database import init_db
    from rules.exporter import export_artifacts


init_db()


def triage_node(state: PhishingState) -> PhishingState:
    return TriageAgent().run(state)


def url_node(state: PhishingState) -> PhishingState:
    return URLAgent().run(state)


def dom_node(state: PhishingState) -> PhishingState:
    return DOMAgent().run(state)


def vision_node(state: PhishingState) -> PhishingState:
    return VisionAgent().run(state)


def quishing_node(state: PhishingState) -> PhishingState:
    return QuishingAgent().run(state)


def content_node(state: PhishingState) -> PhishingState:
    return ContentAgent().run(state)


def aggregator_node(state: PhishingState) -> PhishingState:
    t0 = time.time()
    state.execution_steps.append("aggregator: Merging specialist agent evidences")
    # A second pass analyses the lure destination found in an e-mail / document / QR code, unless the
    # landing page is already known (pre-collected dataset artefacts) or networking is not allowed.
    candidate = state.scan_url
    state.should_rescan = bool(
        candidate and candidate.startswith(("http://", "https://"))
        and not state.has_rescanned_url
        and not state.offline_mode
        and not state.precollected_links
        and state.source_type != "url"
    )
    if state.should_rescan:
        state.has_rescanned_url = True

    elapsed_ms = round((time.time() - t0) * 1000, 1)
    state.agent_traces.append(AgentStepTrace(
        agent_id="aggregator",
        agent_name="Dynamic Aggregator & Rescan Router",
        icon="🔄",
        phase="Phase 6: Multi-Agent Convergence",
        status="TRIGGERED" if state.should_rescan else "COMPLETED",
        duration_ms=elapsed_ms,
        reasoning="Сведение улик специализированных агентов и решение об условном переходе LangGraph: нужен ли второй проход по целевой ссылке из письма/вложения/QR.",
        decision=(f"Повторный анализ целевой ссылки {candidate} через Sandbox." if state.should_rescan else
                  "Улик достаточно (или сеть запрещена офлайн-режимом), переход к синтезу."),
        tools_called=["LangGraphConditionalRouter"],
        findings=[
            {"label": "Ссылки из письма/вложений", "value": str(len(state.discovered_urls_from_attachments))},
            {"label": "Целевая ссылка", "value": candidate or "—"},
            {"label": "Динамический рескан", "value": "Да" if state.should_rescan else "Нет"}
        ],
        state_delta={"should_rescan": state.should_rescan}
    ))
    return state


def should_rescan_attachment_url(state: PhishingState) -> Literal["triage_dispatcher", "synthesizer"]:
    return "triage_dispatcher" if state.should_rescan else "synthesizer"


def synthesizer_node(state: PhishingState) -> PhishingState:
    return SynthesizerAgent().run(state)


def persist_node(state: PhishingState) -> PhishingState:
    t0 = time.time()
    state.execution_steps.append("db_persist: Saving incident dossier and L-signatures")
    repo = IncidentRepository()
    public = state.public_dump()

    repo.create_incident({
        "id": state.incident_id,
        "source_type": state.source_type,
        "raw_target": state.raw_target,
        "final_url": state.final_url,
        "verdict": state.verdict,
        "risk_score": state.risk_score,
        "confidence": state.confidence,
        "target_brand": state.brand_evidence.detected_brand_name,
        "reason_codes": state.reason_codes,
        "zero_fpr_passed": state.zero_fpr_passed,
        "explanation": state.explanation,
        "campaign_id": state.campaign_id,
        "dom_hash": state.dom_structural_hash,
        "fingerprints": state.fingerprints,
        "evidence_data": {
            "network": public["network_evidence"],
            "page": public["page_features"],
            "forms": public["dom_forms"],
            "brand": public["brand_evidence"],
            "attachment": {k: v for k, v in public["attachment_evidence"].items() if k != "body_html"},
            "redirect_chain": public["redirect_chain"],
            "reason_details": public["reason_details"],
            "reason_evidence": public["reason_evidence"],
            "screenshot_source": state.screenshot_source,
            "agent_traces": public["agent_traces"],
        }
    })

    exported = None
    if state.generated_l_signature:
        status = state.signature_status or "DRAFT_REQUIRES_TUNING"
        repo.create_signature({
            "id": state.generated_l_signature["rule_id"],
            "incident_id": state.incident_id,
            "name": state.generated_l_signature["name"],
            "target_brand": state.generated_l_signature.get("target_brand") or "Generic",
            "version": 1,
            "status": status,
            "rule_json": state.generated_l_signature,
            "yara_rule": state.generated_yara_rule
        })
        try:
            exported = export_artifacts(state.generated_l_signature, state.generated_yara_rule, status)
        except OSError as e:
            state.execution_steps.append(f"db_persist: export failed: {e}")

    elapsed_ms = round((time.time() - t0) * 1000, 1)
    state.agent_traces.append(AgentStepTrace(
        agent_id="db_persist",
        agent_name="Database Persistence & Catalog Node",
        icon="💾",
        phase="Phase 8: Persistence & Knowledge Base",
        status="COMPLETED",
        duration_ms=elapsed_ms,
        reasoning="Фиксация досье расследования, отпечатков, кампании и сгенерированных правил в базе знаний; экспорт проверенных правил.",
        decision=f"Инцидент {state.incident_id} сохранён. Сигнатура: {state.signature_status}. Кампания: {state.campaign_id or '—'}.",
        tools_called=["IncidentRepository.create_incident", "IncidentRepository.create_signature", "export_artifacts"],
        findings=[
            {"label": "Incident ID", "value": state.incident_id},
            {"label": "L-сигнатура", "value": state.generated_l_signature["rule_id"] if state.generated_l_signature else "Нет"},
            {"label": "Экспорт", "value": exported or "—"}
        ]
    ))
    return state


def build_phishing_pipeline():
    workflow = StateGraph(PhishingState)

    workflow.add_node("triage_dispatcher", triage_node)
    workflow.add_node("url_agent", url_node)
    workflow.add_node("dom_agent", dom_node)
    workflow.add_node("vision_agent", vision_node)
    workflow.add_node("quishing_agent", quishing_node)
    workflow.add_node("content_agent", content_node)
    workflow.add_node("aggregator", aggregator_node)
    workflow.add_node("synthesizer", synthesizer_node)
    workflow.add_node("db_persist", persist_node)

    # Specialists run sequentially: each one reads the evidence of the previous ones
    # (e.g. the vision agent uses the look-alike domain found by the URL agent).
    workflow.add_edge(START, "triage_dispatcher")
    workflow.add_edge("triage_dispatcher", "url_agent")
    workflow.add_edge("url_agent", "dom_agent")
    workflow.add_edge("dom_agent", "vision_agent")
    workflow.add_edge("vision_agent", "quishing_agent")
    workflow.add_edge("quishing_agent", "content_agent")
    workflow.add_edge("content_agent", "aggregator")
    workflow.add_conditional_edges(
        "aggregator",
        should_rescan_attachment_url,
        {"triage_dispatcher": "triage_dispatcher", "synthesizer": "synthesizer"}
    )
    workflow.add_edge("synthesizer", "db_persist")
    workflow.add_edge("db_persist", END)

    return workflow.compile()


_compiled_app = None


def get_pipeline():
    global _compiled_app
    if _compiled_app is None:
        _compiled_app = build_phishing_pipeline()
    return _compiled_app


def run_pipeline(initial_state: PhishingState) -> PhishingState:
    result = get_pipeline().invoke(initial_state)
    if isinstance(result, dict):
        return PhishingState(**result)
    return result
