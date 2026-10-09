import uuid
import time
import datetime
from typing import Dict, Any, Literal
from langgraph.graph import StateGraph, START, END

try:
    from .state import PhishingState, AgentStepTrace
    from ..agents.triage_agent import TriageAgent
    from ..agents.url_agent import URLAgent
    from ..agents.dom_agent import DOMAgent
    from ..agents.vision_agent import VisionAgent
    from ..agents.quishing_agent import QuishingAgent
    from ..agents.synthesizer_agent import SynthesizerAgent
    from ..db.repository import IncidentRepository
    from ..db.database import init_db
except (ImportError, ValueError):
    from orchestrator.state import PhishingState, AgentStepTrace
    from agents.triage_agent import TriageAgent
    from agents.url_agent import URLAgent
    from agents.dom_agent import DOMAgent
    from agents.vision_agent import VisionAgent
    from agents.quishing_agent import QuishingAgent
    from agents.synthesizer_agent import SynthesizerAgent
    from db.repository import IncidentRepository
    from db.database import init_db


# Initialize database schema
init_db()

# Node functions
def triage_node(state: PhishingState) -> PhishingState:
    triage_agent = TriageAgent()
    data = triage_agent.run(state)
    return PhishingState(**data)

def url_node(state: PhishingState) -> PhishingState:
    agent = URLAgent()
    data = agent.run(state)
    return PhishingState(**data)

def dom_node(state: PhishingState) -> PhishingState:
    agent = DOMAgent()
    data = agent.run(state)
    return PhishingState(**data)

def vision_node(state: PhishingState) -> PhishingState:
    agent = VisionAgent()
    data = agent.run(state)
    return PhishingState(**data)

def quishing_node(state: PhishingState) -> PhishingState:
    agent = QuishingAgent()
    data = agent.run(state)
    return PhishingState(**data)

def aggregator_node(state: PhishingState) -> PhishingState:
    t0 = time.time()
    state.execution_steps.append("aggregator: Merging specialist agent evidences")
    # If attachment parser or quishing found URLs and we haven't done a rescan yet:
    if state.discovered_urls_from_attachments and not state.has_rescanned_url:
        state.has_rescanned_url = True
        state.should_rescan = True
        state.raw_target = state.discovered_urls_from_attachments[0]
        state.source_type = "url"
    else:
        state.should_rescan = False

    elapsed_ms = round((time.time() - t0) * 1000, 1)
    state.agent_traces.append(AgentStepTrace(
        agent_id="aggregator",
        agent_name="Dynamic Aggregator & Rescan Router",
        icon="🔄",
        phase="Phase 6: Multi-Agent Convergence",
        status="TRIGGERED" if state.should_rescan else "COMPLETED",
        duration_ms=elapsed_ms,
        reasoning="Сведение и синхронизация улик со всех 5 специализированных агентов. Проверка необходимости динамического ветвления (Conditional Edge) конвейера LangGraph.",
        decision=f"Обнаружено {len(state.discovered_urls_from_attachments)} ссылок во вложениях. " + ("Требуется дополнительный цикл анализа извлеченного URL через песочницу." if state.should_rescan else "Улик достаточно, переход к этапу финального синтеза."),
        tools_called=["LangGraphConditionalRouter"],
        findings=[
            {"label": "Ссылки из вложений", "value": str(len(state.discovered_urls_from_attachments))},
            {"label": "Динамический рескан", "value": "Да" if state.should_rescan else "Нет"}
        ],
        state_delta={"should_rescan": state.should_rescan}
    ))
    return state

def should_rescan_attachment_url(state: PhishingState) -> Literal["triage_dispatcher", "synthesizer"]:
    if state.should_rescan:
        return "triage_dispatcher"
    return "synthesizer"

def synthesizer_node(state: PhishingState) -> PhishingState:
    agent = SynthesizerAgent()
    data = agent.run(state)
    return PhishingState(**data)

def persist_node(state: PhishingState) -> PhishingState:
    t0 = time.time()
    state.execution_steps.append("db_persist: Saving incident dossier and L-signatures")
    repo = IncidentRepository()
    
    # Save incident
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
        "evidence_data": {
            "network": state.network_evidence,
            "dom_forms_count": len(state.dom_forms),
            "brand": state.brand_evidence.model_dump(),
            "attachment": state.attachment_evidence,
            "redirect_chain": [h.model_dump() for h in state.redirect_chain],
            "agent_traces": [t.model_dump() for t in state.agent_traces]
        }
    })

    # Save L-signature if generated
    if state.generated_l_signature:
        repo.create_signature({
            "id": state.generated_l_signature["rule_id"],
            "incident_id": state.incident_id,
            "name": state.generated_l_signature["name"],
            "target_brand": state.brand_evidence.detected_brand_name or "Generic",
            "version": 1,
            "status": "ACTIVE_VERIFIED" if state.zero_fpr_passed else "DRAFT_REQUIRES_TUNING",
            "rule_json": state.generated_l_signature,
            "yara_rule": state.generated_yara_rule
        })

    elapsed_ms = round((time.time() - t0) * 1000, 1)
    state.agent_traces.append(AgentStepTrace(
        agent_id="db_persist",
        agent_name="Database Persistence & Catalog Node",
        icon="💾",
        phase="Phase 8: Persistence & Knowledge Base",
        status="COMPLETED",
        duration_ms=elapsed_ms,
        reasoning="Фиксация полного досье расследования, цепочки улик и сгенерированных правил в реляционной базе данных SQLite.",
        decision=f"Инцидент {state.incident_id} успешно сохранен в базе данных. Статус сигнатуры: {'АКТИВНА' if state.zero_fpr_passed else 'ЧЕРНОВИК'}.",
        tools_called=["IncidentRepository.create_incident", "IncidentRepository.create_signature"],
        findings=[
            {"label": "Incident ID", "value": state.incident_id},
            {"label": "Сохранена L-сигнатура", "value": "Да" if state.generated_l_signature else "Нет"},
            {"label": "Сохранено YARA правило", "value": "Да" if state.generated_yara_rule else "Нет"}
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
    workflow.add_node("aggregator", aggregator_node)
    workflow.add_node("synthesizer", synthesizer_node)
    workflow.add_node("db_persist", persist_node)

    # Graph wiring
    workflow.add_edge(START, "triage_dispatcher")
    
    # Fan-out to specialist analysis nodes
    workflow.add_edge("triage_dispatcher", "url_agent")
    workflow.add_edge("url_agent", "dom_agent")
    workflow.add_edge("dom_agent", "vision_agent")
    workflow.add_edge("vision_agent", "quishing_agent")
    workflow.add_edge("quishing_agent", "aggregator")

    # Dynamic conditional edge: re-scan URL from QR if discovered
    workflow.add_conditional_edges(
        "aggregator",
        should_rescan_attachment_url,
        {
            "triage_dispatcher": "triage_dispatcher",
            "synthesizer": "synthesizer"
        }
    )

    workflow.add_edge("synthesizer", "db_persist")
    workflow.add_edge("db_persist", END)

    return workflow.compile()

# Global compiled pipeline instance
_compiled_app = None

def get_pipeline():
    global _compiled_app
    if _compiled_app is None:
        _compiled_app = build_phishing_pipeline()
    return _compiled_app

def run_pipeline(initial_state: PhishingState) -> PhishingState:
    pipeline = get_pipeline()
    result = pipeline.invoke(initial_state)
    if isinstance(result, dict):
        return PhishingState(**result)
    return result
