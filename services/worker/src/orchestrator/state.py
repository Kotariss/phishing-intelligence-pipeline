from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class RedirectHop(BaseModel):
    url: str
    status_code: int = 200
    hop_type: str = "http_redirect"

class FormEvidence(BaseModel):
    action: str = ""
    method: str = "GET"
    has_password: bool = False
    has_email: bool = False
    has_card: bool = False
    is_external_target: bool = False
    submit_target_url: Optional[str] = None
    submit_mechanism: str = "standard_submit"  # standard_submit, onclick_ajax, telegram_bot

class BrandEvidence(BaseModel):
    detected_brand_name: Optional[str] = None
    vlm_confidence: float = 0.0
    visual_lure_type: Optional[str] = None  # b2b_invoice, banking_login, delivery_awb, security_alert
    is_domain_in_allowlist: bool = True
    brand_impersonation_confirmed: bool = False
    impersonation_reason: Optional[str] = None

class AgentStepTrace(BaseModel):
    agent_id: str
    agent_name: str
    icon: str = "🤖"
    phase: str = "Analysis"
    status: str = "COMPLETED"  # COMPLETED, TRIGGERED, CLEAN, SKIPPED, WARNING
    duration_ms: float = 0.0
    reasoning: str = ""
    decision: str = ""
    tools_called: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    llm_audit: Optional[Dict[str, Any]] = None
    state_delta: Dict[str, Any] = Field(default_factory=dict)

class PhishingState(BaseModel):
    # Ingestion Metadata
    incident_id: str
    source_type: str = "url"  # url, eml, html, pdf, office, image
    raw_target: str = ""      # Target URL or file path/name
    raw_bytes: Optional[bytes] = None

    # Sandbox Raw Artifacts
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    dom_html: Optional[str] = None
    screenshot_base64: Optional[str] = None
    discovered_urls_from_attachments: List[str] = Field(default_factory=list)
    has_rescanned_url: bool = False
    should_rescan: bool = False

    # Specialist Agent Evidences
    network_evidence: Dict[str, Any] = Field(default_factory=dict)
    dom_forms: List[FormEvidence] = Field(default_factory=list)
    script_obfuscation_detected: bool = False
    dom_structural_hash: Optional[str] = None
    dom_skeleton: Optional[str] = None
    brand_evidence: BrandEvidence = Field(default_factory=BrandEvidence)
    attachment_evidence: Dict[str, Any] = Field(default_factory=dict)

    # Synthesizer Outputs & Verdicts
    risk_score: float = 0.0   # [0.0; 1.0]
    confidence: str = "LOW"   # LOW, MEDIUM, HIGH
    verdict: str = "CLEAN"    # CLEAN, SUSPICIOUS, MALICIOUS
    reason_codes: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None

    # Output Signatures & Rules
    generated_l_signature: Optional[Dict[str, Any]] = None
    generated_yara_rule: Optional[str] = None
    zero_fpr_passed: bool = True
    execution_steps: List[str] = Field(default_factory=list)
    agent_traces: List[AgentStepTrace] = Field(default_factory=list)
