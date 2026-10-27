from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class RedirectHop(BaseModel):
    url: str
    status_code: int = 200
    hop_type: str = "http_redirect"

class FormEvidence(BaseModel):
    action: str = ""
    action_host: str = ""
    method: str = "GET"
    has_password: bool = False
    has_email: bool = False
    has_card: bool = False
    prefilled_victim_email: bool = False
    is_external_target: bool = False
    submit_target_url: Optional[str] = None
    submit_mechanism: str = "standard_submit"  # standard_submit, onclick_ajax, telegram_bot
    origin: str = "page"  # page | attachment
    snippet: str = ""  # HTML of the form (evidence)

class BrandEvidence(BaseModel):
    detected_brand_name: Optional[str] = None
    brand_id: Optional[str] = None
    detection_source: Optional[str] = None  # display_name | vlm | title | lookalike_domain | body_text | official_domain
    vlm_confidence: float = 0.0
    visual_lure_type: Optional[str] = None  # b2b_invoice, banking_login, delivery_awb, security_alert
    is_domain_in_allowlist: bool = True
    brand_impersonation_confirmed: bool = False
    impersonation_reason: Optional[str] = None
    logo_box: Optional[List[float]] = None  # [x1, y1, x2, y2] as fractions of the screenshot (VLM)

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
    source_type: str = "url"  # url, eml, html, pdf, office, image, sample_dir
    raw_target: str = ""      # Target URL or file path/name (never overwritten)
    raw_bytes: Optional[bytes] = None
    offline_mode: bool = False  # True: never touch the network (pre-collected dataset artefacts only)
    # Pre-collected link artefacts (dataset: Link_N/{url.txt, chain_info.json, html.html, screenshot.png})
    precollected_links: List[Dict[str, Any]] = Field(default_factory=list)

    # Sandbox Raw Artifacts
    scan_url: Optional[str] = None  # URL currently being analysed (initial URL or rescan target)
    final_url: Optional[str] = None
    http_status: Optional[int] = None
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    dom_html: Optional[str] = None
    page_features: Dict[str, Any] = Field(default_factory=dict)
    screenshot_base64: Optional[str] = None
    screenshot_source: Optional[str] = None  # browser | attachment_render | dataset | image_file | embedded_image
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
    reason_details: Dict[str, str] = Field(default_factory=dict)  # code -> human-readable evidence
    # code -> supporting artefact: {"type": "dom"|"url"|"hash"|"header"|"image_region", "value"/"box": ..., "label": ...}
    reason_evidence: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    explanation: Optional[str] = None

    # Output Signatures, Fingerprints & Campaigns
    generated_l_signature: Optional[Dict[str, Any]] = None
    generated_yara_rule: Optional[str] = None
    signature_status: Optional[str] = None  # ACTIVE_VERIFIED | DRAFT_REQUIRES_TUNING | NOT_GENERATED
    fingerprints: Dict[str, Any] = Field(default_factory=dict)
    campaign_id: Optional[str] = None
    # Provenance and duplicates (ТЗ 4.1.1.3): source type + original object (`source_type`, `raw_target`), upload time, content hash
    ingested_at: Optional[str] = None
    object_sha256: Optional[str] = None
    duplicate_of: Optional[str] = None   # id of the first incident analysed from the same object
    zero_fpr_passed: bool = True
    zero_fpr_note: Optional[str] = None
    execution_steps: List[str] = Field(default_factory=list)
    agent_traces: List[AgentStepTrace] = Field(default_factory=list)

    def add_reason(self, code: str, detail: str, evidence: Optional[Dict[str, Any]] = None) -> None:
        if code not in self.reason_codes:
            self.reason_codes.append(code)
            self.reason_codes.sort()
        # tokens / e-mails in URLs are masked in every report (ТЗ п. 4.5.2.3)
        try:
            from ..features.url_features import mask_urls_in_text
        except (ImportError, ValueError):
            from features.url_features import mask_urls_in_text
        self.reason_details.setdefault(code, mask_urls_in_text(detail))
        if evidence and evidence.get("value") not in (None, "", []) or (evidence or {}).get("box"):
            ev = dict(evidence)
            if ev.get("type") in ("url", "dom", "header", "text") and isinstance(ev.get("value"), str):
                ev["value"] = mask_urls_in_text(ev["value"])
            elif ev.get("type") == "chain" and isinstance(ev.get("value"), list):
                ev["value"] = [mask_urls_in_text(u) for u in ev["value"]]
            self.reason_evidence.setdefault(code, ev)

    def drop_reason(self, code: str) -> None:
        if code in self.reason_codes:
            self.reason_codes.remove(code)
        self.reason_details.pop(code, None)
        self.reason_evidence.pop(code, None)

    @property
    def current_url(self) -> str:
        return self.scan_url or self.raw_target

    def public_dump(self) -> Dict[str, Any]:
        """JSON-safe representation for the API / database (no raw sample bytes)."""
        return self.model_dump(mode="json", exclude={"raw_bytes", "precollected_links"})
