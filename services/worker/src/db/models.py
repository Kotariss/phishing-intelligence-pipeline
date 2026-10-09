import datetime
from sqlalchemy import Column, String, Float, Boolean, DateTime, Text, JSON, Integer
from .database import Base


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    created_at = Column(DateTime, default=_utcnow, index=True)
    source_type = Column(String(32), index=True)  # url, eml, html, pdf, docx, png
    raw_target = Column(Text, nullable=False)
    final_url = Column(Text, nullable=True)
    verdict = Column(String(32), index=True, default="CLEAN")  # CLEAN, SUSPICIOUS, MALICIOUS
    risk_score = Column(Float, default=0.0)
    confidence = Column(String(16), default="LOW")  # LOW, MEDIUM, HIGH
    target_brand = Column(String(128), index=True, nullable=True)
    reason_codes = Column(JSON, default=list)
    zero_fpr_passed = Column(Boolean, default=True)
    explanation = Column(Text, nullable=True)
    campaign_id = Column(String(32), index=True, nullable=True)
    dom_hash = Column(String(64), index=True, nullable=True)
    fingerprints = Column(JSON, default=dict)
    evidence_data = Column(JSON, default=dict)

class LSignatureModel(Base):
    __tablename__ = "l_signatures"

    id = Column(String(64), primary_key=True, index=True)  # LAR-2026-SBER-0142
    incident_id = Column(String(64), index=True, nullable=True)
    name = Column(String(256), nullable=False)
    target_brand = Column(String(128), index=True, nullable=False)
    version = Column(Integer, default=1)
    status = Column(String(32), default="ACTIVE_VERIFIED")  # ACTIVE_VERIFIED, DRAFT_REQUIRES_TUNING
    rule_json = Column(JSON, nullable=False)
    yara_rule = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_utcnow, index=True)

class BrandAllowlistModel(Base):
    __tablename__ = "brand_allowlist"

    brand_id = Column(String(64), primary_key=True, index=True)
    display_name = Column(String(128), nullable=False)
    category = Column(String(64), default="general")
    allowed_domains = Column(JSON, default=list)
    allowed_patterns = Column(JSON, default=list)
    aliases = Column(JSON, default=list)
