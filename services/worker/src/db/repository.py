from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from .models import IncidentModel, LSignatureModel, BrandAllowlistModel
from .database import SessionLocal, init_db

class IncidentRepository:
    def __init__(self, db: Optional[Session] = None):
        self._db = db

    def _get_session(self) -> Session:
        return self._db if self._db is not None else SessionLocal()

    def create_incident(self, incident_data: Dict[str, Any]) -> IncidentModel:
        db = self._get_session()
        try:
            model = IncidentModel(
                id=incident_data["id"],
                source_type=incident_data.get("source_type", "url"),
                raw_target=incident_data.get("raw_target", ""),
                final_url=incident_data.get("final_url"),
                verdict=incident_data.get("verdict", "CLEAN"),
                risk_score=float(incident_data.get("risk_score", 0.0)),
                confidence=incident_data.get("confidence", "LOW"),
                target_brand=incident_data.get("target_brand"),
                reason_codes=incident_data.get("reason_codes", []),
                zero_fpr_passed=incident_data.get("zero_fpr_passed", True),
                explanation=incident_data.get("explanation"),
                evidence_data=incident_data.get("evidence_data", {})
            )
            db.merge(model)
            db.commit()
            return model
        finally:
            if self._db is None:
                db.close()

    def get_incident(self, incident_id: str) -> Optional[IncidentModel]:
        db = self._get_session()
        try:
            return db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        finally:
            if self._db is None:
                db.close()

    def list_incidents(
        self,
        limit: int = 100,
        offset: int = 0,
        verdict: Optional[str] = None,
        brand: Optional[str] = None
    ) -> List[IncidentModel]:
        db = self._get_session()
        try:
            query = db.query(IncidentModel)
            if verdict:
                query = query.filter(IncidentModel.verdict == verdict)
            if brand:
                query = query.filter(IncidentModel.target_brand == brand)
            return query.order_by(IncidentModel.created_at.desc()).offset(offset).limit(limit).all()
        finally:
            if self._db is None:
                db.close()

    def create_signature(self, sig_data: Dict[str, Any]) -> LSignatureModel:
        db = self._get_session()
        try:
            sig = LSignatureModel(
                id=sig_data["id"],
                incident_id=sig_data.get("incident_id"),
                name=sig_data.get("name", "Unnamed Rule"),
                target_brand=sig_data.get("target_brand", "Unknown"),
                version=sig_data.get("version", 1),
                status=sig_data.get("status", "ACTIVE_VERIFIED"),
                rule_json=sig_data.get("rule_json", {}),
                yara_rule=sig_data.get("yara_rule")
            )
            db.merge(sig)
            db.commit()
            return sig
        finally:
            if self._db is None:
                db.close()

    def list_signatures(self, limit: int = 100) -> List[LSignatureModel]:
        db = self._get_session()
        try:
            return db.query(LSignatureModel).order_by(LSignatureModel.created_at.desc()).limit(limit).all()
        finally:
            if self._db is None:
                db.close()

    def count_stats(self) -> Dict[str, Any]:
        db = self._get_session()
        try:
            total_incidents = db.query(IncidentModel).count()
            malicious_count = db.query(IncidentModel).filter(IncidentModel.verdict == "MALICIOUS").count()
            suspicious_count = db.query(IncidentModel).filter(IncidentModel.verdict == "SUSPICIOUS").count()
            clean_count = db.query(IncidentModel).filter(IncidentModel.verdict == "CLEAN").count()
            total_signatures = db.query(LSignatureModel).count()
            return {
                "total_incidents": total_incidents,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "clean_count": clean_count,
                "total_signatures": total_signatures
            }
        finally:
            if self._db is None:
                db.close()
