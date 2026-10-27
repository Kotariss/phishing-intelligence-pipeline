from typing import List, Optional, Dict, Any
from sqlalchemy import func
from sqlalchemy.orm import Session
from .models import IncidentModel, LSignatureModel, KnownIOCModel
from .database import SessionLocal

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
                campaign_id=incident_data.get("campaign_id"),
                dom_hash=incident_data.get("dom_hash"),
                fingerprints=incident_data.get("fingerprints", {}),
                evidence_data=incident_data.get("evidence_data", {}),
                object_sha256=incident_data.get("object_sha256"),
                duplicate_of=incident_data.get("duplicate_of"),
            )
            db.merge(model)
            db.commit()
            return model
        finally:
            if self._db is None:
                db.close()

    def find_first_by_object_hash(self, object_sha256: str, exclude_id: Optional[str] = None) -> Optional[IncidentModel]:
        """The earliest incident analysed from an object with this content hash (duplicate detection, ТЗ 4.1.1.3)."""
        db = self._get_session()
        try:
            query = db.query(IncidentModel).filter(IncidentModel.object_sha256 == object_sha256)
            if exclude_id:
                query = query.filter(IncidentModel.id != exclude_id)
            return query.order_by(IncidentModel.created_at.asc()).first()
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

    def register_iocs(self, hashes: List[str], kind: str, incident_id: str) -> int:
        """Stores content hashes of a confirmed phishing incident as exact indicators (first confirmation wins)."""
        db = self._get_session()
        try:
            added = 0
            for h in {x for x in hashes if x}:
                if db.get(KnownIOCModel, h) is None:
                    db.add(KnownIOCModel(sha256=h, kind=kind, incident_id=incident_id))
                    added += 1
            db.commit()
            return added
        finally:
            if self._db is None:
                db.close()

    def find_iocs(self, hashes: List[str], exclude_incident: Optional[str] = None) -> List[KnownIOCModel]:
        hashes = [h for h in {x for x in hashes if x}]
        if not hashes:
            return []
        db = self._get_session()
        try:
            rows = db.query(KnownIOCModel).filter(KnownIOCModel.sha256.in_(hashes)).all()
            return [r for r in rows if r.incident_id != exclude_incident]
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

    def list_signatures(self, limit: int = 100, incident_id: Optional[str] = None) -> List[LSignatureModel]:
        db = self._get_session()
        try:
            query = db.query(LSignatureModel)
            if incident_id:
                query = query.filter(LSignatureModel.incident_id == incident_id)
            return query.order_by(LSignatureModel.created_at.desc()).limit(limit).all()
        finally:
            if self._db is None:
                db.close()

    def list_campaigns(self, min_size: int = 2, limit: int = 50) -> List[Dict[str, Any]]:
        """Groups incidents sharing infrastructure / kit fingerprints into campaigns."""
        db = self._get_session()
        try:
            rows = (db.query(IncidentModel.campaign_id, func.count(IncidentModel.id), func.min(IncidentModel.created_at),
                             func.max(IncidentModel.created_at), func.max(IncidentModel.risk_score))
                    .filter(IncidentModel.campaign_id.isnot(None))
                    .group_by(IncidentModel.campaign_id)
                    .having(func.count(IncidentModel.id) >= min_size)
                    .order_by(func.count(IncidentModel.id).desc())
                    .limit(limit).all())
            result = []
            for campaign_id, count, first_seen, last_seen, max_risk in rows:
                members = db.query(IncidentModel).filter(IncidentModel.campaign_id == campaign_id).limit(200).all()
                result.append({
                    "campaign_id": campaign_id,
                    "incidents": count,
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "last_seen": last_seen.isoformat() if last_seen else None,
                    "max_risk": max_risk,
                    "brands": sorted({m.target_brand for m in members if m.target_brand}),
                    "final_urls": sorted({m.final_url for m in members if m.final_url})[:20],
                    "reason_codes": sorted({c for m in members for c in (m.reason_codes or [])}),
                    "incident_ids": [m.id for m in members][:50],
                })
            return result
        finally:
            if self._db is None:
                db.close()

    def list_visual_clusters(self, max_distance: int = 8, min_size: int = 2) -> List[Dict[str, Any]]:
        """Phishing incidents with alike screenshots (perceptual hash), whatever their DOM / domain."""
        try:
            from ..features.fingerprints import visual_clusters
        except (ImportError, ValueError):
            from features.fingerprints import visual_clusters
        db = self._get_session()
        try:
            rows = db.query(IncidentModel).filter(IncidentModel.verdict.in_(("MALICIOUS", "SUSPICIOUS"))).all()
            by_id = {r.id: r for r in rows}
            items = [(r.id, (r.fingerprints or {}).get("screenshot_dhash")) for r in rows]
            groups = visual_clusters([(i, h) for i, h in items if h], max_distance)
            return [{"incidents": len(g), "incident_ids": g[:50],
                     "brands": sorted({by_id[i].target_brand for i in g if by_id[i].target_brand}),
                     "domains": sorted({(by_id[i].final_url or "").split("/")[2] for i in g
                                        if (by_id[i].final_url or "").count("/") >= 2})[:20],
                     "campaign_ids": sorted({by_id[i].campaign_id for i in g if by_id[i].campaign_id})[:20]}
                    for g in groups if len(g) >= min_size]
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
            active_signatures = db.query(LSignatureModel).filter(LSignatureModel.status == "ACTIVE_VERIFIED").count()
            return {
                "total_incidents": total_incidents,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "clean_count": clean_count,
                "total_signatures": total_signatures,
                "active_signatures": active_signatures
            }
        finally:
            if self._db is None:
                db.close()
