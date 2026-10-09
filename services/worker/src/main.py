import os
import sys
import io
import uuid
import zipfile
from typing import Optional, List

_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

try:
    from .orchestrator.state import PhishingState
    from .orchestrator.graph import run_pipeline
    from .db.repository import IncidentRepository
    from .db.database import init_db
    from .config import get_settings
except (ImportError, ValueError):
    from orchestrator.state import PhishingState
    from orchestrator.graph import run_pipeline
    from db.repository import IncidentRepository
    from db.database import init_db
    from config import get_settings


app = FastAPI(
    title="Phishing Intelligence Worker",
    description="LangGraph Multi-Agent Threat Analysis & L-Signature Distillation Backend",
    version="1.0.0"
)

init_db()
repo = IncidentRepository()
settings = get_settings()

@app.on_event("startup")
def on_startup():
    init_db()
    try:
        try:
            from .brands.matcher import get_brand_registry
            from .db.models import BrandAllowlistModel
            from .db.database import SessionLocal
        except (ImportError, ValueError):
            from brands.matcher import get_brand_registry
            from db.models import BrandAllowlistModel
            from db.database import SessionLocal
        reg = get_brand_registry()
        db = SessionLocal()
        try:
            if db.query(BrandAllowlistModel).count() == 0:
                for b in reg.brands:
                    db.add(BrandAllowlistModel(
                        brand_id=b["brand_id"],
                        display_name=b["display_name"],
                        category=b.get("category", "general"),
                        allowed_domains=b.get("official_domains", []),
                        allowed_patterns=b.get("allowed_domain_patterns", []),
                        aliases=b.get("aliases", [])
                    ))
                db.commit()
                print(f"[Worker] Pre-populated {len(reg.brands)} brands into allowlist table.")
        finally:
            db.close()
    except Exception as e:
        print(f"[Worker] Brand pre-population note: {e}")

class ScanUrlRequest(BaseModel):
    url: str

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "worker",
        "llm_model": settings.LLM_TEXT_MODEL,
        "vlm_model": settings.LLM_VISION_MODEL
    }

@app.post("/api/v1/scan")
async def scan_endpoint(
    url: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    incident_id = f"inc_{uuid.uuid4().hex[:10]}"

    if url:
        initial_state = PhishingState(
            incident_id=incident_id,
            source_type="url",
            raw_target=url.strip()
        )
    elif file:
        content = await file.read()
        filename = file.filename or "uploaded_sample"
        # Determine source type
        ext = filename.lower().split(".")[-1] if "." in filename else "bin"
        initial_state = PhishingState(
            incident_id=incident_id,
            source_type=ext,
            raw_target=filename,
            raw_bytes=content
        )
    else:
        raise HTTPException(status_code=400, detail="Either 'url' or 'file' must be provided.")

    try:
        final_state = run_pipeline(initial_state)
        return final_state.model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {e}")

@app.get("/api/v1/incidents")
def get_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = None,
    brand: Optional[str] = None
):
    incidents = repo.list_incidents(limit=limit, offset=offset, verdict=verdict, brand=brand)
    return [
        {
            "id": inc.id,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "source_type": inc.source_type,
            "raw_target": inc.raw_target,
            "final_url": inc.final_url,
            "verdict": inc.verdict,
            "risk_score": inc.risk_score,
            "confidence": inc.confidence,
            "target_brand": inc.target_brand,
            "reason_codes": inc.reason_codes,
            "zero_fpr_passed": inc.zero_fpr_passed,
            "explanation": inc.explanation
        }
        for inc in incidents
    ]

@app.get("/api/v1/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    inc = repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id": inc.id,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "source_type": inc.source_type,
        "raw_target": inc.raw_target,
        "final_url": inc.final_url,
        "verdict": inc.verdict,
        "risk_score": inc.risk_score,
        "confidence": inc.confidence,
        "target_brand": inc.target_brand,
        "reason_codes": inc.reason_codes,
        "zero_fpr_passed": inc.zero_fpr_passed,
        "explanation": inc.explanation,
        "evidence_data": inc.evidence_data
    }

@app.get("/api/v1/signatures")
def get_signatures(limit: int = 50):
    sigs = repo.list_signatures(limit=limit)
    return [
        {
            "id": s.id,
            "incident_id": s.incident_id,
            "name": s.name,
            "target_brand": s.target_brand,
            "version": s.version,
            "status": s.status,
            "rule_json": s.rule_json,
            "yara_rule": s.yara_rule,
            "created_at": s.created_at.isoformat() if s.created_at else None
        }
        for s in sigs
    ]

@app.get("/api/v1/stats")
def get_stats():
    return repo.count_stats()

@app.get("/api/v1/signatures/export-zip")
def export_rules_zip():
    """Generates an in-memory ZIP archive of all exported L-signatures and YARA rules."""
    zip_buffer = io.BytesIO()
    
    exports_dir = settings.EXPORTS_DIR
    sig_dir = os.path.join(exports_dir, "l_signatures")
    yara_dir = os.path.join(exports_dir, "yara")

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add L-signatures
        if os.path.exists(sig_dir):
            for fname in os.listdir(sig_dir):
                if fname.endswith(".json"):
                    fpath = os.path.join(sig_dir, fname)
                    zf.write(fpath, arcname=f"l_signatures/{fname}")

        # Add YARA rules
        if os.path.exists(yara_dir):
            for fname in os.listdir(yara_dir):
                if fname.endswith(".yar"):
                    fpath = os.path.join(yara_dir, fname)
                    zf.write(fpath, arcname=f"yara/{fname}")

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=phishing_signatures.zip"}
    )

@app.get("/api/v1/llm_audit")
def get_llm_audit(limit: int = 20):
    """Returns recent LLM/VLM audit logs."""
    log_path = os.path.join(os.getcwd(), "logs", "llm_audit.log")
    if not os.path.exists(log_path):
        return {"logs": []}
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            content = f.read()
        entries = [e.strip() for e in content.split("-" * 70) if e.strip()]
        return {"logs": entries[-limit:]}
    except Exception as e:
        return {"logs": [], "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.WORKER_HOST, port=settings.WORKER_PORT)
