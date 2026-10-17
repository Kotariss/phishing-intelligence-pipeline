import os
import sys
import io
import json
import uuid
import zipfile
from contextlib import asynccontextmanager
from typing import Optional

_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

try:
    from .orchestrator.state import PhishingState
    from .orchestrator.graph import run_pipeline
    from .db.repository import IncidentRepository
    from .db.database import init_db, SessionLocal
    from .db.models import BrandAllowlistModel
    from .brands.matcher import get_brand_registry
    from .config import get_settings
except (ImportError, ValueError):
    from orchestrator.state import PhishingState
    from orchestrator.graph import run_pipeline
    from db.repository import IncidentRepository
    from db.database import init_db, SessionLocal
    from db.models import BrandAllowlistModel
    from brands.matcher import get_brand_registry
    from config import get_settings


settings = get_settings()
repo = IncidentRepository()
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def _populate_brand_allowlist() -> None:
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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    _populate_brand_allowlist()
    yield


app = FastAPI(
    title="Phishing Intelligence Worker",
    description="LangGraph Multi-Agent Threat Analysis & L-Signature Distillation Backend",
    version="1.1.0",
    lifespan=lifespan,
)


def _incident_dict(inc, with_evidence: bool = False) -> dict:
    data = {
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
        "campaign_id": inc.campaign_id,
        "explanation": inc.explanation
    }
    if with_evidence:
        data["fingerprints"] = inc.fingerprints
        data["evidence_data"] = inc.evidence_data
    return data


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "worker",
        "llm_mode": settings.llm_mode,
        "llm_enabled": settings.llm_configured,
        "llm_model": settings.text_model,
        "vlm_model": settings.vision_model
    }


@app.post("/api/v1/scan")
async def scan_endpoint(
    url: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    incident_id = f"inc_{uuid.uuid4().hex[:10]}"

    if url:
        url = url.strip()
        if not url.lower().startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Only http(s) URLs can be scanned.")
        initial_state = PhishingState(incident_id=incident_id, source_type="url", raw_target=url)
    elif file:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File exceeds 25 MB limit")
        filename = os.path.basename(file.filename or "uploaded_sample")
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else "bin"
        initial_state = PhishingState(incident_id=incident_id, source_type=ext, raw_target=filename, raw_bytes=content)
    else:
        raise HTTPException(status_code=400, detail="Either 'url' or 'file' must be provided.")

    try:
        final_state = await run_in_threadpool(run_pipeline, initial_state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {type(e).__name__}: {e}")
    return final_state.public_dump()


@app.post("/api/v1/scan/snapshot")
async def scan_snapshot(
    html: UploadFile = File(...),
    url: str = Form(""),
    screenshot: Optional[UploadFile] = File(None)
):
    """Saved web page: HTML (+ optional screenshot) with the URL it was captured from. Analysed offline."""
    import base64
    content = await html.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="HTML exceeds 25 MB limit")
    url = url.strip()
    if url and not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")
    link = {"url": url, "final_url": url, "html": content.decode("utf-8", errors="ignore"), "redirect_chain": []}
    if screenshot is not None:
        link["screenshot_base64"] = base64.b64encode(await screenshot.read(MAX_UPLOAD_BYTES)).decode("ascii")
    state = PhishingState(incident_id=f"inc_{uuid.uuid4().hex[:10]}", source_type="url" if url else "html",
                          raw_target=url or (html.filename or "page.html"), offline_mode=True, precollected_links=[link])
    if not url:  # an HTML file without origin is analysed as an attachment
        state = PhishingState(incident_id=state.incident_id, source_type="html", raw_target=html.filename or "page.html",
                              raw_bytes=content, offline_mode=True)
    final_state = await run_in_threadpool(run_pipeline, state)
    return final_state.public_dump()


@app.post("/api/v1/scan/sample")
async def scan_dataset_sample(path: str = Form(...)):
    """A sample directory of the customer dataset (EML + Link_N artefacts), relative to DATASET_DIR."""
    try:
        from .ingest.dataset import build_state_from_sample_dir, is_sample_dir
    except (ImportError, ValueError):
        from ingest.dataset import build_state_from_sample_dir, is_sample_dir
    root = os.path.realpath(settings.DATASET_DIR)
    target = os.path.realpath(os.path.join(root, path))
    if not target.startswith(root + os.sep) or not is_sample_dir(target):
        raise HTTPException(status_code=400, detail="path must be a sample directory inside DATASET_DIR")
    final_state = await run_in_threadpool(run_pipeline, build_state_from_sample_dir(target))
    return final_state.public_dump()


@app.get("/api/v1/incidents")
def get_incidents(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = None,
    brand: Optional[str] = None
):
    return [_incident_dict(inc) for inc in repo.list_incidents(limit=limit, offset=offset, verdict=verdict, brand=brand)]


@app.get("/api/v1/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    inc = repo.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incident_dict(inc, with_evidence=True)


@app.get("/api/v1/campaigns")
def get_campaigns(min_size: int = Query(2, ge=1, le=100), limit: int = Query(50, ge=1, le=200)):
    """Incidents linked by shared infrastructure / phishing-kit fingerprints."""
    return repo.list_campaigns(min_size=min_size, limit=limit)


@app.get("/api/v1/signatures")
def get_signatures(limit: int = Query(50, ge=1, le=1000), incident_id: Optional[str] = None):
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
        for s in repo.list_signatures(limit=limit, incident_id=incident_id)
    ]


@app.get("/api/v1/stats")
def get_stats():
    return repo.count_stats()


@app.get("/api/v1/signatures/export-zip")
def export_rules_zip():
    """In-memory ZIP of all VERIFIED L-signatures and YARA rules (drafts are excluded)."""
    zip_buffer = io.BytesIO()
    exports_dir = settings.EXPORTS_DIR
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for sub, ext in (("l_signatures", ".json"), ("yara", ".yar")):
            folder = os.path.join(exports_dir, sub)
            if os.path.isdir(folder):
                for fname in sorted(os.listdir(folder)):
                    if fname.endswith(ext):
                        zf.write(os.path.join(folder, fname), arcname=f"{sub}/{fname}")
    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=phishing_signatures.zip"}
    )


@app.post("/api/v1/package")
def export_package():
    """Builds and saves a new version of the artefact package; returns it as JSON."""
    try:
        from .rules.package import build_package, save_package
    except (ImportError, ValueError):
        from rules.package import build_package, save_package
    info = save_package(build_package(), os.path.join(settings.EXPORTS_DIR, "package"))
    with open(info["json"], "r", encoding="utf-8") as f:
        package = json.load(f)
    return {"version": info["version"], "sha256": info["sha256"], "package": package}


@app.get("/api/v1/reason-codes")
def get_reason_codes():
    """Catalogue of reason codes: weight, category, severity, description."""
    try:
        from .rules.reason_codes import REASON_CODES
    except (ImportError, ValueError):
        from rules.reason_codes import REASON_CODES
    return {code: {"weight": i.weight, "category": i.category, "severity": i.severity, "description": i.description}
            for code, i in REASON_CODES.items()}


@app.get("/api/v1/llm_audit")
def get_llm_audit(limit: int = Query(20, ge=1, le=200)):
    """Returns recent LLM/VLM audit log entries."""
    log_path = os.path.join(settings.LOGS_DIR, "llm_audit.log")
    if not os.path.exists(log_path):
        return {"logs": []}
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            content = f.read()
        entries = [e.strip() for e in content.split("-" * 70) if e.strip()]
        return {"logs": entries[-limit:]}
    except OSError as e:
        return {"logs": [], "error": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.WORKER_HOST, port=settings.WORKER_PORT)
