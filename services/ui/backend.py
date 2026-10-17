"""Data access for the UI: the worker REST API when it is running (Docker), otherwise the pipeline in-process."""
import base64
import json
import os
import sys
import uuid
from typing import Any, Dict, List, Optional

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.environ.get("ROOT_DIR") or os.path.abspath(os.path.join(_HERE, "..", ".."))
WORKER_SRC = os.path.join(ROOT_DIR, "services", "worker", "src")
SANDBOX_SRC = os.path.join(ROOT_DIR, "services", "sandbox", "src")
FIXTURES = os.path.join(ROOT_DIR, "tests", "fixtures")
for _p in (WORKER_SRC, SANDBOX_SRC, FIXTURES):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

WORKER_API = f"http://{os.getenv('WORKER_HOST', 'localhost')}:{os.getenv('WORKER_PORT', '8000')}"
DATASET = os.path.join(ROOT_DIR, "file_for_case")
REPORTS = os.path.join(ROOT_DIR, "reports")
EXPORTS = os.path.join(ROOT_DIR, "exports")
TIMEOUT = 300


_ALIVE = {"value": False, "checked": 0.0}


def api_alive() -> bool:
    import time
    if time.time() - _ALIVE["checked"] < 10:
        return _ALIVE["value"]
    try:
        _ALIVE["value"] = requests.get(f"{WORKER_API}/health", timeout=1.5).status_code == 200
    except requests.RequestException:
        _ALIVE["value"] = False
    _ALIVE["checked"] = time.time()
    return _ALIVE["value"]


def local_available() -> bool:
    return os.path.isdir(WORKER_SRC)


def mode() -> str:
    return "api" if api_alive() else ("local" if local_available() else "none")


def health() -> Dict[str, Any]:
    if api_alive():
        return requests.get(f"{WORKER_API}/health", timeout=3).json()
    if local_available():
        from config import get_settings
        s = get_settings()
        return {"llm_mode": s.llm_mode, "llm_enabled": s.llm_configured, "llm_model": s.text_model,
                "vlm_model": s.vision_model}
    return {}


# ------------------------------------------------------------------------------ analysis
def _run_local(state) -> Dict[str, Any]:
    from orchestrator.graph import run_pipeline
    result = run_pipeline(state)
    data = result.public_dump()
    return data


def _api(path: str, **kwargs) -> Dict[str, Any]:
    r = requests.post(f"{WORKER_API}{path}", timeout=TIMEOUT, **kwargs)
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {r.text[:400]}"}
    return r.json()


def analyze_file(name: str, data: bytes) -> Dict[str, Any]:
    if api_alive():
        return _api("/api/v1/scan", files={"file": (name, data)})
    from orchestrator.state import PhishingState
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else "bin"
    return _run_local(PhishingState(incident_id=f"ui_{uuid.uuid4().hex[:8]}", source_type=ext, raw_target=name,
                                    raw_bytes=data, offline_mode=True))


def analyze_snapshot(url: str, html: bytes, screenshot: Optional[bytes] = None) -> Dict[str, Any]:
    if api_alive():
        files = {"html": ("page.html", html)}
        if screenshot:
            files["screenshot"] = ("shot.png", screenshot)
        return _api("/api/v1/scan/snapshot", data={"url": url}, files=files)
    from orchestrator.state import PhishingState
    link = {"url": url, "final_url": url, "html": html.decode("utf-8", errors="ignore"), "redirect_chain": []}
    if screenshot:
        link["screenshot_base64"] = base64.b64encode(screenshot).decode("ascii")
    return _run_local(PhishingState(incident_id=f"ui_{uuid.uuid4().hex[:8]}", source_type="url", raw_target=url,
                                    offline_mode=True, precollected_links=[link]))


def analyze_url(url: str) -> Dict[str, Any]:
    if api_alive():
        return _api("/api/v1/scan", data={"url": url})
    from orchestrator.state import PhishingState
    return _run_local(PhishingState(incident_id=f"ui_{uuid.uuid4().hex[:8]}", source_type="url", raw_target=url))


def analyze_dataset_sample(rel_path: str) -> Dict[str, Any]:
    """A sample directory of the customer dataset (EML + Link_N artefacts), path relative to file_for_case."""
    if api_alive():
        return _api("/api/v1/scan/sample", data={"path": rel_path})
    from ingest.dataset import build_state_from_sample_dir
    return _run_local(build_state_from_sample_dir(os.path.join(DATASET, rel_path), f"ui_{uuid.uuid4().hex[:8]}"))


# ------------------------------------------------------------------------------ dataset browser
def dataset_brands() -> List[str]:
    root = os.path.join(DATASET, "keis2")
    if not os.path.isdir(root):
        return []
    return sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))


def dataset_samples(brand: str) -> List[str]:
    root = os.path.join(DATASET, "keis2", brand)
    return sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []


def dataset_files(folder: str, limit: int = 400) -> List[str]:
    root = os.path.join(DATASET, folder)
    if not os.path.isdir(root):
        return []
    out = []
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            out.append(os.path.relpath(os.path.join(dirpath, f), root))
            if len(out) >= limit:
                return out
    return out


def read_dataset_file(folder: str, rel: str) -> bytes:
    with open(os.path.join(DATASET, folder, rel), "rb") as f:
        return f.read()


# ------------------------------------------------------------------------------ knowledge base
def _get(path: str) -> Any:
    r = requests.get(f"{WORKER_API}{path}", timeout=10)
    r.raise_for_status()
    return r.json()


def kb_stats() -> Dict[str, Any]:
    if api_alive():
        return _get("/api/v1/stats")
    from db.repository import IncidentRepository
    return IncidentRepository().count_stats()


def kb_incidents(limit: int = 200, verdict: Optional[str] = None) -> List[Dict[str, Any]]:
    if api_alive():
        q = f"/api/v1/incidents?limit={limit}" + (f"&verdict={verdict}" if verdict else "")
        return _get(q)
    from db.repository import IncidentRepository
    return [{"id": i.id, "created_at": i.created_at.isoformat() if i.created_at else "", "source_type": i.source_type,
             "raw_target": i.raw_target, "final_url": i.final_url, "verdict": i.verdict, "risk_score": i.risk_score,
             "target_brand": i.target_brand, "reason_codes": i.reason_codes, "campaign_id": i.campaign_id}
            for i in IncidentRepository().list_incidents(limit=limit, verdict=verdict)]


def kb_incident(incident_id: str) -> Optional[Dict[str, Any]]:
    """A stored incident converted to the same shape as a fresh analysis result."""
    if api_alive():
        inc = _get(f"/api/v1/incidents/{incident_id}")
        sigs = _get(f"/api/v1/signatures?limit=10&incident_id={incident_id}")
    else:
        from db.repository import IncidentRepository
        repo = IncidentRepository()
        i = repo.get_incident(incident_id)
        if not i:
            return None
        inc = {"id": i.id, "created_at": i.created_at.isoformat() if i.created_at else "", "source_type": i.source_type,
               "raw_target": i.raw_target, "final_url": i.final_url, "verdict": i.verdict, "risk_score": i.risk_score,
               "confidence": i.confidence, "target_brand": i.target_brand, "reason_codes": i.reason_codes,
               "campaign_id": i.campaign_id, "explanation": i.explanation, "fingerprints": i.fingerprints,
               "evidence_data": i.evidence_data}
        sigs = [{"rule_json": s.rule_json, "yara_rule": s.yara_rule, "status": s.status}
                for s in repo.list_signatures(limit=10, incident_id=incident_id)]
    ev = inc.get("evidence_data") or {}
    sig = sigs[0] if sigs else {}
    return {
        "incident_id": inc["id"], "created_at": inc.get("created_at"), "source_type": inc.get("source_type"),
        "raw_target": inc.get("raw_target"), "final_url": inc.get("final_url"), "verdict": inc.get("verdict"),
        "risk_score": inc.get("risk_score") or 0.0, "confidence": inc.get("confidence"),
        "reason_codes": inc.get("reason_codes") or [], "explanation": inc.get("explanation"),
        "campaign_id": inc.get("campaign_id"), "fingerprints": inc.get("fingerprints") or {},
        "reason_details": ev.get("reason_details") or {}, "reason_evidence": ev.get("reason_evidence") or {},
        "brand_evidence": ev.get("brand") or {}, "redirect_chain": ev.get("redirect_chain") or [],
        "dom_forms": ev.get("forms") or [], "page_features": ev.get("page") or {},
        "attachment_evidence": ev.get("attachment") or {}, "network_evidence": ev.get("network") or {},
        "agent_traces": ev.get("agent_traces") or [], "screenshot_source": ev.get("screenshot_source"),
        "generated_l_signature": sig.get("rule_json"), "generated_yara_rule": sig.get("yara_rule"),
        "signature_status": sig.get("status"), "from_knowledge_base": True,
    }


def kb_campaigns() -> List[Dict[str, Any]]:
    if api_alive():
        return _get("/api/v1/campaigns?min_size=2")
    from db.repository import IncidentRepository
    return IncidentRepository().list_campaigns(min_size=2)


def kb_signatures() -> List[Dict[str, Any]]:
    if api_alive():
        return _get("/api/v1/signatures?limit=500")
    from db.repository import IncidentRepository
    return [{"id": s.id, "incident_id": s.incident_id, "name": s.name, "target_brand": s.target_brand,
             "status": s.status, "rule_json": s.rule_json, "yara_rule": s.yara_rule,
             "created_at": s.created_at.isoformat() if s.created_at else ""}
            for s in IncidentRepository().list_signatures(limit=500)]


def build_package() -> Dict[str, Any]:
    if api_alive():
        return _api("/api/v1/package")
    from rules.package import build_package as _build, save_package
    info = save_package(_build(), os.path.join(EXPORTS, "package"))
    with open(info["json"], "r", encoding="utf-8") as f:
        return {"version": info["version"], "sha256": info["sha256"], "package": json.load(f)}


def reason_catalogue() -> Dict[str, Any]:
    if api_alive():
        try:
            return _get("/api/v1/reason-codes")
        except (requests.RequestException, ValueError):
            pass
    try:
        from rules.reason_codes import REASON_CODES
        return {code: {"weight": i.weight, "category": i.category, "severity": i.severity, "description": i.description}
                for code, i in REASON_CODES.items()}
    except ImportError:
        pass
    return {}


def load_report(name: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(REPORTS, name)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
