import os
from typing import Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

try:
    from .security import SecurityError
    from .browser import BrowserController
    from .dispatch import parse_file_bytes
except ImportError:
    try:
        from security import SecurityError
        from browser import BrowserController
        from dispatch import parse_file_bytes
    except ImportError:
        from src.security import SecurityError
        from src.browser import BrowserController
        from src.dispatch import parse_file_bytes


app = FastAPI(
    title="Phishing Intelligence Sandbox",
    description="Untrusted malware analysis sandbox with Anti-SSRF, Playwright browser and attachment parsers",
    version="1.1.0"
)

ANTI_SSRF = os.getenv("ANTI_SSRF_ENABLED", "true").lower() in ("1", "true", "yes")
MAX_REDIRECTS = int(os.getenv("SANDBOX_MAX_REDIRECTS", "10"))
MAX_FILE_BYTES = int(float(os.getenv("SANDBOX_MAX_FILE_SIZE_MB", "25")) * 1024 * 1024)
MAX_TIMEOUT = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "10")) * 3
browser_ctrl = BrowserController(anti_ssrf_enabled=ANTI_SSRF, max_redirects=MAX_REDIRECTS)


class URLExtractRequest(BaseModel):
    url: str
    timeout_seconds: Optional[int] = 10
    user_agent: Optional[str] = None


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "sandbox",
        "anti_ssrf_enabled": ANTI_SSRF,
        "max_file_mb": MAX_FILE_BYTES // (1024 * 1024)
    }


@app.post("/api/v1/extract/url")
def extract_url(req: URLExtractRequest):
    try:
        timeout = max(1, min(req.timeout_seconds or 10, MAX_TIMEOUT))
        kwargs = {"timeout_seconds": timeout}
        if req.user_agent:
            kwargs["user_agent"] = req.user_agent
        return browser_ctrl.extract_url(req.url, **kwargs)
    except SecurityError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failure: {type(e).__name__}: {e}")


@app.post("/api/v1/extract/file")
async def extract_file(file: UploadFile = File(...), base_url: str = Form("")):
    content = await file.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_FILE_BYTES // (1024 * 1024)} MB limit")
    try:
        parsed = parse_file_bytes(content, file.filename or "", browser_ctrl=browser_ctrl, base_url=base_url)
        parsed.setdefault("filename", file.filename or "")
        return parsed
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File parsing error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8001")))
