import os
import io
import base64
from typing import Optional
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel, HttpUrl

try:
    from .security import validate_url_safety, SecurityError
    from .browser import BrowserController, create_synthetic_screenshot
    from .attachment_parser import AttachmentParser
    from .qr_scanner import scan_qr_codes
except ImportError:
    try:
        from security import validate_url_safety, SecurityError
        from browser import BrowserController, create_synthetic_screenshot
        from attachment_parser import AttachmentParser
        from qr_scanner import scan_qr_codes
    except ImportError:
        from src.security import validate_url_safety, SecurityError
        from src.browser import BrowserController, create_synthetic_screenshot
        from src.attachment_parser import AttachmentParser
        from src.qr_scanner import scan_qr_codes


app = FastAPI(
    title="Phishing Intelligence Sandbox",
    description="Untrusted malware analysis sandbox with Anti-SSRF, Playwright browser and attachment parsers",
    version="1.0.0"
)

ANTI_SSRF = os.getenv("ANTI_SSRF_ENABLED", "true").lower() in ("1", "true", "yes")
browser_ctrl = BrowserController(anti_ssrf_enabled=ANTI_SSRF)

class URLExtractRequest(BaseModel):
    url: str
    timeout_seconds: Optional[int] = 10
    user_agent: Optional[str] = None

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "sandbox",
        "anti_ssrf_enabled": ANTI_SSRF
    }

@app.post("/api/v1/extract/url")
def extract_url(req: URLExtractRequest):
    try:
        kwargs = {"timeout_seconds": req.timeout_seconds or 10}
        if req.user_agent:
            kwargs["user_agent"] = req.user_agent
        result = browser_ctrl.extract_url(req.url, **kwargs)
        return result
    except SecurityError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failure: {e}")

@app.post("/api/v1/extract/file")
async def extract_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        filename = (file.filename or "").lower()

        if filename.endswith(".eml") or filename.endswith(".msg"):
            parsed = AttachmentParser.parse_eml(content)
            # Remove raw bytes from response
            parsed.pop("raw_attachments", None)
            return parsed

        elif filename.endswith(".html") or filename.endswith(".htm"):
            html_text = content.decode("utf-8", errors="ignore")
            parsed = AttachmentParser.parse_html(html_text)
            parsed["screenshot_base64"] = create_synthetic_screenshot(
                url=f"attachment://{filename}",
                title=parsed.get("title", ""),
                forms_count=parsed.get("forms_count", 0)
            )
            return parsed

        elif filename.endswith(".pdf"):
            parsed = AttachmentParser.parse_pdf(content)
            return parsed

        elif filename.endswith(".docx") or filename.endswith(".xlsx"):
            parsed = AttachmentParser.parse_office(content, filename=filename)
            return parsed

        elif filename.endswith((".png", ".jpg", ".jpeg")):
            qr_urls = scan_qr_codes(content)
            b64_img = base64.b64encode(content).decode("utf-8")
            return {
                "type": "image",
                "filename": filename,
                "qr_codes": qr_urls,
                "screenshot_base64": b64_img
            }
        else:
            # Fallback text/binary parse
            text_cand = content.decode("utf-8", errors="ignore")
            parsed = AttachmentParser.parse_html(text_cand)
            return parsed

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File parsing error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8001")))
