import base64
from typing import Dict, Any

try:
    from .attachment_parser import AttachmentParser, sniff_file_kind
    from .qr_scanner import scan_qr_codes
    from .ocr import ocr_image
except ImportError:
    try:
        from attachment_parser import AttachmentParser, sniff_file_kind
        from qr_scanner import scan_qr_codes
        from ocr import ocr_image
    except ImportError:
        from src.attachment_parser import AttachmentParser, sniff_file_kind
        from src.qr_scanner import scan_qr_codes
        from src.ocr import ocr_image


def parse_file_bytes(content: bytes, filename: str, browser_ctrl=None, base_url: str = "") -> Dict[str, Any]:
    """Dispatches a sample to the right offline parser based on content sniffing."""
    kind = sniff_file_kind(filename, content)
    if kind == "eml":
        return AttachmentParser.parse_eml(content)
    if kind == "html":
        html_text = content.decode("utf-8", errors="ignore")
        parsed = AttachmentParser.parse_html(html_text, base_url=base_url)
        parsed["screenshot_base64"] = (browser_ctrl.render_html_offline(html_text) if browser_ctrl else "") or None
        return parsed
    if kind == "pdf":
        return AttachmentParser.parse_pdf(content)
    if kind == "office":
        return AttachmentParser.parse_office(content, filename=filename)
    if kind == "image":
        return {
            "type": "image",
            "filename": filename,
            "qr_codes": scan_qr_codes(content),
            "ocr_text": ocr_image(content),
            "screenshot_base64": base64.b64encode(content).decode("utf-8")
        }
    if kind == "archive":
        parsed = AttachmentParser.parse_archive(content)
        parsed.update({"type": "archive", "filename": filename, "links": []})
        return parsed
    parsed = AttachmentParser.parse_html(content.decode("utf-8", errors="ignore"))
    parsed["type"] = "other"
    return parsed
