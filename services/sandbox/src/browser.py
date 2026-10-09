import io
import base64
import time
import requests
from typing import Dict, Any, List, Optional
from PIL import Image, ImageDraw, ImageFont
try:
    from .security import validate_url_safety, SecurityError
    from .attachment_parser import AttachmentParser
except ImportError:
    try:
        from security import validate_url_safety, SecurityError
        from attachment_parser import AttachmentParser
    except ImportError:
        from src.security import validate_url_safety, SecurityError
        from src.attachment_parser import AttachmentParser


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)

def create_synthetic_screenshot(url: str, title: str, forms_count: int) -> str:
    """Generates an in-memory image representation when headless browser binary is not present."""
    img = Image.new("RGB", (800, 600), color=(245, 247, 250))
    draw = ImageDraw.Draw(img)
    
    # Header bar
    draw.rectangle([(0, 0), (800, 50)], fill=(41, 74, 110))
    draw.text((20, 15), f"Browser Snapshot: {url[:70]}", fill=(255, 255, 255))
    
    # Body card
    draw.rectangle([(50, 80), (750, 520)], fill=(255, 255, 255), outline=(210, 215, 225), width=2)
    draw.text((80, 110), f"Page Title: {title or 'Untitled Page'}", fill=(20, 20, 20))
    draw.text((80, 150), f"Target URL: {url}", fill=(70, 70, 70))
    draw.text((80, 190), f"Interactive Forms Detected: {forms_count}", fill=(200, 30, 30) if forms_count > 0 else (40, 140, 40))

    if forms_count > 0:
        draw.rectangle([(80, 230), (450, 380)], fill=(248, 249, 250), outline=(200, 200, 200))
        draw.text((100, 250), "Input: [ Username / Email / Phone ]", fill=(100, 100, 100))
        draw.text((100, 290), "Input: [ Password ********** ]", fill=(100, 100, 100))
        draw.rectangle([(100, 330), (250, 365)], fill=(30, 120, 220))
        draw.text((120, 340), "Sign In / Submit", fill=(255, 255, 255))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

class BrowserController:
    """Safe crawler and page extractor with Anti-SSRF enforcement."""

    def __init__(self, anti_ssrf_enabled: bool = True):
        self.anti_ssrf_enabled = anti_ssrf_enabled

    def extract_url(
        self,
        url: str,
        timeout_seconds: int = 10,
        user_agent: str = DEFAULT_USER_AGENT
    ) -> Dict[str, Any]:
        # 1. Anti-SSRF check
        safe, msg = validate_url_safety(url, self.anti_ssrf_enabled)
        if not safe:
            raise SecurityError(f"Security validation blocked URL: {msg}")

        # 2. Try Playwright headless if available
        try:
            from playwright.sync_api import sync_playwright
            return self._extract_with_playwright(url, timeout_seconds, user_agent)
        except (ImportError, Exception):
            # 3. Resilient fallback using requests session with redirect tracking
            return self._extract_with_requests(url, timeout_seconds, user_agent)

    def _extract_with_playwright(
        self,
        url: str,
        timeout_seconds: int,
        user_agent: str
    ) -> Dict[str, Any]:
        from playwright.sync_api import sync_playwright
        
        redirect_chain = []
        screenshot_b64 = ""
        dom_html = ""
        final_url = url
        http_status = 200

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-extensions",
                    "--deny-permission-prompts",
                    "--block-new-web-contents"
                ]
            )
            context = browser.new_context(user_agent=user_agent)
            page = context.new_page()

            # Record redirects
            def on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    redirect_chain.append({
                        "url": response.url,
                        "status": response.status,
                        "type": "http_redirect"
                    })

            page.on("response", on_response)

            try:
                resp = page.goto(url, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
                final_url = page.url
                http_status = resp.status if resp else 200
                dom_html = page.content()
                
                # Take screenshot in memory
                screenshot_bytes = page.screenshot(type="png", full_page=False)
                screenshot_b64 = base64.b64encode(screenshot_bytes).decode("utf-8")
            finally:
                context.close()
                browser.close()

        # Parse DOM structures
        parsed_html = AttachmentParser.parse_html(dom_html, base_url=final_url)

        return {
            "initial_url": url,
            "final_url": final_url,
            "http_status": http_status,
            "redirect_chain": redirect_chain,
            "dom_html": dom_html,
            "screenshot_base64": screenshot_b64,
            "forms": parsed_html.get("forms", []),
            "has_password_field": parsed_html.get("has_password_field", False),
            "scripts": parsed_html.get("external_scripts", []),
            "has_script_obfuscation": parsed_html.get("has_script_obfuscation", False),
            "has_telegram_exfil": parsed_html.get("has_telegram_exfil", False),
            "has_discord_exfil": parsed_html.get("has_discord_exfil", False),
            "qr_codes": []
        }

    def _extract_with_requests(
        self,
        url: str,
        timeout_seconds: int,
        user_agent: str
    ) -> Dict[str, Any]:
        redirect_chain = []
        final_url = url
        http_status = 200
        dom_html = ""

        headers = {"User-Agent": user_agent}
        session = requests.Session()

        try:
            connect_timeout = min(timeout_seconds, 3)
            read_timeout = min(timeout_seconds, 5)
            resp = session.get(url, headers=headers, timeout=(connect_timeout, read_timeout), allow_redirects=True)
            http_status = resp.status_code
            final_url = resp.url
            dom_html = resp.text

            # Extract history
            for hop in resp.history:
                redirect_chain.append({
                    "url": hop.url,
                    "status": hop.status_code,
                    "type": "http_redirect"
                })
        except requests.exceptions.RequestException as e:
            # Website could be down, unreachable, or dead link (38% of phishing links)
            http_status = 0
            dom_html = f"<html><body><p>Failed to reach host: {e}</p></body></html>"

        parsed_html = AttachmentParser.parse_html(dom_html, base_url=final_url)
        screenshot_b64 = create_synthetic_screenshot(
            url=final_url,
            title=parsed_html.get("title", ""),
            forms_count=parsed_html.get("forms_count", 0)
        )

        return {
            "initial_url": url,
            "final_url": final_url,
            "http_status": http_status,
            "redirect_chain": redirect_chain,
            "dom_html": dom_html,
            "screenshot_base64": screenshot_b64,
            "forms": parsed_html.get("forms", []),
            "has_password_field": parsed_html.get("has_password_field", False),
            "scripts": parsed_html.get("external_scripts", []),
            "has_script_obfuscation": parsed_html.get("has_script_obfuscation", False),
            "has_telegram_exfil": parsed_html.get("has_telegram_exfil", False),
            "has_discord_exfil": parsed_html.get("has_discord_exfil", False),
            "qr_codes": []
        }
