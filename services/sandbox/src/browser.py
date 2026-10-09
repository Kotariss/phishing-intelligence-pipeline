import base64
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

import requests

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
MAX_BODY_BYTES = 5 * 1024 * 1024
REDIRECT_CODES = (301, 302, 303, 307, 308)


def _playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


class BrowserController:
    """Safe crawler and page extractor with Anti-SSRF enforcement on every hop and sub-request."""

    def __init__(self, anti_ssrf_enabled: bool = True, max_redirects: int = 10):
        self.anti_ssrf_enabled = anti_ssrf_enabled
        self.max_redirects = max_redirects

    def _check(self, url: str) -> None:
        safe, msg = validate_url_safety(url, self.anti_ssrf_enabled)
        if not safe:
            raise SecurityError(f"Security validation blocked URL: {msg}")

    def extract_url(
        self,
        url: str,
        timeout_seconds: int = 10,
        user_agent: str = DEFAULT_USER_AGENT
    ) -> Dict[str, Any]:
        self._check(url)
        if _playwright_available():
            try:
                return self._extract_with_playwright(url, timeout_seconds, user_agent)
            except SecurityError:
                raise
            except Exception as e:
                # Browser could not start (missing binaries etc.): degrade to plain HTTP.
                result = self._extract_with_requests(url, timeout_seconds, user_agent)
                result["engine_note"] = f"playwright failed: {type(e).__name__}"
                return result
        return self._extract_with_requests(url, timeout_seconds, user_agent)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _result(url: str, final_url: str, http_status: int, redirect_chain: List[Dict[str, Any]],
                dom_html: str, screenshot_b64: str, engine: str, error: Optional[str] = None) -> Dict[str, Any]:
        parsed_html = AttachmentParser.parse_html(dom_html, base_url=final_url) if dom_html else {}
        parsed_html.pop("type", None)
        result = {
            "initial_url": url,
            "final_url": final_url,
            "http_status": http_status,
            "redirect_chain": redirect_chain,
            "dom_html": dom_html,
            "screenshot_base64": screenshot_b64,
            "engine": engine,
            "qr_codes": [],
        }
        result.update(parsed_html)
        if error:
            result["error"] = error
        return result

    # ---------------------------------------------------------------- playwright
    def _extract_with_playwright(self, url: str, timeout_seconds: int, user_agent: str) -> Dict[str, Any]:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError

        redirect_chain: List[Dict[str, Any]] = []
        blocked: List[str] = []
        screenshot_b64 = ""
        dom_html = ""
        final_url = url
        http_status = 0
        error = None
        checked_hosts: Dict[str, bool] = {}

        def guard(route, request):
            target = request.url
            if target.startswith(("data:", "blob:", "about:")):
                return route.continue_()
            host_key = target.split("/")[2] if "//" in target else target
            if host_key not in checked_hosts:
                checked_hosts[host_key] = validate_url_safety(target, self.anti_ssrf_enabled)[0]
            if not checked_hosts[host_key]:
                blocked.append(target[:200])
                return route.abort("blockedbyclient")
            return route.continue_()

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-gpu", "--disable-dev-shm-usage", "--disable-extensions",
                      "--deny-permission-prompts", "--block-new-web-contents"]
            )
            context = browser.new_context(user_agent=user_agent, accept_downloads=False,
                                          java_script_enabled=True, ignore_https_errors=True)
            context.route("**/*", guard)
            page = context.new_page()

            main_frame_navs: List[str] = []
            page.on("framenavigated", lambda frame: main_frame_navs.append(frame.url) if frame == page.main_frame else None)

            try:
                resp = page.goto(url, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=3000)
                except PlaywrightError:
                    pass
                final_url = page.url
                http_status = resp.status if resp else 0
                if resp is not None:
                    hops = []
                    req = resp.request.redirected_from
                    while req is not None:
                        r = req.response()
                        hops.append({"url": req.url, "status": r.status if r else 0, "type": "http_redirect"})
                        req = req.redirected_from
                    redirect_chain.extend(reversed(hops))
                # JS / meta-refresh navigations after the document loaded
                http_urls = {h["url"] for h in redirect_chain} | {resp.url if resp else url}
                for nav in main_frame_navs:
                    if nav not in http_urls and nav != final_url and nav.startswith("http"):
                        redirect_chain.append({"url": nav, "status": 200, "type": "js_or_meta_redirect"})
                dom_html = page.content()
                screenshot_b64 = base64.b64encode(page.screenshot(type="png", full_page=False)).decode("utf-8")
            except PlaywrightError as e:
                error = f"Navigation failed: {str(e).splitlines()[0][:300]}"
            finally:
                context.close()
                browser.close()

        result = self._result(url, final_url, http_status, redirect_chain, dom_html, screenshot_b64, "playwright", error)
        result["blocked_requests"] = blocked[:50]
        return result

    def render_html_offline(self, html: str, timeout_seconds: int = 10) -> str:
        """Renders an HTML attachment with ALL network access blocked and returns a PNG screenshot (base64)."""
        if not _playwright_available():
            return ""
        from playwright.sync_api import sync_playwright
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--disable-gpu", "--disable-dev-shm-usage"])
                context = browser.new_context(java_script_enabled=False, accept_downloads=False)
                context.route("**/*", lambda route, request: route.continue_()
                              if request.url.startswith(("data:", "about:")) else route.abort())
                page = context.new_page()
                page.set_content(html, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
                shot = page.screenshot(type="png", full_page=False)
                context.close()
                browser.close()
                return base64.b64encode(shot).decode("utf-8")
        except Exception:
            return ""

    # ------------------------------------------------------------------ requests
    def _extract_with_requests(self, url: str, timeout_seconds: int, user_agent: str) -> Dict[str, Any]:
        redirect_chain: List[Dict[str, Any]] = []
        session = requests.Session()
        session.headers["User-Agent"] = user_agent
        current = url
        http_status = 0
        dom_html = ""
        error = None

        try:
            for _ in range(self.max_redirects + 1):
                # Every hop is re-validated (redirect-based SSRF). A blocked hop ends the crawl
                # but the chain collected so far is still returned as evidence.
                safe, msg = validate_url_safety(current, self.anti_ssrf_enabled)
                if not safe:
                    error = f"Redirect hop blocked by Anti-SSRF: {msg}"
                    http_status = 0
                    break
                resp = session.get(current, timeout=(min(timeout_seconds, 5), timeout_seconds),
                                   allow_redirects=False, stream=True)
                http_status = resp.status_code
                if resp.status_code in REDIRECT_CODES and resp.headers.get("Location"):
                    redirect_chain.append({"url": current, "status": resp.status_code, "type": "http_redirect"})
                    current = urljoin(current, resp.headers["Location"])
                    resp.close()
                    continue
                body = resp.raw.read(MAX_BODY_BYTES, decode_content=True) or b""
                resp.close()
                dom_html = body.decode(resp.encoding or "utf-8", errors="ignore")
                break
            else:
                error = f"Too many redirects (>{self.max_redirects})"
        except requests.exceptions.RequestException as e:
            error = f"Failed to reach host: {type(e).__name__}"
            http_status = 0

        # No screenshot without a real browser: a fabricated image would mislead the vision agent.
        return self._result(url, current, http_status, redirect_chain, dom_html, "", "requests", error)
