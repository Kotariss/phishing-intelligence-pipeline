"""
Access to the sandbox extractors.

Primary path: HTTP calls to the isolated `sandbox` service.
Secondary path (offline parsers only, or explicit opt-in): the same extractor code imported in-process.
  * Local checkout: services/sandbox/src
  * Docker worker image: /app/sandbox_src (copied at build time)
"""
import os
import socket
import sys
from typing import Any, Dict, Optional

import requests

try:
    from .config import get_settings
except (ImportError, ValueError):
    from config import get_settings

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = [
    os.path.abspath(os.path.join(_SRC_DIR, "..", "..", "sandbox", "src")),
    os.path.abspath(os.path.join(_SRC_DIR, "..", "sandbox_src")),
]


def _ensure_sandbox_path() -> bool:
    for path in _CANDIDATES:
        if os.path.isdir(path):
            if path not in sys.path:
                sys.path.append(path)
            return True
    return False


def load_parsers():
    """Returns (AttachmentParser, parse_file_bytes, scan_qr_codes) or raises ImportError."""
    if not _ensure_sandbox_path():
        raise ImportError("sandbox extractor sources are not available")
    from attachment_parser import AttachmentParser  # type: ignore
    from dispatch import parse_file_bytes  # type: ignore
    from qr_scanner import scan_qr_codes  # type: ignore
    return AttachmentParser, parse_file_bytes, scan_qr_codes


def dom_skeleton_hash(html: str) -> Dict[str, Any]:
    try:
        AttachmentParser, _, _ = load_parsers()
    except ImportError:
        return {}
    return AttachmentParser.extract_dom_skeleton_hash(html)


class SandboxClient:
    def __init__(self, settings=None):
        self.settings = settings or get_settings()
        self._available: Optional[bool] = None
        self._offline_renderer = None  # BrowserController for in-process parsing, False when unavailable

    @property
    def base_url(self) -> str:
        return f"http://{self.settings.SANDBOX_HOST}:{self.settings.SANDBOX_PORT}"

    def available(self) -> bool:
        if self._available is None:
            try:
                with socket.create_connection((self.settings.SANDBOX_HOST, self.settings.SANDBOX_PORT), timeout=0.5):
                    self._available = True
            except OSError:
                self._available = False
        return self._available

    def extract_url(self, url: str) -> Dict[str, Any]:
        """Returns sandbox extraction result. Never raises: errors are reported in the result."""
        timeout = self.settings.SANDBOX_TIMEOUT_SECONDS
        if self.available():
            try:
                resp = requests.post(f"{self.base_url}/api/v1/extract/url",
                                     json={"url": url, "timeout_seconds": timeout},
                                     timeout=(2.0, timeout * 3 + 10))
                if resp.status_code == 200:
                    return resp.json()
                detail = resp.json().get("detail", resp.text[:200]) if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:200]
                return self._failed(url, f"sandbox HTTP {resp.status_code}: {detail}",
                                    blocked=resp.status_code == 403)
            except requests.RequestException as e:
                return self._failed(url, f"sandbox request failed: {type(e).__name__}")

        if not self.settings.SANDBOX_INPROCESS_FALLBACK:
            return self._failed(url, "sandbox service unreachable and in-process fetching is disabled "
                                     "(set SANDBOX_INPROCESS_FALLBACK=true for local development)")
        try:
            _ensure_sandbox_path()
            from browser import BrowserController  # type: ignore
            from security import SecurityError  # type: ignore
        except ImportError as e:
            return self._failed(url, f"in-process sandbox unavailable: {e}")
        try:
            ctrl = BrowserController(anti_ssrf_enabled=self.settings.ANTI_SSRF_ENABLED)
            result = ctrl.extract_url(url, timeout_seconds=timeout)
            result["engine"] = f"in-process/{result.get('engine', '?')}"
            return result
        except SecurityError as e:
            return self._failed(url, str(e), blocked=True)
        except Exception as e:
            return self._failed(url, f"in-process extraction failed: {type(e).__name__}: {e}")

    def extract_file(self, content: bytes, filename: str, base_url: str = "") -> Dict[str, Any]:
        """Parses an untrusted file (EML/HTML/PDF/Office/image). `base_url` resolves relative links
        when the file is a pre-collected landing page."""
        if self.available():
            try:
                resp = requests.post(f"{self.base_url}/api/v1/extract/file",
                                     files={"file": (os.path.basename(filename) or "sample", content)},
                                     data={"base_url": base_url} if base_url else None,
                                     timeout=(2.0, 60.0))
                if resp.status_code == 200:
                    return resp.json()
                return {"type": "unknown", "error": f"sandbox HTTP {resp.status_code}", "links": []}
            except requests.RequestException as e:
                return {"type": "unknown", "error": f"sandbox request failed: {type(e).__name__}", "links": []}

        # Parsing untrusted files is the sandbox's job; in-process parsing is an explicit opt-in.
        if not self.settings.SANDBOX_INPROCESS_FALLBACK:
            return {"type": "unknown", "links": [],
                    "error": "sandbox service unreachable and in-process parsing is disabled "
                             "(set SANDBOX_INPROCESS_FALLBACK=true for local development)"}
        try:
            _, parse_file_bytes, _ = load_parsers()
        except ImportError as e:
            return {"type": "unknown", "error": f"no parser available: {e}", "links": []}
        # Same as the sandbox service: HTML is rendered offline (network blocked) so the VLM gets a screenshot.
        if self._offline_renderer is None:
            try:
                from browser import BrowserController  # type: ignore
                self._offline_renderer = BrowserController(anti_ssrf_enabled=self.settings.ANTI_SSRF_ENABLED)
            except ImportError:
                self._offline_renderer = False
        try:
            return parse_file_bytes(content, filename, browser_ctrl=self._offline_renderer or None, base_url=base_url)
        except Exception as e:
            return {"type": "unknown", "error": f"{type(e).__name__}: {e}", "links": []}

    @staticmethod
    def _failed(url: str, error: str, blocked: bool = False) -> Dict[str, Any]:
        return {
            "initial_url": url,
            "final_url": url,
            "http_status": 0,
            "redirect_chain": [],
            "dom_html": "",
            "screenshot_base64": "",
            "forms": [],
            "error": error,
            "ssrf_blocked": blocked,
        }
