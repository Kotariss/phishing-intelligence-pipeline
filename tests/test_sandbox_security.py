import ipaddress

import pytest

from security import validate_url_safety, is_ip_forbidden
from browser import BrowserController


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin",
    "http://10.1.2.3/",
    "http://192.168.0.10/",
    "http://172.20.0.5/",
    "http://169.254.169.254/latest/meta-data/",
    "http://100.64.0.1/",                 # CGNAT
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",         # IPv4-mapped IPv6
    "http://0.0.0.0/",
    "http://localhost:8000/",
    "http://db:5432/",                    # trusted-zone service name
    "http://metadata.google.internal/",
    "file:///etc/passwd",
    "ftp://example.com/",
    "javascript:alert(1)",
])
def test_ssrf_targets_are_blocked(url):
    safe, _ = validate_url_safety(url)
    assert safe is False


def test_public_ip_is_allowed():
    assert validate_url_safety("http://8.8.8.8/")[0] is True


def test_dead_domain_is_permitted_but_marked():
    safe, msg = validate_url_safety("https://definitely-not-existing-domain-zz9.invalid/")
    assert safe is True and "DNS" in msg


def test_ip_classification():
    assert is_ip_forbidden(ipaddress.ip_address("198.18.0.1"))
    assert not is_ip_forbidden(ipaddress.ip_address("93.184.216.34"))


class _FakeResponse:
    def __init__(self, status, location=None, body=b"<html></html>"):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.encoding = "utf-8"
        self._body = body

        class _Raw:
            def __init__(self, data):
                self.data = data

            def read(self, *_a, **_k):
                return self.data
        self.raw = _Raw(body)

    def close(self):
        pass


def test_redirect_to_internal_address_is_blocked(monkeypatch):
    """A public URL answering 302 -> http://169.254.169.254 must not be followed (redirect-based SSRF)."""
    calls = []

    def fake_get(self, url, **kwargs):
        calls.append(url)
        return _FakeResponse(302, location="http://169.254.169.254/latest/meta-data/")

    monkeypatch.setattr("requests.Session.get", fake_get)
    ctrl = BrowserController(anti_ssrf_enabled=True)
    result = ctrl._extract_with_requests("http://8.8.8.8/start", 5, "test-agent")
    assert calls == ["http://8.8.8.8/start"]
    assert "blocked" in result["error"].lower()
    assert result["redirect_chain"][0]["status"] == 302


def test_requests_engine_never_fabricates_screenshots(monkeypatch):
    monkeypatch.setattr("requests.Session.get", lambda self, url, **kw: _FakeResponse(200, body=b"<title>x</title>"))
    result = BrowserController()._extract_with_requests("http://8.8.8.8/", 5, "ua")
    assert result["screenshot_base64"] == ""
    assert result["http_status"] == 200


def test_playwright_redirect_to_forbidden_address_is_not_followed(monkeypatch):
    """Playwright calls the route handler only for the first URL of a 302 chain: every hop must still be checked."""
    pytest.importorskip("playwright")
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import browser as browser_mod

    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path in ("/start", "/middle"):
                self.send_response(302)
                self.send_header("Location", "/middle" if self.path == "/start" else f"{forbidden}/internal/secret")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<title>internal</title>")

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    # 127.0.0.1 plays a public site; 'localhost' (same server) plays the forbidden target (metadata service, worker API).
    forbidden = f"http://localhost:{server.server_port}"
    monkeypatch.setattr(browser_mod, "validate_url_safety",
                        lambda url, enabled=True: ("//localhost" not in url, "forbidden host" if "//localhost" in url else "ok"))
    try:
        result = BrowserController()._extract_with_playwright(base + "/start", 10, "ua")
    except Exception as e:  # browser binaries missing in this environment
        pytest.skip(f"playwright unavailable: {e}")
    finally:
        server.shutdown()
    assert hits == ["/start", "/middle"]
    assert result["blocked_requests"] == [f"{forbidden}/internal/secret"]
    assert [h["url"] for h in result["redirect_chain"]] == [base + "/start"]
