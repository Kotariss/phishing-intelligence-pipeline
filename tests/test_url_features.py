from features.url_features import confusable_skeleton, qr_payload_url
from helpers import run_page


def test_qr_payload_without_scheme_is_a_url():
    assert qr_payload_url("https://a.example/x") == "https://a.example/x"
    assert qr_payload_url("www.sber-login.ru/auth") == "http://www.sber-login.ru/auth"
    assert qr_payload_url("pay-gosuslugi.ru") == "http://pay-gosuslugi.ru"
    assert qr_payload_url("hxxps://evil[.]top/a") == "https://evil.top/a"
    for not_url in ("invoice.pdf", "WIFI:S:home;T:WPA;P:secret;;", "Hello world", "+7 900 000-00-00", ""):
        assert qr_payload_url(not_url) is None


def test_confusable_skeleton():
    assert confusable_skeleton("аррӏе.com".encode("idna").decode()) == "apple.com"   # whole-Cyrillic label
    assert confusable_skeleton("g00gle.com") == "google.com"
    assert confusable_skeleton("rnicrosoft.com") == "microsoft.com"
    assert confusable_skeleton("example.com") is None
    assert confusable_skeleton("госуслуги.рф".encode("idna").decode()) is None       # genuine national IDN


def test_whole_cyrillic_homograph_of_brand_domain_is_flagged():
    host = "аррӏе.com".encode("idna").decode()
    state = run_page(f"https://{host}/signin", "<html><title>Sign in</title><body>Hello</body></html>")
    assert "BRAND_HOMOGRAPH_DOMAIN" in state.reason_codes
    assert "apple.com" in state.reason_details["BRAND_HOMOGRAPH_DOMAIN"]


def test_ascii_lookalike_of_brand_domain_is_flagged():
    state = run_page("https://rnicrosoft.com/login", "<html><title>Sign in</title><body>Hello</body></html>")
    assert "BRAND_LOOKALIKE_DOMAIN" in state.reason_codes
