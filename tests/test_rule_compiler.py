"""L-signature distillation, the light rule engine (portability) and YARA generation."""

import pytest

from rules.engine import rule_matches, build_record
from rules.zero_fpr_guard import ZeroFPRGuard
from rules.yara_gen import compile_check, yara_escape
from attachment_parser import AttachmentParser
from helpers import run_page, run_file, TELEGRAM_KIT, BRAND_LOGIN_KIT


def _record(url, html):
    parsed = AttachmentParser.parse_html(html, base_url=url)
    return build_record(url=url, page=parsed, forms=parsed["forms"], dom_hash=parsed.get("dom_structural_hash"))


def test_exfil_rule_is_active_and_matches_the_kit_on_any_domain():
    state = run_page("https://sber-online-auth.top/login", TELEGRAM_KIT)
    assert state.verdict == "MALICIOUS"
    rule = state.generated_l_signature
    assert rule["kind"] == "exfil_channel" and state.signature_status == "ACTIVE_VERIFIED"
    assert rule["validation_metrics"]["self_match"] is True
    assert rule["validation_metrics"]["false_positives_count"] == 0
    # robustness: the same kit re-hosted on a different domain/path is still matched by the light engine
    moved = _record("https://totally-different.example/xyz/index.html", TELEGRAM_KIT)
    assert rule_matches(rule, moved)


def test_brand_credential_rule_generalises_over_domains_and_paths():
    html = BRAND_LOGIN_KIT.format(title="Госуслуги — вход", h1="Вход на Госуслуги", path="esia", footer="")
    state = run_page("https://gosuslugi-vhod.online/esia/login", html)
    assert state.verdict == "MALICIOUS"
    assert "COMBO_BRAND_CREDENTIAL_FORM" in state.reason_codes
    rule = state.generated_l_signature
    assert rule["kind"] == "brand_credential_phish"
    assert state.signature_status == "ACTIVE_VERIFIED"
    other = BRAND_LOGIN_KIT.format(title="Госуслуги — авторизация", h1="Госуслуги", path="x", footer="")
    assert rule_matches(rule, _record("https://another-host.xyz/a/b", other))
    # ...but not the official site
    assert not rule_matches(rule, _record("https://esia.gosuslugi.ru/login", other))


def test_guard_rejects_overbroad_rules():
    guard = ZeroFPRGuard()
    overbroad = {"rule_id": "X", "predicates": {"all_of": [{"type": "dom_form_structure", "has_password_input": True}], "any_of": []}}
    passed, fp_count, details = guard.evaluate_rule_on_baseline(overbroad)
    assert not passed and fp_count >= 3  # every legitimate login page has a password field
    verdict = guard.verify_rule(overbroad, {"forms": [{"has_password": True}]}, risk_score=0.95)
    assert verdict["approved"] is False and "нарушение нулевых ложных" in verdict["note"]


def test_guard_requires_self_match():
    guard = ZeroFPRGuard()
    rule = {"rule_id": "Y", "predicates": {"all_of": [{"type": "dom_structural_hash", "hash": "dom_skel_x"}], "any_of": []}}
    assert guard.verify_rule(rule, {"dom_hash": "dom_skel_other"}, 0.95)["approved"] is False


def test_unknown_predicates_never_match():
    rule = {"predicates": {"all_of": [{"type": "something_new"}], "any_of": []}}
    assert rule_matches(rule, {"host": "x"}) is False


def test_level1_brand_allowlist():
    registry = ZeroFPRGuard().registry
    def allowed(brand: str, url: str) -> bool:
        return registry.is_domain_allowed(registry.find_brand(brand)["brand_id"], url)
    assert allowed("Сбер", "https://online.sberbank.ru/auth") is True
    assert allowed("Госуслуги", "https://esia.gosuslugi.ru/login") is True
    assert allowed("Сбер", "https://sber-hack.org") is False


def test_yara_rule_is_specific_and_compiles():
    pytest.importorskip("yara")
    state = run_page("https://sber-online-auth.top/login", TELEGRAM_KIT)
    yara_text = state.generated_yara_rule
    assert yara_text and "api.telegram.org/bot7123456789:" in yara_text
    ok, err = compile_check(yara_text)
    assert ok, err
    import yara
    rules = yara.compile(source=yara_text)
    assert rules.match(data=TELEGRAM_KIT.encode("utf-8"))
    assert not rules.match(data=b"<html><form><input type='password'></form></html>")


def test_yara_escaping_handles_unicode_and_quotes():
    assert yara_escape('Сбер "x"\\') == '\\xd0\\xa1\\xd0\\xb1\\xd0\\xb5\\xd1\\x80 \\"x\\"\\\\'


def test_no_rule_for_clean_objects():
    state = run_page("https://online.sberbank.ru/CSAFront/index.do",
                     BRAND_LOGIN_KIT.format(title="СберБанк Онлайн", h1="Вход", path="CSAFront", footer=""))
    assert state.verdict == "CLEAN"
    assert state.generated_l_signature is None and state.generated_yara_rule is None


def test_html_attachment_rule():
    att = BRAND_LOGIN_KIT.format(title="Microsoft 365 — Sign in", h1="Microsoft", path="o365",
                                 footer="").replace('action="/o365/auth.php"', 'action="https://grab.example.top/m.php"')
    state = run_file("Invoice_2026.pdf.html", att.encode("utf-8"))
    assert state.verdict == "MALICIOUS"
    assert {"ATTACH_OFFLINE_FORM", "RC_LURE_DOUBLE_EXTENSION"} <= set(state.reason_codes)
    assert state.generated_l_signature["kind"] in ("exfil_channel", "brand_credential_phish", "html_attachment")
