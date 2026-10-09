"""Verdict policy (ТЗ п. 4.1.4.6, таблица 4): single indicators never yield "phishing";
known-legitimate objects never get "phishing" and rarely "suspicious"."""
import pytest

import benign_samples
from rules import reason_codes as rc
from helpers import run_page, run_file, BRAND_LOGIN_KIT


@pytest.mark.parametrize("code", sorted(c for c, info in rc.REASON_CODES.items()
                                        if info.severity not in ("critical",) and info.category != "combo"))
def test_no_single_non_critical_indicator_reaches_block(code):
    assert rc.combine([code]) < 0.70


def test_two_independent_strong_indicators_block():
    assert rc.combine(["RC_BRAND_SPOOF_DISPLAYNAME", "ATTACH_OFFLINE_FORM"]) >= 0.70
    assert rc.combine(["BRAND_IMPERSONATION_CONFIRMED", "COMBO_BRAND_CREDENTIAL_FORM"]) >= 0.70


@pytest.mark.parametrize("sample", benign_samples.HTML_PAGES, ids=lambda s: s["id"])
def test_benign_pages_are_never_phishing(sample):
    state = run_page(sample["url"], sample["html"])
    assert state.verdict != "MALICIOUS", (state.reason_codes, state.reason_details)
    assert state.generated_l_signature is None or state.signature_status != "ACTIVE_VERIFIED"


@pytest.mark.parametrize("sample", benign_samples.EMAILS, ids=lambda s: s["id"])
def test_benign_emails_are_clean(sample):
    state = run_file(f"{sample['id']}.eml", sample["eml"])
    assert state.verdict == "CLEAN", (state.reason_codes, state.reason_details)


def test_benign_suspicious_share_within_limit():
    verdicts = [run_page(s["url"], s["html"]).verdict for s in benign_samples.HTML_PAGES]
    verdicts += [run_file(f"{s['id']}.eml", s["eml"]).verdict for s in benign_samples.EMAILS]
    assert verdicts.count("MALICIOUS") == 0
    assert verdicts.count("SUSPICIOUS") / len(verdicts) <= 0.10


def test_password_form_alone_is_not_phishing():
    html = BRAND_LOGIN_KIT.format(title="Личный кабинет", h1="Вход", path="lk", footer="")
    assert run_page("https://my-small-shop.ru/lk/login", html).verdict == "CLEAN"


def test_brand_news_without_form_is_not_impersonation():
    html = "<html><head><title>Сбербанк повысил ставки</title></head><body><h1>Сбербанк повысил ставки</h1></body></html>"
    state = run_page("https://news.example.ru/a", html)
    assert "BRAND_IMPERSONATION_CONFIRMED" not in state.reason_codes
    assert state.verdict == "CLEAN"


def test_official_landing_neutralises_page_evidence_but_keeps_email_evidence():
    from orchestrator.state import PhishingState
    from orchestrator.graph import run_pipeline
    eml = (b"From: =?utf-8?B?0KHQsdC10YDQsdCw0L3Qug==?= <alert@sber-notify.top>\nReply-To: x@mail.ru\nTo: a@b.ru\n"
           b"Subject: test\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n"
           b'<a href="https://track.evil-redirect.top/r?id=1">Open</a>')
    landing = "<html><head><title>СберБанк</title></head><body><form><input type='password'></form></body></html>"
    state = run_pipeline(PhishingState(
        incident_id="t_cloak", source_type="eml", raw_target="m.eml", raw_bytes=eml, offline_mode=True,
        precollected_links=[{"url": "https://track.evil-redirect.top/r?id=1", "final_url": "https://www.sberbank.ru/",
                             "html": landing, "redirect_chain": [{"from": "https://track.evil-redirect.top/r?id=1",
                                                                  "to": "https://www.sberbank.ru/", "status_code": 302}]}]))
    assert "RC_ATTACH_PASSWORD_INPUT" not in state.reason_codes          # official page evidence neutralised
    assert {"RC_BRAND_SPOOF_DISPLAYNAME", "RC_CLOAKING_TO_OFFICIAL"} <= set(state.reason_codes)
    assert state.verdict == "MALICIOUS"


def test_every_reason_code_is_explained():
    state = run_page("https://gosuslugi-vhod.online/esia/login",
                     BRAND_LOGIN_KIT.format(title="Госуслуги", h1="Госуслуги", path="esia", footer=""))
    assert state.reason_codes
    for code in state.reason_codes:
        assert state.reason_details.get(code), code
    assert "Обоснование" in state.explanation


def test_newsletter_linking_to_product_named_domain_is_not_phishing():
    """Regression (labelled EML test set): one link to a third-party domain named after a product
    must not be counted twice as look-alike domain + brand impersonation of an unrelated page."""
    eml = (b"From: Tech Weekly <news@techweekly-digest.com>\nTo: a@b.ru\nSubject: Weekly tips\nMIME-Version: 1.0\n"
           b"Content-Type: text/html; charset=utf-8\n\n"
           b'<a href="https://jake.example-blog.com/post">Read</a> <a href="https://outlook.4team.example/addins">Outlook add-ins</a>'
           b' <a href="https://paypal-giftcards-review.example.org/">review</a>')
    state = run_file("newsletter.eml", eml)
    assert state.verdict != "MALICIOUS", state.reason_details
    assert "BRAND_IMPERSONATION_CONFIRMED" not in state.reason_codes


def test_lookalike_counts_when_the_page_is_hosted_on_it():
    html = BRAND_LOGIN_KIT.format(title="Вход", h1="Вход", path="auth", footer="")
    state = run_page("https://gosuslugi-pay.help-center.ru/auth/login", html)
    assert "BRAND_LOOKALIKE_DOMAIN" in state.reason_codes
    assert state.verdict == "MALICIOUS"


def test_findings_carry_supporting_artefacts():
    """ТЗ 4.1.5.1: each verdict lists reason codes with supporting evidence (URL, DOM fragment, hash ...)."""
    from helpers_demo import TELEGRAM_KIT
    state = run_page("https://sber-online-auth.top/login", TELEGRAM_KIT)
    ev = state.reason_evidence
    assert ev["RC_ATTACH_TELEGRAM_EXFIL"]["type"] == "dom" and "api.telegram.org/bot7123456789:" in ev["RC_ATTACH_TELEGRAM_EXFIL"]["value"]
    assert "AAHdqTcvCH1v" not in ev["RC_ATTACH_TELEGRAM_EXFIL"]["value"]  # bot secret masked
    assert "<form" in ev["RC_ATTACH_PASSWORD_INPUT"]["value"]
    assert ev["BRAND_IMPERSONATION_CONFIRMED"]["type"] == "dom" and "<title>" in ev["BRAND_IMPERSONATION_CONFIRMED"]["value"]
    assert state.fingerprints.get("dom_structural_hash")
