"""ТЗ 4.1.4.6: единичные признаки не дают «фишинг»; нужны признаки из двух независимых групп."""
import pytest

from agents.synthesizer_agent import SynthesizerAgent
from orchestrator.state import PhishingState
from rules import reason_codes as rc


def _verdict(*codes):
    state = PhishingState(incident_id="t_ind", source_type="eml", raw_target="x.eml")
    for code in codes:
        state.add_reason(code, "test", None)
    state = SynthesizerAgent().run(state)
    return state


@pytest.mark.parametrize("code", ["RC_DROP_SCREENCONNECT_RAT", "RC_ATTACH_TELEGRAM_EXFIL", "RC_ATTACH_DISCORD_EXFIL"])
def test_single_group_critical_code_is_only_suspicious(code):
    state = _verdict(code)
    assert state.verdict == "SUSPICIOUS"
    assert state.risk_score >= 0.7  # вес кода сам по себе дотянул бы до «фишинга»
    assert state.network_evidence["verdict_capped"]["independent_groups"]


def test_two_independent_groups_give_phishing():
    state = _verdict("RC_ATTACH_TELEGRAM_EXFIL", "RC_ATTACH_PASSWORD_INPUT")  # отправка данных + запрос пароля
    assert state.verdict == "MALICIOUS"
    assert "verdict_capped" not in state.network_evidence


def test_composite_code_counts_as_two_groups():
    assert len(rc.independent_groups(["ATTACH_OFFLINE_FORM"])) == 2
    assert _verdict("ATTACH_OFFLINE_FORM").verdict == "MALICIOUS"


def test_two_codes_of_one_group_are_not_independent():
    assert rc.independent_groups(["EMAIL_REPLY_TO_MISMATCH", "EMAIL_AUTH_FAIL"]) == {"sender_mismatch"}


def test_weak_support_codes_form_no_group():
    assert rc.independent_groups(["RC_ATTACH_OBFUSCATED_JS", "RC_SANDBOX_EVASION_CODE", "BRAND_MENTION_OFF_DOMAIN"]) == set()


def test_exact_match_with_a_confirmed_indicator_is_phishing(monkeypatch):
    """ТЗ 4.1.4.6: a re-submitted known phishing file is «phishing» by the exact indicator alone; metric runs switch this off."""
    from helpers import run_file
    monkeypatch.delenv("DW2_DISABLE_IOC", raising=False)
    data = b"<html><title>kit</title><form action='https://drop.ioc-test.top/p'><input type='password'></form></html>"
    first = run_file("ioc_kit.html", data)
    assert first.verdict == "MALICIOUS"
    second = run_file("ioc_kit_again.html", data)
    assert "RC_KNOWN_IOC_MATCH" in second.reason_codes and second.verdict == "MALICIOUS"
    assert "RC_KNOWN_IOC_MATCH" in second.reason_details or second.reason_evidence.get("RC_KNOWN_IOC_MATCH")
    monkeypatch.setenv("DW2_DISABLE_IOC", "1")
    third = run_file("ioc_kit_third.html", data)
    assert "RC_KNOWN_IOC_MATCH" not in third.reason_codes


def test_link_text_mismatch_on_an_official_domain_is_not_evidence():
    """A big brand site routinely shows one address and links to another (trackers): neutralised on the official domain like other page evidence."""
    from helpers import run_page
    html = '<html><head><title>Help</title></head><body><a href="https://track.partner-example.top/x?u=1">www.paypal.com/help</a></body></html>'
    assert run_page("https://www.paypal.com/help", html).verdict == "CLEAN"
    assert run_page("https://paypal-help-center.top/help", html).verdict in ("SUSPICIOUS", "MALICIOUS")
