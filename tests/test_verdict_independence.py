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
