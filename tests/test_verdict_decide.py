"""One verdict function for the pipeline and for re-scoring (rules/verdict.py)."""
from rules.verdict import decide


def test_decide_matches_the_documented_rules():
    assert decide([])["verdict"] == "CLEAN"
    assert decide(["CONTENT_LLM_LURE"])["verdict"] == "CLEAN" and decide(["CONTENT_LLM_LURE"])["advisory"] == ["CONTENT_LLM_LURE"]
    assert decide(["CONTENT_LLM_LURE", "EMAIL_REPLY_TO_MISMATCH"])["verdict"] == "SUSPICIOUS"
    assert decide(["RC_DROP_SCREENCONNECT_RAT"])["verdict"] == "SUSPICIOUS" and decide(["RC_DROP_SCREENCONNECT_RAT"])["capped"]
    assert decide(["RC_ATTACH_TELEGRAM_EXFIL", "RC_ATTACH_PASSWORD_INPUT"])["verdict"] == "MALICIOUS"
    assert decide(["RC_KNOWN_IOC_MATCH"])["verdict"] == "MALICIOUS"
