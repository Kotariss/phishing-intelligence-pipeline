"""Lure techniques come from the model; each claim must quote the sent text verbatim."""
import pytest

from agents.content_agent import _techniques_from_llm
from evaluation import _run_object
from helpers import run_file
from llm.client import LLMUnavailable
from orchestrator.state import PhishingState

SENT = "Subject: Mailbox notice. Dear info@company.cz, your password will expire today. Keep your current password here."


def test_quotes_must_occur_in_the_sent_text():
    ok = _techniques_from_llm({"techniques": {"account_threat": "your password will expire today",
                                              "victim_addressed": "Dear info@company.cz", "fake_human_check": None}}, SENT)
    assert ok["account_threat"] == ["your password will expire today"] and ok["victim_address"] == "info@company.cz"
    invented = _techniques_from_llm({"techniques": {"account_threat": "your account will be deleted in 24 hours",
                                                    "victim_addressed": "Dear customer"}}, SENT)
    assert invented["account_threat"] == [] and invented["victim_address"] is None


def _eml(body: str) -> bytes:
    return ("From: IT <it@helpdesk-mail.example>\nTo: info@company.cz\nSubject: Mailbox notice\n"
            "Content-Type: text/plain; charset=utf-8\n\n" + body + "\nhttps://mail-verify.example.top/login\n").encode()


def test_a_phrase_is_not_evidence_unless_the_model_names_it(fake_llm):
    state = run_file("mail.eml", _eml("Dear info@company.cz, your password will expire today."))
    assert "CONTENT_ACCOUNT_THREAT" not in state.reason_codes  # default answer: no technique


def test_model_technique_with_a_verbatim_quote_is_evidence(fake_llm):
    fake_llm.lure.update(is_phishing_lure=True, lure_type="account_alert", indicators=["mailbox full"],
                         techniques={"account_threat": "your mailbox storage is full", "victim_addressed": None})
    state = run_file("mail.eml", _eml("Hello, your mailbox storage is full and incoming mail is paused."))
    assert {"CONTENT_ACCOUNT_THREAT", "CONTENT_LLM_LURE"} <= set(state.reason_codes)


def test_unavailable_model_skips_the_object(fake_llm):
    fake_llm.fail = True
    with pytest.raises(LLMUnavailable):
        run_file("mail.eml", _eml("Hello, your mailbox storage is full and incoming mail is paused."))
    row = _run_object("phishing", "keis2_email", "mail.eml",
                      lambda: PhishingState(incident_id="t_skip", source_type="eml", raw_target="mail.eml",
                                            raw_bytes=_eml("Hello there, please read this message."), offline_mode=True))
    assert row["status"] == "skipped_llm" and "unavailable" in row["error"]
