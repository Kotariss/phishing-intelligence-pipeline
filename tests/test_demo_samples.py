"""The synthetic demo samples of the repository behave as documented (README, ПМИ А-1)."""
import os

import pytest

from helpers import run_file, run_page

DEMO = os.path.join(os.path.dirname(__file__), "..", "samples", "demo")


def _run(name):
    with open(os.path.join(DEMO, name), "rb") as f:
        return run_file(name, f.read())


@pytest.mark.parametrize("name", ["04_phish_html_attachment_password_telegram.html", "02_phish_email_html_attachment.eml"])
def test_phishing_samples_are_detected(name):
    state = _run(name)
    assert state.verdict == "MALICIOUS" and state.reason_codes


def test_legitimate_newsletter_is_clean():
    assert _run("03_legit_email_newsletter.eml").verdict == "CLEAN"


def test_legitimate_login_page_is_clean_with_its_url():
    with open(os.path.join(DEMO, "05_legit_login_page.html"), encoding="utf-8") as f:
        state = run_page("https://www.examplebank.example/login", f.read())
    assert state.verdict == "CLEAN", (state.reason_codes, state.risk_score)


def test_spoofed_bank_email_is_flagged():
    assert _run("01_phish_email_bank_spoof.eml").verdict in ("SUSPICIOUS", "MALICIOUS")
