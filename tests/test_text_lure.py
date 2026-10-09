"""Deterministic lure signals in e-mail / HTML-attachment text, IPFS links, masking of victim addresses."""
import base64

from features.text_lure import text_lure_signals
from features.url_features import mask_emails_in_text
from benign_samples import EMAILS
from helpers import run_file


def _d(b64: str) -> str:
    """Phishing sample texts are stored base64-encoded so antivirus scanners do not flag the test files."""
    return base64.b64decode(b64).decode("utf-8")


WEBMAIL_KIT = _d("PGh0bWw+PGJvZHk+PHA+RGVhciBpbmZvQHZpY3RpbS1jb21wYW55LmN6LDwvcD4KPHA+WW91ciBpbmZvQHZpY3RpbS1jb21wYW55LmN6IGFjY291bnQgcGFzc3dvcmQgaXMgc2V0IHRvIGV4cGlyZSB0b2RheS48L3A+CjxwPjUgbmV3IG1lc3NhZ2VzIGhhdmUgYmVlbiBwdXQgb24gaG9sZC4gS2VlcCB5b3VyIGN1cnJlbnQgcGFzc3dvcmQ6PC9wPgo8YSBocmVmPSJodHRwczovL2lwZnMuaW8vaXBmcy9iYWZrcmVpYWhtZGEzZmJoamJtczV3emJ2ajNib24zY3RsNHJzaXl5cHp2Y3k0dzN6I2luZm9AdmljdGltLWNvbXBhbnkuY3oiPktFRVAgU0FNRSBQQVNTV09SRDwvYT4KPC9ib2R5PjwvaHRtbD4=")


def test_signals_on_webmail_kit_text():
    s = text_lure_signals(_d("RGVhciBpbmZvQHZpY3RpbS5jeiwgeW91ciBwYXNzd29yZCBpcyBzZXQgdG8gZXhwaXJlLiA1IG5ldyBtZXNzYWdlcyBoYXZlIGJlZW4gcHV0IG9uIGhvbGQ="))
    quoted = " ".join(s["account_threat"])
    assert "expire" in quoted and "on hold" in quoted and s["victim_address"] == "info@victim.cz"
    assert text_lure_signals(_d("U29sdmUgQ0FQVENIQSB0byBwcm92ZSBub3QgYSBib3QuIFZlcmlmeSB5b3UgYXJlIGh1bWFu"))["human_check"]


def test_signals_quiet_on_ordinary_mail():
    for text in ("Ваш полис продлён на год. Личный кабинет",
                 "Romashka LLC sent you a document to review and sign.",
                 "A new public key was added to your account. Review keys"):
        s = text_lure_signals(text)
        assert not s["account_threat"] and not s["human_check"]


def test_webmail_kit_attachment_is_suspicious_with_masked_evidence():
    state = run_file("notice.html", WEBMAIL_KIT.encode("utf-8"))
    assert {"CONTENT_ACCOUNT_THREAT", "CONTENT_VICTIM_ADDRESSED", "URL_IPFS_LINK"} <= set(state.reason_codes)
    assert state.verdict in ("SUSPICIOUS", "MALICIOUS")
    for code in ("CONTENT_ACCOUNT_THREAT", "CONTENT_VICTIM_ADDRESSED"):
        assert "info@" not in state.reason_evidence[code]["value"] and "info@" not in state.reason_details[code]


def test_known_legit_mail_gets_no_text_lure_codes():
    for sample in EMAILS:
        state = run_file(f"{sample['id']}.eml", sample["eml"])
        assert not {"CONTENT_ACCOUNT_THREAT", "ATTACH_FAKE_HUMAN_CHECK"} & set(state.reason_codes), sample["id"]


def test_mask_emails_keeps_domain():
    assert mask_emails_in_text("Hello user@victim.example!") == "Hello ***@victim.example!"
