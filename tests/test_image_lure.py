"""Image lures: text on an image attachment (OCR) — fake document viewers and sign-in screenshots."""
import base64

import dispatch
from features.image_text import image_lure_signals
from benign_samples import IMAGES
from helpers import run_file


def _d(b64: str) -> str:
    """Phishing sample texts are stored base64-encoded so antivirus scanners do not flag the test files."""
    return base64.b64decode(b64).decode("utf-8")


FAKE_VIEWER = _d("TWljcm9zb2Z0IEV4Y2VsIHZpY3RpbUBtYWlsLnJ1IEVudGVyIHBhc3N3b3JkIEF1dGhlbnRpY2F0aW9uIHJlcXVpcmVkIHRvIHZpZXcgdGhpcyBmaWxlLiBOb3RlOiBQYXNzd29yZCBwcm90ZWN0ZWQgZmlsZS4gT25seSB0aGlzIHVzZXIgY2FuIHZpZXcgdGhpcyBmaWxlIFZpZXc=")


def test_signals_fake_viewer_multilingual():
    assert image_lure_signals(FAKE_VIEWER)["document_gate"]
    zh = image_lure_signals(_d("T3JkZXJTaGVldC0jNzQ1MjQ5Lnhsc3gg6KaB5p+l55yL5oKo55qE55S15a2Q6KGo5qC877yM6K+36aqM6K+B5LiL6Z2i55qE55S15a2Q6YKu5Lu2IElEIGFAYi5jb20g5a+G56CBIOiusOS9j+aIkeeahElE"))
    assert zh["credential_prompt"] and zh["document_gate"]


def test_signals_ignore_ordinary_images():
    for text in ("FedEx AWB shipment tracking number 1234 delivery scheduled",
                 "INVOICE No 2026-118 Amount due: 1200 EUR Payment by bank transfer",
                 "Microsoft Teams meeting Friday 15:00 Join on your computer"):
        s = image_lure_signals(text)
        assert not s["credential_prompt"] and not s["document_gate"]


def test_fake_viewer_image_is_detected_with_evidence(monkeypatch):
    monkeypatch.setattr(dispatch, "ocr_image", lambda content: FAKE_VIEWER)
    state = run_file("Invoice_Bill_of_Lading.png", IMAGES[0]["png"])
    assert {"IMAGE_CREDENTIAL_PROMPT", "IMAGE_FAKE_DOCUMENT_VIEWER"} <= set(state.reason_codes)
    assert state.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert "password" in state.reason_evidence["IMAGE_CREDENTIAL_PROMPT"]["value"].lower()
    # brand named on the image + fake viewer = impersonation of that brand
    assert state.brand_evidence.detection_source == "ocr"
    assert "BRAND_IMPERSONATION_CONFIRMED" in state.reason_codes


def test_sign_in_howto_is_never_malicious(monkeypatch):
    monkeypatch.setattr(dispatch, "ocr_image",
                        lambda content: "How to open the HR portal 1. Go to portal 2. Enter your login and password")
    state = run_file("howto.png", IMAGES[0]["png"])
    assert state.verdict != "MALICIOUS"
    assert "IMAGE_FAKE_DOCUMENT_VIEWER" not in state.reason_codes
