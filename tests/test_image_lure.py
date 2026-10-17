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


def _eml_with_picture(png: bytes) -> bytes:
    return (b"From: Docs <docs@files-share.example>\nTo: a@b.ru\nSubject: Document\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nSee attached.\n'
            b'--B\nContent-Type: image/png; name="scan.png"\nContent-Disposition: attachment; filename="scan.png"\n'
            b"Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(png) + b"\n--B--\n")


def test_picture_inside_email_is_read_by_ocr(monkeypatch):
    """ТЗ 4.1.1.2: a picture attached to an e-mail goes to OCR like a standalone image file."""
    import os
    import attachment_parser
    monkeypatch.setattr(attachment_parser, "ocr_image", lambda content: FAKE_VIEWER)
    png = b"\x89PNG\r\n\x1a\n" + os.urandom(attachment_parser.OCR_MIN_IMAGE_BYTES)
    parsed = attachment_parser.AttachmentParser.parse_eml(_eml_with_picture(png))
    assert parsed["attachments_analysis"][0]["ocr_text"].startswith("Microsoft Excel")
    state = run_file("letter.eml", _eml_with_picture(png))
    assert "IMAGE_CREDENTIAL_PROMPT" in state.reason_codes
    assert "scan.png" in state.reason_evidence["IMAGE_CREDENTIAL_PROMPT"]["label"]


def test_small_inline_pictures_are_not_ocred(monkeypatch):
    import attachment_parser
    calls = []
    monkeypatch.setattr(attachment_parser, "ocr_image", lambda content: calls.append(1) or "x")
    attachment_parser.AttachmentParser.parse_eml(_eml_with_picture(b"\x89PNG\r\n\x1a\n" + b"0" * 500))
    assert calls == []
