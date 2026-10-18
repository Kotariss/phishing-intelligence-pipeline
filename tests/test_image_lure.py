"""Image lures: the VLM judges the picture (fake document viewers, sign-in screenshots); OCR text of pictures
inside e-mails reaches the text classifier."""
import base64
import os

import attachment_parser
from benign_samples import IMAGES
from helpers import run_file


def test_fake_document_viewer_image_is_detected_with_evidence(fake_llm):
    fake_llm.vlm.update(impersonated_brand="Microsoft", asks_user_action="enter_credentials", lure="document_share",
                        login_form_visible=True, reason="asks for the mailbox password to view a protected file")
    state = run_file("Invoice_Bill.png", IMAGES[0]["png"])
    assert {"IMAGE_CREDENTIAL_PROMPT", "IMAGE_FAKE_DOCUMENT_VIEWER", "BRAND_IMPERSONATION_CONFIRMED"} <= set(state.reason_codes)
    assert state.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert "protected file" in state.reason_evidence["IMAGE_CREDENTIAL_PROMPT"]["label"]
    assert state.brand_evidence.detection_source == "vlm"


def test_ordinary_image_is_clean(fake_llm):
    state = run_file("banner.png", IMAGES[0]["png"])  # default answer: no brand claimed, nothing asked
    assert state.verdict == "CLEAN" and not state.reason_codes
    assert fake_llm.prompts_of("vision_brand")


def _eml_with_picture(png: bytes) -> bytes:
    return (b"From: Docs <docs@files-share.example>\nTo: a@b.ru\nSubject: Document\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nSee attached.\n'
            b'--B\nContent-Type: image/png; name="scan.png"\nContent-Disposition: attachment; filename="scan.png"\n'
            b"Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(png) + b"\n--B--\n")


def test_text_of_a_picture_inside_an_email_reaches_the_model(fake_llm, monkeypatch):
    """ТЗ 4.1.1.2: a picture attached to an e-mail goes to OCR, its text to the lure classifier."""
    monkeypatch.setattr(attachment_parser, "ocr_image", lambda content: "Enter your mailbox password to view the invoice")
    png = b"\x89PNG\r\n\x1a\n" + os.urandom(attachment_parser.OCR_MIN_IMAGE_BYTES)
    assert attachment_parser.AttachmentParser.parse_eml(_eml_with_picture(png))["attachments_analysis"][0]["ocr_text"]
    run_file("letter.eml", _eml_with_picture(png))
    assert any("mailbox password to view the invoice" in p for p in fake_llm.prompts_of("lure_classifier"))


def test_small_inline_pictures_are_not_ocred(monkeypatch):
    calls = []
    monkeypatch.setattr(attachment_parser, "ocr_image", lambda content: calls.append(1) or "x")
    attachment_parser.AttachmentParser.parse_eml(_eml_with_picture(b"\x89PNG\r\n\x1a\n" + b"0" * 500))
    assert calls == []
