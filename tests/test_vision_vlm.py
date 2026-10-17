"""VLM answers are evidence only under the same rules as other brand sources (fake model, no network)."""
import base64
import json

import pytest

import dispatch
from llm.client import LLMClient
from benign_samples import IMAGES
from helpers import run_page, run_file

CHECKOUT = """<html><head><title>Оформление заказа</title></head><body><h1>Оплата заказа № 5512</h1>
<p>Оплата картой. Платёж обрабатывает банк-эквайер.</p>
<form action="https://pay.acquirer-example.ru/init" method="post"><input name="cardnumber" autocomplete="cc-number">
<input name="cvc" autocomplete="cc-csc"><button>Оплатить</button></form></body></html>"""


SHOT = base64.b64encode(IMAGES[0]["png"]).decode()


@pytest.fixture
def fake_vlm(monkeypatch):
    """Model is 'available'; the VLM returns the answer set by the test, text calls fail (no LLM text evidence)."""
    answer = {}
    monkeypatch.setattr(LLMClient, "enabled", property(lambda self: True))
    monkeypatch.setattr(LLMClient, "ask_vlm", lambda self, prompt, image_b64, **kw: json.dumps(answer))
    monkeypatch.setattr(LLMClient, "ask_llm", lambda self, *a, **kw: "[Fallback] test")
    monkeypatch.setattr("agents.vision_agent._VLM_CACHE", {})
    return answer


def test_payment_logo_on_a_shop_checkout_is_not_impersonation(fake_vlm):
    fake_vlm.update(impersonated_brand=None, other_brands=["Сбер", "МИР"], asks_user_action="enter_card",
                    lure="payment", login_form_visible=False, confidence=0.9)
    state = run_page("https://shop.example-store.ru/checkout", CHECKOUT, screenshot_base64=SHOT)
    assert "BRAND_IMPERSONATION_CONFIRMED" not in state.reason_codes
    assert state.verdict != "MALICIOUS"


def test_vlm_brand_confirms_impersonation_only_when_data_is_asked(fake_vlm):
    fake_vlm.update(impersonated_brand="Microsoft", asks_user_action="enter_credentials", lure="account_login",
                    login_form_visible=True, confidence=0.9)
    state = run_page("https://login-check.example.top/", "<html><title>Verify</title><body>Hi</body></html>",
                     screenshot_base64=SHOT)
    assert "BRAND_IMPERSONATION_CONFIRMED" in state.reason_codes


def test_vlm_brand_without_a_data_request_is_only_a_mention(fake_vlm):
    fake_vlm.update(impersonated_brand="Microsoft", asks_user_action="click_link", lure="other",
                    login_form_visible=False, confidence=0.9)
    state = run_page("https://events.example.org/invite", "<html><title>Invite</title><body>Join</body></html>",
                     screenshot_base64=SHOT)
    assert "BRAND_IMPERSONATION_CONFIRMED" not in state.reason_codes


def test_receipt_image_is_not_a_document_lure(fake_vlm, monkeypatch):
    monkeypatch.setattr(dispatch, "ocr_image", lambda content: "")
    fake_vlm.update(impersonated_brand=None, asks_user_action="none", lure="payment", login_form_visible=False, confidence=0.9)
    assert "VISUAL_DOCUMENT_LURE" not in run_file("receipt.png", IMAGES[0]["png"]).reason_codes
    fake_vlm.update(asks_user_action="enter_credentials", lure="b2b_invoice")
    monkeypatch.setattr("agents.vision_agent._VLM_CACHE", {})
    assert "VISUAL_DOCUMENT_LURE" in run_file("invoice.png", IMAGES[0]["png"]).reason_codes
