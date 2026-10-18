"""VLM answers become evidence under the same rules as other brand sources (fake model, no network)."""
import base64

from benign_samples import IMAGES
from helpers import run_page, run_file

SHOT = base64.b64encode(IMAGES[0]["png"]).decode()
CHECKOUT = """<html><head><title>Оформление заказа</title></head><body><h1>Оплата заказа № 5512</h1>
<p>Оплата картой. Платёж обрабатывает банк-эквайер.</p>
<form action="https://pay.acquirer-example.ru/init" method="post"><input name="cardnumber" autocomplete="cc-number">
<input name="cvc" autocomplete="cc-csc"><button>Оплатить</button></form></body></html>"""


def test_payment_logo_on_a_shop_checkout_is_not_impersonation(fake_llm):
    fake_llm.vlm.update(impersonated_brand=None, other_brands=["Сбер", "МИР"], asks_user_action="enter_card", lure="payment")
    state = run_page("https://shop.example-store.ru/checkout", CHECKOUT, screenshot_base64=SHOT)
    assert fake_llm.prompts_of("vision_brand")
    assert "BRAND_IMPERSONATION_CONFIRMED" not in state.reason_codes and state.verdict != "MALICIOUS"


def test_vlm_brand_confirms_impersonation_only_when_data_is_asked(fake_llm):
    fake_llm.vlm.update(impersonated_brand="Microsoft", asks_user_action="enter_credentials", lure="account_login",
                        login_form_visible=True)
    state = run_page("https://login-check.example.top/", "<html><title>Verify</title><body>Hi</body></html>",
                     screenshot_base64=SHOT)
    assert "BRAND_IMPERSONATION_CONFIRMED" in state.reason_codes


def test_vlm_brand_without_a_data_request_is_only_a_mention(fake_llm):
    fake_llm.vlm.update(impersonated_brand="Microsoft", asks_user_action="click_link")
    state = run_page("https://events.example.org/invite", "<html><title>Invite</title><body>Join</body></html>",
                     screenshot_base64=SHOT)
    assert "BRAND_IMPERSONATION_CONFIRMED" not in state.reason_codes


def test_receipt_is_not_a_lure_but_a_gated_invoice_is(fake_llm):
    fake_llm.vlm.update(asks_user_action="none", lure="payment")
    assert not run_file("receipt.png", IMAGES[0]["png"]).reason_codes
    fake_llm.vlm.update(asks_user_action="enter_credentials", lure="b2b_invoice")
    codes = run_file("invoice.png", IMAGES[1]["png"]).reason_codes
    assert {"IMAGE_CREDENTIAL_PROMPT", "IMAGE_FAKE_DOCUMENT_VIEWER"} <= set(codes)
