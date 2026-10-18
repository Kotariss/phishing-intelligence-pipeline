"""QR codes in data-URI images of HTML, on the rendered page, inverted / small codes (ТЗ 4.1.4.5)."""
import base64
import io

import pytest

cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")
from PIL import Image, ImageOps  # noqa: E402

import dispatch  # noqa: E402
from attachment_parser import AttachmentParser  # noqa: E402
from qr_scanner import scan_qr_codes  # noqa: E402

URL = "https://qr-landing.example.top/login"


def _qr_png(scale: int = 8, invert: bool = False) -> bytes:
    matrix = cv2.QRCodeEncoder.create().encode(URL)
    img = Image.fromarray(matrix).convert("L")
    img = ImageOps.expand(img, border=4, fill=255)
    img = img.resize((img.width * scale, img.height * scale), Image.NEAREST)
    if invert:
        img = ImageOps.invert(img)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_inverted_and_small_codes_are_read():
    assert scan_qr_codes(_qr_png()) == [URL]
    assert scan_qr_codes(_qr_png(invert=True)) == [URL]
    assert scan_qr_codes(_qr_png(scale=2)) == [URL]


def test_qr_in_data_uri_images_of_html():
    b64 = base64.b64encode(_qr_png()).decode()
    img_tag = AttachmentParser.parse_html(f'<html><body><p>Scan to sign</p><img src="data:image/png;base64,{b64}"></body></html>')
    css_bg = AttachmentParser.parse_html(f"<html><body><div style=\"background:url('data:image/png;base64,{b64}')\"></div></body></html>")
    assert img_tag["qr_codes"] == [URL] and css_bg["qr_codes"] == [URL]


def test_qr_visible_only_on_the_rendered_page_is_found():
    class FakeRenderer:  # the offline render of a page whose QR is drawn with a table
        def render_html_offline(self, html):
            return base64.b64encode(_qr_png()).decode()
    parsed = dispatch.parse_file_bytes(b"<html><body><table><tr><td></td></tr></table></body></html>", "page.html",
                                       browser_ctrl=FakeRenderer())
    assert parsed["qr_codes"] == [URL]
