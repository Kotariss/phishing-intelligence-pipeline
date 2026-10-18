"""Archive contents, legacy Office (OLE), RTF, DDE and containers (synthetic samples, no network)."""
import base64
import io
import zipfile

from attachment_parser import AttachmentParser, OLE_MAGIC
from helpers import run_file

FORM = b'<html><title>Sign in</title><form action="https://x.top/p"><input type="password"></form></html>'


def _zip(files) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _encrypted(zip_bytes: bytes) -> bytes:
    """Sets the 'encrypted' flag of every entry (local and central headers): content unreadable without a password."""
    b = bytearray(zip_bytes)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = b.find(sig)
        while i != -1:
            b[i + off] |= 0x01
            i = b.find(sig, i + 4)
    return bytes(b)


def _eml_with(filename: str, payload: bytes) -> bytes:
    return (b"From: Billing <b@billing-docs.example>\nTo: a@b.ru\nSubject: Invoice\nMIME-Version: 1.0\n"
            b'Content-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nInvoice attached, password 1234.\n'
            b"--B\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"" + filename.encode()
            + b'"\nContent-Transfer-Encoding: base64\n\n' + base64.encodebytes(payload) + b"\n--B--\n")


def test_html_form_inside_a_zip_is_analysed():
    item = AttachmentParser.analyze_attachment("invoice.zip", "", _zip({"docs/login.html": FORM}))
    inner = item["archive_items"][0]
    assert inner["kind"] == "html" and inner["has_password_field"] and item["forms"]
    state = run_file("mail.eml", _eml_with("invoice.zip", _zip({"docs/login.html": FORM})))
    assert "ATTACH_OFFLINE_FORM" in state.reason_codes
    assert "invoice.zip/docs/login.html" in state.reason_details["ATTACH_OFFLINE_FORM"]


def test_nested_archives_are_limited_in_depth():
    deep = _zip({"l1.zip": _zip({"l2.zip": _zip({"l3.html": FORM})})})
    l1 = AttachmentParser.analyze_attachment("a.zip", "", deep)["archive_items"][0]
    assert l1["archive_items"][0]["archive_items"] == []  # depth limit: the third level is not unpacked


def test_password_protected_archive_is_reported():
    data = _encrypted(_zip({"invoice.exe": b"MZ" + b"\x00" * 64}))
    assert AttachmentParser.analyze_attachment("invoice.zip", "", data)["archive_encrypted_entries"] == ["invoice.exe"]
    assert "ATTACH_ARCHIVE_ENCRYPTED" in run_file("mail.eml", _eml_with("invoice.zip", data)).reason_codes


def test_legacy_office_macros_and_equation_editor():
    doc = OLE_MAGIC + b"\x00" * 512 + "_VBA_PROJECT".encode("utf-16-le") + b"\x00" * 64 + "Equation Native".encode("utf-16-le")
    item = AttachmentParser.analyze_attachment("report.doc", "", doc)
    assert item["kind"] == "ole" and item["has_vba_macros"] and item["has_equation_editor"]
    codes = run_file("report.doc", doc).reason_codes
    assert {"ATTACH_ACTIVE_MACRO_MARKER", "ATTACH_EXPLOIT_DOCUMENT"} <= set(codes)


def test_rtf_exploit_object_and_plain_rtf():
    exploit = (b"{\\rtf1\\ansi {\\object\\objemb\\objupdate{\\*\\objclass Equation.3}"
               b"{\\*\\objdata 01050000020000000b0000004571756174696f6e2e3300}}}")
    item = AttachmentParser.analyze_attachment("order.rtf", "", exploit)
    assert item["kind"] == "rtf" and item["has_object_autoupdate"] and item["has_equation_editor"]
    plain = AttachmentParser.analyze_attachment("notes.rtf", "", b"{\\rtf1\\ansi Solve the equation x+1=2.}")
    assert not plain["has_embedded_object"] and not plain["has_equation_editor"]


def test_dde_in_docx_and_csv():
    docx = _zip({"[Content_Types].xml": b"<Types/>",
                 "word/document.xml": b'<w:document><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" </w:instrText></w:r></w:document>'})
    assert AttachmentParser.analyze_attachment("letter.docx", "", docx)["has_dde"]
    csv = b"name,amount\n=cmd|' /C calc'!A0,1\n"
    assert AttachmentParser.analyze_attachment("table.csv", "", csv)["has_dde"]
    assert not AttachmentParser.analyze_attachment("ok.csv", "", b"name,amount\nA,=1+2\n")["has_dde"]
    assert "ATTACH_DDE" in run_file("mail.eml", _eml_with("letter.docx", docx)).reason_codes


def test_containers_are_recognised_but_not_unpacked():
    iso = b"\x00" * 0x8001 + b"CD001" + b"\x00" * 100
    item = AttachmentParser.analyze_attachment("scan.pdf", "application/pdf", iso)  # disk image renamed to .pdf
    assert item["kind"] == "container" and item["container_type"] == "iso" and item["is_executable"]
    seven = AttachmentParser.analyze_attachment("docs.7z", "", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64)
    assert seven["container_type"] == "7z" and seven["container_unpacked"] is False and not seven["is_executable"]
