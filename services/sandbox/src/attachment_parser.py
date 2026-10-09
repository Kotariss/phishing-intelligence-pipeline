import io
import re
import hashlib
import zipfile
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import warnings

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

try:
    from .qr_scanner import scan_qr_codes
except ImportError:
    try:
        from qr_scanner import scan_qr_codes
    except ImportError:
        from src.qr_scanner import scan_qr_codes


# Try importing fitz (PyMuPDF)
try:
    import pymupdf as fitz
except ImportError:
    try:
        import fitz
    except ImportError:
        fitz = None


URL_IN_TEXT = re.compile(r'https?:/{1,3}[^\s<>"\'\)\]]+', re.IGNORECASE)
TELEGRAM_BOT = re.compile(r'api\.telegram\.org/bot(\d{6,12}):([A-Za-z0-9_-]{30,})', re.IGNORECASE)
TELEGRAM_ANY = re.compile(r'api\.telegram\.org/bot', re.IGNORECASE)
TELEGRAM_CHAT_ID = re.compile(r'chat_id["\'\s:=]+["\']?(-?\d{5,15})', re.IGNORECASE)
DISCORD_WEBHOOK = re.compile(r'discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', re.IGNORECASE)
DISCORD_ANY = re.compile(r'discord(?:app)?\.com/api/webhooks', re.IGNORECASE)
JS_REDIRECT = re.compile(
    r'(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)
JS_NETWORK_SINK = re.compile(
    r'(?:fetch\s*\(|\.open\s*\(\s*["\'](?:POST|GET)["\']\s*,|\$\.(?:ajax|post|get)\s*\(\s*\{?\s*(?:url\s*:\s*)?|axios\.(?:post|get)\s*\(|sendBeacon\s*\()\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)
META_REFRESH_URL = re.compile(r'url\s*=\s*["\']?([^"\'>\s;]+)', re.IGNORECASE)
LONG_BASE64 = re.compile(r'[A-Za-z0-9+/]{400,}={0,2}')
HEX_ESCAPES = re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}')
EMAIL_VALUE = re.compile(r'^[^@\s]+@[^@\s]+\.[a-z]{2,}$', re.IGNORECASE)

HTML_EXTENSIONS = (".html", ".htm", ".shtml", ".xhtml", ".svg")
OFFICE_EXTENSIONS = (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm")
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")
ARCHIVE_EXTENSIONS = (".zip",)
EXECUTABLE_EXTENSIONS = (".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
                         ".hta", ".ps1", ".lnk", ".iso", ".img", ".jar", ".wsf", ".cab")
MAX_NESTED_ATTACHMENTS = 20


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _registrable(host: str) -> str:
    """Naive eTLD+1 (good enough to tell same-site from cross-site form actions)."""
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "or", "ne", "go"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _absolute(url: str, base_url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if url.startswith("//"):
        return "https:" + url
    if base_url:
        try:
            return urljoin(base_url, url)
        except ValueError:
            return url
    return url


def compact_html(fragment: str, limit: int = 700) -> str:
    """Readable evidence fragment: long attribute values (data URIs, tokens) shortened, whitespace collapsed."""
    text = re.sub(r'(=\s*["\'])([^"\']{80})[^"\']+(["\'])', r'\1\2…\3', str(fragment))
    text = re.sub(r'\s+', ' ', text).strip()
    return text if len(text) <= limit else text[:limit] + " …"


def window(text: str, pattern, before: int = 120, after: int = 220) -> str:
    """Fragment of `text` around the first match of `pattern` (regex or compiled)."""
    m = pattern.search(text) if hasattr(pattern, "search") else re.search(pattern, text, re.I)
    if not m:
        return ""
    return compact_html(text[max(0, m.start() - before):m.end() + after], limit=before + after + 200)


def normalize_url(url: str) -> str:
    """Repairs malformed links that browsers still follow: 'https:/host', 'https://https://host',
    'https//host', surrounding whitespace/quotes and trailing punctuation from plain text."""
    u = (url or "").strip().strip('"\'<>').rstrip(".,;)")
    u = re.sub(r'^(https?)(?::/*|//)(?=[^/])', r'\1://', u, flags=re.IGNORECASE)
    u = re.sub(r'^(https?://)+(https?)(?::/*|//)', r'\2://', u, flags=re.IGNORECASE)
    return u


def _is_http(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


def _safe_decode(payload: bytes, charset: Optional[str]) -> str:
    for enc in (charset, "utf-8", "cp1251", "latin-1"):
        if not enc:
            continue
        try:
            return payload.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", errors="ignore")


def _attachment_kind(filename: str, content_type: str, payload: bytes) -> str:
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    if name.endswith(HTML_EXTENSIONS) or ctype in ("text/html", "image/svg+xml"):
        return "html"
    if name.endswith(".pdf") or ctype == "application/pdf" or payload[:4] == b"%PDF":
        return "pdf"
    if name.endswith(OFFICE_EXTENSIONS):
        return "office"
    if name.endswith(IMAGE_EXTENSIONS) or ctype.startswith("image/"):
        return "image"
    if name.endswith(ARCHIVE_EXTENSIONS) or payload[:4] == b"PK\x03\x04":
        return "archive"
    return "other"


B64_LITERAL = re.compile(r'["\'`]([A-Za-z0-9+/\s]{80,}={0,2})["\'`]')
PCT_LITERAL = re.compile(r'["\']((?:%[0-9A-Fa-f]{2}|[^"\'\s%]){60,})["\']')
HEX_LITERAL = re.compile(r'(?:\\x[0-9a-fA-F]{2}){16,}')
UNICODE_LITERAL = re.compile(r'(?:\\u00[0-9a-fA-F]{2}){16,}')
CHARCODE_CALL = re.compile(r'fromCharCode\s*\(\s*((?:\d{2,3}\s*,\s*){10,}\d{2,3})\s*\)', re.IGNORECASE)
DECODED_LOOKS_ACTIVE = re.compile(r'<\s*(?:form|input|script|iframe|meta|html|body|div|a\s)|https?://|location|password', re.IGNORECASE)
MAX_DECODED_BYTES = 2 * 1024 * 1024


HUNTER_CALL = re.compile(
    r'eval\(function\(h,u,n,t,e,r\)\{.*?\}\("([^"]*)",\s*\d+,\s*"([^"]+)",\s*(\d+),\s*(\d+),\s*\d+\)\)', re.DOTALL)
PACKER_CALL = re.compile(
    r"eval\(function\(p,a,c,k,e,[rd]\)\{.*?\}\('(.*?)',\s*(\d+),\s*(\d+),\s*'(.*?)'\.split\('\|'\)", re.DOTALL)
_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _unhunter(payload: str, alphabet: str, offset: int, base: int) -> str:
    """Decoder for the widespread 'hunter' obfuscator: eval(function(h,u,n,t,e,r){...}("...",u,"n",t,e,r))."""
    delimiter = alphabet[base]
    out = []
    for chunk in payload.split(delimiter):
        if not chunk:
            continue
        for idx, ch in enumerate(alphabet):
            chunk = chunk.replace(ch, str(idx))
        out.append(chr(int(chunk, base) - offset))
    raw = "".join(out)
    try:
        return raw.encode("latin-1").decode("utf-8")  # decodeURIComponent(escape(r))
    except (UnicodeEncodeError, UnicodeDecodeError):
        return raw


def _unpack_packer(payload: str, radix: int, count: int, words: List[str]) -> str:
    """Decoder for Dean Edwards' packer: eval(function(p,a,c,k,e,d){...}('...',a,c,'..'.split('|')))."""
    def to_base(n: int) -> str:
        if n < radix:
            return _DIGITS[n] if radix <= 62 else str(n)
        return to_base(n // radix) + _DIGITS[n % radix]

    lookup = {to_base(i): (words[i] if i < len(words) and words[i] else to_base(i)) for i in range(count)}
    return re.sub(r'\b\w+\b', lambda m: lookup.get(m.group(0), m.group(0)), payload)


def deobfuscate_payloads(text: str) -> List[str]:
    """Statically decodes common encodings used to hide phishing markup / URLs. Only decoded
    strings that look like markup, URLs or navigation code are returned."""
    import base64
    from urllib.parse import unquote

    found: List[str] = []
    budget = MAX_DECODED_BYTES

    def keep(candidate: str) -> None:
        nonlocal budget
        if candidate and budget > 0 and DECODED_LOOKS_ACTIVE.search(candidate) and candidate not in found:
            found.append(candidate[:budget])
            budget -= len(candidate)

    for m in B64_LITERAL.finditer(text):
        raw = re.sub(r'\s+', '', m.group(1))
        if len(raw) % 4 == 1:
            continue
        try:
            keep(base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    for m in PCT_LITERAL.finditer(text):
        if m.group(1).count("%") >= 10:
            keep(unquote(m.group(1)))
    for m in HEX_LITERAL.finditer(text):
        try:
            keep(bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8", errors="ignore"))
        except ValueError:
            continue
    for m in UNICODE_LITERAL.finditer(text):
        keep("".join(chr(int(h, 16)) for h in re.findall(r'\\u([0-9a-fA-F]{4})', m.group(0))))
    for m in CHARCODE_CALL.finditer(text):
        try:
            keep("".join(chr(int(n)) for n in re.findall(r'\d+', m.group(1))))
        except ValueError:
            continue
    for m in HUNTER_CALL.finditer(text):
        try:
            keep(_unhunter(m.group(1), m.group(2), int(m.group(3)), int(m.group(4))))
        except (ValueError, IndexError, OverflowError):
            continue
    for m in PACKER_CALL.finditer(text):
        try:
            keep(_unpack_packer(m.group(1).replace("\\'", "'"), int(m.group(2)), int(m.group(3)), m.group(4).split("|")))
        except (ValueError, IndexError, RecursionError):
            continue
    return found


def _merge_layer(base: Dict[str, Any], layer: Dict[str, Any]) -> None:
    """Merges features of a de-obfuscated layer into the outer document's features."""
    base["forms"] = base["forms"] + layer["forms"]
    base["forms_count"] = len(base["forms"])
    for flag in ("has_password_field", "has_telegram_exfil", "has_discord_exfil", "has_sandbox_evasion"):
        base[flag] = bool(base.get(flag) or layer.get(flag))
    for key in ("telegram_bot_tokens", "telegram_chat_ids", "discord_webhooks", "external_scripts",
                "external_resource_hosts", "iframes", "js_redirects", "js_endpoints", "js_external_endpoints",
                "links", "obfuscation_markers", "evasion_markers"):
        base[key] = sorted(set(base.get(key) or []) | set(layer.get(key) or []))
    for key in ("title", "meta_refresh", "favicon", "embedded_image_base64", "brand_context_text"):
        if not base.get(key) and layer.get(key):
            base[key] = layer[key]
    snippets = base.setdefault("evidence_snippets", {})
    for key, value in (layer.get("evidence_snippets") or {}).items():
        snippets.setdefault(key, "[раскодировано] " + value)
    if layer.get("visible_text"):
        base["visible_text"] = (base.get("visible_text", "") + " " + layer["visible_text"]).strip()[:4000]


_HEADER_LINE = re.compile(rb'^[A-Za-z][A-Za-z0-9-]{1,60}:[ \t]', re.MULTILINE)


def sniff_file_kind(filename: str, payload: bytes) -> str:
    """Detects the sample type by name AND content: eml | html | pdf | office | image | archive | other.
    Dataset EML files have no extension, so content sniffing is mandatory."""
    name = (filename or "").lower()
    head = payload[:65536]
    if name.endswith((".eml", ".msg")):
        return "eml"
    if head.startswith(b"%PDF") or name.endswith(".pdf"):
        return "pdf"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"BM")) or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    if head.startswith(b"PK\x03\x04"):
        return "office" if name.endswith(OFFICE_EXTENSIONS) else "archive"
    first_line = head.lstrip()[:200]
    if _HEADER_LINE.match(first_line):
        header_block = head.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
        lowered = header_block.lower()
        if (b"\nfrom:" in lowered or lowered.startswith(b"from:")) and (b"subject:" in lowered or b"mime-version:" in lowered or b"received:" in lowered):
            return "eml"
    if name.endswith(HTML_EXTENSIONS) or re.search(rb'<(?:!doctype\s+html|html|head|body|form|script|div)\b', head[:4096], re.I):
        return "html"
    if name.endswith(OFFICE_EXTENSIONS):
        return "office"
    if name.endswith(IMAGE_EXTENSIONS):
        return "image"
    return "other"


class AttachmentParser:
    """Safe, offline multi-format parser for EML, HTML, PDF, Office documents and images."""

    @staticmethod
    def _decode_header_str(header_val: Any) -> str:
        if not header_val:
            return ""
        decoded_parts = []
        try:
            for part, enc in decode_header(str(header_val)):
                if isinstance(part, bytes):
                    decoded_parts.append(_safe_decode(part, enc))
                else:
                    decoded_parts.append(str(part))
            return "".join(decoded_parts).strip()
        except Exception:
            return str(header_val).strip()

    # ------------------------------------------------------------------ EML
    @staticmethod
    def parse_eml(file_bytes: bytes) -> Dict[str, Any]:
        msg = BytesParser(policy=policy.compat32).parsebytes(file_bytes)

        from_header = AttachmentParser._decode_header_str(msg.get("From", ""))
        subject = AttachmentParser._decode_header_str(msg.get("Subject", ""))
        to_header = AttachmentParser._decode_header_str(msg.get("To", ""))
        date_header = str(msg.get("Date", ""))
        reply_to = AttachmentParser._decode_header_str(msg.get("Reply-To", ""))
        auth_results = str(msg.get("Authentication-Results", "")).lower()
        spf_header = str(msg.get("Received-SPF", "")).lower()

        from_name, from_address = "", ""
        parsed_from = getaddresses([from_header])
        if parsed_from:
            from_name, from_address = parsed_from[0]
        from_name = from_name.strip().strip('"').strip("'")
        from_address = from_address.strip()
        from_domain = from_address.split("@")[1].lower().strip() if "@" in from_address else ""
        reply_to_addr = getaddresses([reply_to])[0][1] if reply_to else ""
        reply_to_domain = reply_to_addr.split("@")[1].lower() if "@" in reply_to_addr else ""

        body_text, body_html = "", ""
        attachments: List[Dict[str, Any]] = []

        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", "")).lower()
            filename = AttachmentParser._decode_header_str(part.get_filename() or "")
            payload = part.get_payload(decode=True) or b""

            is_attachment = "attachment" in disposition or bool(filename)
            if not is_attachment and content_type == "text/plain":
                body_text += _safe_decode(payload, part.get_content_charset())
            elif not is_attachment and content_type == "text/html":
                body_html += _safe_decode(payload, part.get_content_charset())
            elif payload:
                # Real attachments and inline (cid:) images are both analysed.
                attachments.append({
                    "filename": filename or f"inline_{content_type.replace('/', '_')}",
                    "content_type": content_type,
                    "inline": not is_attachment,
                    "bytes": payload
                })

        # Links from body
        links = set()
        link_text_mismatch = []
        if body_html:
            soup = BeautifulSoup(body_html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = normalize_url(a["href"])
                if not _is_http(href):
                    continue
                links.add(href)
                anchor = a.get_text(" ", strip=True)
                shown = URL_IN_TEXT.search(anchor) or re.match(r'^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+$', anchor, re.I)
                if shown:
                    shown_host = _host(shown.group(0) if shown.group(0).startswith("http") else "http://" + shown.group(0))
                    if shown_host and _registrable(shown_host) != _registrable(_host(href)):
                        link_text_mismatch.append({"shown": anchor[:120], "href": href[:300]})
        for raw_url in URL_IN_TEXT.findall(body_text):
            links.add(normalize_url(raw_url))

        # Recursive analysis of attachments (HTML / PDF / Office / images / archives)
        analysis = [AttachmentParser.analyze_attachment(a["filename"], a["content_type"], a["bytes"], inline=a["inline"])
                    for a in attachments[:MAX_NESTED_ATTACHMENTS]]

        qr_codes, forms = [], []
        for item in analysis:
            for u in item.get("links", []):
                links.add(u)
            qr_codes.extend(item.get("qr_codes", []))
            forms.extend(item.get("forms", []))
        for q in qr_codes:
            if _is_http(q):
                links.add(q)

        spf_pass = "spf=pass" in auth_results or spf_header.startswith("pass")
        spf_fail = any(f"spf={v}" in auth_results for v in ("fail", "softfail")) or spf_header.startswith(("fail", "softfail"))
        dkim_pass = "dkim=pass" in auth_results
        dmarc_fail = "dmarc=fail" in auth_results

        return {
            "type": "eml",
            "from_name": from_name,
            "from_address": from_address,
            "from_domain": from_domain,
            "subject": subject,
            "to": to_header,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "reply_to_mismatch": bool(reply_to_domain and from_domain and _registrable(reply_to_domain) != _registrable(from_domain)),
            "date": date_header,
            "auth_results_raw": str(msg.get("Authentication-Results", ""))[:400],
            "spf_pass": spf_pass,
            "spf_fail": spf_fail,
            "dkim_pass": dkim_pass,
            "dmarc_fail": dmarc_fail,
            "links": sorted(links),
            "link_text_mismatch": link_text_mismatch[:20],
            "body_html": body_html,
            "body_text_preview": body_text[:1500],
            "attachments_count": len(attachments),
            "attachments_meta": [{"filename": a["filename"], "content_type": a["content_type"],
                                  "size": len(a["bytes"]), "inline": a["inline"],
                                  "sha256": hashlib.sha256(a["bytes"]).hexdigest()} for a in attachments],
            "attachments_analysis": analysis,
            "qr_codes": sorted(set(qr_codes)),
            "forms": forms,
            "has_password_field": any(i.get("has_password_field") for i in analysis),
            "has_telegram_exfil": any(i.get("has_telegram_exfil") for i in analysis),
            "has_discord_exfil": any(i.get("has_discord_exfil") for i in analysis),
            "has_script_obfuscation": any(i.get("has_script_obfuscation") for i in analysis),
            "has_vba_macros": any(i.get("has_vba_macros") for i in analysis),
            "has_executable_attachment": any(i.get("is_executable") for i in analysis),
        }

    @staticmethod
    def analyze_attachment(filename: str, content_type: str, payload: bytes, inline: bool = False) -> Dict[str, Any]:
        """Analyses one attachment and returns a JSON-safe summary (no raw bytes)."""
        kind = _attachment_kind(filename, content_type, payload)
        name_low = (filename or "").lower()
        summary: Dict[str, Any] = {
            "filename": filename,
            "content_type": content_type,
            "kind": kind,
            "inline": inline,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "is_executable": name_low.endswith(EXECUTABLE_EXTENSIONS),
            "links": [],
            "qr_codes": [],
        }
        try:
            if kind == "html":
                parsed = AttachmentParser.parse_html(_safe_decode(payload, None))
                parsed.pop("embedded_image_base64", None)
                parsed.pop("visible_text", None)
                summary.update({k: v for k, v in parsed.items() if k != "type"})
            elif kind == "pdf":
                summary.update({k: v for k, v in AttachmentParser.parse_pdf(payload).items() if k != "type"})
            elif kind == "office":
                summary.update({k: v for k, v in AttachmentParser.parse_office(payload, filename).items() if k not in ("type", "filename")})
            elif kind == "image":
                summary["qr_codes"] = scan_qr_codes(payload)
            elif kind == "archive":
                summary.update(AttachmentParser.parse_archive(payload))
        except Exception as e:
            summary["error"] = f"{type(e).__name__}: {e}"
        return summary

    @staticmethod
    def parse_archive(file_bytes: bytes) -> Dict[str, Any]:
        names: List[str] = []
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                names = zf.namelist()[:200]
        except zipfile.BadZipFile:
            return {"archive_error": "not a zip archive"}
        return {
            "archive_entries": names,
            "is_executable": any(n.lower().endswith(EXECUTABLE_EXTENSIONS) for n in names),
            "archive_has_html": any(n.lower().endswith(HTML_EXTENSIONS) for n in names),
        }

    # ------------------------------------------------------------------ DOM
    @staticmethod
    def extract_dom_skeleton_hash(html_str: str) -> Dict[str, Any]:
        """
        Extracts structural DOM skeleton (tag hierarchy stripped of text, inline styles, IDs and comments)
        and computes normalized structural hash (dom_skel_<hash>) to identify phishing kit reuse.
        """
        try:
            soup = BeautifulSoup(html_str, "html.parser")

            def _traverse(node) -> List[str]:
                tag_reprs = []
                for child in node.find_all(recursive=False):
                    tag_name = child.name
                    if not tag_name:
                        continue
                    if tag_name in ("script", "style", "svg", "noscript", "meta", "link"):
                        tag_reprs.append(tag_name)
                        continue
                    if tag_name == "input":
                        inp_type = (child.get("type") or "text").lower().strip()
                        tag_reprs.append(f"input:{inp_type}")
                    elif tag_name in ("button", "a"):
                        tag_reprs.append(tag_name)
                    else:
                        inner = _traverse(child)
                        tag_reprs.append(f"{tag_name}({','.join(inner)})" if inner else tag_name)
                return tag_reprs

            target_node = soup.body if soup.body else soup
            skeleton_parts = _traverse(target_node)
            skeleton_str = ">".join(skeleton_parts) if skeleton_parts else "empty_dom"
            skel_hash = hashlib.sha256(skeleton_str.encode("utf-8")).hexdigest()[:16]

            return {
                "dom_skeleton": skeleton_str[:500],
                "dom_structural_hash": f"dom_skel_{skel_hash}",
                "tags_count": len(soup.find_all())
            }
        except Exception:
            return {"dom_skeleton": "", "dom_structural_hash": None, "tags_count": 0}

    @staticmethod
    def _form_features(form, base_url: str, base_site: str) -> Dict[str, Any]:
        action_raw = (form.get("action") or "").strip()
        action_abs = _absolute(action_raw, base_url)
        action_host = _host(action_abs) if _is_http(action_abs) else ""
        if action_host:
            is_external = (not base_site) or _registrable(action_host) != base_site
        else:
            is_external = False

        inputs = form.find_all(["input", "select", "textarea"])

        def _attr_blob(inp) -> str:
            return " ".join(str(inp.get(a) or "") for a in ("name", "id", "placeholder", "autocomplete", "aria-label")).lower()

        has_password = any((inp.get("type") or "").lower() == "password" for inp in inputs)
        has_email = any((inp.get("type") or "").lower() == "email"
                        or re.search(r'e-?mail|login|user|почт|логин', _attr_blob(inp)) for inp in inputs)
        has_card = any(re.search(r'card|cvv|cvc|ccnum|cc-number|pan\b|expir|карт', _attr_blob(inp)) for inp in inputs)
        has_phone = any((inp.get("type") or "").lower() == "tel" or re.search(r'phone|tel\b|телефон', _attr_blob(inp)) for inp in inputs)
        prefilled_email = any(EMAIL_VALUE.match((inp.get("value") or "").strip()) for inp in inputs)

        submit_btn = form.find(["button", "input"], {"type": re.compile(r"submit", re.I)}) or form.find("button")
        submit_meta: Dict[str, Any] = {}
        if submit_btn:
            submit_text = submit_btn.get_text(strip=True) if submit_btn.name == "button" else (submit_btn.get("value") or "")
            onclick = submit_btn.get("onclick") or ""
            formaction = _absolute(submit_btn.get("formaction") or "", base_url)
            submit_meta = {
                "text": submit_text[:80],
                "onclick": onclick[:200],
                "has_telegram": bool(TELEGRAM_ANY.search(onclick)),
                "target_url": formaction or action_abs or action_raw,
            }

        return {
            "action": action_raw,
            "action_absolute": action_abs,
            "action_host": action_host,
            "method": (form.get("method") or "GET").upper(),
            "has_password": has_password,
            "has_email": bool(has_email),
            "has_card": bool(has_card),
            "has_phone": bool(has_phone),
            "prefilled_victim_email": prefilled_email,
            "is_external": is_external,
            "submit_button": submit_meta,
            "snippet": compact_html(form),
        }

    @staticmethod
    def parse_html(html_str: str, base_url: str = "") -> Dict[str, Any]:
        """HTML/DOM feature extraction with static de-obfuscation: payloads hidden in
        atob()/unescape()/hex escapes/fromCharCode are decoded (up to 2 layers) and re-parsed,
        because phishing kits commonly build the credential form via document.write()."""
        result = AttachmentParser._parse_html_layer(html_str or "", base_url)
        pending = deobfuscate_payloads(html_str or "")
        layers = 0
        while pending and layers < 2:
            layers += 1
            decoded_html = "\n".join(pending)
            layer = AttachmentParser._parse_html_layer(decoded_html, base_url)
            _merge_layer(result, layer)
            pending = deobfuscate_payloads(decoded_html)
        result["deobfuscated_layers"] = layers
        if layers:
            result["obfuscation_markers"] = sorted(set(result["obfuscation_markers"]) | {"encoded_html_payload"})
            result["has_script_obfuscation"] = True
        return result

    @staticmethod
    def _parse_html_layer(html_str: str, base_url: str = "") -> Dict[str, Any]:
        html_str = html_str or ""
        soup = BeautifulSoup(html_str, "html.parser")
        base_site = _registrable(_host(base_url)) if _is_http(base_url) else ""

        title = soup.title.get_text(strip=True) if soup.title else ""

        forms_data = [AttachmentParser._form_features(f, base_url, base_site) for f in soup.find_all("form")]
        password_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})

        # Links / iframes / resources
        links = set()
        for a in soup.find_all("a", href=True):
            href = _absolute(normalize_url(a["href"]), base_url)
            if _is_http(href):
                links.add(href)
        iframes = [_absolute(f.get("src") or "", base_url) for f in soup.find_all(["iframe", "frame"]) if f.get("src")]
        external_scripts = [_absolute(s["src"], base_url) for s in soup.find_all("script", src=True)]
        resource_urls = external_scripts + [_absolute(l.get("href") or "", base_url) for l in soup.find_all("link", href=True)] \
            + [_absolute(i.get("src") or "", base_url) for i in soup.find_all("img", src=True) if not (i.get("src") or "").startswith("data:")]
        resource_hosts = sorted({_host(u) for u in resource_urls if _is_http(u)} - {""})
        external_resource_hosts = [h for h in resource_hosts if not base_site or _registrable(h) != base_site]

        favicon = ""
        for l in soup.find_all("link", href=True):
            rel = " ".join(l.get("rel") or []).lower()
            if "icon" in rel:
                favicon = _absolute(l["href"], base_url)
                break

        # Client-side redirects
        meta_refresh = ""
        for m in soup.find_all("meta"):
            if (m.get("http-equiv") or "").lower() == "refresh":
                mm = META_REFRESH_URL.search(m.get("content") or "")
                if mm:
                    meta_refresh = _absolute(mm.group(1), base_url)
                    break

        inline_js = "\n".join(s.get_text() for s in soup.find_all("script") if not s.get("src"))
        js_redirects = sorted({_absolute(u, base_url) for u in JS_REDIRECT.findall(inline_js) if not u.startswith("#")})[:10]
        js_endpoints = sorted({_absolute(u, base_url) for u in JS_NETWORK_SINK.findall(inline_js)})[:20]
        js_external_endpoints = [u for u in js_endpoints if _is_http(u) and (not base_site or _registrable(_host(u)) != base_site)]

        # Exfiltration channels (the whole document: kits hide them in attributes too)
        tg_tokens = sorted({f"{m[0]}:{m[1][:6]}…" for m in TELEGRAM_BOT.findall(html_str)})
        tg_chat_ids = sorted(set(TELEGRAM_CHAT_ID.findall(html_str)))[:5]
        has_telegram = bool(TELEGRAM_ANY.search(html_str))
        has_discord = bool(DISCORD_ANY.search(html_str))

        # Obfuscation: count independent techniques so that one atob() on a legit page is not enough
        js_low = inline_js.lower()
        obfuscation_markers = []
        if "string.fromcharcode" in js_low:
            obfuscation_markers.append("fromCharCode")
        if re.search(r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k', js_low):
            obfuscation_markers.append("packer")
        if "unescape(" in js_low and "document.write" in js_low:
            obfuscation_markers.append("unescape_document_write")
        if "atob(" in js_low and re.search(r'eval\s*\(|document\.write|new\s+function', js_low):
            obfuscation_markers.append("atob_eval")
        if LONG_BASE64.search(inline_js):
            obfuscation_markers.append("long_base64_blob")
        if HEX_ESCAPES.search(inline_js):
            obfuscation_markers.append("hex_escapes")
        evasion_markers = [m for m in ("navigator.webdriver", "debugger;", "outerwidth - window.innerwidth", "headlesschrome")
                           if m in js_low]

        # Largest embedded image (kits embed brand logos / screenshots as data URIs)
        embedded_img_b64 = None
        best_len = 0
        for img in soup.find_all("img", src=True):
            src = img["src"].strip()
            if src.startswith("data:image/") and "base64," in src:
                data = src.split("base64,", 1)[1]
                if len(data) > best_len:
                    embedded_img_b64, best_len = data, len(data)

        # Evidence fragments (ТЗ 4.1.5.1): the exact HTML/JS that triggered a finding
        evidence = {}
        if soup.title:
            evidence["title"] = compact_html(soup.title)
        pw = soup.find("input", {"type": re.compile(r"^password$", re.I)})
        if pw is not None:
            evidence["password_input"] = compact_html(pw.find_parent("form") or pw)
        if has_telegram:
            evidence["telegram"] = window(html_str, TELEGRAM_ANY)
        if has_discord:
            evidence["discord"] = window(html_str, DISCORD_ANY)
        refresh_tag = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if refresh_tag is not None:
            evidence["meta_refresh"] = compact_html(refresh_tag)
        if js_redirects:
            evidence["js_redirect"] = window(inline_js, JS_REDIRECT, 60, 160)
        if js_external_endpoints:
            evidence["js_endpoint"] = window(inline_js, JS_NETWORK_SINK, 60, 200)
        if obfuscation_markers:
            marker_rx = {"fromCharCode": r'fromCharCode', "packer": r'eval\s*\(\s*function', "unescape_document_write": r'unescape\(',
                         "atob_eval": r'atob\(', "long_base64_blob": LONG_BASE64, "hex_escapes": HEX_ESCAPES}
            evidence["obfuscation"] = window(inline_js, marker_rx[obfuscation_markers[0]], 40, 160)
        if evasion_markers:
            evidence["evasion"] = window(inline_js, re.escape(evasion_markers[0]), 60, 120)

        # the bot token is the attacker's credential: keep the bot id (IOC), mask the secret
        evidence = {k: TELEGRAM_BOT.sub(lambda m: f"api.telegram.org/bot{m.group(1)}:{m.group(2)[:4]}***", v)
                    for k, v in evidence.items() if v}

        headings = " ".join(h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"])[:6])
        brand_context = re.sub(r'\s+', ' ', f"{title} {headings}").strip()[:600]

        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        visible_text = re.sub(r'\s+', ' ', soup.get_text(" ", strip=True))[:4000]

        skel_data = AttachmentParser.extract_dom_skeleton_hash(html_str)

        return {
            "type": "html",
            "title": title[:300],
            "forms": forms_data,
            "forms_count": len(forms_data),
            "has_password_field": bool(password_inputs) or any(f["has_password"] for f in forms_data),
            "has_telegram_exfil": has_telegram,
            "telegram_bot_tokens": tg_tokens,
            "telegram_chat_ids": tg_chat_ids,
            "has_discord_exfil": has_discord,
            "discord_webhooks": sorted({m[:60] for m in DISCORD_WEBHOOK.findall(html_str)}),
            "has_script_obfuscation": len(obfuscation_markers) > 0,
            "obfuscation_markers": obfuscation_markers,
            "has_sandbox_evasion": bool(evasion_markers),
            "evasion_markers": evasion_markers,
            "external_scripts": external_scripts[:50],
            "external_resource_hosts": external_resource_hosts[:50],
            "iframes": iframes[:20],
            "favicon": favicon,
            "meta_refresh": meta_refresh,
            "js_redirects": js_redirects,
            "js_endpoints": js_endpoints,
            "js_external_endpoints": js_external_endpoints,
            "links": sorted(links),
            "embedded_image_base64": embedded_img_b64,
            "visible_text": visible_text,
            "brand_context_text": brand_context,
            "evidence_snippets": evidence,
            "dom_skeleton": skel_data.get("dom_skeleton", ""),
            "dom_structural_hash": skel_data.get("dom_structural_hash"),
            "tags_count": skel_data.get("tags_count", 0)
        }

    # ------------------------------------------------------------------ PDF
    @staticmethod
    def parse_pdf(file_bytes: bytes) -> Dict[str, Any]:
        links = set()
        qr_urls: List[str] = []
        text_content = ""
        has_js = False
        has_launch = False
        has_forms = False
        error = None

        if fitz is not None:
            try:
                doc = fitz.open(stream=file_bytes, filetype="pdf")
                for page_idx in range(min(len(doc), 30)):
                    page = doc[page_idx]
                    text_content += page.get_text() + "\n"
                    for link in page.get_links():
                        uri = link.get("uri")
                        if uri and _is_http(uri):
                            links.add(uri)
                    for img_meta in page.get_images(full=True)[:20]:
                        try:
                            img_bytes = doc.extract_image(img_meta[0]).get("image")
                        except Exception:
                            img_bytes = None
                        if img_bytes:
                            qr_urls.extend(scan_qr_codes(img_bytes))
                    # QR codes drawn as vector graphics: rasterise the first pages.
                    if page_idx < 3:
                        try:
                            pix = page.get_pixmap(dpi=110)
                            qr_urls.extend(scan_qr_codes(pix.tobytes("png")))
                        except Exception:
                            pass
                for i in range(1, min(doc.xref_length(), 5000)):
                    try:
                        obj = doc.xref_object(i)
                    except Exception:
                        continue
                    if "/JavaScript" in obj or re.search(r'/JS\b', obj):
                        has_js = True
                    if "/Launch" in obj:
                        has_launch = True
                    if "/AcroForm" in obj:
                        has_forms = True
                doc.close()
            except Exception as e:
                error = f"PDF parse error: {e}"
        else:
            for m in re.findall(rb'https?://[^\s<>"()]+', file_bytes):
                links.add(m.decode("utf-8", errors="ignore"))
            has_js = b"/JavaScript" in file_bytes or b"/JS" in file_bytes
            has_launch = b"/Launch" in file_bytes

        for m in URL_IN_TEXT.findall(text_content):
            links.add(m.rstrip(".,;"))

        result = {
            "type": "pdf",
            "links": sorted(links),
            "qr_codes": sorted(set(qr_urls)),
            "has_javascript": has_js,
            "has_launch_action": has_launch,
            "has_acroform": has_forms,
            "text_preview": text_content[:1000]
        }
        if error:
            result["error"] = error
        return result

    # --------------------------------------------------------------- Office
    @staticmethod
    def parse_office(file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Detects VBA macros, external relationships, remote templates and QR images in Office OpenXML."""
        has_vba = False
        has_remote_template = False
        links = set()
        qr_urls: List[str] = []
        error = None

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                namelist = zf.namelist()
                has_vba = any(name.lower().endswith("vbaproject.bin") for name in namelist)
                for name in namelist:
                    info = zf.getinfo(name)
                    if info.file_size > 20 * 1024 * 1024:
                        continue  # zip-bomb guard
                    low = name.lower()
                    if low.endswith(".rels"):
                        rels = zf.read(name).decode("utf-8", errors="ignore")
                        for rel in re.finditer(r'<Relationship\b[^>]*>', rels):
                            tag = rel.group(0)
                            target = re.search(r'Target="([^"]+)"', tag)
                            if not target or not _is_http(target.group(1)):
                                continue
                            links.add(target.group(1))
                            if "attachedTemplate" in tag or "oleObject" in tag:
                                has_remote_template = True
                    elif low.endswith(".xml") and ("document" in low or "sheet" in low or "slide" in low or "sharedstrings" in low):
                        xml_text = zf.read(name).decode("utf-8", errors="ignore")
                        for m in URL_IN_TEXT.findall(xml_text):
                            if "schemas.openxmlformats.org" in m or "schemas.microsoft.com" in m or "purl.org" in m or "w3.org" in m:
                                continue
                            links.add(m.rstrip(".,;"))
                    elif "/media/" in low and low.endswith(IMAGE_EXTENSIONS):
                        qr_urls.extend(scan_qr_codes(zf.read(name)))
        except zipfile.BadZipFile:
            error = "Not an Office OpenXML (zip) container"
        except Exception as e:
            error = f"Office parse error: {e}"

        result = {
            "type": "office",
            "filename": filename,
            "has_vba_macros": has_vba,
            "has_remote_template": has_remote_template,
            "links": sorted(links),
            "qr_codes": sorted(set(qr_urls))
        }
        if error:
            result["error"] = error
        return result
