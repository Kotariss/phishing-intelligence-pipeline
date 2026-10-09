import io
import re
import os
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
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

class AttachmentParser:
    """Safe, offline multi-format parser for EML, HTML, PDF, Office documents."""

    @staticmethod
    def _decode_header_str(header_val: Any) -> str:
        if not header_val:
            return ""
        from email.header import decode_header
        decoded_parts = []
        try:
            for part, enc in decode_header(str(header_val)):
                if isinstance(part, bytes):
                    decoded_parts.append(part.decode(enc or "utf-8", errors="ignore"))
                else:
                    decoded_parts.append(str(part))
            return "".join(decoded_parts).strip()
        except Exception:
            return str(header_val).strip()

    @staticmethod
    def parse_eml(file_bytes: bytes) -> Dict[str, Any]:
        msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

        from_header = AttachmentParser._decode_header_str(msg.get("From", ""))
        subject = AttachmentParser._decode_header_str(msg.get("Subject", ""))
        to_header = AttachmentParser._decode_header_str(msg.get("To", ""))
        date_header = str(msg.get("Date", ""))
        reply_to = AttachmentParser._decode_header_str(msg.get("Reply-To", ""))
        auth_results = str(msg.get("Authentication-Results", ""))
        spf_header = str(msg.get("Received-SPF", ""))


        # Extract sender name and domain
        from_name = ""
        from_address = ""
        from_domain = ""
        if "<" in from_header and ">" in from_header:
            from_name = from_header.split("<")[0].strip().strip('"').strip("'")
            from_address = from_header.split("<")[1].split(">")[0].strip()
        else:
            from_address = from_header.strip()

        if "@" in from_address:
            from_domain = from_address.split("@")[1].lower().strip()

        # Parse body and attachments
        body_text = ""
        body_html = ""
        attachments = []
        links = set()

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                if "attachment" in content_disposition or filename:
                    payload = part.get_payload(decode=True)
                    if payload:
                        attachments.append({
                            "filename": filename or "unknown_attachment",
                            "content_type": content_type,
                            "size_bytes": len(payload),
                            "bytes": payload
                        })
                elif content_type == "text/plain":
                    try:
                        body_text += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        body_html += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                    except Exception:
                        pass
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
                if content_type == "text/html":
                    body_html = text
                else:
                    body_text = text

        # Extract links from HTML and text
        if body_html:
            soup = BeautifulSoup(body_html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith("http://") or href.startswith("https://"):
                    links.add(href)
        
        for raw_url in re.findall(r'https?://[^\s<>"]+', body_text):
            links.add(raw_url.strip())

        # Check SPF / DKIM auth flags
        spf_pass = "spf=pass" in auth_results.lower() or "pass" in spf_header.lower()
        spf_fail = "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower() or "fail" in spf_header.lower()

        return {
            "type": "eml",
            "from_name": from_name,
            "from_address": from_address,
            "from_domain": from_domain,
            "subject": subject,
            "to": to_header,
            "reply_to": reply_to,
            "date": date_header,
            "spf_pass": spf_pass,
            "spf_fail": spf_fail,
            "links": sorted(list(links)),
            "body_html": body_html,
            "body_text_preview": body_text[:500] if body_text else "",
            "attachments_count": len(attachments),
            "attachments_meta": [{"filename": a["filename"], "content_type": a["content_type"], "size": a["size_bytes"]} for a in attachments],
            "raw_attachments": attachments
        }

    @staticmethod
    def extract_dom_skeleton_hash(html_str: str) -> Dict[str, Any]:
        """
        Extracts structural DOM skeleton (tag hierarchy stripped of text, inline styles, IDs and comments)
        and computes normalized structural hash (dom_skel_<hash>) to identify phishing kit reuse.
        """
        import hashlib
        try:
            soup = BeautifulSoup(html_str, "html.parser")

            def _traverse(node) -> List[str]:
                tag_reprs = []
                for child in node.find_all(recursive=False):
                    tag_name = child.name
                    if not tag_name:
                        continue
                    # Normalize common resource and non-structural tags
                    if tag_name in ("script", "style", "svg", "noscript", "meta", "link"):
                        tag_reprs.append(tag_name)
                        continue
                    if tag_name == "input":
                        inp_type = child.get("type", "text").lower().strip()
                        tag_reprs.append(f"input:{inp_type}")
                    elif tag_name in ("button", "a"):
                        tag_reprs.append(tag_name)
                    else:
                        inner = _traverse(child)
                        if inner:
                            tag_reprs.append(f"{tag_name}({','.join(inner)})")
                        else:
                            tag_reprs.append(tag_name)
                return tag_reprs

            target_node = soup.body if soup.body else soup
            skeleton_parts = _traverse(target_node)
            skeleton_str = ">".join(skeleton_parts) if skeleton_parts else "empty_dom"

            skel_hash = hashlib.sha256(skeleton_str.encode("utf-8")).hexdigest()[:16]
            total_tags = len(soup.find_all())

            return {
                "dom_skeleton": skeleton_str[:500],
                "dom_structural_hash": f"dom_skel_{skel_hash}",
                "tags_count": total_tags
            }
        except Exception:
            return {
                "dom_skeleton": "",
                "dom_structural_hash": "dom_skel_0000000000000000",
                "tags_count": 0
            }

    @staticmethod
    def parse_html(html_str: str, base_url: str = "") -> Dict[str, Any]:
        soup = BeautifulSoup(html_str, "html.parser")

        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        forms_data = []
        
        # Analyze forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            
            has_password = bool(form.find("input", {"type": re.compile(r"password", re.I)}))
            has_email = bool(form.find("input", {"type": re.compile(r"(email|text)", re.I)}))
            has_card = bool(form.find("input", {"name": re.compile(r"(card|cvv|pan|cc)", re.I)}))

            # Submit button inspection
            submit_btn = form.find(["button", "input"], {"type": re.compile(r"submit", re.I)}) or form.find("button")
            submit_meta = {}
            if submit_btn:
                submit_text = submit_btn.get_text(strip=True) if submit_btn.name == "button" else submit_btn.get("value", "")
                onclick = submit_btn.get("onclick", "")
                submit_meta = {
                    "text": submit_text,
                    "onclick": onclick,
                    "has_telegram": "api.telegram.org" in onclick,
                    "target_url": action
                }

            forms_data.append({
                "action": action,
                "method": method,
                "has_password": has_password,
                "has_email": has_email,
                "has_card": has_card,
                "is_external": bool(action.startswith("http://") or action.startswith("https://")),
                "submit_button": submit_meta
            })

        # Obfuscation & exfiltration indicators
        html_lower = html_str.lower()
        has_telegram = "api.telegram.org/bot" in html_lower
        has_discord = "discord.com/api/webhooks" in html_lower or "discordapp.com/api/webhooks" in html_lower
        has_fromcharcode = "string.fromcharcode" in html_lower
        has_packer = "eval(function(p,a,c,k" in html_lower
        has_atob = "atob(" in html_lower
        has_webdriver_check = "navigator.webdriver" in html_lower or "devtools" in html_lower

        # Extract links
        links = set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("http://") or href.startswith("https://"):
                links.add(href)

        # External scripts
        external_scripts = []
        for s in soup.find_all("script", src=True):
            external_scripts.append(s["src"])

        # Extract embedded data:image base64 if present
        embedded_img_b64 = None
        for img in soup.find_all("img", src=True):
            src = img["src"].strip()
            if src.startswith("data:image/") and "base64," in src:
                embedded_img_b64 = src.split("base64,")[1]
                break

        # Compute DOM Skeleton and Structural Hash
        skel_data = AttachmentParser.extract_dom_skeleton_hash(html_str)

        return {
            "type": "html",
            "title": title,
            "forms": forms_data,
            "forms_count": len(forms_data),
            "has_password_field": any(f["has_password"] for f in forms_data) or 'type="password"' in html_lower,
            "has_telegram_exfil": has_telegram,
            "has_discord_exfil": has_discord,
            "has_script_obfuscation": bool(has_fromcharcode or has_packer or (has_atob and len(html_str) > 200)),
            "has_sandbox_evasion": has_webdriver_check,
            "external_scripts": external_scripts,
            "links": sorted(list(links)),
            "screenshot_base64": embedded_img_b64,
            "dom_skeleton": skel_data.get("dom_skeleton", ""),
            "dom_structural_hash": skel_data.get("dom_structural_hash", "dom_skel_0000000000000000"),
            "tags_count": skel_data.get("tags_count", 0)
        }

    @staticmethod
    def parse_pdf(file_bytes: bytes) -> Dict[str, Any]:
        links = set()
        qr_urls = []
        text_content = ""
        has_js = False

        if fitz is not None:
            try:
                doc = fitz.open(stream=file_bytes, filetype="pdf")
                for page_idx in range(len(doc)):
                    page = doc[page_idx]
                    text_content += page.get_text() + "\n"

                    # Extract page links
                    for link in page.get_links():
                        uri = link.get("uri")
                        if uri and (uri.startswith("http://") or uri.startswith("https://")):
                            links.add(uri)

                    # Extract images for QR code scanning
                    image_list = page.get_images(full=True)
                    for img_meta in image_list:
                        xref = img_meta[0]
                        base_image = doc.extract_image(xref)
                        img_bytes = base_image.get("image")
                        if img_bytes:
                            detected_qr = scan_qr_codes(img_bytes)
                            qr_urls.extend(detected_qr)

                # Check for PDF JavaScript streams
                for i in range(doc.xref_length()):
                    try:
                        obj = doc.xref_object(i)
                        if "/JavaScript" in obj or "/JS" in obj or "/Launch" in obj:
                            has_js = True
                            break
                    except Exception:
                        pass
                doc.close()
            except Exception as e:
                text_content += f" [PDF parse error: {e}]"
        else:
            # Fallback regex extraction from raw bytes
            for m in re.findall(rb'https?://[^\s<>"]+', file_bytes):
                try:
                    links.add(m.decode("utf-8", errors="ignore"))
                except Exception:
                    pass
            if b"/JavaScript" in file_bytes or b"/JS" in file_bytes:
                has_js = True

        for m in re.findall(r'https?://[^\s<>"]+', text_content):
            links.add(m)

        return {
            "type": "pdf",
            "links": sorted(list(links)),
            "qr_codes": sorted(list(set(qr_urls))),
            "has_javascript": has_js,
            "text_preview": text_content[:500]
        }

    @staticmethod
    def parse_office(file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Detects VBA macros and extracts external relationships from Office OpenXML."""
        has_vba = False
        links = set()
        
        # Check for macro markers in zip
        try:
            import zipfile
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                namelist = zf.namelist()
                if any("vbaProject.bin" in name for name in namelist):
                    has_vba = True
                
                # Extract external target URLs from .rels files
                for name in namelist:
                    if name.endswith(".rels"):
                        rels_content = zf.read(name).decode("utf-8", errors="ignore")
                        for target in re.findall(r'Target="(https?://[^"]+)"', rels_content):
                            links.add(target)
        except Exception:
            pass

        return {
            "type": "office",
            "filename": filename,
            "has_vba_macros": has_vba,
            "links": sorted(list(links))
        }
