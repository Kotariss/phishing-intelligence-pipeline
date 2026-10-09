import ipaddress
import re
import unicodedata
from typing import Optional
from urllib.parse import urlparse, urlunparse

FREE_HOSTING_SUFFIXES = (
    "pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com", "github.io", "glitch.me",
    "netlify.app", "vercel.app", "herokuapp.com", "onrender.com", "repl.co", "weebly.com",
    "wixsite.com", "blogspot.com", "sites.google.com", "000webhostapp.com", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "ipfs.io", "dweb.link", "w3s.link", "cloudflare-ipfs.com", "fleek.co",
    "webflow.io", "framer.app", "godaddysites.com", "square.site", "mystrikingly.com", "tilda.ws",
    "storage.googleapis.com", "blob.core.windows.net", "s3.amazonaws.com", "appspot.com",
    "run.app", "azurewebsites.net", "web.core.windows.net", "firebasestorage.googleapis.com",
    "translate.goog", "notion.site", "canva.site", "wordpress.com", "carrd.co", "jimdosite.com",
)

# Shared infrastructure: never usable as a domain-level IOC (would block everything that uses it).
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "ok.me", "clck.ru", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly", "t.ly",
    "ow.ly", "buff.ly", "lnkd.in", "vk.cc", "vk.com", "trk.mail.ru", "mail.ru", "google.com", "search.app",
    "microsoftonline.com", "facebook.com", "linktr.ee", "qrco.de", "s.id", "shorturl.at", "rb.gy",
}

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "ne.jp", "or.jp", "go.jp",
    "ac.jp", "com.br", "com.cn", "com.tr", "co.in", "com.mx", "com.ru", "net.ru", "org.ru", "msk.ru",
    "spb.ru", "com.ua", "co.kr", "com.sg", "co.za",
}


def hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def registrable_domain(host: str) -> str:
    """eTLD+1 using a small list of multi-part public suffixes."""
    parts = [p for p in (host or "").lower().split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r'0x[0-9a-f]+|\d{8,10}', host or ""))  # hex / dword IP encodings


def free_hosting_suffix(host: str) -> Optional[str]:
    for suffix in FREE_HOSTING_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None


def is_shared_infrastructure(host: str) -> bool:
    host = (host or "").lower()
    site = registrable_domain(host)
    return site in SHORTENER_DOMAINS or host in SHORTENER_DOMAINS or free_hosting_suffix(host) is not None


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "OTHER"
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CJK", "HIRAGANA", "KATAKANA", "HANGUL"):
        if name.startswith(script):
            return script
    return "OTHER"


def homograph_label(host: str) -> Optional[str]:
    """Returns the decoded IDN label if it mixes Latin with another confusable script
    (e.g. 'sbеrbank' with Cyrillic 'е'). Pure national IDNs like 'госуслуги.рф' are NOT flagged."""
    for label in (host or "").split("."):
        if not label.startswith("xn--"):
            continue
        try:
            decoded = label.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            return label  # undecodable punycode is itself suspicious
        scripts = {_script_of(c) for c in decoded if c.isalpha()}
        scripts.discard("OTHER")
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK", "ARMENIAN"}:
            return decoded
    return None


def generalize_path(path: str) -> Optional[str]:
    """Turns a concrete URL path into a host-independent regex template:
    /secure/login/8f3a9c0d2b1e4f5a/index.php -> ^/secure/login/[A-Za-z0-9_-]{16,}/index\\.php
    Returns None when the path is too generic to be a useful indicator."""
    segments = [s for s in (path or "").split("/") if s]
    if not segments:
        return None
    out = []
    informative = 0
    for seg in segments[:8]:
        if re.fullmatch(r'\d+', seg):
            out.append(r'\d+')
        elif re.fullmatch(r'[A-Za-z0-9_-]{16,}', seg) and re.search(r'\d', seg) and re.search(r'[A-Za-z]', seg):
            out.append(r'[A-Za-z0-9_-]{16,}')
        else:
            out.append(re.escape(seg))
            informative += 1
    if informative == 0 or (len(segments) == 1 and informative == 1 and not re.search(r'\.(php|aspx?|jsp|cgi)$', segments[0], re.I)):
        return None
    return "^/" + "/".join(out)


_EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
_URL_IN_TEXT = re.compile(r'https?://[^\s<>"\')\]]+')


def mask_url(url: str) -> str:
    """Masks tokens / personal data in URLs for reports and packages (ТЗ п. 4.5.2.3)."""
    try:
        p = urlparse(url)
    except ValueError:
        return "<unparseable>"
    query = "&".join(f"{kv.split('=', 1)[0]}=***" if "=" in kv else "***" for kv in p.query.split("&") if kv) if p.query else ""
    fragment = "***" if p.fragment else ""
    path = _EMAIL.sub("***@***", p.path)
    path = re.sub(r'(?<=/)[A-Za-z0-9_-]{24,}(?=/|$)', "***", path)
    return urlunparse((p.scheme, p.netloc, path, "", query, fragment))


def mask_urls_in_text(text: str) -> str:
    return _URL_IN_TEXT.sub(lambda m: mask_url(m.group(0)), text or "")
