"""
Brand-independent lure signals in the text recognised on an image (OCR), ТЗ п. 4.1.4.3:
"enter your password to view the document" screenshots sent as image attachments.

* credential prompt — the image asks for a password (or for an e-mail together with a sign-in action);
* document gate     — the image offers access to a document / file / invoice (fake document viewer).

Patterns are multilingual (en, ru, zh and common European languages of the corpus) and deterministic.
"""
import re
from typing import Dict, List

PASSWORD = re.compile(
    r"pass\s?word|passcode|credentials?|凭据|凭证|учётн\w*\s+данн|учетн\w*\s+данн|пароль|密码|密碼|passwort|kennwort|mot\s+de\s+passe|contrase[ñn]a|senha|wachtwoord|heslo|"
    r"has[łl]o|parola|salasana|l[öo]senord", re.I)
SIGN_IN = re.compile(
    r"sign\s?-?\s?in|log\s?-?\s?in|log\s?on|verify\s+(?:your\s+)?(?:e-?mail|account|identity)|войти|вход|авториз|"
    r"登录|登入|登陆|验证|anmelden|connexion|iniciar\s+sesi[óo]n|accedi|inloggen|přihlás", re.I)
EMAIL_FIELD = re.compile(r"e-?mail|邮箱|邮件|почт|[\w.+-]+@[\w-]+\.[\w.]+", re.I)
DOC_ACTION = re.compile(
    r"\b(?:view|open|access|download|preview|read|review|unlock)\b|просмотр|открыть|доступ|скачать|查看|打开|下载|"
    r"anzeigen|öffnen|afficher|ouvrir|ver\b|visualizar|bekijken|zobrazit", re.I)
DOC_OBJECT = re.compile(
    r"document|file|invoice|attachment|\bpdf\b|xlsx?|excel|\bdocx?\b|spreadsheet|statement|remittance|contract|"
    r"purchase\s+order|\bP\.?O\b|bill\s+of\s+lading|\bAWB\b|shipment|parcel|onedrive|sharepoint|docusign|"
    r"документ|файл|сч[её]т|накладн|договор|文件|表格|文档|附件|订单|发票|合同|"
    r"dokument|datei|rechnung|fichier|facture|archivo|factura|bestand|soubor|faktura", re.I)
PROTECTED = re.compile(
    r"protected\s+(?:file|document)|to\s+view\s+(?:this|the)\s+(?:file|document)|authenticat\w*\s+required|"
    r"login\s+to\s+continue|confirm\s+(?:your\s+)?(?:e-?mail|identity)\s+to|登录以查看|защищ[её]н\w*\s+(?:файл|документ)|要查看|请验证", re.I)


def _snippets(text: str, patterns: List[re.Pattern], width: int = 45, limit: int = 3) -> List[str]:
    out: List[str] = []
    for pat in patterns:
        for m in pat.finditer(text):
            s = text[max(0, m.start() - width): m.end() + width].strip()
            if not any(s in o or o in s for o in out):
                out.append(s)
            if len(out) >= limit:
                return out
    return out


def image_lure_signals(text: str) -> Dict[str, object]:
    """{'credential_prompt': bool, 'document_gate': bool, 'snippets': [...]} for OCR text of one image."""
    text = " ".join((text or "").split())
    if len(text) < 6:
        return {"credential_prompt": False, "document_gate": False, "snippets": []}
    password = bool(PASSWORD.search(text))
    document = bool(PROTECTED.search(text)) or (bool(DOC_ACTION.search(text)) and bool(DOC_OBJECT.search(text)))
    # sign-in wording counts when the image also shows an e-mail field or gates a document behind it
    credential = password or (bool(SIGN_IN.search(text)) and (bool(EMAIL_FIELD.search(text)) or document))
    snippets = _snippets(text, [PROTECTED, PASSWORD, SIGN_IN, DOC_OBJECT]) if (credential or document) else []
    return {"credential_prompt": credential, "document_gate": credential and document, "snippets": snippets}
